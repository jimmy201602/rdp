// Package gateway is the G3-3 authorization gateway: it accepts a real RDP
// client with the server role (package server), asks a caller-supplied
// Route policy which target the client may reach, dials the target with the
// client role (transport.Dial) passing the Client Info credentials through
// once, then relays the session. Capability sets are filtered through an
// allow-list in both directions (Demand Active / Confirm Active are decoded
// and re-encoded, everything else is forwarded as received); fast-path
// frames are forwarded unchanged; client input is decoded for counting
// only (keystroke codes are never logged). Static virtual channels the
// client requests are opened towards the target when AllowChannel admits
// them and their chunks are relayed unchanged (CHANNEL_PDU_HEADER included)
// with the MCS channel ID mapped between the two sides; data for channels
// the policy refused is dropped. Either side closing or failing closes the
// other and frees the session.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"rdp.local/kernel/server"
	"rdp.local/kernel/transport"
	"rdp.local/kernel/wire"
)

// Errors reported in server.Summary.Err for gateway sessions.
var (
	ErrBackend  = errors.New("rdp gateway: target connection failed")
	ErrRelay    = errors.New("rdp gateway: relay protocol error")
	ErrNoTarget = errors.New("rdp gateway: no target for client")
)

// Target is the backend a Route decision points to.
type Target struct {
	NLA           bool           // require CredSSP/NTLMv2 towards the target (independent of front-end NLA)
	LegacyCredSSP bool           // with NLA: also accept CredSSP 2-4 (unpatched Windows 7 / 2008 R2, CVE-2018-0886); pair with PinSHA256
	Address       string         // host:port
	ServerName    string         // TLS name to verify (default: host of Address)
	RootCAs       *x509.CertPool // nil: system roots
	PinSHA256     string         // hex SHA-256 of the target leaf certificate; replaces chain/name verification (self-signed RDP hosts)
	MinTLS        uint16         // lowest TLS version accepted from the target (0: TLS 1.2; Windows 7 needs tls.VersionTLS10)
	Timeout       time.Duration  // backend handshake budget (default 20s)
}

// Config configures a Gateway.
type Config struct {
	// TLS is the front-end server certificate.
	TLS *tls.Config
	// Route decides, for a peer (no password), which target it may reach.
	// Returning an error denies the client with
	// ERRINFO_SERVER_DENIED_CONNECTION. Required unless Form is set.
	Route func(ctx context.Context, p server.Peer) (Target, error)
	// Form, when set, shows every client an interactive logon form and
	// dials the server the user typed instead of calling Route.
	Form *FormConfig
	// NLA enables CredSSP on the front end (see server.Config.NLA): the
	// identity proven by NTLMv2 reaches Route in Peer and the credentials
	// the client delegated are what the target receives. RequireNLA refuses
	// clients that only offer TLS.
	NLA        func(user, domain string) (password string, ok bool)
	RequireNLA bool
	// AllowCapability filters capability set types relayed in Demand /
	// Confirm Active. nil uses DefaultAllowCapability.
	AllowCapability func(typ uint16) bool
	// AllowChannel decides which static virtual channels requested by the
	// client (by name, e.g. "cliprdr", "rdpdr", "rdpsnd", "drdynvc") are
	// opened towards the target. nil admits all of them.
	AllowChannel func(name string) bool
	// HandshakeTimeout bounds the front-end handshake (default 30s).
	HandshakeTimeout time.Duration
	// MaxSessions limits concurrent client connections (default 64).
	MaxSessions int
	// Logf receives state transitions; credentials and keystrokes never
	// appear.
	Logf func(format string, args ...any)
	// Trace additionally logs the type of every slow-path share PDU relayed
	// in either direction (never their contents), for protocol debugging.
	Trace bool
	// OnSession reports every finished front-end connection.
	OnSession func(s server.Summary)
	// OnRelay reports every relayed session (after the target was dialed).
	OnRelay func(r Summary)
}

// Summary describes one relayed session.
type Summary struct {
	RemoteAddr          net.Addr
	UserName, Domain    string
	ClientName          string
	NLA                 bool // front-end identity proven by CredSSP
	Target              string
	ClientPDUs          int // slow-path PDUs client -> target
	ClientFastPath      int // fast-path input frames
	ServerPDUs          int // slow-path PDUs target -> client
	ServerFastPath      int // fast-path output frames
	ClientBytes         int64
	ServerBytes         int64
	InputEvents         map[string]int
	DroppedCapabilities map[uint16]int
	ChannelPDUs         map[string]int // relayed chunks per channel name (both directions)
	DroppedChannels     map[string]int // chunks dropped on channels the policy refused
	Reactivations       int
	LoginForm           bool   // target and credentials came from the logon form
	FormAttempts        int    // connection attempts made from the form (1 = first try)
	End                 string // "client-closed", "target-closed", "canceled", "error"
	Err                 error
	Duration            time.Duration
}

// DefaultAllowCapability admits the capability sets the relay understands
// enough to pass through: core, caches, pointer, input, fonts, virtual
// channel sizing, large pointer and multifragment. Codecs, surface
// commands, frame acknowledge, RAIL/window, nine-grid, GDI+ and desktop
// composition are dropped so that neither side enables them.
func DefaultAllowCapability(typ uint16) bool {
	switch typ {
	case wire.CapsTypeGeneral, wire.CapsTypeBitmap, wire.CapsTypeOrder, wire.CapsTypeBitmapCache,
		wire.CapsTypeControl, wire.CapsTypeActivation, wire.CapsTypePointer, wire.CapsTypeShare,
		wire.CapsTypeColorCache, wire.CapsTypeSound, wire.CapsTypeInput, wire.CapsTypeFont,
		wire.CapsTypeBrush, wire.CapsTypeGlyphCache, wire.CapsTypeOffscreenCache,
		wire.CapsTypeBitmapCacheHostSupport, wire.CapsTypeBitmapCacheRev2, wire.CapsTypeVirtualChannel,
		wire.CapsTypeLargePointer, wire.CapsTypeMultifragmentUpdate:
		return true
	}
	return false
}

// Gateway serves clients and relays them to routed targets.
type Gateway struct {
	cfg Config
	srv *server.Server
}

// New validates cfg and builds the front-end server.
func New(cfg Config) (*Gateway, error) {
	if cfg.Form != nil {
		if cfg.Form.Route == nil {
			return nil, fmt.Errorf("%w: Form.Route policy required", server.ErrConfig)
		}
		fc := *cfg.Form
		if fc.Attempts <= 0 {
			fc.Attempts = 5
		}
		if fc.IdleTimeout <= 0 {
			fc.IdleTimeout = 5 * time.Minute
		}
		cfg.Form = &fc
	} else if cfg.Route == nil {
		return nil, fmt.Errorf("%w: Route policy required", server.ErrConfig)
	}
	if cfg.AllowCapability == nil {
		cfg.AllowCapability = DefaultAllowCapability
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	g := &Gateway{cfg: cfg}
	srv, err := server.New(server.Config{
		TLS:              cfg.TLS,
		NLA:              cfg.NLA,
		RequireNLA:       cfg.RequireNLA,
		Handler:          g.handle,
		HandshakeTimeout: cfg.HandshakeTimeout,
		MaxSessions:      cfg.MaxSessions,
		Logf:             cfg.Logf,
		OnSession:        cfg.OnSession,
	})
	if err != nil {
		return nil, err
	}
	g.srv = srv
	return g, nil
}

// Serve accepts clients on ln until ctx is done.
func (g *Gateway) Serve(ctx context.Context, ln net.Listener) error { return g.srv.Serve(ctx, ln) }

func (g *Gateway) handle(ctx context.Context, c *server.Conn) error {
	if g.cfg.Form != nil {
		return g.handleForm(ctx, c)
	}
	peer := c.Peer()
	target, err := g.cfg.Route(ctx, peer)
	if err != nil {
		g.cfg.Logf("%s: route denied user %q client %q: %v", peer.RemoteAddr, peer.UserName, peer.ClientName, err)
		_ = c.Deny(wire.ErrInfoServerDeniedConnection)
		return fmt.Errorf("%w: %v", server.ErrDenied, err)
	}
	if target.Address == "" {
		_ = c.Deny(wire.ErrInfoServerDeniedConnection)
		return ErrNoTarget
	}
	c.MarkAuthorized()
	if target.Timeout <= 0 {
		target.Timeout = 20 * time.Second
	}
	depth := peer.ColorDepth
	switch depth {
	case 15, 16, 24:
	default:
		depth = 24
	}
	channels := newChannelMap(c, g.cfg.AllowChannel)
	creds := c.Credentials()
	opts := transport.Options{
		NLA: target.NLA, LegacyCredSSP: target.LegacyCredSSP, ServerName: target.ServerName, RootCAs: target.RootCAs, PinSHA256: target.PinSHA256, MinTLSVersion: target.MinTLS, Timeout: target.Timeout,
		ClientName: peer.ClientName, DesktopWidth: peer.DesktopWidth, DesktopHeight: peer.DesktopHeight, ColorDepth: depth,
		Channels: channels.defs,
		Domain:   creds.Domain, UserName: creds.UserName, Password: creds.Password,
	}
	creds = server.Credentials{}
	_ = creds
	backend, err := transport.Dial(ctx, target.Address, opts)
	opts = transport.Options{}
	_ = opts
	if err != nil {
		g.cfg.Logf("%s: target %s failed at handshake: %v", peer.RemoteAddr, target.Address, err)
		_ = c.Deny(wire.ErrInfoServerDeniedConnection)
		return fmt.Errorf("%w: %s: %v", ErrBackend, target.Address, err)
	}
	channels.bind(backend.StaticChannels())
	g.cfg.Logf("%s: target %s licensed (user channel %d, channels %v), relaying", peer.RemoteAddr, target.Address, backend.UserChannel(), channels.names())
	r := &relay{g: g, client: c, backend: backend, channels: channels, sum: Summary{
		RemoteAddr: peer.RemoteAddr, UserName: peer.UserName, Domain: peer.Domain, ClientName: peer.ClientName, NLA: peer.NLA,
		Target: target.Address, InputEvents: map[string]int{}, DroppedCapabilities: map[uint16]int{},
		ChannelPDUs: map[string]int{}, DroppedChannels: map[string]int{},
	}}
	return r.run(ctx)
}

// channelMap pairs the static channels the client requested with the ones
// opened towards the target.
type channelMap struct {
	defs        []wire.ChannelDef // requested from the target, in order
	frontIDs    []uint16          // client-side IDs of defs
	frontNames  map[uint16]string // every client channel, admitted or not
	frontToBack map[uint16]uint16
	backToFront map[uint16]uint16
	backToName  map[uint16]string
}

func newChannelMap(c *server.Conn, allow func(string) bool) *channelMap {
	m := &channelMap{frontNames: map[uint16]string{}, frontToBack: map[uint16]uint16{}, backToFront: map[uint16]uint16{}, backToName: map[uint16]string{}}
	ids := c.ChannelIDs()
	for i, def := range c.Channels() {
		m.frontNames[ids[i]] = def.Name
		if allow == nil || allow(def.Name) {
			m.defs = append(m.defs, def)
			m.frontIDs = append(m.frontIDs, ids[i])
		}
	}
	return m
}

func (m *channelMap) bind(backIDs []uint16) {
	for i, back := range backIDs {
		if i >= len(m.frontIDs) {
			break
		}
		m.frontToBack[m.frontIDs[i]] = back
		m.backToFront[back] = m.frontIDs[i]
		m.backToName[back] = m.defs[i].Name
	}
}

func (m *channelMap) names() []string {
	names := make([]string, len(m.defs))
	for i, d := range m.defs {
		names[i] = d.Name
	}
	return names
}

type relay struct {
	g        *Gateway
	client   *server.Conn
	backend  *transport.Session
	channels *channelMap
	// dropInput discards client input until the client's Confirm Active
	// has been relayed: after the logon form's Deactivate All, key releases
	// already in flight must not reach the target before it is active.
	dropInput bool
	// firstServer is a target PDU already read (the Demand Active the logon
	// form waited for) that targetToClient forwards before reading more.
	firstServer *transport.PDU
	mu          sync.Mutex
	sum         Summary
}

type relayEnd struct {
	end string
	err error
}

func (r *relay) run(ctx context.Context) error {
	start := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		_ = r.backend.Close()
		_ = r.client.Close()
	})
	defer stop()
	results := make(chan relayEnd, 2)
	go func() { results <- r.clientToTarget() }()
	go func() { results <- r.targetToClient() }()
	first := <-results
	parentDone := ctx.Err() != nil
	switch first.end {
	case "client-closed":
		_ = r.backend.Disconnect()
	case "target-closed":
		_ = r.client.Disconnect(wire.DisconnectReasonProviderInit)
	}
	cancel()
	<-results
	r.mu.Lock()
	r.sum.Duration = time.Since(start)
	r.sum.End, r.sum.Err = first.end, first.err
	if parentDone {
		r.sum.End, r.sum.Err = "canceled", nil
	}
	sum := r.sum
	r.mu.Unlock()
	r.g.cfg.Logf("%s: relay to %s ended (%s): client %d pdus + %d fast-path, target %d pdus + %d fast-path, input %v, dropped caps %v, channels %v, dropped channels %v, reactivations %d",
		sum.RemoteAddr, sum.Target, sum.End, sum.ClientPDUs, sum.ClientFastPath, sum.ServerPDUs, sum.ServerFastPath,
		sum.InputEvents, sum.DroppedCapabilities, sum.ChannelPDUs, sum.DroppedChannels, sum.Reactivations)
	if r.g.cfg.OnRelay != nil {
		r.g.cfg.OnRelay(sum)
	}
	return sum.Err
}

func (r *relay) trace(dir string, pduType uint16, data []byte) {
	if !r.g.cfg.Trace {
		return
	}
	if pduType == wire.PDUTypeData {
		if sh, _, err := wire.DecodeShareData(data); err == nil {
			r.g.cfg.Logf("%s: %s data pduType2 0x%02x (%d bytes)", r.sum.RemoteAddr, dir, sh.PDUType2, len(data))
			return
		}
	}
	r.g.cfg.Logf("%s: %s share control pduType %d (%d bytes)", r.sum.RemoteAddr, dir, pduType, len(data))
}

func closedErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}

func (r *relay) clientToTarget() relayEnd {
	for {
		pdu, err := r.client.ReadPDU()
		if err != nil {
			if closedErr(err) {
				return relayEnd{end: "client-closed"}
			}
			return relayEnd{end: "error", err: fmt.Errorf("client: %w", err)}
		}
		r.mu.Lock()
		r.sum.ClientBytes += int64(len(pdu.Data))
		r.mu.Unlock()
		if pdu.FastPath {
			events, err := wire.DecodeFastPathInput(pdu.Data)
			if err != nil {
				return relayEnd{end: "error", err: fmt.Errorf("%w: %v", ErrRelay, err)}
			}
			if r.dropInput {
				continue
			}
			r.countInput(events)
			r.mu.Lock()
			r.sum.ClientFastPath++
			r.mu.Unlock()
			if err := r.backend.WriteFastPath(pdu.Data); err != nil {
				return relayEnd{end: "target-closed"}
			}
			continue
		}
		if pdu.Channel != 0 {
			back, ok := r.channels.frontToBack[pdu.Channel]
			name := r.channels.frontNames[pdu.Channel]
			r.mu.Lock()
			if ok {
				r.sum.ChannelPDUs[name]++
			} else {
				r.sum.DroppedChannels[name]++
			}
			r.mu.Unlock()
			if !ok {
				continue
			}
			if err := r.backend.WriteChannel(back, pdu.Data); err != nil {
				return relayEnd{end: "target-closed"}
			}
			continue
		}
		out, err := r.rewriteClientPDU(pdu.Data)
		if err != nil {
			return relayEnd{end: "error", err: err}
		}
		if out == nil {
			continue
		}
		r.mu.Lock()
		r.sum.ClientPDUs++
		r.mu.Unlock()
		if err := r.backend.WriteIO(out); err != nil {
			return relayEnd{end: "target-closed"}
		}
	}
}

// rewriteClientPDU re-encodes Confirm Active (filtered capabilities, the
// target's user channel as pduSource) and patches pduSource on the other
// Share Control PDUs; input PDUs are decoded for counting.
func (r *relay) rewriteClientPDU(data []byte) ([]byte, error) {
	hdr, _, err := wire.DecodeShareControl(data)
	if err != nil {
		return nil, fmt.Errorf("%w: client share control: %v", ErrRelay, err)
	}
	r.trace("client -> target", hdr.PDUType, data)
	switch hdr.PDUType {
	case wire.PDUTypeConfirmActive:
		ca, err := wire.DecodeConfirmActive(data)
		if err != nil {
			return nil, fmt.Errorf("%w: confirm active: %v", ErrRelay, err)
		}
		caps := r.filterCaps(ca.Capabilities)
		r.dropInput = false
		return wire.EncodeConfirmActive(ca.ShareID, r.backend.UserChannel(), strings.TrimRight(string(ca.SourceDescriptor), "\x00"), caps)
	case wire.PDUTypeData:
		sh, body, err := wire.DecodeShareData(data)
		if err != nil {
			return nil, fmt.Errorf("%w: client share data: %v", ErrRelay, err)
		}
		if sh.PDUType2 == wire.PDUType2Input {
			if r.dropInput {
				return nil, nil
			}
			events, err := wire.DecodeInputPDU(body)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrRelay, err)
			}
			r.countInput(events)
		}
	}
	out := append([]byte(nil), data...)
	user := r.backend.UserChannel()
	out[4], out[5] = byte(user), byte(user>>8)
	return out, nil
}

func (r *relay) targetToClient() relayEnd {
	pending := r.firstServer
	r.firstServer = nil
	for {
		var pdu transport.PDU
		if pending != nil {
			pdu, pending = *pending, nil
		} else {
			var err error
			if pdu, err = r.backend.ReadPDU(); err != nil {
				if errors.Is(err, transport.ErrDisconnected) || closedErr(err) {
					return relayEnd{end: "target-closed"}
				}
				return relayEnd{end: "error", err: fmt.Errorf("target: %w", err)}
			}
		}
		r.mu.Lock()
		r.sum.ServerBytes += int64(len(pdu.Data))
		r.mu.Unlock()
		if pdu.FastPath {
			r.mu.Lock()
			r.sum.ServerFastPath++
			r.mu.Unlock()
			if err := r.client.WriteFastPath(pdu.Data); err != nil {
				return relayEnd{end: "client-closed"}
			}
			continue
		}
		if pdu.Channel != 0 {
			front, ok := r.channels.backToFront[pdu.Channel]
			if !ok {
				return relayEnd{end: "error", err: fmt.Errorf("%w: target data on unmapped channel %d", ErrRelay, pdu.Channel)}
			}
			r.mu.Lock()
			r.sum.ChannelPDUs[r.channels.backToName[pdu.Channel]]++
			r.mu.Unlock()
			if err := r.client.WriteChannel(front, pdu.Data); err != nil {
				return relayEnd{end: "client-closed"}
			}
			continue
		}
		out, err := r.rewriteServerPDU(pdu.Data)
		if err != nil {
			return relayEnd{end: "error", err: err}
		}
		r.mu.Lock()
		r.sum.ServerPDUs++
		r.mu.Unlock()
		if err := r.client.WriteIO(out); err != nil {
			return relayEnd{end: "client-closed"}
		}
	}
}

// rewriteServerPDU re-encodes Demand Active with the filtered capability
// list; everything else (Deactivate All, Share Data) is forwarded as is.
func (r *relay) rewriteServerPDU(data []byte) ([]byte, error) {
	hdr, _, err := wire.DecodeShareControl(data)
	if err != nil {
		return nil, fmt.Errorf("%w: target share control: %v", ErrRelay, err)
	}
	r.trace("target -> client", hdr.PDUType, data)
	switch hdr.PDUType {
	case wire.PDUTypeDemandActive:
		da, err := wire.DecodeDemandActive(data)
		if err != nil {
			return nil, fmt.Errorf("%w: demand active: %v", ErrRelay, err)
		}
		caps := r.filterCaps(da.Capabilities)
		return wire.EncodeDemandActive(da.ShareID, strings.TrimRight(string(da.SourceDescriptor), "\x00"), caps)
	case wire.PDUTypeDeactivateAll:
		r.mu.Lock()
		r.sum.Reactivations++
		r.mu.Unlock()
	}
	return data, nil
}

func (r *relay) filterCaps(sets []wire.CapabilitySet) []wire.CapabilitySet {
	kept := make([]wire.CapabilitySet, 0, len(sets))
	for _, s := range sets {
		if r.g.cfg.AllowCapability(s.Type) {
			kept = append(kept, s)
			continue
		}
		r.mu.Lock()
		r.sum.DroppedCapabilities[s.Type]++
		r.mu.Unlock()
	}
	return kept
}

func (r *relay) countInput(events []wire.InputEvent) {
	r.mu.Lock()
	for _, e := range events {
		r.sum.InputEvents[e.Kind.String()]++
	}
	r.mu.Unlock()
}
