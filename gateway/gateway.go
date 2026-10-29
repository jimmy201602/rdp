// Package gateway is the G3-3 authorization gateway: it accepts a real RDP
// client with the server role (package server), asks a caller-supplied
// Route policy which target the client may reach, dials the target with the
// client role (transport.Dial) passing the Client Info credentials through
// once, then relays the session. Capability sets are filtered through an
// allow-list in both directions (Demand Active / Confirm Active are decoded
// and re-encoded, everything else is forwarded as received); fast-path
// frames are forwarded unchanged; client input is decoded for counting
// only (keystroke codes are never logged). Static virtual channels the
// client requests are accepted on the front end but not opened towards the
// target, so their data is dropped. Either side closing or failing closes
// the other and frees the session.
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
	Address    string         // host:port
	ServerName string         // TLS name to verify (default: host of Address)
	RootCAs    *x509.CertPool // nil: system roots
	Timeout    time.Duration  // backend handshake budget (default 20s)
}

// Config configures a Gateway.
type Config struct {
	// TLS is the front-end server certificate.
	TLS *tls.Config
	// Route decides, for a peer (no password), which target it may reach.
	// Returning an error denies the client with
	// ERRINFO_SERVER_DENIED_CONNECTION. Required.
	Route func(ctx context.Context, p server.Peer) (Target, error)
	// AllowCapability filters capability set types relayed in Demand /
	// Confirm Active. nil uses DefaultAllowCapability.
	AllowCapability func(typ uint16) bool
	// HandshakeTimeout bounds the front-end handshake (default 30s).
	HandshakeTimeout time.Duration
	// MaxSessions limits concurrent client connections (default 64).
	MaxSessions int
	// Logf receives state transitions; credentials and keystrokes never
	// appear.
	Logf func(format string, args ...any)
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
	Target              string
	ClientPDUs          int // slow-path PDUs client -> target
	ClientFastPath      int // fast-path input frames
	ServerPDUs          int // slow-path PDUs target -> client
	ServerFastPath      int // fast-path output frames
	ClientBytes         int64
	ServerBytes         int64
	InputEvents         map[string]int
	DroppedCapabilities map[uint16]int
	Reactivations       int
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
	if cfg.Route == nil {
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
	creds := c.Credentials()
	opts := transport.Options{
		ServerName: target.ServerName, RootCAs: target.RootCAs, Timeout: target.Timeout,
		ClientName: peer.ClientName, DesktopWidth: peer.DesktopWidth, DesktopHeight: peer.DesktopHeight, ColorDepth: depth,
		Domain: creds.Domain, UserName: creds.UserName, Password: creds.Password,
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
	g.cfg.Logf("%s: target %s licensed (user channel %d), relaying", peer.RemoteAddr, target.Address, backend.UserChannel())
	r := &relay{g: g, client: c, backend: backend, sum: Summary{
		RemoteAddr: peer.RemoteAddr, UserName: peer.UserName, Domain: peer.Domain, ClientName: peer.ClientName,
		Target: target.Address, InputEvents: map[string]int{}, DroppedCapabilities: map[uint16]int{},
	}}
	return r.run(ctx)
}

type relay struct {
	g       *Gateway
	client  *server.Conn
	backend *transport.Session
	mu      sync.Mutex
	sum     Summary
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
	r.g.cfg.Logf("%s: relay to %s ended (%s): client %d pdus + %d fast-path, target %d pdus + %d fast-path, input %v, dropped caps %v, reactivations %d",
		sum.RemoteAddr, sum.Target, sum.End, sum.ClientPDUs, sum.ClientFastPath, sum.ServerPDUs, sum.ServerFastPath,
		sum.InputEvents, sum.DroppedCapabilities, sum.Reactivations)
	if r.g.cfg.OnRelay != nil {
		r.g.cfg.OnRelay(sum)
	}
	return sum.Err
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
			r.countInput(events)
			r.mu.Lock()
			r.sum.ClientFastPath++
			r.mu.Unlock()
			if err := r.backend.WriteFastPath(pdu.Data); err != nil {
				return relayEnd{end: "target-closed"}
			}
			continue
		}
		out, err := r.rewriteClientPDU(pdu.Data)
		if err != nil {
			return relayEnd{end: "error", err: err}
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
	switch hdr.PDUType {
	case wire.PDUTypeConfirmActive:
		ca, err := wire.DecodeConfirmActive(data)
		if err != nil {
			return nil, fmt.Errorf("%w: confirm active: %v", ErrRelay, err)
		}
		caps := r.filterCaps(ca.Capabilities)
		return wire.EncodeConfirmActive(ca.ShareID, r.backend.UserChannel(), strings.TrimRight(string(ca.SourceDescriptor), "\x00"), caps)
	case wire.PDUTypeData:
		sh, body, err := wire.DecodeShareData(data)
		if err != nil {
			return nil, fmt.Errorf("%w: client share data: %v", ErrRelay, err)
		}
		if sh.PDUType2 == wire.PDUType2Input {
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
	for {
		pdu, err := r.backend.ReadPDU()
		if err != nil {
			if errors.Is(err, transport.ErrDisconnected) || closedErr(err) {
				return relayEnd{end: "target-closed"}
			}
			return relayEnd{end: "error", err: fmt.Errorf("target: %w", err)}
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
