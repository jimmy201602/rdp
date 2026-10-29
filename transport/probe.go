// Package transport performs the client side of the RDP connection sequence
// over TCP + TLS (MS-RDPBCGR 1.3.1.1): Probe stops after the TLS upgrade,
// Connect after Channel Connection, Activate after Connection Finalization
// (Font Map).
//
// Enhanced RDP Security uses PROTOCOL_SSL, or PROTOCOL_HYBRID when NLA is
// explicitly required. Certificates are verified using roots and hostname,
// or an explicit leaf fingerprint. There is no clear-text or NLA downgrade.
// Probe stops at TLS without authenticating; Connect with NLA delegates
// credentials via CredSSP, but never sends a Client Info PDU.
package transport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"rdp.local/kernel/bitmap"
	"rdp.local/kernel/wire"
)

const maxConnectionConfirmSize = 1024

var (
	// ErrProtocolNotSelected means the server answered the negotiation but did
	// not pick TLS. The connection is closed instead of continuing in clear text.
	ErrProtocolNotSelected = errors.New("server did not select the required security protocol")
)

type Options struct {
	// NLA requires PROTOCOL_HYBRID and CredSSP 5/6 with NTLMv2. No fallback
	// to TLS-only is allowed. Probe still stops before authentication.
	NLA bool
	// ServerName is used for SNI and certificate verification. Defaults to the
	// host part of the address.
	ServerName string
	// RootCAs is the trust store. nil uses the system roots.
	RootCAs *x509.CertPool
	// PinSHA256, when set, is the hex SHA-256 of the leaf certificate the
	// server must present; chain and name verification are then skipped
	// (self-signed Windows RDP hosts). A mismatch fails the handshake and the
	// error names the observed fingerprint.
	PinSHA256 string
	// MinTLSVersion is the lowest TLS version accepted from the server
	// (tls.VersionTLS10..13). Zero means TLS 1.2; Windows 7 / 2008 R2 only
	// offer TLS 1.0 and need tls.VersionTLS10 explicitly.
	MinTLSVersion uint16
	// Cookie is sent as the X.224 routing token / cookie; empty omits it.
	Cookie string
	// Timeout bounds the whole exchange. Zero means 10s.
	Timeout time.Duration
	// ClientName is advertised in Client Core Data (at most 15 characters).
	// Defaults to "rdpkernel".
	ClientName string
	// DesktopWidth/DesktopHeight are advertised in Client Core Data. Zero
	// means 1024x768.
	DesktopWidth, DesktopHeight uint16
	// ColorDepth is the highColorDepth requested in Client Core Data and
	// the preferred depth in Confirm Active: 15, 16 or 24 (0 means 24).
	ColorDepth uint16
	// Channels are the static virtual channels requested in Client Network
	// Data (at most 31) and joined after the I/O channel. Dial exposes the
	// allocated IDs via Session.StaticChannels in the same order. Empty
	// requests none.
	Channels []wire.ChannelDef

	// Domain, UserName and Password fill the Client Info PDU sent by
	// Activate. A non-empty Password sets INFO_AUTOLOGON and makes the
	// server attempt a logon; leave it empty to only exercise the protocol.
	Domain, UserName, Password string
	// StopAfter makes Activate return once this stage completes. Empty means
	// StageActivated. Must be StageClientInfo or later.
	StopAfter string
	// Observe keeps the connection open for this long after Font Map and
	// summarises the server output in Result.Observation. Zero closes the
	// connection right after activation.
	Observe time.Duration
	// Render decodes the Bitmap Updates received during Observe (including
	// Interleaved RLE) into Result.Framebuffer, sized DesktopWidth x
	// DesktopHeight, and pointer updates into Result.Pointer; both are
	// summarised in Observation.Frame / Observation.Pointer.
	Render bool
}

func (o Options) colorDepth() uint16 {
	switch o.ColorDepth {
	case 15, 16, 24:
		return o.ColorDepth
	}
	return 24
}

// Stage names in the order they are reached.
const (
	StageNegotiation  = "negotiation"
	StageTLS          = "tls"
	StageMCSConnect   = "mcs-connect"
	StageAttachUser   = "attach-user"
	StageChannelJoin  = "channel-join"
	StageClientInfo   = "client-info"
	StageLicense      = "license"
	StageCapabilities = "capabilities"
	StageActivated    = "activated"
)

// Stages lists the stage names in order.
var Stages = []string{
	StageNegotiation, StageTLS, StageMCSConnect, StageAttachUser, StageChannelJoin,
	StageClientInfo, StageLicense, StageCapabilities, StageActivated,
}

// StageIndex returns the position of stage in Stages, or -1 for an unknown
// or empty name.
func StageIndex(stage string) int {
	for i, s := range Stages {
		if s == stage {
			return i
		}
	}
	return -1
}

type Result struct {
	// Stage is the last stage that completed successfully.
	Stage string

	SelectedProtocol uint32
	NLA              bool // CredSSP public-key proof verified and credentials delegated
	CredSSPVersion   int
	NegotiationFlags uint8
	TLSVersion       uint16
	CipherSuite      uint16
	PeerSubject      string
	PeerSHA256       string // hex SHA-256 of the leaf certificate
	PeerNotAfter     time.Time

	// Basic Settings Exchange.
	ServerVersion           uint32
	ServerEarlyCapabilities uint32
	ProtocolReconfirmed     bool // SC_CORE echoed the requested protocols
	EncryptionMethod        uint32
	EncryptionLevel         uint32
	IOChannel               uint16
	StaticChannels          []uint16

	// Channel Connection.
	UserChannel    uint16
	JoinedChannels []uint16

	// Secure Settings Exchange.
	ClientInfoSent bool
	AutoLogon      bool // INFO_AUTOLOGON was set (a password was sent)

	// Licensing.
	LicenseOutcome   string // "valid-client", "new-license" or "upgrade-license"
	LicenseProductID string

	// Capabilities Exchange.
	ShareID                uint32
	ServerChannel          uint16
	ServerSourceDescriptor string
	ServerCapabilities     []uint16 // capability set types in Demand Active

	// Connection Finalization: server PDUs received, in order, up to Font Map.
	Finalization []string

	// Server output read after activation when Options.Observe > 0.
	Observation *Observation
	// Framebuffer holds the decoded Bitmap Updates and Pointer the cursor
	// cache, shape, position and visibility when Options.Render is set.
	Framebuffer *bitmap.Framebuffer
	Pointer     *bitmap.PointerState

	Duration time.Duration
}

// Probe dials address, completes X.224 negotiation requesting PROTOCOL_SSL,
// performs a verified TLS handshake and closes the connection. Success proves
// only transport negotiation and TLS server authentication.
func Probe(ctx context.Context, address string, opts Options) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	start := time.Now()
	conn, res, err := secureTransport(ctx, address, opts)
	if err != nil {
		return res, err
	}
	res.Duration = time.Since(start)
	_ = conn.Close()
	return res, nil
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return 10 * time.Second
	}
	return o.Timeout
}

// secureTransport runs Connection Initiation and the TLS upgrade. The caller
// owns the returned connection; its deadline is the context deadline.
func secureTransport(ctx context.Context, address string, opts Options) (*tls.Conn, Result, error) {
	var res Result
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, res, fmt.Errorf("address: %w", err)
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = host
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, res, fmt.Errorf("dial: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, res, err
		}
	}

	cc, err := Negotiate(conn, opts.Cookie, opts.requestedProtocol())
	if err != nil {
		_ = conn.Close()
		return nil, res, err
	}
	res.NegotiationFlags = cc.Flags
	res.SelectedProtocol = cc.SelectedProtocol
	if !cc.HasNegotiation || cc.SelectedProtocol != opts.requestedProtocol() {
		_ = conn.Close()
		return nil, res, fmt.Errorf("%w: server selected %s", ErrProtocolNotSelected, selectedString(cc))
	}
	res.Stage = StageNegotiation

	cfg := &tls.Config{
		ServerName: serverName,
		RootCAs:    opts.RootCAs,
		MinVersion: tls.VersionTLS12,
	}
	if opts.MinTLSVersion != 0 {
		cfg.MinVersion = opts.MinTLSVersion
	}
	if pin := strings.ToLower(strings.ReplaceAll(opts.PinSHA256, ":", "")); pin != "" {
		cfg.InsecureSkipVerify = true // the pin below is the only check
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			sum := sha256.Sum256(raw[0])
			got := hex.EncodeToString(sum[:])
			if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
				return fmt.Errorf("server certificate sha256 %s does not match pin", got)
			}
			return nil
		}
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, res, fmt.Errorf("tls handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	res.TLSVersion = state.Version
	res.CipherSuite = state.CipherSuite
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		res.PeerSubject = leaf.Subject.String()
		sum := sha256.Sum256(leaf.Raw)
		res.PeerSHA256 = hex.EncodeToString(sum[:])
		res.PeerNotAfter = leaf.NotAfter
	}
	res.Stage = StageTLS
	return tlsConn, res, nil
}

// Negotiate writes the X.224 Connection Request and reads the Connection
// Confirm on an already connected stream. Deadlines are the caller's job.
func Negotiate(conn net.Conn, cookie string, requested uint32) (wire.ConnectionConfirm, error) {
	payload, err := wire.ConnectionRequest{Cookie: cookie, RequestedProtocols: requested}.Encode()
	if err != nil {
		return wire.ConnectionConfirm{}, err
	}
	if err := wire.WriteTPKT(conn, payload); err != nil {
		return wire.ConnectionConfirm{}, fmt.Errorf("send connection request: %w", err)
	}
	reply, err := wire.ReadTPKT(conn, maxConnectionConfirmSize)
	if err != nil {
		return wire.ConnectionConfirm{}, fmt.Errorf("receive connection confirm: %w", err)
	}
	cc, err := wire.DecodeConnectionConfirm(reply)
	if err != nil {
		return cc, fmt.Errorf("connection confirm: %w", err)
	}
	return cc, nil
}

func selectedString(cc wire.ConnectionConfirm) string {
	if !cc.HasNegotiation {
		return "no RDP_NEG_RSP (implicit Standard RDP Security)"
	}
	return wire.ProtocolString(cc.SelectedProtocol)
}

func (o Options) requestedProtocol() uint32 {
	if o.NLA {
		return wire.ProtocolHybrid
	}
	return wire.ProtocolSSL
}

func TLSVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
