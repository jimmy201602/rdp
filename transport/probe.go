// Package transport performs the client side of the RDP connection sequence
// over TCP + TLS (MS-RDPBCGR 1.3.1.1): Probe stops after the TLS upgrade,
// Connect after Channel Connection, Activate after Connection Finalization
// (Font Map).
//
// Only Enhanced RDP Security with PROTOCOL_SSL is requested. The server
// certificate is verified against RootCAs (or the system roots) with hostname
// checking; there is no fallback to Standard RDP Security and no CredSSP.
// Probe and Connect never send a Client Info PDU; Activate sends one and
// only includes a password when Options.Password is set by the caller.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"rdp.local/kernel/bitmap"
	"rdp.local/kernel/wire"
)

const maxConnectionConfirmSize = 1024

var (
	// ErrProtocolNotSelected means the server answered the negotiation but did
	// not pick TLS. The connection is closed instead of continuing in clear text.
	ErrProtocolNotSelected = errors.New("server did not select PROTOCOL_SSL")
)

type Options struct {
	// ServerName is used for SNI and certificate verification. Defaults to the
	// host part of the address.
	ServerName string
	// RootCAs is the trust store. nil uses the system roots.
	RootCAs *x509.CertPool
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
	NegotiationFlags uint8
	TLSVersion       uint16
	CipherSuite      uint16
	PeerSubject      string
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

	cc, err := Negotiate(conn, opts.Cookie, wire.ProtocolSSL)
	if err != nil {
		_ = conn.Close()
		return nil, res, err
	}
	res.NegotiationFlags = cc.Flags
	res.SelectedProtocol = cc.SelectedProtocol
	if !cc.HasNegotiation || cc.SelectedProtocol != wire.ProtocolSSL {
		_ = conn.Close()
		return nil, res, fmt.Errorf("%w: server selected %s", ErrProtocolNotSelected, selectedString(cc))
	}
	res.Stage = StageNegotiation

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: serverName,
		RootCAs:    opts.RootCAs,
		MinVersion: tls.VersionTLS12,
	})
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

func TLSVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
