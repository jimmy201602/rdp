package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"rdp.local/kernel/form"
	"rdp.local/kernel/server"
	"rdp.local/kernel/transport"
	"rdp.local/kernel/wire"
)

// FormConfig enables the interactive logon form. Instead of routing on the
// Client Info credentials, the gateway activates the client with a desktop
// drawn by package form, lets the user type a server address, user name,
// password and domain, and dials that target with those credentials. On
// failure the form shows a reason and the user may retry; after Attempts
// failures the client is disconnected.
type FormConfig struct {
	// Route decides whether and how the address the user typed may be
	// reached (certificate policy, NLA, timeout). Returning an error shows
	// form.MsgNotAllowed. Required.
	Route func(ctx context.Context, p server.Peer, address string) (Target, error)
	// Attempts is the number of failed connection attempts allowed before
	// the client is disconnected (default 5).
	Attempts int
	// IdleTimeout disconnects a client that leaves the form untouched
	// (default 5 minutes).
	IdleTimeout time.Duration
	// Prefill copies the user name and domain from the Client Info PDU into
	// the form (the password is never prefilled).
	Prefill bool
}

// ErrFormAttempts is reported when a client exhausted FormConfig.Attempts.
var ErrFormAttempts = errors.New("rdp gateway: too many failed logon attempts")

func (g *Gateway) handleForm(ctx context.Context, c *server.Conn) error {
	cfg := g.cfg.Form
	peer := c.Peer()
	act, err := c.Activate()
	if err != nil {
		return err
	}
	f := form.New(int(act.Width), int(act.Height))
	if cfg.Prefill && peer.UserName != "" {
		f.Prefill(form.Values{UserName: peer.UserName, Domain: peer.Domain})
	}
	canvas := f.Canvas()
	frame := &server.Frame{Width: uint16(canvas.Width), Height: uint16(canvas.Height), BGR: canvas.BGR}
	if err := c.SendFrame(frame); err != nil {
		return err
	}
	if err := c.SendPointer(nil); err != nil {
		return err
	}
	f.Flush()
	flush := func() error {
		if r, ok := f.Flush(); ok {
			return c.SendBitmap(frame, r.X, r.Y, r.W, r.H)
		}
		return nil
	}
	g.cfg.Logf("%s: logon form shown to client %q (%dx%d)", peer.RemoteAddr, peer.ClientName, act.Width, act.Height)
	attempts := 0
	for {
		_ = c.SetDeadline(time.Now().Add(cfg.IdleTimeout))
		p, err := c.ReadPDU()
		if err != nil {
			return err
		}
		in, err := c.DecodeInput(p)
		if err != nil {
			return err
		}
		if in.Shutdown {
			g.cfg.Logf("%s: client closed the logon form", peer.RemoteAddr)
			_ = c.Disconnect(wire.DisconnectReasonUserRequested)
			return nil
		}
		if in.Refresh {
			f.Invalidate()
		}
		switch f.HandleAll(in.Events, in.FastPath) {
		case form.ActionCancel:
			g.cfg.Logf("%s: client cancelled the logon form", peer.RemoteAddr)
			_ = c.Disconnect(wire.DisconnectReasonUserRequested)
			return nil
		case form.ActionSubmit:
			if err := flush(); err != nil {
				return err
			}
			vals := f.Values()
			_ = c.SetDeadline(time.Time{})
			r, err := g.dialForm(ctx, c, peer, vals)
			vals = form.Values{}
			_ = vals
			if err == nil {
				r.sum.FormAttempts = attempts + 1
				return r.run(ctx)
			}
			if errors.Is(err, transport.ErrNoCredentials) {
				// Nothing reached the target (typically a repeated Enter
				// after Fail cleared the password); not an attempt.
				f.Fail(form.MsgNeedPassword)
				break
			}
			attempts++
			msg := describeDialError(err)
			g.cfg.Logf("%s: logon form attempt %d failed (%s): %v", peer.RemoteAddr, attempts, msg, err)
			if attempts >= cfg.Attempts {
				_ = c.Deny(wire.ErrInfoServerDeniedConnection)
				return fmt.Errorf("%w: %v", ErrFormAttempts, err)
			}
			f.Fail(msg)
		}
		if err := flush(); err != nil {
			return err
		}
	}
}

// dialForm connects to the server the user asked for and, on success,
// deactivates the form so the target's Demand Active re-activates the
// client through the relay.
func (g *Gateway) dialForm(ctx context.Context, c *server.Conn, peer server.Peer, vals form.Values) (*relay, error) {
	address := vals.Address
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(strings.Trim(address, "[]"), "3389")
	}
	target, err := g.cfg.Form.Route(ctx, peer, address)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", server.ErrDenied, err)
	}
	if target.Address == "" {
		target.Address = address
	}
	if target.Timeout <= 0 {
		target.Timeout = 20 * time.Second
	}
	if target.NLA && (vals.UserName == "" || vals.Password == "") {
		return nil, fmt.Errorf("%w: %s: %w", ErrBackend, target.Address, transport.ErrNoCredentials)
	}
	depth := peer.ColorDepth
	switch depth {
	case 15, 16, 24:
	default:
		depth = 24
	}
	channels := newChannelMap(c, g.cfg.AllowChannel)
	opts := transport.Options{
		NLA: target.NLA, LegacyCredSSP: target.LegacyCredSSP, ServerName: target.ServerName, RootCAs: target.RootCAs, PinSHA256: target.PinSHA256, MinTLSVersion: target.MinTLS, Timeout: target.Timeout,
		ClientName: peer.ClientName, DesktopWidth: peer.DesktopWidth, DesktopHeight: peer.DesktopHeight, ColorDepth: depth,
		Channels: channels.defs,
		Domain:   vals.Domain, UserName: vals.UserName, Password: vals.Password,
	}
	backend, err := transport.Dial(ctx, target.Address, opts)
	opts = transport.Options{}
	_ = opts
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrBackend, target.Address, err)
	}
	// A target that denies the logon after licensing answers with Set Error
	// Info (or just disconnects) instead of Demand Active; find out before
	// the form is torn down so the user can retry.
	first, err := awaitDemandActive(backend, target.Timeout)
	if err != nil {
		_ = backend.Close()
		return nil, fmt.Errorf("%w: %s: %w", ErrBackend, target.Address, err)
	}
	c.MarkAuthorized()
	if err := c.DeactivateAll(); err != nil {
		_ = backend.Close()
		return nil, err
	}
	channels.bind(backend.StaticChannels())
	g.cfg.Logf("%s: target %s licensed via logon form (user channel %d, channels %v), relaying", peer.RemoteAddr, target.Address, backend.UserChannel(), channels.names())
	return &relay{g: g, client: c, backend: backend, channels: channels, dropInput: true, firstServer: &first, sum: Summary{
		RemoteAddr: peer.RemoteAddr, UserName: vals.UserName, Domain: vals.Domain, ClientName: peer.ClientName, NLA: peer.NLA,
		Target: target.Address, LoginForm: true, InputEvents: map[string]int{}, DroppedCapabilities: map[uint16]int{},
		ChannelPDUs: map[string]int{}, DroppedChannels: map[string]int{},
	}}, nil
}

// awaitDemandActive reads the target's first I/O PDU and returns it if it is
// a Demand Active; a Set Error Info PDU is returned as *wire.ErrorInfo.
func awaitDemandActive(backend *transport.Session, timeout time.Duration) (transport.PDU, error) {
	_ = backend.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = backend.SetDeadline(time.Time{}) }()
	for {
		p, err := backend.ReadPDU()
		if err != nil {
			return p, err
		}
		if p.FastPath || p.Channel != 0 {
			continue
		}
		hdr, _, err := wire.DecodeShareControl(p.Data)
		if err != nil {
			return p, fmt.Errorf("%w: %v", ErrRelay, err)
		}
		switch hdr.PDUType {
		case wire.PDUTypeDemandActive:
			return p, nil
		case wire.PDUTypeData:
			if _, err := wire.DecodeDataPDU(p.Data); err != nil {
				return p, err
			}
			return p, fmt.Errorf("%w: target sent share data before Demand Active", ErrRelay)
		default:
			return p, fmt.Errorf("%w: target sent pduType %d before Demand Active", ErrRelay, hdr.PDUType)
		}
	}
}

// describeDialError maps a target connection error to a form message. The
// detail (addresses, certificate names) stays in the log only.
func describeDialError(err error) string {
	var (
		dnsErr   *net.DNSError
		opErr    *net.OpError
		tlsErr   *tls.CertificateVerificationError
		negFail  *wire.NegotiationFailure
		unkAuth  x509.UnknownAuthorityError
		hostErr  x509.HostnameError
		certErr  x509.CertificateInvalidError
		netErr   net.Error
		errInfo  *wire.ErrorInfo
		timedOut = errors.Is(err, context.DeadlineExceeded)
	)
	switch {
	case errors.Is(err, server.ErrDenied):
		return form.MsgNotAllowed
	case errors.As(err, &errInfo):
		return form.MsgRejected
	case errors.Is(err, transport.ErrCredSSP):
		return form.MsgBadCredential
	case errors.As(err, &dnsErr):
		return form.MsgUnresolved
	case errors.As(err, &tlsErr), errors.As(err, &unkAuth), errors.As(err, &hostErr), errors.As(err, &certErr),
		strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "pin"):
		return form.MsgBadCert
	case errors.As(err, &negFail):
		return form.MsgNegotiation
	case errors.Is(err, transport.ErrDisconnected):
		return form.MsgDisconnected
	case timedOut, errors.As(err, &netErr) && netErr.Timeout():
		return form.MsgTimeout
	case errors.As(err, &opErr):
		if opErr.Op == "dial" && strings.Contains(opErr.Err.Error(), "refused") {
			return form.MsgRefused
		}
		return form.MsgUnreachable
	case errors.Is(err, transport.ErrProtocolNotSelected), errors.Is(err, transport.ErrSettingsMismatch),
		errors.Is(err, transport.ErrEncryptionRequested), errors.Is(err, transport.ErrMissingServerData):
		return form.MsgNegotiation
	}
	return form.MsgFailed
}
