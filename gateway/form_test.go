package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"rdp.local/kernel/form"
	"rdp.local/kernel/server"
	"rdp.local/kernel/transport"
	"rdp.local/kernel/wire"
)

func (l *logs) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

type formFixture struct {
	*fixture
	backAddr string
	backPool *x509.CertPool
}

func setupForm(t *testing.T, fc FormConfig) *formFixture {
	t.Helper()
	f := &fixture{backend: make(chan server.Summary, 4), relays: make(chan Summary, 4), sessions: make(chan server.Summary, 4), log: &logs{}}
	backCert, backPool := testCertificate(t, "target")
	backSrv, err := server.New(server.Config{
		TLS: &tls.Config{Certificates: []tls.Certificate{backCert}},
		Authorize: func(_ context.Context, p server.Peer) error {
			if p.UserName != "alice" || p.Password != "pw-typed" || p.Domain != "corp" {
				return errors.New("target rejected credentials")
			}
			return nil
		},
		HandshakeTimeout: 10 * time.Second,
		Logf:             f.log.logf,
		OnSession:        func(s server.Summary) { f.backend <- s },
	})
	if err != nil {
		t.Fatal(err)
	}
	ff := &formFixture{fixture: f, backAddr: serve(t, "target", backSrv.Serve), backPool: backPool}
	if fc.Route == nil {
		fc.Route = func(_ context.Context, _ server.Peer, address string) (Target, error) {
			if address != ff.backAddr {
				return Target{Timeout: 2 * time.Second}, nil // unknown host: dial it with default policy
			}
			return Target{ServerName: "target", RootCAs: backPool, Timeout: 5 * time.Second}, nil
		}
	}
	gwCert, gwPool := testCertificate(t, "gateway")
	gw, err := New(Config{
		TLS:              &tls.Config{Certificates: []tls.Certificate{gwCert}},
		Form:             &fc,
		HandshakeTimeout: 10 * time.Second,
		Logf:             f.log.logf,
		OnSession:        func(s server.Summary) { f.sessions <- s },
		OnRelay:          func(r Summary) { f.relays <- r },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.gwAddr, f.gwPool = serve(t, "gateway", gw.Serve), gwPool
	return ff
}

// formClient drives the gateway's logon form over a transport.Session.
type formClient struct {
	t       *testing.T
	s       *transport.Session
	shareID uint32
	srvChan uint16
}

func dialForm(t *testing.T, f *formFixture) *formClient {
	t.Helper()
	opts := clientOpts(f.fixture)
	opts.Password = "" // the form supplies the password
	s, err := transport.Dial(context.Background(), f.gwAddr, opts)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	c := &formClient{t: t, s: s}
	c.activate(nil)
	return c
}

// activate completes Demand Active / Confirm Active / finalization and
// returns once the Font Map arrives.
func (c *formClient) activate(first []byte) {
	c.t.Helper()
	data := first
	if data == nil {
		p, err := c.s.ReadPDU()
		if err != nil {
			c.t.Fatalf("demand active: %v", err)
		}
		data = p.Data
	}
	demand, err := wire.DecodeDemandActive(data)
	if err != nil {
		c.t.Fatalf("demand active: %v", err)
	}
	c.shareID, c.srvChan = demand.ShareID, demand.Control.PDUSource
	user := c.s.UserChannel()
	sets := wire.DefaultClientCapabilities(wire.ClientCapabilityOptions{DesktopWidth: 320, DesktopHeight: 200, ColorDepth: 16, KeyboardType: wire.KeyboardTypeIBMEnhance})
	for _, enc := range []func() ([]byte, error){
		func() ([]byte, error) { return wire.EncodeConfirmActive(demand.ShareID, user, "FRONT", sets) },
		func() ([]byte, error) { return wire.EncodeSynchronize(demand.ShareID, user, c.srvChan) },
		func() ([]byte, error) { return wire.EncodeControl(demand.ShareID, user, wire.CtrlActionCooperate) },
		func() ([]byte, error) { return wire.EncodeControl(demand.ShareID, user, wire.CtrlActionRequestControl) },
		func() ([]byte, error) { return wire.EncodeFontList(demand.ShareID, user) },
	} {
		p, err := enc()
		if err != nil {
			c.t.Fatal(err)
		}
		if err := c.s.WriteIO(p); err != nil {
			c.t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		p, err := c.s.ReadPDU()
		if err != nil {
			c.t.Fatalf("finalization: %v", err)
		}
		if d, err := wire.DecodeDataPDU(p.Data); err == nil && d.Header.PDUType2 == wire.PDUType2FontMap {
			return
		}
	}
	c.t.Fatal("no Font Map")
}

func (c *formClient) input(events ...wire.InputEvent) {
	c.t.Helper()
	body, err := wire.EncodeInputPDU(events)
	if err != nil {
		c.t.Fatal(err)
	}
	pdu, err := wire.EncodeShareData(c.shareID, c.s.UserChannel(), wire.PDUType2Input, body)
	if err != nil {
		c.t.Fatal(err)
	}
	if err := c.s.WriteIO(pdu); err != nil {
		c.t.Fatal(err)
	}
}

func (c *formClient) typeText(s string) {
	for _, r := range s {
		c.input(wire.InputEvent{Kind: wire.InputKindUnicode, Code: uint16(r)}, wire.InputEvent{Kind: wire.InputKindUnicode, Code: uint16(r), Flags: 0x8000})
	}
}

func (c *formClient) key(code uint16) {
	c.input(wire.InputEvent{Kind: wire.InputKindScancode, Code: code})
	// The release goes on the fast path, as real clients do, so it is in
	// flight when the gateway switches to the target.
	frame, err := wire.EncodeFastPathInput([]wire.InputEvent{{Kind: wire.InputKindScancode, Code: code, Flags: 0x01}})
	if err != nil {
		c.t.Fatal(err)
	}
	if err := c.s.WriteFastPath(frame); err != nil {
		c.t.Fatal(err)
	}
}

// expect reads share PDUs until pred returns true or timeout elapses; it
// reports whether pred matched.
func (c *formClient) expect(timeout time.Duration, pred func(pduType uint16, data []byte) bool) bool {
	c.t.Helper()
	_ = c.s.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = c.s.SetDeadline(time.Time{}) }()
	for {
		p, err := c.s.ReadPDU()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return false
			}
			c.t.Fatalf("read: %v", err)
		}
		if p.FastPath || p.Channel != 0 {
			continue
		}
		ctl, _, err := wire.DecodeShareControl(p.Data)
		if err != nil {
			c.t.Fatal(err)
		}
		if pred(ctl.PDUType, p.Data) {
			return true
		}
	}
}

func waitLog(t *testing.T, l *logs, substr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !l.contains(substr) {
		if time.Now().After(deadline) {
			t.Fatalf("log line %q not seen in %v", substr, l.all())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func isDeactivateAll(pduType uint16, _ []byte) bool { return pduType == wire.PDUTypeDeactivateAll }

func isUpdate(pduType uint16, data []byte) bool {
	if pduType != wire.PDUTypeData {
		return false
	}
	d, err := wire.DecodeDataPDU(data)
	return err == nil && d.Header.PDUType2 == wire.PDUType2Update
}

func TestFormRetryThenRelay(t *testing.T) {
	f := setupForm(t, FormConfig{Prefill: true})
	c := dialForm(t, f)
	if !c.expect(3*time.Second, isUpdate) {
		t.Fatal("form never painted")
	}
	// Address, then Tab past the prefilled user name to the password.
	c.typeText(f.backAddr)
	c.key(0x0F)
	c.key(0x0F)
	c.typeText("wrong")
	c.key(0x1C)
	// The failed attempt repaints the form (status + cleared password) and
	// must not deactivate the client.
	waitLog(t, f.log, "logon form attempt 1 failed")
	if c.expect(300*time.Millisecond, isDeactivateAll) {
		t.Fatal("deactivated after wrong password")
	}
	// The form cleared the password and focused it: retry with the right one.
	c.typeText("pw-typed")
	c.key(0x1C)
	var demand []byte
	var deactivated bool
	if !c.expect(5*time.Second, func(pt uint16, data []byte) bool {
		switch pt {
		case wire.PDUTypeDeactivateAll:
			deactivated = true
		case wire.PDUTypeDemandActive:
			demand = data
			return true
		}
		return false
	}) || !deactivated {
		t.Fatalf("no Deactivate All + Demand Active (deactivated=%v)", deactivated)
	}
	c.activate(demand)
	if !c.expect(5*time.Second, isUpdate) {
		t.Fatal("no graphics from the target after reactivation")
	}
	// Input now reaches the target (the Enter release in flight was dropped).
	c.key(0x1E)
	_ = c.s.Close()
	r := wait(t, f.relays, "relay summary")
	if !r.LoginForm || r.FormAttempts != 2 || r.UserName != "alice" || r.Domain != "corp" || r.Target != f.backAddr {
		t.Fatalf("relay summary %+v", r)
	}
	if r.InputEvents["scancode"] != 2 {
		t.Fatalf("input after reactivation %v (the stale Enter release must be dropped)", r.InputEvents)
	}
	// The backend saw two sessions: the denied one, then the relayed one.
	if b := wait(t, f.backend, "backend summary"); b.Authorized || !errors.Is(b.Err, server.ErrDenied) {
		t.Fatalf("first backend summary %+v", b)
	}
	if b := wait(t, f.backend, "backend summary"); !b.Authorized || b.UserName != "alice" {
		t.Fatalf("second backend summary %+v", b)
	}
	for _, l := range f.log.all() {
		if strings.Contains(l, "pw-typed") || strings.Contains(l, "wrong") {
			t.Fatalf("form secret leaked into log: %q", l)
		}
	}
}

func TestFormAttemptsExhaustedAndEscape(t *testing.T) {
	denied := errors.New("policy: host not allowed")
	f := setupForm(t, FormConfig{Attempts: 2, Route: func(_ context.Context, _ server.Peer, address string) (Target, error) {
		if strings.HasPrefix(address, "10.") {
			return Target{}, denied
		}
		return Target{Timeout: time.Second}, nil
	}})
	c := dialForm(t, f)
	c.expect(3*time.Second, isUpdate)
	// Attempt 1: denied by policy (keeps the form), attempt 2: refused port.
	c.typeText("10.9.9.9")
	c.key(0x0F)
	c.typeText("bob")
	c.key(0x1C)
	waitLog(t, f.log, "logon form attempt 1 failed")
	if c.expect(300*time.Millisecond, isDeactivateAll) {
		t.Fatal("deactivated after policy denial")
	}
	c.key(0x0F) // back to the address field (Tab cycles from password → domain → address)
	c.key(0x0F)
	c.key(0x0F)
	for i := 0; i < 8; i++ {
		c.key(0x0E) // Backspace the old address
	}
	c.typeText("127.0.0.1:1")
	c.key(0x1C)
	s := wait(t, f.sessions, "front-end summary")
	if !errors.Is(s.Err, ErrFormAttempts) {
		t.Fatalf("summary %+v", s)
	}
	if !f.log.contains("attempt 2 failed") {
		t.Fatalf("logs %v", f.log.all())
	}

	// Esc disconnects cleanly.
	f2 := setupForm(t, FormConfig{})
	c2 := dialForm(t, f2)
	c2.expect(3*time.Second, isUpdate)
	c2.key(0x01)
	_ = c2.s.SetDeadline(time.Now().Add(5 * time.Second))
	var err error
	for i := 0; i < 64 && err == nil; i++ { // drain repaints until the ultimatum / close
		_, err = c2.s.ReadPDU()
	}
	if err == nil {
		t.Fatal("expected disconnect after Esc")
	}
	s2 := wait(t, f2.sessions, "front-end summary")
	if s2.Err != nil || !f2.log.contains("cancelled the logon form") {
		t.Fatalf("summary %+v logs %v", s2, f2.log.all())
	}
}

// Enter with an empty password on an NLA target must not contact the target
// nor burn an attempt (xfreerdp repeats Enter after Fail cleared the field).
func TestFormEmptyPasswordIsNotAnAttempt(t *testing.T) {
	f := setupForm(t, FormConfig{Attempts: 1, Route: func(context.Context, server.Peer, string) (Target, error) {
		return Target{NLA: true, Timeout: time.Second}, nil
	}})
	c := dialForm(t, f)
	c.expect(3*time.Second, isUpdate)
	c.typeText("127.0.0.1:1")
	c.key(0x0F)
	c.typeText("bob")
	c.key(0x1C)
	if !c.expect(2*time.Second, isUpdate) {
		t.Fatal("no repaint after the empty submit")
	}
	if f.log.contains("attempt") {
		t.Fatalf("logs %v", f.log.all())
	}
	c.typeText("pw") // Fail focused the password field
	c.key(0x1C)
	s := wait(t, f.sessions, "front-end summary")
	if !errors.Is(s.Err, ErrFormAttempts) || !f.log.contains("attempt 1 failed") {
		t.Fatalf("summary %+v logs %v", s, f.log.all())
	}
}

func TestDescribeDialError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{transport.ErrCredSSP, form.MsgBadCredential},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, form.MsgRefused},
		{&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, form.MsgUnreachable},
		{&net.DNSError{Err: "no such host", Name: "x"}, form.MsgUnresolved},
		{context.DeadlineExceeded, form.MsgTimeout},
		{x509.UnknownAuthorityError{}, form.MsgBadCert},
		{errors.New("server certificate sha256 ab does not match pin"), form.MsgBadCert},
		{&wire.NegotiationFailure{Code: 2}, form.MsgNegotiation},
		{transport.ErrDisconnected, form.MsgDisconnected},
		{server.ErrDenied, form.MsgNotAllowed},
		{&wire.ErrorInfo{Code: wire.ErrInfoServerDeniedConnection}, form.MsgRejected},
		{errors.New("something else"), form.MsgFailed},
	}
	for _, tc := range cases {
		if got := describeDialError(tc.err); got != tc.want {
			t.Errorf("%v → %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestNewRequiresFormRoute(t *testing.T) {
	cert, _ := testCertificate(t, "gateway")
	_, err := New(Config{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Form: &FormConfig{}})
	if !errors.Is(err, server.ErrConfig) {
		t.Fatalf("New without Form.Route: %v", err)
	}
}
