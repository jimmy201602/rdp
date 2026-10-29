package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"rdp.local/kernel/transport"
	"rdp.local/kernel/wire"
)

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "go-rdp-server"},
		DNSNames:     []string{"go-rdp-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

type harness struct {
	addr      string
	pool      *x509.CertPool
	cancel    context.CancelFunc
	done      chan error
	mu        sync.Mutex
	summaries []Summary
	logs      []string
}

func start(t *testing.T, authorize func(context.Context, Peer) error) *harness {
	t.Helper()
	cert, pool := testCertificate(t)
	h := &harness{pool: pool, done: make(chan error, 1)}
	cfg := Config{
		TLS:              &tls.Config{Certificates: []tls.Certificate{cert}},
		Authorize:        authorize,
		HandshakeTimeout: 10 * time.Second,
		Logf: func(f string, a ...any) {
			h.mu.Lock()
			h.logs = append(h.logs, strings.TrimSpace(sprintf(f, a...)))
			h.mu.Unlock()
		},
		OnSession: func(s Summary) {
			h.mu.Lock()
			h.summaries = append(h.summaries, s)
			h.mu.Unlock()
		},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.addr, h.cancel = ln.Addr().String(), cancel
	go func() { h.done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-h.done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	return h
}

func (h *harness) waitSummary(t *testing.T) Summary {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		n := len(h.summaries)
		var s Summary
		if n > 0 {
			s = h.summaries[n-1]
		}
		h.mu.Unlock()
		if n > 0 {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no session summary")
	return Summary{}
}

func clientOpts(h *harness) transport.Options {
	return transport.Options{
		ServerName: "go-rdp-server", RootCAs: h.pool, Timeout: 10 * time.Second,
		ClientName: "GOTEST", DesktopWidth: 320, DesktopHeight: 200,
		Domain: "dom", UserName: "alice", Password: "pw-not-logged",
	}
}

func TestLoopbackActivationAndGraphics(t *testing.T) {
	var got Peer
	h := start(t, func(_ context.Context, p Peer) error {
		got = p
		if p.UserName != "alice" || p.Password != "pw-not-logged" {
			return errors.New("unexpected credentials")
		}
		return nil
	})
	opts := clientOpts(h)
	opts.Observe = 500 * time.Millisecond
	opts.Render = true
	res, err := transport.Activate(context.Background(), h.addr, opts)
	if err != nil {
		t.Fatalf("activate: %v (stage %s)", err, res.Stage)
	}
	if res.SelectedProtocol != wire.ProtocolSSL || res.LicenseOutcome != "valid-client" || res.ShareID != shareID || res.IOChannel != ioChannel {
		t.Fatalf("result %+v", res)
	}
	if !res.ProtocolReconfirmed || res.EncryptionLevel != 0 || res.UserChannel < userChannelBase {
		t.Fatalf("settings %+v", res)
	}
	if len(res.Finalization) != 4 {
		t.Fatalf("finalization %v", res.Finalization)
	}
	if got.ClientName != "GOTEST" || got.DesktopWidth != 320 || got.Domain != "dom" || !got.AutoLogon {
		t.Fatalf("peer %+v", got)
	}
	obs := res.Observation
	if obs == nil || obs.BitmapRects == 0 || obs.Pointers["color"] != 1 || obs.ErrorInfo != nil {
		t.Fatalf("observation %+v", obs)
	}
	if res.Framebuffer == nil || res.Pointer == nil {
		t.Fatal("no rendered framebuffer / pointer")
	}
	img := res.Framebuffer.Image()
	want := TestPattern(320, 200)
	for _, pt := range [][2]int{{5, 5}, {100, 50}, {300, 100}, {160, 180}, {0, 199}} {
		r, g, b, _ := img.At(pt[0], pt[1]).RGBA()
		i := (pt[1]*320 + pt[0]) * 3
		if uint8(r>>8) != want.BGR[i+2] || uint8(g>>8) != want.BGR[i+1] || uint8(b>>8) != want.BGR[i] {
			t.Errorf("pixel %v = %d,%d,%d want %d,%d,%d", pt, r>>8, g>>8, b>>8, want.BGR[i+2], want.BGR[i+1], want.BGR[i])
		}
	}
	h.mu.Lock()
	for _, l := range h.logs {
		if strings.Contains(l, "pw-not-logged") {
			t.Errorf("password leaked into log: %q", l)
		}
	}
	h.mu.Unlock()
	h.cancel()
	s := h.waitSummary(t)
	if !s.Authorized || s.UserName != "alice" || s.Stage != "output" || (s.Err != nil && !errors.Is(s.Err, context.Canceled)) {
		t.Fatalf("summary %+v", s)
	}
}

func TestPolicyDenied(t *testing.T) {
	h := start(t, func(_ context.Context, p Peer) error { return errors.New("no such user") })
	opts := clientOpts(h)
	opts.Observe = 500 * time.Millisecond
	_, err := transport.Activate(context.Background(), h.addr, opts)
	if err == nil {
		t.Fatal("activation succeeded against denying policy")
	}
	var ei *wire.ErrorInfo
	if !errors.As(err, &ei) || ei.Code != wire.ErrInfoServerDeniedConnection {
		t.Fatalf("client error %v, want ERRINFO_SERVER_DENIED_CONNECTION", err)
	}
	s := h.waitSummary(t)
	if s.Authorized || !errors.Is(s.Err, ErrDenied) || s.Stage != "mcs-join" {
		t.Fatalf("summary %+v", s)
	}
}

func TestRefusesNonTLSClient(t *testing.T) {
	h := start(t, func(context.Context, Peer) error { return nil })
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	cr, _ := wire.ConnectionRequest{RequestedProtocols: wire.ProtocolRDP}.Encode()
	if err := wire.WriteTPKT(c, cr); err != nil {
		t.Fatal(err)
	}
	p, err := wire.ReadTPKT(c, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.DecodeConnectionConfirm(p); err == nil || !strings.Contains(err.Error(), "SSL") {
		t.Fatalf("expected RDP_NEG_FAILURE, got %x (%v)", p, err)
	}
	s := h.waitSummary(t)
	if !errors.Is(s.Err, ErrNegotiation) {
		t.Fatalf("summary %+v", s)
	}
}

func TestHandshakeTimeoutAndGarbage(t *testing.T) {
	h := start(t, func(context.Context, Peer) error { return nil })
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("server answered garbage with %x", buf[:n])
	}
	_ = c.Close()
	s := h.waitSummary(t)
	if !errors.Is(s.Err, ErrProtocol) {
		t.Fatalf("summary %+v", s)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	cert, _ := testCertificate(t)
	if _, err := New(Config{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}}); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
}

func sprintf(f string, a ...any) string { return strings.TrimSpace(fmtSprintf(f, a...)) }

func fmtSprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }
