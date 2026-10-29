package gateway

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

	"rdp.local/kernel/server"
	"rdp.local/kernel/transport"
	"rdp.local/kernel/wire"
)

func testCertificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(f string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
	l.mu.Unlock()
}

func (l *logs) contains(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, s) {
			return true
		}
	}
	return false
}

func serve(t *testing.T, name string, run func(ctx context.Context, ln net.Listener) error) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s did not stop", name)
		}
	})
	return ln.Addr().String()
}

type fixture struct {
	gwAddr   string
	gwPool   *x509.CertPool
	backend  chan server.Summary
	relays   chan Summary
	sessions chan server.Summary
	log      *logs
}

func setup(t *testing.T, route func(context.Context, server.Peer) (Target, error)) *fixture {
	t.Helper()
	f := &fixture{backend: make(chan server.Summary, 4), relays: make(chan Summary, 4), sessions: make(chan server.Summary, 4), log: &logs{}}
	backCert, backPool := testCertificate(t, "target")
	backSrv, err := server.New(server.Config{
		TLS: &tls.Config{Certificates: []tls.Certificate{backCert}},
		Authorize: func(_ context.Context, p server.Peer) error {
			if p.UserName != "alice" || p.Password != "pw-pass-through" || p.Domain != "corp" {
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
	backAddr := serve(t, "target", backSrv.Serve)
	if route == nil {
		route = func(context.Context, server.Peer) (Target, error) {
			return Target{Address: backAddr, ServerName: "target", RootCAs: backPool}, nil
		}
	}
	gwCert, gwPool := testCertificate(t, "gateway")
	gw, err := New(Config{
		TLS:              &tls.Config{Certificates: []tls.Certificate{gwCert}},
		Route:            route,
		HandshakeTimeout: 10 * time.Second,
		Logf:             f.log.logf,
		OnSession:        func(s server.Summary) { f.sessions <- s },
		OnRelay:          func(r Summary) { f.relays <- r },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.gwAddr, f.gwPool = serve(t, "gateway", gw.Serve), gwPool
	return f
}

func clientOpts(f *fixture) transport.Options {
	return transport.Options{
		ServerName: "gateway", RootCAs: f.gwPool, Timeout: 10 * time.Second,
		ClientName: "FRONT", DesktopWidth: 320, DesktopHeight: 200, ColorDepth: 16,
		Domain: "corp", UserName: "alice", Password: "pw-pass-through",
	}
}

func wait[T any](t *testing.T, ch chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("no %s", what)
		var zero T
		return zero
	}
}

func absDiff(a, b uint8) int {
	if a > b {
		return int(a - b)
	}
	return int(b - a)
}

func TestRelayEndToEnd(t *testing.T) {
	f := setup(t, nil)
	opts := clientOpts(f)
	opts.Observe = 600 * time.Millisecond
	opts.Render = true
	res, err := transport.Activate(context.Background(), f.gwAddr, opts)
	if err != nil {
		t.Fatalf("activate through gateway: %v (stage %s)", err, res.Stage)
	}
	if res.LicenseOutcome != "valid-client" || len(res.Finalization) != 4 || res.Observation == nil || res.Observation.BitmapRects == 0 || res.Observation.Pointers["color"] != 1 {
		t.Fatalf("result %+v obs %+v", res, res.Observation)
	}
	want := server.TestPattern(320, 200)
	img := res.Framebuffer.Image()
	for _, pt := range [][2]int{{5, 5}, {100, 50}, {300, 100}, {160, 180}} {
		r, g, b, _ := img.At(pt[0], pt[1]).RGBA()
		i := (pt[1]*320 + pt[0]) * 3
		if d := absDiff(uint8(r>>8), want.BGR[i+2]) + absDiff(uint8(g>>8), want.BGR[i+1]) + absDiff(uint8(b>>8), want.BGR[i]); d > 24 {
			t.Errorf("pixel %v = %d,%d,%d want %d,%d,%d", pt, r>>8, g>>8, b>>8, want.BGR[i+2], want.BGR[i+1], want.BGR[i])
		}
	}
	rs := wait(t, f.relays, "relay summary")
	if rs.End != "client-closed" || rs.Err != nil || rs.ClientPDUs < 5 || rs.ServerPDUs < 6 || rs.UserName != "alice" || rs.Target == "" {
		t.Fatalf("relay %+v", rs)
	}
	bs := wait(t, f.backend, "target summary")
	if !bs.Authorized || bs.UserName != "alice" || bs.ClientName != "FRONT" || bs.Err != nil {
		t.Fatalf("target %+v", bs)
	}
	fs := wait(t, f.sessions, "front summary")
	if !fs.Authorized || fs.Stage != "handler" || fs.Err != nil {
		t.Fatalf("front %+v", fs)
	}
	if f.log.contains("pw-pass-through") {
		t.Fatal("password leaked into gateway/target logs")
	}
}

func TestRouteDenied(t *testing.T) {
	f := setup(t, func(_ context.Context, p server.Peer) (Target, error) {
		return Target{}, errors.New("user " + p.UserName + " has no targets")
	})
	_, err := transport.Activate(context.Background(), f.gwAddr, clientOpts(f))
	var ei *wire.ErrorInfo
	if !errors.As(err, &ei) || ei.Code != wire.ErrInfoServerDeniedConnection {
		t.Fatalf("client error %v", err)
	}
	fs := wait(t, f.sessions, "front summary")
	if fs.Authorized || !errors.Is(fs.Err, server.ErrDenied) {
		t.Fatalf("front %+v", fs)
	}
}

func TestTargetUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	_ = ln.Close()
	f := setup(t, func(context.Context, server.Peer) (Target, error) {
		return Target{Address: dead, Timeout: 2 * time.Second}, nil
	})
	_, err := transport.Activate(context.Background(), f.gwAddr, clientOpts(f))
	var ei *wire.ErrorInfo
	if !errors.As(err, &ei) || ei.Code != wire.ErrInfoServerDeniedConnection {
		t.Fatalf("client error %v", err)
	}
	fs := wait(t, f.sessions, "front summary")
	if !errors.Is(fs.Err, ErrBackend) {
		t.Fatalf("front %+v", fs)
	}
}

func TestTargetRejectsPassedThroughCredentials(t *testing.T) {
	f := setup(t, nil)
	opts := clientOpts(f)
	opts.Password = "wrong"
	_, err := transport.Activate(context.Background(), f.gwAddr, opts)
	var ei *wire.ErrorInfo
	if !errors.As(err, &ei) || ei.Code != wire.ErrInfoServerDeniedConnection {
		t.Fatalf("client error %v (want the target's ERRINFO relayed)", err)
	}
	bs := wait(t, f.backend, "target summary")
	if bs.Authorized || !errors.Is(bs.Err, server.ErrDenied) {
		t.Fatalf("target %+v", bs)
	}
	rs := wait(t, f.relays, "relay summary")
	if rs.End != "target-closed" {
		t.Fatalf("relay %+v", rs)
	}
}

func TestCapabilityFilter(t *testing.T) {
	r := &relay{g: &Gateway{cfg: Config{AllowCapability: DefaultAllowCapability}}, sum: Summary{DroppedCapabilities: map[uint16]int{}}}
	in := []wire.CapabilitySet{{Type: wire.CapsTypeGeneral}, {Type: wire.CapsTypeBitmapCodecs}, {Type: wire.CapsTypeSurfaceCommands}, {Type: wire.CapsTypeInput}}
	out := r.filterCaps(in)
	if len(out) != 2 || out[0].Type != wire.CapsTypeGeneral || out[1].Type != wire.CapsTypeInput || r.sum.DroppedCapabilities[wire.CapsTypeBitmapCodecs] != 1 {
		t.Fatalf("kept %v dropped %v", out, r.sum.DroppedCapabilities)
	}
	if _, err := New(Config{}); !errors.Is(err, server.ErrConfig) {
		t.Fatal(err)
	}
}

// TestChannelRelay opens a static channel through the gateway to a Handler
// backend that echoes chunks, and checks that a channel the policy refuses
// is not opened towards the target and its data is dropped.
func TestChannelRelay(t *testing.T) {
	echoed := make(chan []wire.ChannelDef, 1)
	backCert, backPool := testCertificate(t, "target")
	backSrv, err := server.New(server.Config{
		TLS: &tls.Config{Certificates: []tls.Certificate{backCert}},
		Handler: func(_ context.Context, c *server.Conn) error {
			echoed <- c.Channels()
			for {
				pdu, err := c.ReadPDU()
				if err != nil {
					return nil
				}
				if pdu.Channel != 0 {
					if err := c.WriteChannel(pdu.Channel, pdu.Data); err != nil {
						return err
					}
				}
			}
		},
		HandshakeTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	backAddr := serve(t, "target", backSrv.Serve)
	relays := make(chan Summary, 1)
	gwCert, gwPool := testCertificate(t, "gateway")
	gw, err := New(Config{
		TLS: &tls.Config{Certificates: []tls.Certificate{gwCert}},
		Route: func(context.Context, server.Peer) (Target, error) {
			return Target{Address: backAddr, ServerName: "target", RootCAs: backPool}, nil
		},
		AllowChannel:     func(name string) bool { return name == "cliprdr" },
		HandshakeTimeout: 10 * time.Second,
		Logf:             func(string, ...any) {},
		OnRelay:          func(r Summary) { relays <- r },
	})
	if err != nil {
		t.Fatal(err)
	}
	gwAddr := serve(t, "gateway", gw.Serve)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := transport.Dial(ctx, gwAddr, transport.Options{
		ServerName: "gateway", RootCAs: gwPool, Timeout: 10 * time.Second,
		Channels: []wire.ChannelDef{{Name: "rdpdr", Options: 0x80800000}, {Name: "cliprdr", Options: 0xc0a00000}},
		UserName: "alice", Password: "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := client.StaticChannels()
	if len(ids) != 2 {
		t.Fatalf("client got channels %v", ids)
	}
	rdpdr, cliprdr := ids[0], ids[1]
	if defs := wait(t, echoed, "target channels"); len(defs) != 1 || defs[0].Name != "cliprdr" || defs[0].Options != 0xc0a00000 {
		t.Fatalf("target saw channels %+v", defs)
	}
	chunk := []byte{8, 0, 0, 0, 3, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8} // CHANNEL_PDU_HEADER + 8 bytes
	if err := client.WriteChannel(rdpdr, chunk); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteChannel(cliprdr, chunk); err != nil {
		t.Fatal(err)
	}
	pdu, err := client.ReadPDU()
	if err != nil {
		t.Fatal(err)
	}
	if pdu.FastPath || pdu.Channel != cliprdr || string(pdu.Data) != string(chunk) {
		t.Fatalf("echo %+v", pdu)
	}
	_ = client.Disconnect()
	sum := wait(t, relays, "relay summary")
	if sum.End != "client-closed" || sum.ChannelPDUs["cliprdr"] != 2 || sum.DroppedChannels["rdpdr"] != 1 || len(sum.ChannelPDUs) != 1 {
		t.Fatalf("summary %+v", sum)
	}
}
