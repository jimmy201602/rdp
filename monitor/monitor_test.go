package monitor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rdp.local/kernel/gateway"
	"rdp.local/kernel/server"
	"rdp.local/kernel/transport"
	"rdp.local/kernel/wire"
)

func testCert(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func serve(t *testing.T, run func(ctx context.Context, ln net.Listener) error) string {
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
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	return ln.Addr().String()
}

type fixture struct {
	gwAddr string
	gwPool *x509.CertPool
	relays chan gateway.Summary
	mon    *Monitor
	dir    string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{relays: make(chan gateway.Summary, 4), dir: t.TempDir()}
	var err error
	f.mon, err = New(Config{RecordDir: f.dir, AllowControl: true, FrameInterval: 20 * time.Millisecond, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	backCert, backPool := testCert(t, "target")
	backSrv, err := server.New(server.Config{
		TLS:              &tls.Config{Certificates: []tls.Certificate{backCert}},
		Authorize:        func(context.Context, server.Peer) error { return nil },
		HandshakeTimeout: 10 * time.Second,
		Logf:             t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	backAddr := serve(t, backSrv.Serve)
	gwCert, gwPool := testCert(t, "gateway")
	gw, err := gateway.New(gateway.Config{
		TLS: &tls.Config{Certificates: []tls.Certificate{gwCert}},
		Route: func(context.Context, server.Peer) (gateway.Target, error) {
			return gateway.Target{Address: backAddr, ServerName: "target", RootCAs: backPool}, nil
		},
		HandshakeTimeout: 10 * time.Second,
		Logf:             t.Logf,
		OnRelay:          func(s gateway.Summary) { f.relays <- s },
		Observe:          f.mon.Observe,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.gwAddr, f.gwPool = serve(t, gw.Serve), gwPool
	return f
}

func (f *fixture) activate(t *testing.T, observe time.Duration) {
	t.Helper()
	opts := transport.Options{
		ServerName: "gateway", RootCAs: f.gwPool, Timeout: 10 * time.Second,
		ClientName: "FRONT", DesktopWidth: 320, DesktopHeight: 200, ColorDepth: 16,
		Domain: "corp", UserName: "alice", Password: "secret-pw", Observe: observe,
	}
	if res, err := transport.Activate(context.Background(), f.gwAddr, opts); err != nil {
		t.Fatalf("activate: %v (stage %s)", err, res.Stage)
	}
}

func (f *fixture) relay(t *testing.T) gateway.Summary {
	t.Helper()
	select {
	case s := <-f.relays:
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("no relay summary")
		return gateway.Summary{}
	}
}

func absDiff(a, b uint8) int {
	if a > b {
		return int(a - b)
	}
	return int(b - a)
}

// compose replays Frame and Key records (payloads) onto a 320x200 screen.
func compose(t *testing.T, rects [][]byte) *image.RGBA {
	t.Helper()
	screen := image.NewRGBA(image.Rect(0, 0, 320, 200))
	for _, p := range rects {
		sub, err := png.Decode(bytes.NewReader(p[8:]))
		if err != nil {
			t.Fatal(err)
		}
		at := image.Pt(int(binary.LittleEndian.Uint16(p)), int(binary.LittleEndian.Uint16(p[2:])))
		draw.Draw(screen, sub.Bounds().Add(at), sub, image.Point{}, draw.Src)
	}
	return screen
}

func checkPattern(t *testing.T, img image.Image) {
	t.Helper()
	want := server.TestPattern(320, 200)
	for _, pt := range [][2]int{{5, 5}, {100, 50}, {300, 100}, {160, 180}} {
		r, g, b, _ := img.At(pt[0], pt[1]).RGBA()
		i := (pt[1]*320 + pt[0]) * 3
		if d := absDiff(uint8(r>>8), want.BGR[i+2]) + absDiff(uint8(g>>8), want.BGR[i+1]) + absDiff(uint8(b>>8), want.BGR[i]); d > 24 {
			t.Errorf("pixel %v = %d,%d,%d want %d,%d,%d", pt, r>>8, g>>8, b>>8, want.BGR[i+2], want.BGR[i+1], want.BGR[i])
		}
	}
}

func TestRecording(t *testing.T) {
	f := setup(t)
	f.activate(t, 500*time.Millisecond)
	rs := f.relay(t)
	list, err := f.mon.Recordings()
	if err != nil || len(list) != 1 {
		t.Fatalf("recordings %+v, %v", list, err)
	}
	m := list[0]
	if !m.Complete || m.End != rs.End || m.UserName != "alice" || m.Width != 320 || m.Height != 200 || m.DurationMS <= 0 {
		t.Fatalf("meta %+v (relay end %q)", m, rs.End)
	}
	file, err := os.Open(filepath.Join(f.dir, m.ID+".rdpv"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	rd, err := NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []uint8
	var rects [][]byte
	for {
		rec, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, rec.Kind)
		if rec.Kind == RecResize && (binary.LittleEndian.Uint16(rec.Payload) != 320 || binary.LittleEndian.Uint16(rec.Payload[2:]) != 200) {
			t.Fatalf("resize %v", rec.Payload)
		}
		if rec.Kind == RecKey || rec.Kind == RecFrame {
			rects = append(rects, rec.Payload)
		}
	}
	if len(kinds) < 3 || kinds[0] != RecResize || kinds[1] != RecKey || kinds[len(kinds)-1] != RecEnd {
		t.Fatalf("record kinds %v", kinds)
	}
	checkPattern(t, compose(t, rects))
	if len(f.mon.Sessions()) != 0 {
		t.Fatal("session still listed")
	}
}

// wsClient is a minimal WebSocket client for the tests.
type wsClient struct {
	c  net.Conn
	br *bufio.Reader
}

// dialWS upgrades path; extra holds additional request header lines
// ("Cookie: ...") without the trailing CRLF.
func dialWS(t *testing.T, base, path string, extra ...string) *wsClient {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	head := ""
	for _, h := range extra {
		head += h + "\r\n"
	}
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n%s\r\n", path, head)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("upgrade %s %v", resp.Status, resp.Header)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &wsClient{c: c, br: br}
}

func (w *wsClient) read(t *testing.T) (byte, []byte) {
	t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(w.br, h[:]); err != nil {
		t.Fatal(err)
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		_, _ = io.ReadFull(w.br, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		_, _ = io.ReadFull(w.br, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(w.br, p); err != nil {
		t.Fatal(err)
	}
	return h[0] & 0x0f, p
}

func (w *wsClient) send(p []byte) error {
	mask := []byte{1, 2, 3, 4}
	out := []byte{0x82, 0x80 | byte(len(p))}
	out = append(out, mask...)
	for i, b := range p {
		out = append(out, b^mask[i%4])
	}
	_, err := w.c.Write(out)
	return err
}

func TestLiveViewAndControl(t *testing.T) {
	f := setup(t)
	api := httptest.NewServer(f.mon.Handler("tok", ""))
	defer api.Close()
	if resp, err := http.Get(api.URL + "/api/sessions"); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list: %v %v", resp, err)
	}
	type result struct {
		hello map[string]any
		kinds []uint8
		rects [][]byte
		err   error
	}
	got := make(chan result, 1)
	go func() {
		var r result
		defer func() { got <- r }()
		deadline := time.Now().Add(5 * time.Second)
		var id string
		for id == "" && time.Now().Before(deadline) {
			for _, s := range f.mon.Sessions() {
				id = s.ID
			}
			time.Sleep(5 * time.Millisecond)
		}
		if id == "" {
			r.err = errors.New("no live session")
			return
		}
		ws := dialWS(t, api.URL, "/api/sessions/"+id+"/live?control=1", "Authorization: Bearer tok")
		defer ws.c.Close()
		op, p := ws.read(t)
		if op != wsText || json.Unmarshal(p, &r.hello) != nil {
			r.err = fmt.Errorf("hello %d %q", op, p)
			return
		}
		sent := false
		for {
			op, p := ws.read(t)
			if op == wsClose {
				return
			}
			if op != wsBinary || len(p) < recordHeader {
				r.err = fmt.Errorf("record %d %q", op, p)
				return
			}
			r.kinds = append(r.kinds, p[0])
			switch p[0] {
			case RecKey, RecFrame:
				r.rects = append(r.rects, p[recordHeader:])
			}
			if p[0] == RecKey && !sent {
				sent = true
				move := []byte{byte(wire.InputKindMouse), 0x00, 0x08, 0, 0, 10, 0, 20, 0} // PTRFLAGS_MOVE to 10,20
				if r.err = ws.send(move); r.err != nil {
					return
				}
			}
		}
	}()
	f.activate(t, 1500*time.Millisecond)
	r := <-got
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.hello["control"] != true || len(r.kinds) < 3 || r.kinds[0] != RecResize || r.kinds[len(r.kinds)-1] != RecEnd {
		t.Fatalf("hello %v kinds %v", r.hello, r.kinds)
	}
	checkPattern(t, compose(t, r.rects))
	rs := f.relay(t)
	if rs.InjectedInput != 1 {
		t.Fatalf("injected %d, relay %+v", rs.InjectedInput, rs)
	}
}

func TestDecodeViewerInput(t *testing.T) {
	ev, err := decodeViewerInput([]byte{byte(wire.InputKindScancode), 0x00, 0x80, 0x1e, 0, 0, 0, 0, 0})
	if err != nil || len(ev) != 1 || ev[0].Kind != wire.InputKindScancode || ev[0].Flags != 0x8000 || ev[0].Code != 0x1e {
		t.Fatalf("%+v %v", ev, err)
	}
	for _, bad := range [][]byte{nil, {1, 2, 3}, {byte(wire.InputKindSync), 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, err := decodeViewerInput(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
