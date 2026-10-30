package monitor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"rdp.local/kernel/gateway"
	"rdp.local/kernel/server"
	"rdp.local/kernel/wire"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestParseAccountsAndVerify(t *testing.T) {
	hash, err := HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAccounts([]byte("# comment\n\nAlice: plain-pw \nbob:" + hash + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 2 || a["alice"] != " plain-pw" {
		t.Fatalf("accounts %v", a)
	}
	for _, c := range []struct {
		user, password string
		want           bool
	}{
		{"alice", " plain-pw", true},
		{"ALICE", " plain-pw", true},
		{"alice", "plain-pw", false},
		{"bob", "s3cret", true},
		{"bob", "s3crеt", false},
		{"bob", "", false},
		{"carol", "s3cret", false},
	} {
		if got := a.Verify(c.user, c.password); got != c.want {
			t.Errorf("Verify(%q, %q) = %v", c.user, c.password, got)
		}
	}
	for _, bad := range []string{"nocolon\n", "alice:\n", ":pw\n", "bob:$pbkdf2-sha256$1$aa$bb\n"} {
		if _, err := ParseAccounts([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	for _, c := range []struct {
		origin, host string
		want         bool
	}{
		{"", "mon.example", true},
		{"null", "mon.example", false},
		{"https://mon.example", "mon.example", true},
		{"https://MON.example", "mon.example", true},
		{"https://evil.example", "mon.example", false},
		{"https://mon.example:8443", "mon.example", false},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/connect", nil)
		r.Host = c.host
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if got := sameOrigin(r, nil); got != c.want {
			t.Errorf("origin %q host %q: %v", c.origin, c.host, got)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/connect", nil)
	r.Host = "10.0.0.5:8090"
	r.Header.Set("Origin", "https://rdp.example.com")
	if sameOrigin(r, nil) || !sameOrigin(r, []string{"https://rdp.example.com/"}) || sameOrigin(r, []string{"http://rdp.example.com"}) {
		t.Error("allowed origins not applied")
	}
}

func TestTokenCookie(t *testing.T) {
	m, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	h := m.Handler("tok", "")
	do := func(method, path, auth string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "/api/sessions?token=tok", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("query token accepted: %d", w.Code)
	}
	if w := do("POST", "/api/token-session", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("token-session without bearer: %d", w.Code)
	}
	w := do("POST", "/api/token-session", "Bearer tok")
	cs := w.Result().Cookies()
	if w.Code != http.StatusNoContent || len(cs) != 1 || cs[0].Name != tokenCookie || !cs[0].HttpOnly {
		t.Fatalf("token-session: %d %v", w.Code, cs)
	}
	if w := do("GET", "/api/sessions", "", cs[0]); w.Code != http.StatusOK {
		t.Fatalf("cookie rejected: %d", w.Code)
	}
	do("POST", "/api/logout", "", cs[0])
	if w := do("GET", "/api/sessions", "", cs[0]); w.Code != http.StatusUnauthorized {
		t.Fatalf("cookie survived logout: %d", w.Code)
	}
}

// webFixture is a monitor whose gateway can open browser sessions to a
// local test server.
type webFixture struct {
	mon     *Monitor
	api     *httptest.Server
	backend string
}

func setupWeb(t *testing.T, tune func(*Config)) *webFixture {
	t.Helper()
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
	cfg := Config{
		RecordDir: t.TempDir(), FrameInterval: 20 * time.Millisecond, Logf: t.Logf,
		Users: Accounts{"bob": "pw-bob"},
		WebRoute: func(_, address string) (gateway.Target, error) {
			if address != backAddr {
				return gateway.Target{}, errors.New("host not in -allow-target")
			}
			return gateway.Target{Address: backAddr, ServerName: "target", RootCAs: backPool}, nil
		},
	}
	if tune != nil {
		tune(&cfg)
	}
	mon, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gwCert, _ := testCert(t, "gateway")
	gw, err := gateway.New(gateway.Config{
		TLS: &tls.Config{Certificates: []tls.Certificate{gwCert}},
		Route: func(context.Context, server.Peer) (gateway.Target, error) {
			return gateway.Target{}, errors.New("no front-end route")
		},
		HandshakeTimeout: 10 * time.Second,
		Logf:             t.Logf,
		Observe:          mon.Observe,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebRoute != nil {
		mon.SetWebConnector(gw)
	}
	f := &webFixture{mon: mon, api: httptest.NewServer(mon.Handler("", "")), backend: backAddr}
	t.Cleanup(func() {
		for _, s := range mon.Sessions() {
			if sess := mon.Session(s.ID); sess != nil {
				sess.Disconnect()
			}
			f.waitGone(t, s.ID)
		}
		f.api.Close()
	})
	return f
}

// waitGone waits until a session has ended and been removed, so no
// recorder goroutine logs after the test.
func (f *webFixture) waitGone(t *testing.T, id string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if f.mon.Session(id) == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("session %s did not end", id)
}

// client returns an HTTP client that keeps the login cookie.
func (f *webFixture) client(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 30 * time.Second}
}

func (f *webFixture) post(t *testing.T, c *http.Client, path string, body any, headers ...[2]string) *http.Response {
	t.Helper()
	js, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, f.api.URL+path, bytes.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (f *webFixture) login(t *testing.T, user, password string) *http.Client {
	t.Helper()
	c := f.client(t)
	resp := f.post(t, c, "/api/login", map[string]string{"user": user, "password": password})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %s", resp.Status)
	}
	return c
}

func (f *webFixture) cookie(t *testing.T, c *http.Client) string {
	t.Helper()
	for _, ck := range c.Jar.Cookies(mustURL(t, f.api.URL)) {
		if ck.Name == sessionCookie {
			return "Cookie: " + ck.Name + "=" + ck.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestWebLoginSessionAndThrottle(t *testing.T) {
	f := setupWeb(t, nil)
	c := f.client(t)
	// Without a login the API is closed, even though no token is set.
	resp, err := c.Get(f.api.URL + "/api/sessions")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous list: %s", resp.Status)
	}
	// Wrong passwords are refused and then throttled per address.
	for i := 0; i < loginMaxFails; i++ {
		r := f.post(t, c, "/api/login", map[string]string{"user": "bob", "password": "wrong"})
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %s", i, r.Status)
		}
	}
	r := f.post(t, c, "/api/login", map[string]string{"user": "bob", "password": "pw-bob"})
	r.Body.Close()
	if r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked out: %s", r.Status)
	}
	f.mon.auth.mu.Lock()
	f.mon.auth.fails = map[string]*failState{}
	f.mon.auth.mu.Unlock()

	c = f.login(t, "BOB ", "pw-bob")
	resp, err = c.Get(f.api.URL + "/api/info")
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&info)
	resp.Body.Close()
	if info["user"] != "bob" || info["login"] != true || info["web"] != true {
		t.Fatalf("info %v", info)
	}
	// Logging out invalidates the cookie.
	r = f.post(t, c, "/api/logout", map[string]string{})
	r.Body.Close()
	resp, err = c.Get(f.api.URL + "/api/sessions")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout: %s", resp.Status)
	}
}

func TestWebCrossSiteRefused(t *testing.T) {
	f := setupWeb(t, nil)
	c := f.login(t, "bob", "pw-bob")
	r := f.post(t, c, "/api/connect", map[string]any{"address": f.backend}, [2]string{"Origin", "https://evil.example"})
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site connect: %s", r.Status)
	}
	// A cross-site WebSocket upgrade is refused before authentication.
	cookie := f.cookie(t, c)
	addr := strings.TrimPrefix(f.api.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /api/sessions/x/live HTTP/1.1\r\nHost: x\r\nOrigin: https://evil.example\r\n%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", cookie)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site upgrade: %s", resp.Status)
	}
}

func TestWebConnectPolicy(t *testing.T) {
	f := setupWeb(t, nil)
	c := f.login(t, "bob", "pw-bob")
	// A token-only request cannot open a session once logins are required.
	anon := f.client(t)
	r := f.post(t, anon, "/api/connect", map[string]any{"address": f.backend})
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous connect: %s", r.Status)
	}
	for _, c2 := range []struct {
		name string
		body map[string]any
		want int
	}{
		{"no address", map[string]any{"user": "u", "password": "p"}, http.StatusBadRequest},
		{"unknown field", map[string]any{"address": f.backend, "shell": "cmd"}, http.StatusBadRequest},
		{"target not allowed", map[string]any{"address": "10.0.0.1:3389", "user": "u", "password": "p"}, http.StatusForbidden},
	} {
		r := f.post(t, c, "/api/connect", c2.body)
		r.Body.Close()
		if r.StatusCode != c2.want {
			t.Errorf("%s: %s, want %d", c2.name, r.Status, c2.want)
		}
	}
}

func TestWebConnectDisabled(t *testing.T) {
	f := setupWeb(t, func(c *Config) { c.WebRoute = nil })
	c := f.login(t, "bob", "pw-bob")
	r := f.post(t, c, "/api/connect", map[string]any{"address": f.backend, "user": "u", "password": "p"})
	r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("connect without WebRoute: %s", r.Status)
	}
}

// connect opens a browser session and returns its id and owner key.
func (f *webFixture) connect(t *testing.T, c *http.Client) (string, string) {
	t.Helper()
	resp := f.post(t, c, "/api/connect", map[string]any{"address": f.backend, "user": "alice", "domain": "corp", "password": "secret-pw", "width": 1024, "height": 768})
	defer resp.Body.Close()
	var out struct {
		ID            string `json:"id"`
		OwnerKey      string `json:"owner_key"`
		Width, Height int
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.ID == "" || out.OwnerKey == "" || out.Width != 1024 || out.Height != 768 {
		t.Fatalf("connect: %+v", out)
	}
	return out.ID, out.OwnerKey
}

func TestWebSessionOwnerControlsWithoutAllowControl(t *testing.T) {
	// AllowControl stays off: only the browser that opened the session
	// (the RDP client itself) may send input.
	f := setupWeb(t, func(c *Config) { c.AllowControl = false })
	c := f.login(t, "bob", "pw-bob")
	id, key := f.connect(t, c)
	s := f.mon.Session(id)
	if s == nil {
		t.Fatal("session not registered")
	}
	if info := s.Info(); !info.Web || info.Owner != "bob" || info.Target != f.backend {
		t.Fatalf("info %+v", info)
	}
	if !s.isOwner(key) || s.isOwner("") || s.isOwner(strings.Repeat("0", len(key))) {
		t.Fatal("owner key check")
	}
	cookie := f.cookie(t, c)
	// A viewer without the owner key only watches.
	plain := dialWS(t, f.api.URL, "/api/sessions/"+id+"/live?control=1", cookie)
	defer plain.c.Close()
	op, p := plain.read(t)
	var hello map[string]any
	if op != wsText || json.Unmarshal(p, &hello) != nil {
		t.Fatalf("hello %d %q", op, p)
	}
	if hello["control"] != false || hello["owner"] != false {
		t.Fatalf("viewer hello %v", hello)
	}
	// The owner gets control, and its input reaches the target.
	ws := dialWS(t, f.api.URL, "/api/sessions/"+id+"/live?owner="+key, cookie)
	defer ws.c.Close()
	op, p = ws.read(t)
	if op != wsText || json.Unmarshal(p, &hello) != nil {
		t.Fatalf("hello %d %q", op, p)
	}
	if hello["control"] != true || hello["owner"] != true {
		t.Fatalf("owner hello %v", hello)
	}
	move := []byte{byte(wire.InputKindMouse), 0x00, 0x08, 0, 0, 10, 0, 20, 0} // PTRFLAGS_MOVE
	if err := ws.send(move); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Info().Injected == 0 {
		if time.Now().After(deadline) {
			t.Fatal("owner input not injected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.Disconnect()
	f.waitGone(t, id)
}

func TestWebSessionLimit(t *testing.T) {
	f := setupWeb(t, func(c *Config) { c.WebMaxSessions = 1 })
	c := f.login(t, "bob", "pw-bob")
	id, _ := f.connect(t, c)
	r := f.post(t, c, "/api/connect", map[string]any{"address": f.backend, "user": "alice", "password": "secret-pw"})
	r.Body.Close()
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second session: %s", r.Status)
	}
	// Once the first session ends the slot is free again.
	f.mon.Session(id).Disconnect()
	f.waitGone(t, id)
	id2, _ := f.connect(t, c)
	f.mon.Session(id2).Disconnect()
	f.waitGone(t, id2)
}
