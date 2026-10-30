package monitor

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Accounts are the browser users allowed to log in (lower-cased user name
// to secret). A secret is either a plain password or a hash produced by
// HashPassword ("$pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>").
type Accounts map[string]string

// ParseAccounts reads one "user:secret" per line; blank lines and lines
// starting with # are skipped.
func ParseAccounts(data []byte) (Accounts, error) {
	a := Accounts{}
	for i, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, secret, ok := strings.Cut(line, ":")
		user = strings.ToLower(strings.TrimSpace(user))
		if !ok || user == "" || secret == "" {
			return nil, fmt.Errorf("line %d: expected user:password", i+1)
		}
		if strings.HasPrefix(secret, "$pbkdf2-sha256$") {
			if _, _, _, err := parseHash(secret); err != nil {
				return nil, fmt.Errorf("line %d: %v", i+1, err)
			}
		}
		a[user] = secret
	}
	return a, nil
}

const (
	hashPrefix     = "$pbkdf2-sha256$"
	hashIterations = 600_000
)

// HashPassword derives a PBKDF2-SHA256 hash suitable for an accounts file.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, hashIterations, 32)
	if err != nil {
		return "", err
	}
	return hashPrefix + strconv.Itoa(hashIterations) + "$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(key), nil
}

func parseHash(s string) (iter int, salt, key []byte, err error) {
	parts := strings.Split(strings.TrimPrefix(s, hashPrefix), "$")
	if len(parts) != 3 {
		return 0, nil, nil, errors.New("malformed password hash")
	}
	if iter, err = strconv.Atoi(parts[0]); err != nil || iter < 1000 || iter > 10_000_000 {
		return 0, nil, nil, errors.New("bad hash iteration count")
	}
	if salt, err = hex.DecodeString(parts[1]); err != nil || len(salt) < 8 {
		return 0, nil, nil, errors.New("bad hash salt")
	}
	if key, err = hex.DecodeString(parts[2]); err != nil || len(key) < 16 {
		return 0, nil, nil, errors.New("bad hash")
	}
	return iter, salt, key, nil
}

// Verify checks a password in constant time with respect to the secret.
func (a Accounts) Verify(user, password string) bool {
	secret, ok := a[strings.ToLower(strings.TrimSpace(user))]
	if !ok || password == "" {
		// Burn comparable time so a missing user is not distinguishable.
		_, _ = pbkdf2.Key(sha256.New, password, []byte("nouser"), hashIterations/4, 32)
		return false
	}
	if strings.HasPrefix(secret, hashPrefix) {
		iter, salt, want, err := parseHash(secret)
		if err != nil {
			return false
		}
		got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
		return err == nil && subtle.ConstantTimeCompare(got, want) == 1
	}
	return subtle.ConstantTimeCompare([]byte(secret), []byte(password)) == 1
}

const (
	sessionCookie   = "rdpmon_session"
	tokenCookie     = "rdpmon_token"
	loginIdle       = 12 * time.Hour
	loginMaxFails   = 5
	loginLockPeriod = time.Minute
)

type loginSession struct {
	user    string
	expires time.Time
}

type failState struct {
	count int
	until time.Time
}

// webAuth holds browser login sessions (in memory; a restart logs
// everyone out) and per-address login throttling.
type webAuth struct {
	cookie   string
	accounts Accounts
	mu       sync.Mutex
	sessions map[string]*loginSession
	fails    map[string]*failState
}

func newWebAuth(a Accounts) *webAuth {
	return &webAuth{cookie: sessionCookie, accounts: a, sessions: map[string]*loginSession{}, fails: map[string]*failState{}}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// userFor returns the logged-in user of r's cookie, or "".
func (a *webAuth) userFor(r *http.Request) string {
	if a == nil {
		return ""
	}
	c, err := r.Cookie(a.cookie)
	if err != nil || c.Value == "" {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return ""
	}
	now := time.Now()
	if now.After(s.expires) {
		delete(a.sessions, c.Value)
		return ""
	}
	s.expires = now.Add(loginIdle)
	return s.user
}

func (a *webAuth) locked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, f := range a.fails {
		if now.After(f.until) && k != ip {
			delete(a.fails, k)
		}
	}
	f := a.fails[ip]
	return f != nil && f.count >= loginMaxFails && now.Before(f.until)
}

func (a *webAuth) failed(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[ip]
	if f == nil || time.Now().After(f.until) {
		f = &failState{}
		a.fails[ip] = f
	}
	f.count++
	f.until = time.Now().Add(loginLockPeriod)
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (a *webAuth) login(w http.ResponseWriter, r *http.Request) {
	var body struct{ User, Password string }
	if err := decodeJSONBody(r, &body, 4096); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip := clientIP(r)
	if a.locked(ip) {
		http.Error(w, "too many failed logins, try again later", http.StatusTooManyRequests)
		return
	}
	if !a.accounts.Verify(body.User, body.Password) {
		a.failed(ip)
		http.Error(w, "wrong user name or password", http.StatusUnauthorized)
		return
	}
	body.Password = ""
	a.mu.Lock()
	delete(a.fails, ip)
	a.mu.Unlock()
	user := strings.ToLower(strings.TrimSpace(body.User))
	if err := a.issue(w, r, user); err != nil {
		http.Error(w, "entropy", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"user": user})
}

// issue starts a cookie session for user.
func (a *webAuth) issue(w http.ResponseWriter, r *http.Request, user string) error {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	key := hex.EncodeToString(id)
	a.mu.Lock()
	a.sessions[key] = &loginSession{user: user, expires: time.Now().Add(loginIdle)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: a.cookie, Value: key, Path: "/", HttpOnly: true, Secure: secureRequest(r),
		SameSite: http.SameSiteStrictMode, MaxAge: int(loginIdle / time.Second),
	})
	return nil
}

// end drops r's cookie session and tells the browser to forget the cookie.
func (a *webAuth) end(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(a.cookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: a.cookie, Value: "", Path: "/", HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// sameOrigin rejects cross-site requests: when the browser sends an Origin
// header it must name the host the request was addressed to or one of
// allowed (scheme://host[:port], for a reverse proxy that rewrites Host).
func sameOrigin(r *http.Request, allowed []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return origin == ""
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimRight(a, "/"), origin) {
			return true
		}
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func decodeJSONBody(r *http.Request, v any, limit int64) error {
	body := http.MaxBytesReader(nil, r.Body, limit)
	defer body.Close()
	dec := jsonDecoder(body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
