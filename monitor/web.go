package monitor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"rdp.local/kernel/gateway"
	"rdp.local/kernel/wire"
)

// WebConnector opens browser-initiated RDP sessions (gateway.Gateway.ConnectWeb).
type WebConnector interface {
	ConnectWeb(ctx context.Context, req gateway.WebRequest) (*gateway.WebSession, error)
}

// SetWebConnector enables POST /api/connect: browser users may open their
// own RDP sessions through connector, restricted by Config.WebRoute.
func (m *Monitor) SetWebConnector(c WebConnector) {
	m.mu.Lock()
	m.web = c
	m.mu.Unlock()
}

func (m *Monitor) webConnector() WebConnector {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.web
}

// ownerGrace is how long a web session waits for its browser to attach
// before it is torn down as orphaned.
const ownerGrace = 60 * time.Second

func jsonDecoder(r io.Reader) *json.Decoder { return json.NewDecoder(r) }

type connectRequest struct {
	Address  string `json:"address"`
	User     string `json:"user"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	// Optional connection settings; zero values keep the defaults.
	ColorDepth     int    `json:"color_depth"`
	KeyboardLayout uint32 `json:"keyboard_layout"`
	Experience     string `json:"experience"`
}

// experienceFlags maps the connect page's visual experience presets to
// TS_INFO_PACKET performance flags ("" or unknown keeps the default).
func experienceFlags(name string) uint32 {
	const noFx = wire.PerfDisableWallpaper | wire.PerfDisableFullWindowDrag | wire.PerfDisableMenuAnimations | wire.PerfDisableTheming
	switch name {
	case "full":
		return wire.PerfEnableFontSmoothing | wire.PerfEnableDesktopComposition
	case "balanced":
		return wire.PerfDisableWallpaper | wire.PerfEnableFontSmoothing | wire.PerfEnableDesktopComposition
	case "fast":
		return noFx
	case "minimal":
		return noFx | wire.PerfDisableCursorShadow
	}
	return 0
}

func (m *Monitor) webSessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.sessions {
		if s.ctl.Web {
			n++
		}
	}
	return n
}

// Failed /api/connect attempts (denied or unreachable targets) per login:
// after connectMaxFails within connectFailWindow the user must wait, so a
// stolen login cannot be used to sweep the allowed networks.
const (
	connectMaxFails   = 10
	connectFailWindow = 10 * time.Minute
)

func (m *Monitor) connectBlocked(user string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.connFails[user]
	return f != nil && f.count >= connectMaxFails && time.Now().Before(f.until)
}

func (m *Monitor) connectFailed(user string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connFails == nil {
		m.connFails = map[string]*failState{}
	}
	now := time.Now()
	for k, f := range m.connFails {
		if now.After(f.until) {
			delete(m.connFails, k)
		}
	}
	f := m.connFails[user]
	if f == nil {
		f = &failState{}
		m.connFails[user] = f
	}
	f.count++
	f.until = now.Add(connectFailWindow)
}

func (m *Monitor) connectSucceeded(user string) {
	m.mu.Lock()
	delete(m.connFails, user)
	m.mu.Unlock()
}

// reserveUser counts a connect in progress against the per-user cap.
func (m *Monitor) reserveUser(user string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	limit := m.cfg.WebMaxPerUser
	if limit > 0 {
		n := m.connecting[user]
		for _, s := range m.sessions {
			s.mu.Lock()
			if s.ctl.Web && s.owner == user && !s.closed {
				n++
			}
			s.mu.Unlock()
		}
		if n >= limit {
			return false
		}
	}
	if m.connecting == nil {
		m.connecting = map[string]int{}
	}
	m.connecting[user]++
	return true
}

func (m *Monitor) releaseUser(user string) {
	m.mu.Lock()
	if m.connecting[user]--; m.connecting[user] <= 0 {
		delete(m.connecting, user)
	}
	m.mu.Unlock()
}

// serveConnect handles POST /api/connect for a logged-in browser user.
func (m *Monitor) serveConnect(w http.ResponseWriter, r *http.Request, user string) {
	gw := m.webConnector()
	if gw == nil || m.cfg.WebRoute == nil {
		http.Error(w, "web connections are not enabled", http.StatusNotFound)
		return
	}
	var req connectRequest
	if err := decodeJSONBody(r, &req, 16384); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	address := strings.TrimSpace(req.Address)
	if address == "" {
		http.Error(w, "server address required", http.StatusBadRequest)
		return
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(strings.Trim(address, "[]"), "3389")
	}
	limit := m.cfg.WebMaxSessions
	if limit <= 0 {
		limit = 8
	}
	if m.webSessionCount() >= limit {
		http.Error(w, "too many web sessions", http.StatusServiceUnavailable)
		return
	}
	if m.connectBlocked(user) {
		http.Error(w, "too many failed connections, try again later", http.StatusTooManyRequests)
		return
	}
	if !m.reserveUser(user) {
		http.Error(w, fmt.Sprintf("you already have %d open sessions", m.cfg.WebMaxPerUser), http.StatusTooManyRequests)
		return
	}
	defer m.releaseUser(user)
	target, err := m.cfg.WebRoute(user, address)
	if err != nil {
		m.connectFailed(user)
		m.cfg.Logf("monitor: web connect by %q from %s to %s denied: %v", user, r.RemoteAddr, address, err)
		http.Error(w, "server not allowed", http.StatusForbidden)
		return
	}
	if target.Address == "" {
		target.Address = address
	}
	wreq := gateway.WebRequest{
		RemoteAddr: r.RemoteAddr, UserName: req.User, Domain: req.Domain, Password: req.Password,
		Target: target, Width: clampDim(req.Width, 1280), Height: clampDim(req.Height, 800),
		ColorDepth: uint16(max(0, min(req.ColorDepth, 32))), KeyboardLayout: req.KeyboardLayout, PerformanceFlags: experienceFlags(req.Experience),
	}
	req.Password = ""
	ws, err := gw.ConnectWeb(context.Background(), wreq)
	wreq.Password = ""
	if err != nil {
		m.connectFailed(user)
		m.cfg.Logf("monitor: web connect by %q from %s to %s failed: %v", user, r.RemoteAddr, target.Address, err)
		http.Error(w, gateway.DescribeDialError(err), http.StatusBadGateway)
		return
	}
	s, ok := ws.Observer().(*Session)
	if !ok {
		ws.Disconnect()
		http.Error(w, "monitor did not observe the session", http.StatusInternalServerError)
		return
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		ws.Disconnect()
		http.Error(w, "entropy", http.StatusInternalServerError)
		return
	}
	m.connectSucceeded(user)
	s.mu.Lock()
	s.owner, s.ownerKey = user, hex.EncodeToString(key)
	s.mu.Unlock()
	time.AfterFunc(ownerGrace, func() {
		s.mu.Lock()
		orphan := !s.ownerSeen && !s.closed
		s.mu.Unlock()
		if orphan {
			m.cfg.Logf("monitor %s: browser never attached, disconnecting", s.ID())
			s.Disconnect()
		}
	})
	m.cfg.Logf("monitor %s: web session by %q from %s to %s", s.ID(), user, r.RemoteAddr, target.Address)
	writeJSON(w, map[string]any{"id": s.ID(), "owner_key": s.ownerKey, "width": wreq.Width, "height": wreq.Height})
}

func clampDim(v, def int) uint16 {
	if v <= 0 {
		return uint16(def)
	}
	if v < 640 {
		v = 640
	}
	if v > 4096 {
		v = 4096
	}
	return uint16(v &^ 3)
}

// isOwner reports whether key is this session's browser owner key.
func (s *Session) isOwner(key string) bool {
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ownerKey != "" && subtle.ConstantTimeCompare([]byte(key), []byte(s.ownerKey)) == 1
}

func (s *Session) ownerAttached() {
	s.mu.Lock()
	s.ownerSeen = true
	s.owners++
	s.lastActive = time.Now()
	if s.ownerGone != nil {
		s.ownerGone.Stop()
		s.ownerGone = nil
		s.m.cfg.Logf("monitor %s: browser reconnected", s.ID())
	}
	s.mu.Unlock()
}

var errOwnerGone = errors.New("browser left")

// ownerLeft ends a web session once its last owner browser has been gone
// for Config.WebReconnect, so a page reload or network change can resume.
func (s *Session) ownerLeft() {
	grace := s.m.cfg.WebReconnect
	if grace == 0 {
		grace = 2 * time.Minute
	}
	s.mu.Lock()
	s.owners--
	last := s.owners <= 0 && !s.closed
	if last && grace > 0 && s.ownerGone == nil {
		s.ownerGone = time.AfterFunc(grace, func() {
			s.mu.Lock()
			gone := s.owners <= 0 && s.ownerGone != nil
			s.mu.Unlock()
			if gone {
				s.m.cfg.Logf("monitor %s: browser did not come back within %v, disconnecting (%v)", s.ID(), grace, errOwnerGone)
				s.Disconnect()
			}
		})
	}
	s.mu.Unlock()
	if !last {
		return
	}
	s.failFS()
	if grace < 0 {
		s.m.cfg.Logf("monitor %s: browser left, disconnecting (%v)", s.ID(), fmt.Errorf("%w", errOwnerGone))
		s.Disconnect()
		return
	}
	s.m.cfg.Logf("monitor %s: browser left, keeping the session %v for a reconnect", s.ID(), grace)
}
