package monitor

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"rdp.local/kernel/wire"
)

var validID = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)

// Handler serves the monitor API under /api/ and, when uiDir is set, the
// built web UI (single-page app) everywhere else. A non-empty token is
// required on every API request as "Authorization: Bearer <token>"; a
// browser exchanges it once (POST /api/token-session) for an HttpOnly
// cookie so WebSocket and download URLs never carry it. With Config.Users
// a browser may instead log in (POST /api/login). Cross-site requests
// (Origin neither Host nor in Config.AllowedOrigins) are refused.
func (m *Monitor) Handler(token, uiDir string) http.Handler {
	mux := http.NewServeMux()
	m.driveRoutes(mux, token)
	mux.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"control": m.cfg.AllowControl, "recording": m.cfg.RecordDir != "", "drive_control": m.cfg.AllowDriveControl && token != "", "events": true,
			"login": m.auth != nil, "user": m.auth.userFor(r), "web": m.webConnector() != nil && m.cfg.WebRoute != nil,
		})
	})
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		if m.auth == nil {
			http.Error(w, "login is not enabled", http.StatusNotFound)
			return
		}
		m.auth.login(w, r)
	})
	mux.HandleFunc("POST /api/token-session", func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := m.tokenAuth.issue(w, r, "token"); err != nil {
			http.Error(w, "entropy", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		m.tokenAuth.end(w, r)
		if m.auth != nil {
			m.auth.end(w, r)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/connect", func(w http.ResponseWriter, r *http.Request) {
		user := m.auth.userFor(r)
		if user == "" {
			if m.auth != nil || token == "" || !m.tokenOK(r, token) {
				http.Error(w, "login required", http.StatusUnauthorized)
				return
			}
			user = "token"
		}
		m.serveConnect(w, r, user)
	})
	mux.HandleFunc("GET /api/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, m.Sessions())
	})
	mux.HandleFunc("GET /api/sessions/{id}/live", m.serveLive)
	mux.HandleFunc("POST /api/sessions/{id}/disconnect", func(w http.ResponseWriter, r *http.Request) {
		s := m.Session(r.PathValue("id"))
		if s == nil {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		m.cfg.Logf("monitor %s: disconnected from the monitor (%s)", s.ID(), r.RemoteAddr)
		s.Disconnect()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/recordings", func(w http.ResponseWriter, r *http.Request) {
		list, err := m.Recordings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, list)
	})
	mux.HandleFunc("GET /api/recordings/{id}", m.serveRecording)
	mux.HandleFunc("DELETE /api/recordings/{id}", m.deleteRecording)
	if uiDir != "" {
		mux.Handle("/", spa(uiDir))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			mux.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r, m.cfg.AllowedOrigins) && (r.Method != http.MethodGet || headerHas(r.Header, "Upgrade", "websocket")) {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/api/login" && r.Method == http.MethodPost {
			mux.ServeHTTP(w, r)
			return
		}
		if !m.authorized(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// authorized admits the API token or, with Config.Users, a login cookie.
// Without either configured the API is open (loopback deployments).
func (m *Monitor) authorized(r *http.Request, token string) bool {
	if m.auth != nil && m.auth.userFor(r) != "" {
		return true
	}
	if token == "" && m.auth != nil {
		return false
	}
	return m.tokenOK(r, token)
}

// tokenOK admits the bearer token or a cookie issued for it.
func (m *Monitor) tokenOK(r *http.Request, token string) bool {
	if token != "" && m.tokenAuth.userFor(r) != "" {
		return true
	}
	return authorized(r, token)
}

func authorized(r *http.Request, token string) bool {
	if token == "" {
		return true
	}
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(token)) == 1
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func spa(dir string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(dir, filepath.FromSlash(filepath.Clean("/"+r.URL.Path)))
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
}

// Viewer input: a binary WebSocket message of 9-byte events, each
// kind u8 (wire.InputKind) | flags u16 | code u16 | x u16 | y u16, with the
// slow-path flag words (KBDFLAGS_*, PTRFLAGS_*).
const (
	viewerEventLen  = 9
	maxViewerEvents = 64
)

func decodeViewerInput(p []byte) ([]wire.InputEvent, error) {
	if len(p) == 0 || len(p)%viewerEventLen != 0 || len(p)/viewerEventLen > maxViewerEvents {
		return nil, fmt.Errorf("monitor: input message of %d bytes", len(p))
	}
	events := make([]wire.InputEvent, 0, len(p)/viewerEventLen)
	for ; len(p) > 0; p = p[viewerEventLen:] {
		ev := wire.InputEvent{
			Kind: wire.InputKind(p[0]), Flags: binary.LittleEndian.Uint16(p[1:]), Code: binary.LittleEndian.Uint16(p[3:]),
			X: binary.LittleEndian.Uint16(p[5:]), Y: binary.LittleEndian.Uint16(p[7:]),
		}
		switch ev.Kind {
		case wire.InputKindScancode, wire.InputKindUnicode, wire.InputKindMouse, wire.InputKindMouseX:
		default:
			return nil, fmt.Errorf("monitor: viewer input kind %d", p[0])
		}
		events = append(events, ev)
	}
	return events, nil
}

func (m *Monitor) serveLive(w http.ResponseWriter, r *http.Request) {
	s := m.Session(r.PathValue("id"))
	if s == nil {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	owner := s.isOwner(r.URL.Query().Get("owner"))
	control := owner || (r.URL.Query().Get("control") == "1" && m.cfg.AllowControl)
	ws, err := wsUpgrade(w, r)
	if err != nil {
		return
	}
	s.mu.Lock()
	drive, canResize := s.driveName, s.canResize
	s.mu.Unlock()
	hello, _ := json.Marshal(map[string]any{"type": "hello", "session": s.Info(), "control": control, "owner": owner,
		"clipboard": owner && s.ctl.Clipboard != nil, "drives": owner && s.ctl.MapDrive != nil, "drive": drive,
		"resize": owner && canResize})
	if err := ws.write(wsText, hello); err != nil {
		_ = ws.conn.Close()
		return
	}
	v := &viewer{out: make(chan []byte, 256), control: control, owner: owner}
	if owner {
		v.ctl = make(chan []byte, 256)
	}
	if !s.attach(v) {
		ws.close(1000, "session ended")
		return
	}
	if owner {
		s.ownerAttached()
	}
	defer s.detach(v)
	if control && !owner {
		m.cfg.Logf("monitor %s: %s joined with control", s.ID(), r.RemoteAddr)
		defer m.cfg.Logf("monitor %s: %s left", s.ID(), r.RemoteAddr)
	}
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			op, p, err := ws.read()
			if err != nil {
				return
			}
			if op == wsText && owner {
				s.ownerMessage(p)
				continue
			}
			if op != wsBinary || !control {
				continue
			}
			if owner {
				s.touch()
			}
			events, err := decodeViewerInput(p)
			if err != nil {
				return
			}
			if err := s.Inject(events); err != nil && !errors.Is(err, ErrControl) {
				m.cfg.Logf("monitor %s: inject: %v", s.ID(), err)
			}
		}
	}()
	for {
		select {
		case msg := <-v.ctl:
			if err := ws.write(wsText, msg); err != nil {
				_ = ws.conn.Close()
				<-readerDone
				return
			}
		case rec := <-v.out:
			if err := ws.write(wsBinary, rec); err != nil {
				_ = ws.conn.Close()
				<-readerDone
				return
			}
		case <-s.finished:
			for drained := false; !drained; {
				select {
				case rec := <-v.out:
					_ = ws.write(wsBinary, rec)
				default:
					drained = true
				}
			}
			ws.close(1000, "session ended")
			<-readerDone
			return
		case <-readerDone:
			_ = ws.conn.Close()
			return
		}
	}
}

// Recordings lists the recordings in RecordDir, newest first. A recording
// still being written has End "recording".
func (m *Monitor) Recordings() ([]Meta, error) {
	out := []Meta{}
	if m.cfg.RecordDir == "" {
		return out, nil
	}
	paths, err := filepath.Glob(filepath.Join(m.cfg.RecordDir, "*.rdpv"))
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		id := strings.TrimSuffix(filepath.Base(p), ".rdpv")
		if !validID.MatchString(id) {
			continue
		}
		var meta Meta
		if s := m.Session(id); s != nil {
			s.mu.Lock()
			meta = s.meta
			s.mu.Unlock()
			meta.DurationMS, meta.End = int64(s.ms()), "recording"
			if st, err := os.Stat(p); err == nil {
				meta.Size = st.Size()
			}
		} else if js, err := os.ReadFile(strings.TrimSuffix(p, ".rdpv") + ".json"); err == nil && json.Unmarshal(js, &meta) == nil {
		} else if meta, err = scanRecording(p); err != nil {
			continue
		}
		meta.ID = id
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out, nil
}

func (m *Monitor) recordingPath(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	id := r.PathValue("id")
	if m.cfg.RecordDir == "" || !validID.MatchString(id) {
		http.Error(w, "no such recording", http.StatusNotFound)
		return "", "", false
	}
	return id, filepath.Join(m.cfg.RecordDir, id+".rdpv"), true
}

func (m *Monitor) serveRecording(w http.ResponseWriter, r *http.Request) {
	id, p, ok := m.recordingPath(w, r)
	if !ok {
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, "no such recording", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.rdpv"`)
	}
	http.ServeContent(w, r, id+".rdpv", st.ModTime(), f)
}

func (m *Monitor) deleteRecording(w http.ResponseWriter, r *http.Request) {
	id, p, ok := m.recordingPath(w, r)
	if !ok {
		return
	}
	if m.Session(id) != nil {
		http.Error(w, "recording in progress", http.StatusConflict)
		return
	}
	if err := os.Remove(p); err != nil {
		http.Error(w, "no such recording", http.StatusNotFound)
		return
	}
	_ = os.Remove(strings.TrimSuffix(p, ".rdpv") + ".json")
	m.cfg.Logf("monitor %s: recording deleted (%s)", id, r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}
