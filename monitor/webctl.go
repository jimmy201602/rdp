package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"rdp.local/kernel/gateway"
)

// Control messages between a web session's owner browser and the monitor
// travel as JSON text frames on the live WebSocket (screen and input stay
// binary):
//
//	browser -> monitor  {"t":"clip","text":...}      offer clipboard text
//	                    {"t":"map","name":...}       share a folder (File System Access API)
//	                    {"t":"unmap"}
//	                    {"t":"fs","id":N,...}        reply to a file request
//	monitor -> browser  {"t":"clip","text":...}      text copied on the remote desktop
//	                    {"t":"drive","name":...,"error":...}
//	                    {"t":"fs","id":N,"op":...}   file request on the shared folder

type ctlMessage struct {
	T    string `json:"t"`
	Text string `json:"text,omitempty"`
	HTML string `json:"html,omitempty"` // clip: HTML fragment; Data carries a PNG image
	Name string `json:"name,omitempty"`
	// fs replies
	ID      uint64    `json:"id,omitempty"`
	Err     string    `json:"err,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Entry   *fsEntry  `json:"entry,omitempty"`
	Entries []fsEntry `json:"entries,omitempty"`
	Data    []byte    `json:"data,omitempty"`
	// resize request (browser -> monitor) / display capability (monitor -> browser)
	W      int   `json:"w,omitempty"`
	H      int   `json:"h,omitempty"`
	Resize *bool `json:"resize,omitempty"`
	// reconnect status (monitor -> browser): attempt > 0 while redialing, 0 once back
	Attempt *int `json:"attempt,omitempty"`
}

type fsEntry struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"` // ms since the Unix epoch
}

func (e fsEntry) entry() gateway.FSEntry {
	var t time.Time
	if e.Mtime > 0 {
		t = time.UnixMilli(e.Mtime)
	}
	return gateway.FSEntry{Name: e.Name, Dir: e.Dir, Size: e.Size, Modified: t}
}

type fsRequest struct {
	T       string `json:"t"`
	ID      uint64 `json:"id"`
	Op      string `json:"op"`
	Path    string `json:"path"`
	To      string `json:"to,omitempty"`
	Off     int64  `json:"off,omitempty"`
	N       int    `json:"n,omitempty"`
	Size    int64  `json:"size,omitempty"`
	Dir     bool   `json:"dir,omitempty"`
	Replace bool   `json:"replace,omitempty"`
	Data    []byte `json:"data,omitempty"`
}

// sendOwner queues a control message for every attached owner browser.
func (s *Session) sendOwner(v any) error {
	js, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.vmu.Lock()
	defer s.vmu.Unlock()
	sent := false
	for vw := range s.viewers {
		if !vw.owner || vw.ctl == nil {
			continue
		}
		select {
		case vw.ctl <- js:
			sent = true
		default:
		}
	}
	if !sent {
		return gateway.FSErrOffline
	}
	return nil
}

// RemoteClipboard is the gateway.ClipboardObserver hook.
func (s *Session) RemoteClipboard(c gateway.ClipContent) {
	_ = s.sendOwner(ctlMessage{T: "clip", Text: c.Text, HTML: c.HTML, Data: c.PNG})
	s.m.cfg.Logf("monitor %s: remote clipboard (%d chars text, %d bytes HTML, %d bytes image) sent to the browser",
		s.ID(), utf8.RuneCountInString(c.Text), len(c.HTML), len(c.PNG))
}

// ownerMessage handles a text frame from the owner browser.
func (s *Session) ownerMessage(p []byte) {
	var msg ctlMessage
	if err := json.Unmarshal(p, &msg); err != nil {
		return
	}
	switch msg.T {
	case "clip":
		if s.ctl.Clipboard == nil {
			return
		}
		if err := s.ctl.Clipboard(gateway.ClipContent{Text: msg.Text, HTML: msg.HTML, PNG: msg.Data}); err != nil {
			s.m.cfg.Logf("monitor %s: clipboard: %v", s.ID(), err)
		}
	case "map":
		name := strings.TrimSpace(msg.Name)
		if name == "" || len(name) > 64 {
			name = "Browser"
		}
		var err error
		if s.ctl.MapDrive == nil {
			err = errors.New("drive redirection unavailable")
		} else {
			err = s.ctl.MapDrive(name, &browserFS{s: s})
		}
		reply := ctlMessage{T: "drive", Name: name}
		if err != nil {
			reply.Name, reply.Err = "", err.Error()
			s.m.cfg.Logf("monitor %s: map browser folder: %v", s.ID(), err)
		} else {
			s.mu.Lock()
			s.driveName = name
			s.mu.Unlock()
			s.m.cfg.Logf("monitor %s: browser folder %q mapped as a drive", s.ID(), name)
		}
		_ = s.sendOwner(reply)
	case "unmap":
		if s.ctl.UnmapDrive != nil {
			_ = s.ctl.UnmapDrive()
		}
		s.mu.Lock()
		s.driveName = ""
		s.mu.Unlock()
		s.failFS()
		_ = s.sendOwner(ctlMessage{T: "drive"})
		s.m.cfg.Logf("monitor %s: browser folder unmapped", s.ID())
	case "resize":
		if s.ctl.Resize == nil || msg.W <= 0 || msg.H <= 0 {
			return
		}
		if err := s.ctl.Resize(msg.W, msg.H); err != nil {
			s.m.cfg.Logf("monitor %s: resize to %dx%d: %v", s.ID(), msg.W, msg.H, err)
		}
	case "fs":
		s.mu.Lock()
		ch := s.fsPending[msg.ID]
		delete(s.fsPending, msg.ID)
		s.mu.Unlock()
		if ch != nil {
			ch <- msg
		}
	}
}

// failFS ends every outstanding file request (owner gone, folder unmapped).
func (s *Session) failFS() {
	s.mu.Lock()
	pending := s.fsPending
	s.fsPending = nil
	s.mu.Unlock()
	for _, ch := range pending {
		ch <- ctlMessage{T: "fs", Err: "offline"}
	}
}

// browserFS is the owner browser's shared folder, reached over the live
// WebSocket.
type browserFS struct{ s *Session }

func fsError(code string) error {
	switch code {
	case "":
		return nil
	case "notfound":
		return gateway.FSErrNotFound
	case "exists":
		return gateway.FSErrExists
	case "notempty":
		return gateway.FSErrNotEmpty
	case "denied":
		return gateway.FSErrDenied
	case "offline":
		return gateway.FSErrOffline
	}
	return fmt.Errorf("browser: %s", code)
}

const fsCallTimeout = 30 * time.Second

func (b *browserFS) call(ctx context.Context, req fsRequest) (ctlMessage, error) {
	s := b.s
	ch := make(chan ctlMessage, 1)
	s.mu.Lock()
	if s.fsPending == nil {
		s.fsPending = map[uint64]chan ctlMessage{}
	}
	s.fsNext++
	req.T, req.ID = "fs", s.fsNext
	s.fsPending[req.ID] = ch
	s.mu.Unlock()
	drop := func() {
		s.mu.Lock()
		delete(s.fsPending, req.ID)
		s.mu.Unlock()
	}
	if err := s.sendOwner(req); err != nil {
		drop()
		return ctlMessage{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, fsCallTimeout)
	defer cancel()
	select {
	case r := <-ch:
		if r.Detail != "" {
			s.m.cfg.Logf("monitor %s: browser folder: %s", s.ID(), r.Detail)
		}
		return r, fsError(r.Err)
	case <-ctx.Done():
		drop()
		return ctlMessage{}, gateway.FSErrOffline
	}
}

func (b *browserFS) Stat(ctx context.Context, p string) (gateway.FSEntry, error) {
	r, err := b.call(ctx, fsRequest{Op: "stat", Path: p})
	if err != nil {
		return gateway.FSEntry{}, err
	}
	if r.Entry == nil {
		return gateway.FSEntry{}, gateway.FSErrNotFound
	}
	return r.Entry.entry(), nil
}

func (b *browserFS) List(ctx context.Context, dir string) ([]gateway.FSEntry, error) {
	r, err := b.call(ctx, fsRequest{Op: "list", Path: dir})
	if err != nil {
		return nil, err
	}
	out := make([]gateway.FSEntry, 0, len(r.Entries))
	for _, e := range r.Entries {
		out = append(out, e.entry())
	}
	return out, nil
}

func (b *browserFS) Read(ctx context.Context, p string, off int64, n int) ([]byte, error) {
	r, err := b.call(ctx, fsRequest{Op: "read", Path: p, Off: off, N: n})
	if len(r.Data) > n {
		r.Data = r.Data[:n]
	}
	return r.Data, err
}

func (b *browserFS) Write(ctx context.Context, p string, off int64, data []byte) error {
	_, err := b.call(ctx, fsRequest{Op: "write", Path: p, Off: off, Data: data})
	return err
}

func (b *browserFS) Create(ctx context.Context, p string, dir bool) error {
	_, err := b.call(ctx, fsRequest{Op: "create", Path: p, Dir: dir})
	return err
}

func (b *browserFS) Truncate(ctx context.Context, p string, size int64) error {
	_, err := b.call(ctx, fsRequest{Op: "truncate", Path: p, Size: size})
	return err
}

func (b *browserFS) Remove(ctx context.Context, p string) error {
	_, err := b.call(ctx, fsRequest{Op: "remove", Path: p})
	return err
}

func (b *browserFS) Rename(ctx context.Context, from, to string, replace bool) error {
	_, err := b.call(ctx, fsRequest{Op: "rename", Path: from, To: to, Replace: replace})
	return err
}

// touch records owner activity for the idle timeout.
func (s *Session) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

// checkIdle disconnects a web session whose owner sent no input for
// Config.WebIdle.
func (s *Session) checkIdle() {
	idle := s.m.cfg.WebIdle
	if !s.ctl.Web || idle <= 0 {
		return
	}
	s.mu.Lock()
	last, closing := s.lastActive, s.idleClosed
	if last.IsZero() {
		last = s.start
	}
	expired := !closing && time.Since(last) >= idle
	if expired {
		s.idleClosed = true
	}
	s.mu.Unlock()
	if expired {
		s.m.cfg.Logf("monitor %s: no input for %v, disconnecting", s.ID(), idle)
		s.Disconnect()
	}
}

// Reconnecting and Reconnected are the gateway.ReconnectObserver hooks.
func (s *Session) Reconnecting(attempt int) {
	_ = s.sendOwner(ctlMessage{T: "reconnect", Attempt: &attempt})
}

func (s *Session) Reconnected() {
	done := 0
	_ = s.sendOwner(ctlMessage{T: "reconnect", Attempt: &done})
}

// DisplayControl is the gateway.DisplayObserver hook: the owner browser
// learns whether resizing its window resizes the remote desktop.
func (s *Session) DisplayControl(ready bool) {
	s.mu.Lock()
	s.canResize = ready
	s.mu.Unlock()
	_ = s.sendOwner(ctlMessage{T: "display", Resize: &ready})
}
