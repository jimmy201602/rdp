// Package monitor watches relayed RDP sessions: it renders each session's
// target output into a framebuffer, streams changed rectangles to live
// viewers over WebSocket, records them to .rdpv files for playback and lets
// permitted viewers inject keyboard and mouse input (collaboration).
//
// It relies on the gateway switching drawing orders off towards the target
// (see gateway.Config.Observe), so the screen consists of bitmap updates.
package monitor

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"rdp.local/kernel/bitmap"
	"rdp.local/kernel/gateway"
	"rdp.local/kernel/wire"
)

// Config configures a Monitor.
type Config struct {
	// RecordDir, when set, receives one .rdpv recording (and a .json
	// sidecar once it ends) per session.
	RecordDir string
	// AllowControl lets viewers that ask for it inject input.
	AllowControl      bool
	AllowDriveControl bool
	// FrameInterval is how often changed screen areas are sent (100ms).
	FrameInterval time.Duration
	// WebFrameInterval replaces FrameInterval for browser-initiated
	// sessions, where the viewer is the user (40ms).
	WebFrameInterval time.Duration
	// KeyInterval is how often a recording gets a full-screen key frame (10s).
	KeyInterval time.Duration
	Logf        func(format string, args ...any)
	// Users, when set, lets browsers log in (POST /api/login) instead of
	// presenting the API token; a login is required for /api/connect.
	Users Accounts
	// WebRoute decides whether a logged-in user may open address and how
	// the target is verified. nil disables /api/connect.
	WebRoute func(user, address string) (gateway.Target, error)
	// WebMaxSessions caps concurrent browser-initiated sessions (8).
	WebMaxSessions int
	// WebMaxPerUser caps concurrent web sessions per login (0: no cap
	// beyond WebMaxSessions).
	WebMaxPerUser int
	// WebIdle disconnects a web session after this long without input
	// from its browser (0: never).
	WebIdle time.Duration
	// WebReconnect is how long a web session survives its browser leaving
	// (network change, page reload) before it is ended (0: 2 minutes,
	// negative: end immediately).
	WebReconnect time.Duration
	// AllowedOrigins are extra browser origins (scheme://host[:port])
	// admitted besides the request's own host, e.g. behind a reverse proxy.
	AllowedOrigins []string
}

// Monitor tracks the live sessions handed to it by the gateway.
type Monitor struct {
	cfg  Config
	auth *webAuth
	// tokenAuth holds cookie sessions exchanged for the API token.
	tokenAuth *webAuth
	mu        sync.Mutex
	sessions  map[string]*Session
	web       WebConnector
	// connect throttling and per-user accounting, guarded by mu
	connFails  map[string]*failState
	connecting map[string]int
}

func New(cfg Config) (*Monitor, error) {
	if cfg.FrameInterval <= 0 {
		cfg.FrameInterval = 100 * time.Millisecond
	}
	if cfg.WebFrameInterval == 0 {
		cfg.WebFrameInterval = 40 * time.Millisecond
	}
	if cfg.KeyInterval <= 0 {
		cfg.KeyInterval = 10 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.RecordDir != "" {
		if err := os.MkdirAll(cfg.RecordDir, 0o750); err != nil {
			return nil, err
		}
	}
	m := &Monitor{cfg: cfg, sessions: map[string]*Session{}, tokenAuth: newWebAuth(nil)}
	m.tokenAuth.cookie = tokenCookie
	if cfg.Users != nil {
		m.auth = newWebAuth(cfg.Users)
	}
	return m, nil
}

func newID(t time.Time) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return t.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// Observe is the gateway.Config.Observe hook.
func (m *Monitor) Observe(o gateway.ObserveSession) gateway.Observer {
	now := time.Now()
	s := &Session{
		m: m, ctl: o, start: now, audit: newAudit(),
		meta: Meta{
			ID: newID(now), RemoteAddr: o.RemoteAddr, UserName: o.UserName, Domain: o.Domain,
			ClientName: o.ClientName, Target: o.Target, LoginForm: o.LoginForm, Web: o.Web, Started: now,
		},
		viewers:  map[*viewer]struct{}{},
		join:     make(chan *viewer),
		done:     make(chan struct{}),
		finished: make(chan struct{}),
	}
	if m.cfg.RecordDir != "" {
		rec, err := createRecorder(filepath.Join(m.cfg.RecordDir, s.meta.ID+".rdpv"), s.meta)
		if err != nil {
			m.cfg.Logf("monitor %s: recording disabled: %v", s.meta.ID, err)
		} else {
			s.rec = rec
			s.audioQ = make(chan []byte, 512)
		}
	}
	m.mu.Lock()
	m.sessions[s.meta.ID] = s
	m.mu.Unlock()
	m.cfg.Logf("monitor %s: watching %s -> %s (recording %v)", s.meta.ID, o.RemoteAddr, o.Target, s.rec != nil)
	go s.loop()
	return s
}

// Session returns the live session with id, or nil.
func (m *Monitor) Session(id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

// Sessions lists the live sessions, oldest first.
func (m *Monitor) Sessions() []SessionInfo {
	m.mu.Lock()
	list := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		list = append(list, s)
	}
	m.mu.Unlock()
	out := make([]SessionInfo, 0, len(list))
	for _, s := range list {
		out = append(out, s.Info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}

// SessionInfo is the state of a live session as listed by the API.
type SessionInfo struct {
	ID           string    `json:"id"`
	RemoteAddr   string    `json:"remote_addr"`
	UserName     string    `json:"user"`
	Domain       string    `json:"domain,omitempty"`
	ClientName   string    `json:"client_name,omitempty"`
	Target       string    `json:"target"`
	LoginForm    bool      `json:"login_form,omitempty"`
	Web          bool      `json:"web,omitempty"`
	Owner        string    `json:"owner,omitempty"`
	Width        int       `json:"width"`
	Height       int       `json:"height"`
	Started      time.Time `json:"started"`
	ServerBytes  int64     `json:"server_bytes"`
	Frames       int       `json:"frames"`
	Orders       int       `json:"orders"`
	DecodeErrors int       `json:"decode_errors"`
	Viewers      int       `json:"viewers"`
	Controllers  int       `json:"controllers"`
	Injected     int       `json:"injected"`
	Recording    bool      `json:"recording"`
}

// Session is one observed relay. ServerPDU, ClientInput and Close are
// called by the gateway; the rest by the HTTP API.
type Session struct {
	m     *Monitor
	ctl   gateway.ObserveSession
	start time.Time
	rec   *recorder // owned by loop
	audit *auditState
	// audioQ (nil without a recording) hands ADPCM blocks to the loop.
	audioQ  chan []byte
	adpcmMu sync.Mutex
	adpcm   adpcmEncoder

	mu       sync.Mutex
	meta     Meta
	fb       *bitmap.Framebuffer
	dirty    []image.Rectangle
	resized  bool
	ptr      image.Point
	ptrMoved bool
	frag     struct {
		active bool
		code   uint8
		data   []byte
	}
	serverBytes  int64
	frames       int
	orders       int
	decodeErrors int
	drawErrors   int
	injected     int
	closed       bool
	end          string
	endErr       error
	owner        string // web session: login user that opened it
	ownerKey     string // web session: secret the owner's viewer presents
	ownerSeen    bool   // web session: the owner's browser has attached
	owners       int    // web session: owner browsers attached right now
	ownerGone    *time.Timer
	lastActive   time.Time
	idleClosed   bool
	driveName    string // web session: shared browser folder
	canResize    bool   // web session: target opened display control
	fsNext       uint64
	fsPending    map[uint64]chan ctlMessage

	vmu     sync.Mutex
	viewers map[*viewer]struct{}

	join     chan *viewer
	done     chan struct{} // closed by Close
	finished chan struct{} // closed when loop has written the last record
}

type viewer struct {
	out     chan []byte
	ctl     chan []byte // owner only: JSON control messages
	control bool
	owner   bool // the browser that opened a web session
	resync  bool // guarded by Session.vmu: out overflowed, send a key frame
}

func (s *Session) ID() string { return s.meta.ID }

func (s *Session) Info() SessionInfo {
	s.mu.Lock()
	i := SessionInfo{
		ID: s.meta.ID, RemoteAddr: s.meta.RemoteAddr, UserName: s.meta.UserName, Domain: s.meta.Domain,
		ClientName: s.meta.ClientName, Target: s.meta.Target, LoginForm: s.meta.LoginForm, Web: s.meta.Web, Owner: s.owner,
		Width: s.meta.Width, Height: s.meta.Height, Started: s.meta.Started,
		ServerBytes: s.serverBytes, Frames: s.frames, Orders: s.orders, DecodeErrors: s.decodeErrors,
		Injected: s.injected, Recording: s.rec != nil,
	}
	s.mu.Unlock()
	s.vmu.Lock()
	for v := range s.viewers {
		i.Viewers++
		if v.control {
			i.Controllers++
		}
	}
	s.vmu.Unlock()
	return i
}

// ServerPDU decodes a copy of target output (fast-path frame or slow-path
// share control PDU). Decoding problems are counted, never returned: the
// relay must not depend on the monitor.
func (s *Session) ServerPDU(fastPath bool, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.serverBytes += int64(len(data))
	var err error
	if fastPath {
		err = s.fastPath(data)
	} else {
		err = s.slowPath(data)
	}
	if err != nil {
		s.decodeErrors++
		if s.decodeErrors == 1 {
			s.m.cfg.Logf("monitor %s: %v (further decode errors are only counted)", s.meta.ID, err)
		}
	}
}

func (s *Session) fastPath(data []byte) error {
	fp, err := wire.DecodeFastPathPDU(data)
	if err != nil {
		return err
	}
	for _, u := range fp.Updates {
		if u.Compressed {
			return fmt.Errorf("bulk-compressed fast-path update 0x%x", u.Code)
		}
		d := u.Data
		switch u.Fragmentation {
		case wire.FastPathFragmentFirst:
			s.frag.active, s.frag.code, s.frag.data = true, u.Code, append([]byte(nil), u.Data...)
			continue
		case wire.FastPathFragmentNext, wire.FastPathFragmentLast:
			if !s.frag.active || s.frag.code != u.Code {
				s.frag.active = false
				return fmt.Errorf("fast-path fragment of update 0x%x without a first fragment", u.Code)
			}
			s.frag.data = append(s.frag.data, u.Data...)
			if u.Fragmentation == wire.FastPathFragmentNext {
				continue
			}
			d, s.frag.active = s.frag.data, false
		}
		switch u.Code {
		case wire.FastPathUpdateBitmap, wire.FastPathUpdatePalette:
			up, err := wire.DecodeUpdate(d)
			if err != nil {
				return err
			}
			s.update(up)
		case wire.FastPathUpdateOrders:
			if n, err := wire.FastPathOrdersCount(d); err == nil {
				s.orders += int(n)
			}
		default:
			if wire.IsFastPathPointer(u.Code) {
				p, err := wire.DecodeFastPathPointer(u.Code, d)
				if err != nil {
					return err
				}
				s.pointer(p)
			}
		}
	}
	return nil
}

func (s *Session) slowPath(data []byte) error {
	ctl, _, err := wire.DecodeShareControl(data)
	if err != nil {
		return err
	}
	switch ctl.PDUType {
	case wire.PDUTypeDemandActive:
		da, err := wire.DecodeDemandActive(data)
		if err != nil {
			return err
		}
		for _, cs := range da.Capabilities {
			if cs.Type != wire.CapsTypeBitmap {
				continue
			}
			b, err := wire.DecodeBitmapCapability(cs)
			if err != nil {
				return err
			}
			s.resize(int(b.DesktopWidth), int(b.DesktopHeight))
		}
	case wire.PDUTypeData:
		d, err := wire.DecodeDataPDU(data)
		if err != nil {
			var ei *wire.ErrorInfo
			if errors.As(err, &ei) {
				return nil
			}
			return err
		}
		switch d.Header.PDUType2 {
		case wire.PDUType2Update:
			u, err := wire.DecodeUpdate(d.Body)
			if err != nil {
				return err
			}
			s.update(u)
		case wire.PDUType2Pointer:
			p, err := wire.DecodePointer(d.Body)
			if err != nil {
				return err
			}
			s.pointer(p)
		}
	}
	return nil
}

const maxDesktop = 8192

func (s *Session) resize(w, h int) {
	if w <= 0 || h <= 0 || w > maxDesktop || h > maxDesktop {
		return
	}
	if s.fb != nil && s.meta.Width == w && s.meta.Height == h {
		return
	}
	s.fb = bitmap.New(w, h)
	s.meta.Width, s.meta.Height = w, h
	s.resized, s.dirty = true, nil
}

func (s *Session) update(u wire.Update) {
	s.orders += int(u.NumOrders)
	if s.fb == nil {
		return
	}
	bounds := s.fb.Image().Rect
	for _, b := range u.Bitmaps {
		if err := s.fb.Draw(b); err != nil {
			s.decodeErrors++
			if s.drawErrors++; s.drawErrors == 1 {
				s.m.cfg.Logf("monitor %s: bitmap not drawn: %v (further draw errors are only counted)", s.meta.ID, err)
			}
			continue
		}
		r := image.Rect(int(b.DestLeft), int(b.DestTop), int(b.DestRight)+1, int(b.DestBottom)+1).Intersect(bounds)
		s.dirty = addDirty(s.dirty, r)
	}
	if u.Type == wire.UpdateTypePalette {
		s.fb.SetPalette(u.Palette)
		s.dirty = []image.Rectangle{bounds}
	}
}

func (s *Session) pointer(p wire.Pointer) {
	if p.Type == wire.PointerTypePosition {
		s.movePointer(int(p.X), int(p.Y))
	}
}

func (s *Session) movePointer(x, y int) {
	if p := image.Pt(x, y); p != s.ptr {
		s.ptr, s.ptrMoved = p, true
	}
}

func trackPointer(s *Session, events []wire.InputEvent) {
	for _, ev := range events {
		if ev.Kind == wire.InputKindMouse || ev.Kind == wire.InputKindMouseX {
			s.movePointer(int(ev.X), int(ev.Y))
		}
	}
}

// ClientInput follows the pointer and records content-free input events.
func (s *Session) ClientInput(events []wire.InputEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		trackPointer(s, events)
		s.inputEvents(events, "client")
	}
}

// ErrControl is returned by Inject when input is not permitted.
var ErrControl = errors.New("monitor: control not permitted")

// Inject sends viewer input to the target.
func (s *Session) Inject(events []wire.InputEvent) error {
	if (!s.m.cfg.AllowControl && !s.ctl.Web) || s.ctl.Inject == nil {
		return ErrControl
	}
	s.mu.Lock()
	closed := s.closed
	if !closed {
		trackPointer(s, events)
		s.injected += len(events)
	}
	s.mu.Unlock()
	if closed {
		return ErrControl
	}
	if err := s.ctl.Inject(events); err != nil {
		return err
	}
	s.inputEvents(events, "admin")
	return nil
}

// Disconnect ends the relayed session.
func (s *Session) Disconnect() {
	if s.ctl.Disconnect != nil {
		s.ctl.Disconnect()
	}
}

// Close is called by the gateway when the relay has ended.
func (s *Session) Close(end string, err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed, s.end, s.endErr = true, end, err
	s.mu.Unlock()
	close(s.done)
	<-s.finished
	s.m.mu.Lock()
	delete(s.m.sessions, s.meta.ID)
	s.m.mu.Unlock()
}

// attach registers a viewer; false once the session has ended.
func (s *Session) attach(v *viewer) bool {
	select {
	case s.join <- v:
		return true
	case <-s.finished:
		return false
	}
}

func (s *Session) detach(v *viewer) {
	s.vmu.Lock()
	delete(s.viewers, v)
	s.vmu.Unlock()
	if v.owner {
		s.ownerLeft()
	}
}

func (s *Session) ms() uint32 { return uint32(time.Since(s.start) / time.Millisecond) }

func copyRect(src *image.RGBA, r image.Rectangle) *image.RGBA {
	out := image.NewRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	for y := 0; y < r.Dy(); y++ {
		i := src.PixOffset(r.Min.X, r.Min.Y+y)
		copy(out.Pix[y*out.Stride:y*out.Stride+r.Dx()*4], src.Pix[i:i+r.Dx()*4])
	}
	return out
}

var pngEncoder = png.Encoder{CompressionLevel: png.BestSpeed}

func rectRecord(kind uint8, ms uint32, at image.Point, img *image.RGBA) []byte {
	var buf bytes.Buffer
	if err := pngEncoder.Encode(&buf, img); err != nil {
		return nil
	}
	return encodeRecord(kind, ms, rectPayload(at.X, at.Y, img.Rect.Dx(), img.Rect.Dy(), buf.Bytes()))
}

// frameRecord encodes a changed area as PNG or, for photo-like content,
// JPEG (reported as lossy so it can be refined later).
func frameRecord(ms uint32, at image.Point, img *image.RGBA, lossless bool) ([]byte, bool) {
	data, lossy := encodeRect(img, lossless)
	if data == nil {
		return nil, false
	}
	return encodeRecord(RecFrame, ms, rectPayload(at.X, at.Y, img.Rect.Dx(), img.Rect.Dy(), data)), lossy
}

type part struct {
	r   image.Rectangle
	img *image.RGBA
}

func resizeRecord(ms uint32, w, h int) []byte {
	p := make([]byte, 4)
	binary.LittleEndian.PutUint16(p, uint16(w))
	binary.LittleEndian.PutUint16(p[2:], uint16(h))
	return encodeRecord(RecResize, ms, p)
}

// snapshot is what one tick takes from the decoder state under s.mu.
type snapshot struct {
	w, h     int
	resized  bool
	parts    []part
	full     *image.RGBA
	ptr      image.Point
	ptrMoved bool
}

func (s *Session) take(wantFull bool) (snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fb == nil {
		return snapshot{}, false
	}
	img := s.fb.Image()
	sn := snapshot{w: s.meta.Width, h: s.meta.Height, resized: s.resized, ptr: s.ptr, ptrMoved: s.ptrMoved}
	if sn.resized || wantFull {
		sn.full = copyRect(img, img.Rect)
	}
	if !sn.resized && len(s.dirty) > 0 {
		for _, r := range s.dirty {
			sn.parts = append(sn.parts, part{r: r, img: copyRect(img, r)})
		}
		s.frames++
	}
	s.resized, s.dirty, s.ptrMoved = false, nil, false
	return sn, true
}

// capture copies areas of the current screen (lossless refinement).
func (s *Session) capture(rects []image.Rectangle) []part {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fb == nil {
		return nil
	}
	img := s.fb.Image()
	out := make([]part, 0, len(rects))
	for _, r := range rects {
		if r = r.Intersect(img.Rect); !r.Empty() {
			out = append(out, part{r: r, img: copyRect(img, r)})
		}
	}
	return out
}

// viewersBehind reports whether every viewer still has a backlog of
// unsent records: the tick is skipped so changes coalesce instead of
// queueing ever more frames on a slow link.
func (s *Session) viewersBehind() bool {
	s.vmu.Lock()
	defer s.vmu.Unlock()
	if len(s.viewers) == 0 {
		return false
	}
	for v := range s.viewers {
		if len(v.out) < behindRecords {
			return false
		}
	}
	return true
}

const behindRecords = 24

func (s *Session) broadcast(rec []byte) {
	if rec == nil {
		return
	}
	s.vmu.Lock()
	defer s.vmu.Unlock()
	for v := range s.viewers {
		if v.resync {
			continue
		}
		select {
		case v.out <- rec:
		default:
			v.resync = true
		}
	}
}

func (s *Session) record(rec []byte) {
	if s.rec != nil && rec != nil {
		s.rec.write(rec)
	}
}

type tickState struct {
	lastKey time.Time
	changed bool        // since the last key frame of the recording
	lossy   []lossyRect // areas last sent as JPEG, refined when still
}

func (s *Session) tick(ts *tickState, final bool) {
	s.vmu.Lock()
	resync := false
	for v := range s.viewers {
		resync = resync || v.resync
	}
	s.vmu.Unlock()
	keyDue := s.rec != nil && ts.changed && time.Since(ts.lastKey) >= s.m.cfg.KeyInterval
	if !resync && !keyDue && !final && s.rec == nil && s.viewersBehind() {
		return
	}
	sn, ok := s.take(resync || keyDue || final)
	if !ok {
		return
	}
	ms := s.ms()
	if sn.resized {
		rz, key := resizeRecord(ms, sn.w, sn.h), rectRecord(RecKey, ms, image.Point{}, sn.full)
		s.broadcast(rz)
		s.broadcast(key)
		s.record(rz)
		s.record(key)
		ts.lastKey, ts.changed, ts.lossy = time.Now(), false, nil
	} else if len(sn.parts) > 0 {
		now := time.Now()
		for _, p := range sn.parts {
			fr, lossy := frameRecord(ms, p.r.Min, p.img, false)
			s.broadcast(fr)
			s.record(fr)
			if lossy {
				ts.lossy = noteLossy(ts.lossy, p.r, now)
			} else {
				ts.lossy = dropCovered(ts.lossy, p.r)
			}
		}
		ts.changed = true
	}
	if !sn.resized && len(ts.lossy) > 0 {
		dirty := make([]image.Rectangle, len(sn.parts))
		for i, p := range sn.parts {
			dirty[i] = p.r
		}
		var due []image.Rectangle
		ts.lossy, due = dueRefine(ts.lossy, dirty, time.Now())
		for _, p := range s.capture(due) {
			fr, _ := frameRecord(ms, p.r.Min, p.img, true)
			s.broadcast(fr)
			s.record(fr)
		}
	}
	if sn.full != nil && !sn.resized {
		key := rectRecord(RecKey, ms, image.Point{}, sn.full)
		if (keyDue || final) && ts.changed {
			s.record(key)
			ts.lastKey, ts.changed = time.Now(), false
		}
		if resync {
			s.vmu.Lock()
			for v := range s.viewers {
				if !v.resync || len(v.out)+2 > cap(v.out) {
					continue
				}
				v.out <- resizeRecord(ms, sn.w, sn.h)
				v.out <- key
				v.resync = false
			}
			s.vmu.Unlock()
		}
	}
	if sn.ptrMoved {
		p := encodeRecord(RecPointer, ms, pointPayload(sn.ptr.X, sn.ptr.Y))
		s.broadcast(p)
		s.record(p)
	}
}

func (s *Session) welcome(v *viewer) {
	s.vmu.Lock()
	s.viewers[v] = struct{}{}
	v.resync = true // the next tick sends the current screen
	s.vmu.Unlock()
}

func (s *Session) loop() {
	defer close(s.finished)
	interval := s.m.cfg.FrameInterval
	if s.ctl.Web && s.m.cfg.WebFrameInterval > 0 {
		interval = s.m.cfg.WebFrameInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	flush := time.NewTicker(2 * time.Second)
	defer flush.Stop()
	ts := &tickState{}
	for {
		select {
		case v := <-s.join:
			s.welcome(v)
			s.tick(ts, false)
		case <-t.C:
			s.flushEvents()
			s.flushAudio()
			s.tick(ts, false)
		case <-flush.C:
			s.checkIdle()
			if s.rec != nil {
				s.rec.flush()
			}
		case <-s.done:
			s.flushEvents()
			s.flushAudio()
			s.tick(ts, false)
			end := encodeRecord(RecEnd, s.ms(), nil)
			s.broadcast(end)
			s.finish(end)
			return
		}
	}
}

func (s *Session) finish(end []byte) {
	if s.rec == nil {
		return
	}
	s.record(end)
	size, err := s.rec.close()
	if err != nil {
		s.m.cfg.Logf("monitor %s: recording: %v", s.meta.ID, err)
	}
	s.mu.Lock()
	m := s.meta
	m.DurationMS = int64(s.ms())
	m.End, m.Size, m.Complete = s.end, size, err == nil
	if s.endErr != nil {
		m.Error = s.endErr.Error()
	}
	s.mu.Unlock()
	js, _ := json.MarshalIndent(m, "", "  ")
	side := filepath.Join(s.m.cfg.RecordDir, m.ID+".json")
	if err := os.WriteFile(side+".tmp", js, 0o640); err == nil {
		_ = os.Rename(side+".tmp", side)
	}
	s.m.cfg.Logf("monitor %s: recording finished (%d bytes, %d ms)", m.ID, m.Size, m.DurationMS)
}
