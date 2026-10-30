package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"rdp.local/kernel/transport"
	"rdp.local/kernel/wire"
)

// ErrNoObserver means Config.Observe is unset, so a web session would have
// nowhere to draw.
var ErrNoObserver = errors.New("rdp gateway: web sessions need Config.Observe")

// WebRequest describes a session the gateway opens on behalf of a browser:
// there is no front-end RDP client, the gateway itself plays the client role
// towards Target and hands the output to the Observer (the monitor), which
// streams it to the browser and injects its input.
type WebRequest struct {
	RemoteAddr                 string // browser address, for logs and the session list
	UserName, Domain, Password string // target credentials, kept in memory for reconnects until the session ends
	Target                     Target
	Width, Height              uint16
	ColorDepth                 uint16 // 15, 16, 24 or 32; 0 means 24
	KeyboardLayout             uint32 // input locale, 0 means US English
	PerformanceFlags           uint32 // wire.Perf*, 0 means transport's default
	Timeout                    time.Duration
}

// WebSession is a running browser-initiated session.
type WebSession struct {
	obs     Observer
	cancel  context.CancelFunc
	backend *transport.Session
	wmu     sync.Mutex
	mu      sync.Mutex
	shareID uint32
	active  bool
	done    chan struct{}
	end     string
	err     error

	depth  uint16 // requested colour depth and keyboard layout, reused on reactivation
	layout uint32

	clipCh, driveCh, sndCh, dvcCh uint16
	clip                          *webClip
	sound                         *webSound
	dvc                           *webDVC
	disp                          *displayControl
	onAudio                       func(AudioFormat, []byte) // guarded by mu
	drive                         *webDrive
	reasm                         map[uint16]*wire.ChannelReassembler
	hmu                           sync.Mutex // guards the channel handlers above against a reconnect swapping them
	logf                          func(string, ...any)

	// Reconnect state: the dial options (credentials included, cleared when
	// the session ends) and the latest auto-reconnect cookie.
	address string
	opts    transport.Options
	timeout time.Duration
	cookie  *wire.ARCCookie
	redial  bool
}

// Reconnect policy for a target connection lost without a disconnect PDU.
var webReconnectDelays = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second}

// ReconnectObserver is told when a web session lost its target connection
// and is redialing (attempt counts from 1), and when that succeeded.
type ReconnectObserver interface {
	Reconnecting(attempt int)
	Reconnected()
}

// webDropAfter, for testing reconnects, closes the target connection once
// this long after a web session started.
var webDropAfter, _ = time.ParseDuration(os.Getenv("RDPGW_DEBUG_DROP_TARGET"))

// Channel options for the web client's static channels (MS-RDPBCGR 2.2.1.3.4.1).
const (
	chanOptInitialized = 0x80000000
	chanOptEncryptRDP  = 0x40000000
	chanOptCompressRDP = 0x00800000
	chanOptShowProto   = 0x00200000
)

// Windows only starts drive redirection (Server Announce on rdpdr) when the
// client also opened rdpsnd. Order and options follow FreeRDP.
var webChannels = []wire.ChannelDef{
	{Name: "rdpdr", Options: chanOptInitialized | chanOptCompressRDP},
	{Name: "rdpsnd", Options: chanOptInitialized | chanOptEncryptRDP},
	{Name: "cliprdr", Options: chanOptInitialized | chanOptEncryptRDP | chanOptCompressRDP | chanOptShowProto},
	{Name: "drdynvc", Options: chanOptInitialized | chanOptEncryptRDP | chanOptCompressRDP},
}

// writeChannel frames messages for channel id; showProto sets
// CHANNEL_FLAG_SHOW_PROTOCOL on every chunk, which Windows expects on
// channels opened with CHANNEL_OPTION_SHOW_PROTOCOL.
func (ws *WebSession) writeChannel(id uint16, showProto bool) func([]byte) error {
	return func(msg []byte) error {
		ws.wmu.Lock()
		defer ws.wmu.Unlock()
		backend := ws.backend
		return sendChannel(msg, func(p []byte) error {
			if showProto {
				binary.LittleEndian.PutUint32(p[4:], binary.LittleEndian.Uint32(p[4:])|wire.ChannelFlagShowProtocol)
			}
			return backend.WriteChannel(id, p)
		})
	}
}

func (ws *WebSession) setupChannels() {
	ids := ws.backend.StaticChannels()
	ws.hmu.Lock()
	defer ws.hmu.Unlock()
	ws.reasm = map[uint16]*wire.ChannelReassembler{}
	ws.sound, ws.clip, ws.drive, ws.disp, ws.dvc = nil, nil, nil, nil, nil
	if len(ids) != len(webChannels) {
		return
	}
	ws.driveCh, ws.sndCh, ws.clipCh, ws.dvcCh = ids[0], ids[1], ids[2], ids[3]
	ws.sound = ws.newSound(ws.writeChannel(ws.sndCh, false))
	ws.clip = &webClip{send: ws.writeChannel(ws.clipCh, true)}
	ws.drive = newWebDrive(ws.writeChannel(ws.driveCh, false))
	ws.disp = &displayControl{}
	ws.dvc = &webDVC{send: ws.writeChannel(ws.dvcCh, false), logf: ws.logf, handlers: map[string]func() dvcHandler{
		"Microsoft::Windows::RDS::DisplayControl": func() dvcHandler { return ws.disp },
		"AUDIO_PLAYBACK_DVC":                      func() dvcHandler { return &soundDVC{mk: ws.newSound} },
	}}
}

func (ws *WebSession) newSound(send func([]byte) error) *webSound {
	return &webSound{send: send, logf: ws.logf, onAudio: func(f AudioFormat, pcm []byte) {
		ws.mu.Lock()
		on := ws.onAudio
		ws.mu.Unlock()
		if on != nil {
			on(f, pcm)
		}
	}}
}

// resize asks the target for a new desktop size (display control).
func (ws *WebSession) resize(w, h int) error {
	ws.hmu.Lock()
	disp := ws.disp
	ws.hmu.Unlock()
	if disp == nil {
		return ErrNoDisplayControl
	}
	return disp.resize(w, h)
}

func (ws *WebSession) channel(id uint16, chunk []byte) {
	ra := ws.reasm[id]
	if ra == nil {
		ra = &wire.ChannelReassembler{}
		ws.reasm[id] = ra
	}
	msg, done, _, err := ra.Add(chunk)
	if err != nil || !done {
		return
	}
	var herr error
	switch id {
	case ws.clipCh:
		if ws.clip != nil {
			herr = ws.clip.handle(msg)
		}
	case ws.driveCh:
		if ws.drive != nil {
			herr = ws.drive.handle(msg)
		}
	case ws.sndCh:
		if ws.sound != nil {
			herr = ws.sound.handle(msg)
		}
	case ws.dvcCh:
		if ws.dvc != nil {
			herr = ws.dvc.handle(msg)
		}
	}
	if herr != nil {
		ws.logf("web session channel %d: %v", id, herr)
	}
}

func (ws *WebSession) setClipboard(c ClipContent) error {
	ws.hmu.Lock()
	clip := ws.clip
	ws.hmu.Unlock()
	if clip == nil {
		return fmt.Errorf("%w: target did not allocate the clipboard channel", ErrRelay)
	}
	return clip.set(c)
}

func (ws *WebSession) mapDrive(name string, fs WebFS) error {
	ws.hmu.Lock()
	drive := ws.drive
	ws.hmu.Unlock()
	if drive == nil {
		return fmt.Errorf("%w: target did not allocate the drive redirection channel", ErrRelay)
	}
	if fs == nil {
		return drive.unmount()
	}
	return drive.mount(name, fs)
}

// hookObserver connects the channel handlers to the observer's optional
// hooks; it runs after every (re)connection.
func (ws *WebSession) hookObserver() {
	ws.hmu.Lock()
	clip, disp := ws.clip, ws.disp
	ws.hmu.Unlock()
	if co, ok := ws.obs.(ClipboardObserver); ok && clip != nil {
		clip.mu.Lock()
		clip.onText = co.RemoteClipboard
		clip.mu.Unlock()
	}
	if ao, ok := ws.obs.(AudioObserver); ok {
		ws.mu.Lock()
		ws.onAudio = ao.RemoteAudio
		ws.mu.Unlock()
	}
	if do, ok := ws.obs.(DisplayObserver); ok && disp != nil {
		disp.mu.Lock()
		disp.onReady = do.DisplayControl
		disp.mu.Unlock()
	}
}

func (ws *WebSession) closeChannels() {
	ws.hmu.Lock()
	drive, dvc := ws.drive, ws.dvc
	ws.hmu.Unlock()
	if drive != nil {
		drive.close()
	}
	if dvc != nil {
		dvc.closeAll()
	}
}

func (ws *WebSession) unmapDrive() error { return ws.mapDrive("", nil) }

// Observer returns the Observer created for this session (the monitor
// session), so the caller can route the browser to it.
func (w *WebSession) Observer() Observer { return w.obs }

// Done is closed when the session has ended; End tells why.
func (w *WebSession) Done() <-chan struct{} { return w.done }

func (w *WebSession) End() (string, error) {
	<-w.done
	return w.end, w.err
}

// Disconnect ends the session.
func (w *WebSession) Disconnect() { w.cancel() }

const webClientName = "rdpgw-web"

// ConnectWeb dials req.Target with req's credentials, completes capability
// exchange (drawing orders off, bitmap updates only) and connection
// finalization itself, registers the session with Config.Observe and keeps
// reading target output in the background. Credentials stay in memory
// only so a lost target connection can be redialed; they are dropped when
// the session ends.
func (g *Gateway) ConnectWeb(ctx context.Context, req WebRequest) (*WebSession, error) {
	if g.cfg.Observe == nil {
		return nil, ErrNoObserver
	}
	target := req.Target
	if target.Timeout <= 0 {
		target.Timeout = 20 * time.Second
	}
	if target.ServerName == "" {
		target.ServerName = webTargetName(target.Address)
	}
	if req.Timeout <= 0 {
		req.Timeout = target.Timeout
	}
	if target.NLA && (req.UserName == "" || req.Password == "") {
		return nil, fmt.Errorf("%w: %s: %w", ErrBackend, target.Address, transport.ErrNoCredentials)
	}
	w, h := req.Width, req.Height
	if w < 200 || h < 200 || w > 8192 || h > 8192 {
		w, h = 1280, 800
	}
	depth := req.ColorDepth
	switch depth {
	case 15, 16, 24, 32:
	default:
		depth = 24
	}
	layout := req.KeyboardLayout
	if layout == 0 {
		layout = 0x0409
	}
	opts := transport.Options{
		NLA: target.NLA, LegacyCredSSP: target.LegacyCredSSP, ServerName: target.ServerName, RootCAs: target.RootCAs, PinSHA256: target.PinSHA256, MinTLSVersion: target.MinTLS, Timeout: target.Timeout,
		ClientName: webClientName, DesktopWidth: w, DesktopHeight: h, ColorDepth: depth,
		KeyboardLayout: layout, PerformanceFlags: req.PerformanceFlags,
		Domain: req.Domain, UserName: req.UserName, Password: req.Password,
		Channels: webChannels,
	}
	req.Password = ""
	backend, err := transport.Dial(ctx, target.Address, opts)
	if err != nil {
		g.cfg.Logf("%s: web target %s failed at handshake: %v", req.RemoteAddr, target.Address, err)
		return nil, fmt.Errorf("%w: %s: %w", ErrBackend, target.Address, err)
	}
	first, err := awaitDemandActive(backend, req.Timeout)
	if err != nil {
		_ = backend.Close()
		g.cfg.Logf("%s: web target %s refused the session: %v", req.RemoteAddr, target.Address, err)
		return nil, fmt.Errorf("%w: %s: %w", ErrBackend, target.Address, err)
	}
	sctx, cancel := context.WithCancel(ctx)
	ws := &WebSession{cancel: cancel, backend: backend, done: make(chan struct{}), logf: g.cfg.Logf, depth: depth, layout: layout,
		address: target.Address, opts: opts, timeout: req.Timeout}
	ws.setupChannels()
	if err := ws.activate(first.Data, w, h, depth, layout); err != nil {
		cancel()
		_ = backend.Close()
		return nil, fmt.Errorf("%w: %s: %w", ErrRelay, target.Address, err)
	}
	obs := ObserveSession{
		RemoteAddr: req.RemoteAddr, UserName: req.UserName, Domain: req.Domain, ClientName: webClientName,
		Target: target.Address, Web: true,
		Disconnect: cancel,
		Inject:     ws.inject,
	}
	if ws.clip != nil {
		obs.Clipboard = ws.setClipboard
	}
	if ws.drive != nil {
		obs.MapDrive, obs.UnmapDrive = ws.mapDrive, ws.unmapDrive
	}
	if ws.disp != nil {
		obs.Resize = ws.resize
	}
	// Without credentials a redial would stop at the logon screen.
	ws.redial = target.NLA || opts.Password != ""
	if !ws.redial {
		ws.opts = transport.Options{}
	}
	ws.obs = g.cfg.Observe(obs)
	ws.hookObserver()
	g.cfg.Logf("%s: web session to %s active (%dx%d, %d bpp, keyboard %#04x, performance %#x)", req.RemoteAddr, target.Address, w, h, depth, layout, req.PerformanceFlags)
	// The observer must see the Demand Active (it sizes its framebuffer from it).
	ws.obs.ServerPDU(false, first.Data)
	go ws.run(sctx, g, req.RemoteAddr, target.Address)
	return ws, nil
}

// activate answers a Demand Active with Confirm Active and the finalization
// PDUs. Font Map and the other finalization replies arrive in run.
func (ws *WebSession) activate(demandPDU []byte, w, h, depth uint16, layout uint32) error {
	demand, err := wire.DecodeDemandActive(demandPDU)
	if err != nil {
		return fmt.Errorf("demand active: %w", err)
	}
	if cs, ok := wire.FindCapability(demand.Capabilities, wire.CapsTypeBitmap); ok {
		if b, err := wire.DecodeBitmapCapability(cs); err == nil && b.DesktopWidth > 0 && b.DesktopHeight > 0 {
			w, h = b.DesktopWidth, b.DesktopHeight
		}
	}
	caps := withoutOrders(wire.DefaultClientCapabilities(wire.ClientCapabilityOptions{
		DesktopWidth: w, DesktopHeight: h, ColorDepth: depth,
		KeyboardLayout: layout, KeyboardType: wire.KeyboardTypeIBMEnhance, FunctionKeys: 12,
	}))
	user, server := ws.backend.UserChannel(), demand.Control.PDUSource
	confirm, err := wire.EncodeConfirmActive(demand.ShareID, user, webClientName, caps)
	if err != nil {
		return err
	}
	pdus := [][]byte{confirm}
	for _, enc := range []func() ([]byte, error){
		func() ([]byte, error) { return wire.EncodeSynchronize(demand.ShareID, user, server) },
		func() ([]byte, error) { return wire.EncodeControl(demand.ShareID, user, wire.CtrlActionCooperate) },
		func() ([]byte, error) { return wire.EncodeControl(demand.ShareID, user, wire.CtrlActionRequestControl) },
		func() ([]byte, error) { return wire.EncodeFontList(demand.ShareID, user) },
	} {
		p, err := enc()
		if err != nil {
			return err
		}
		pdus = append(pdus, p)
	}
	ws.wmu.Lock()
	defer ws.wmu.Unlock()
	for _, p := range pdus {
		if err := ws.backend.WriteIO(p); err != nil {
			return err
		}
	}
	ws.mu.Lock()
	ws.shareID, ws.active = demand.ShareID, true
	ws.mu.Unlock()
	return nil
}

func (ws *WebSession) inject(events []wire.InputEvent) error {
	ws.mu.Lock()
	shareID, active := ws.shareID, ws.active
	ws.mu.Unlock()
	if !active {
		return fmt.Errorf("%w: target not active, input not injected", ErrRelay)
	}
	body, err := wire.EncodeInputPDU(events)
	if err != nil {
		return err
	}
	ws.wmu.Lock()
	defer ws.wmu.Unlock()
	pdu, err := wire.EncodeShareData(shareID, ws.backend.UserChannel(), wire.PDUType2Input, body)
	if err != nil {
		return err
	}
	return ws.backend.WriteIO(pdu)
}

func (ws *WebSession) currentBackend() *transport.Session {
	ws.wmu.Lock()
	defer ws.wmu.Unlock()
	return ws.backend
}

func (ws *WebSession) run(ctx context.Context, g *Gateway, remote, target string) {
	stop := context.AfterFunc(ctx, func() { _ = ws.currentBackend().Close() })
	if webDropAfter > 0 {
		b := ws.backend
		time.AfterFunc(webDropAfter, func() { _ = b.Close() })
	}
	var end string
	var err error
	for {
		var lost bool
		end, err, lost = ws.read(ctx)
		if !lost || ctx.Err() != nil || !ws.redial {
			break
		}
		ws.mu.Lock()
		hasCookie := ws.cookie != nil
		ws.mu.Unlock()
		g.cfg.Logf("%s: web session lost target %s (%v), reconnecting (auto-reconnect cookie: %v)", remote, target, err, hasCookie)
		if rerr := ws.reconnect(ctx); rerr != nil {
			g.cfg.Logf("%s: web session reconnect to %s failed: %v", remote, target, rerr)
			break
		}
		g.cfg.Logf("%s: web session reconnected to %s", remote, target)
	}
	stop()
	if ctx.Err() != nil {
		end, err = "client-closed", nil
		_ = ws.currentBackend().Disconnect()
	}
	_ = ws.currentBackend().Close()
	ws.closeChannels()
	ws.mu.Lock()
	ws.active = false
	ws.end, ws.err = end, err
	ws.cookie = nil
	ws.mu.Unlock()
	ws.opts = transport.Options{}
	close(ws.done)
	g.cfg.Logf("%s: web session to %s ended (%s)", remote, target, end)
	ws.obs.Close(end, err)
}

// read relays target output until the connection ends. lost reports an
// end without a Disconnect Provider Ultimatum (network failure, reset),
// which run answers with a reconnect.
func (ws *WebSession) read(ctx context.Context) (end string, err error, lost bool) {
	for {
		pdu, err := ws.backend.ReadPDU()
		if err != nil {
			if errors.Is(err, transport.ErrDisconnected) {
				return "target-closed", nil, false
			}
			if closedErr(err) {
				return "target-closed", nil, true
			}
			return "error", fmt.Errorf("target: %w", err), true
		}
		if pdu.FastPath {
			ws.obs.ServerPDU(true, pdu.Data)
			continue
		}
		if pdu.Channel != 0 {
			ws.channel(pdu.Channel, pdu.Data)
			continue
		}
		hdr, _, err := wire.DecodeShareControl(pdu.Data)
		if err != nil {
			return "error", fmt.Errorf("%w: target share control: %v", ErrRelay, err), false
		}
		switch hdr.PDUType {
		case wire.PDUTypeDeactivateAll:
			ws.mu.Lock()
			ws.active = false
			ws.mu.Unlock()
		case wire.PDUTypeDemandActive:
			if err := ws.activate(pdu.Data, 0, 0, ws.depth, ws.layout); err != nil {
				return "error", fmt.Errorf("%w: reactivation: %v", ErrRelay, err), false
			}
		case wire.PDUTypeData:
			if h, body, err := wire.DecodeShareData(pdu.Data); err == nil && h.PDUType2 == wire.PDUType2SaveSessionInfo {
				if s, err := wire.DecodeSaveSessionInfo(body); err == nil && s.AutoReconnect != nil {
					ws.mu.Lock()
					ws.cookie = s.AutoReconnect
					ws.mu.Unlock()
				}
			}
		}
		ws.obs.ServerPDU(false, pdu.Data)
	}
}

// reconnect redials the target with the session's options and the latest
// auto-reconnect cookie, swaps the backend and channel handlers, and
// re-shares a mapped browser folder. The observer keeps its viewers; the
// new Demand Active resizes its framebuffer.
func (ws *WebSession) reconnect(ctx context.Context) error {
	ws.mu.Lock()
	ws.active = false
	cookie := ws.cookie
	ws.mu.Unlock()
	ws.hmu.Lock()
	drive := ws.drive
	ws.hmu.Unlock()
	var folder string
	var fs WebFS
	if drive != nil {
		folder, fs = drive.mountedFS()
	}
	ws.closeChannels()
	_ = ws.currentBackend().Close()
	ro, _ := ws.obs.(ReconnectObserver)
	if do, ok := ws.obs.(DisplayObserver); ok {
		do.DisplayControl(false)
	}
	var lastErr error
	for i, delay := range webReconnectDelays {
		if ro != nil {
			ro.Reconnecting(i + 1)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		opts := ws.opts
		if cookie != nil {
			opts.AutoReconnect = cookie.ClientPacket()
		}
		backend, err := transport.Dial(ctx, ws.address, opts)
		if err != nil {
			lastErr = err
			continue
		}
		first, err := awaitDemandActive(backend, ws.timeout)
		if err != nil {
			_ = backend.Close()
			lastErr = err
			continue
		}
		ws.wmu.Lock()
		ws.backend = backend
		ws.wmu.Unlock()
		if ctx.Err() != nil {
			_ = backend.Close()
			return ctx.Err()
		}
		ws.setupChannels()
		ws.hookObserver()
		if err := ws.activate(first.Data, 0, 0, ws.depth, ws.layout); err != nil {
			_ = backend.Close()
			lastErr = err
			continue
		}
		if fs != nil {
			if err := ws.mapDrive(folder, fs); err != nil {
				ws.logf("web session: re-sharing folder after reconnect: %v", err)
			}
		}
		ws.obs.ServerPDU(false, first.Data)
		if ro != nil {
			ro.Reconnected()
		}
		return nil
	}
	return lastErr
}

// DescribeDialError maps a target connection error to a message fit for
// the user; addresses and certificate details stay in the log.
func DescribeDialError(err error) string { return describeDialError(err) }

// webTargetName returns the TLS name to verify for address when the policy
// gave none.
func webTargetName(address string) string {
	host := address
	if i := strings.LastIndex(address, ":"); i > 0 {
		host = address[:i]
	}
	return strings.Trim(host, "[]")
}
