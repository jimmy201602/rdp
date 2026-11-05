package monitor

import (
	"fmt"
	"time"

	"rdp.local/kernel/wire"
)

// RemoteApp auditing: the rail channel tells which program the client
// launched and whether the target accepted it; Window orders tell which
// windows the program opened, moved and closed. Both become "rail" and
// "window" events in the live feed and the recording; arguments are logged
// as the client sent them (they are a command line, never a credential).

const maxWindows = 256

// rail handles a reassembled rail channel PDU. Only the exec request and
// its result are logged; handshake, system parameters and window moves are
// relayed without comment.
func (s *Session) rail(client bool, data []byte) {
	a := s.audit
	typ, body, err := wire.DecodeRailHeader(data)
	if err != nil {
		return
	}
	switch {
	case client && typ == wire.RailOrderExec:
		e, err := wire.DecodeRailExec(body)
		if err != nil {
			return
		}
		app := e.ExeOrFile
		a.app.CompareAndSwap(nil, &app)
		s.emit(Event{Kind: "rail", Source: "client", Action: "exec", Path: e.ExeOrFile, Detail: e.Arguments, Status: e.WorkingDir})
	case !client && typ == wire.RailOrderExecResult:
		r, err := wire.DecodeRailExecResult(body)
		if err != nil {
			return
		}
		status := wire.RailExecResultString(r.ExecResult)
		if r.ExecResult != wire.RailExecOK {
			status = fmt.Sprintf("%s (0x%08x)", status, r.RawResult)
		}
		s.emit(Event{Kind: "rail", Source: "target", Action: "exec_result", Path: r.ExeOrFile, Status: status})
	case !client && typ == wire.RailOrderHandshake, !client && typ == wire.RailOrderHandshakeEx:
		s.emit(Event{Kind: "rail", Source: "target", Action: "handshake"})
	}
}

// windowOrders decodes the Window alternate secondary orders of a fast-path
// orders update (data starts after numberOrders). Called with s.mu held.
func (s *Session) windowOrders(data []byte) {
	ws, err := wire.DecodeWindowOrders(data)
	if err != nil {
		s.decodeErrors++
	}
	if len(ws) == 0 {
		return
	}
	a := s.audit
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.windows == nil {
		a.windows = map[uint32]windowState{}
	}
	for _, w := range ws {
		switch w.Type() {
		case wire.WindowOrderTypeWindow:
			s.windowOrder(w)
		case wire.WindowOrderTypeDesktop:
			if w.Fields&wire.WindowFieldDesktopActiveWnd != 0 && w.ActiveWindow != a.activeWnd {
				a.activeWnd = w.ActiveWindow
				if st, ok := a.windows[w.ActiveWindow]; ok {
					s.emit(windowEvent("activate", w.ActiveWindow, st))
				}
			}
		}
	}
}

func (s *Session) windowOrder(w wire.WindowOrder) {
	a := s.audit
	if w.Fields&(wire.WindowOrderIcon|wire.WindowOrderCachedIcon) != 0 {
		return
	}
	st, known := a.windows[w.WindowID]
	if w.Deleted() {
		if known {
			delete(a.windows, w.WindowID)
			s.emit(windowEvent("closed", w.WindowID, st))
		}
		return
	}
	if !known && len(a.windows) >= maxWindows {
		return
	}
	action := ""
	if w.New() || !known {
		action = "new"
	}
	if w.Fields&wire.WindowFieldTitle != 0 && w.Title != st.title {
		st.title = w.Title
		if action == "" {
			action = "title"
		}
	}
	if w.Fields&wire.WindowFieldShow != 0 && w.Show != st.show {
		st.show = w.Show
		if action == "" {
			action = "show"
		}
	}
	moved := false
	if w.Fields&wire.WindowFieldWndOffset != 0 && (w.X != st.x || w.Y != st.y) {
		st.x, st.y, moved = w.X, w.Y, true
	}
	if w.Fields&wire.WindowFieldWndSize != 0 && (w.Width != st.w || w.Height != st.h) {
		st.w, st.h, moved = w.Width, w.Height, true
	}
	a.windows[w.WindowID] = st
	if action == "" && moved {
		// A drag streams Window orders; log the geometry at most once a second.
		key := fmt.Sprintf("window:%d", w.WindowID)
		now := time.Now()
		if last, ok := a.lastMove[key]; ok && now.Sub(last) < time.Second {
			return
		}
		a.lastMove[key] = now
		action = "move"
	}
	if action != "" {
		s.emit(windowEvent(action, w.WindowID, st))
	}
}

func windowEvent(action string, id uint32, st windowState) Event {
	e := Event{Kind: "window", Source: "target", Action: action, Device: id, Detail: st.title, Status: showState(st.show), W: clamp16(int64(st.w)), H: clamp16(int64(st.h))}
	e.X, e.Y = clamp16(int64(st.x)), clamp16(int64(st.y))
	return e
}

// showState names a Window order ShowState ([MS-RDPERP] 2.2.1.3.1.2.1).
func showState(v uint8) string {
	switch v {
	case 0x00:
		return "hidden"
	case 0x02:
		return "minimized"
	case 0x03:
		return "maximized"
	case 0x05:
		return "shown"
	}
	return fmt.Sprintf("show 0x%02x", v)
}

func clamp16(v int64) uint16 {
	if v < 0 {
		return 0
	}
	if v > 0xFFFF {
		return 0xFFFF
	}
	return uint16(v)
}
