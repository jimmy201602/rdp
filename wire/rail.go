package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// RemoteApp (RAIL) encoding: the "rail" static virtual channel of
// [MS-RDPERP] 2.2.2 and the Window alternate secondary drawing orders of
// [MS-RDPERP] 2.2.1.3. The gateway relays both verbatim; the monitor decodes
// just enough to log which program a client launched and which windows the
// server drew, so RemoteApp recordings can be followed without a desktop.

// ErrRail is wrapped by RAIL decoding failures.
var ErrRail = errors.New("rail: malformed")

// RailChannel is the static virtual channel name RemoteApp clients request.
const RailChannel = "rail"

// INFO_HIDEF_RAIL_SUPPORTED in TS_INFO_PACKET.flags ([MS-RDPBCGR] 2.2.1.11.1.1).
const InfoHiDefRailSupported uint32 = 0x02000000

// TS_RAIL_PDU_HEADER orderType values ([MS-RDPERP] 2.2.2.1).
const (
	RailOrderExec          uint16 = 0x0001
	RailOrderActivate      uint16 = 0x0002
	RailOrderSysParam      uint16 = 0x0003
	RailOrderSysCommand    uint16 = 0x0004
	RailOrderHandshake     uint16 = 0x0005
	RailOrderNotifyEvent   uint16 = 0x0006
	RailOrderWindowMove    uint16 = 0x0008
	RailOrderLocalMoveSize uint16 = 0x0009
	RailOrderMinMaxInfo    uint16 = 0x000A
	RailOrderClientStatus  uint16 = 0x000B
	RailOrderSysMenu       uint16 = 0x000C
	RailOrderLangBarInfo   uint16 = 0x000D
	RailOrderExecResult    uint16 = 0x0080
	RailOrderGetAppIDReq   uint16 = 0x000E
	RailOrderGetAppIDResp  uint16 = 0x000F
	RailOrderHandshakeEx   uint16 = 0x0013
)

// TS_RAIL_ORDER_EXEC flags ([MS-RDPERP] 2.2.2.3.1).
const (
	RailExecExpandWorkingDir uint16 = 0x0001
	RailExecTranslateFiles   uint16 = 0x0002
	RailExecFile             uint16 = 0x0004
	RailExecExpandArguments  uint16 = 0x0008
	RailExecAppUserModelID   uint16 = 0x0010
)

// TS_RAIL_ORDER_EXEC_RESULT execResult values ([MS-RDPERP] 2.2.2.3.2).
const (
	RailExecOK             uint16 = 0x0000
	RailExecHookNotLoaded  uint16 = 0x0001
	RailExecDecodeFailed   uint16 = 0x0002
	RailExecNotInAllowList uint16 = 0x0003
	RailExecFileNotFound   uint16 = 0x0005
	RailExecFail           uint16 = 0x0006
	RailExecSessionLocked  uint16 = 0x0007
)

// RailExecResultString names an execResult code for logs.
func RailExecResultString(r uint16) string {
	switch r {
	case RailExecOK:
		return "ok"
	case RailExecHookNotLoaded:
		return "hook not loaded"
	case RailExecDecodeFailed:
		return "decode failed"
	case RailExecNotInAllowList:
		return "not in allow list"
	case RailExecFileNotFound:
		return "file not found"
	case RailExecFail:
		return "failed"
	case RailExecSessionLocked:
		return "session locked"
	}
	return fmt.Sprintf("0x%04x", r)
}

// DecodeRailHeader splits a reassembled rail channel PDU into its
// TS_RAIL_PDU_HEADER orderType and the body that follows the header.
func DecodeRailHeader(data []byte) (orderType uint16, body []byte, err error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("%w: rail pdu %d bytes", ErrRail, len(data))
	}
	orderType = binary.LittleEndian.Uint16(data)
	n := int(binary.LittleEndian.Uint16(data[2:]))
	if n < 4 || n > len(data) {
		return 0, nil, fmt.Errorf("%w: rail order length %d of %d", ErrRail, n, len(data))
	}
	return orderType, data[4:n], nil
}

// RailExec is a TS_RAIL_ORDER_EXEC: the client asks the server to start a
// program (ExeOrFile is "||Alias" for an allow-listed RemoteApp).
type RailExec struct {
	Flags      uint16
	ExeOrFile  string
	WorkingDir string
	Arguments  string
}

// DecodeRailExec parses the body of a TS_RAIL_ORDER_EXEC.
func DecodeRailExec(body []byte) (RailExec, error) {
	var e RailExec
	if len(body) < 8 {
		return e, fmt.Errorf("%w: exec %d bytes", ErrRail, len(body))
	}
	e.Flags = binary.LittleEndian.Uint16(body)
	exeLen := int(binary.LittleEndian.Uint16(body[2:]))
	dirLen := int(binary.LittleEndian.Uint16(body[4:]))
	argLen := int(binary.LittleEndian.Uint16(body[6:]))
	rest := body[8:]
	if exeLen+dirLen+argLen > len(rest) || exeLen%2 != 0 || dirLen%2 != 0 || argLen%2 != 0 {
		return e, fmt.Errorf("%w: exec strings %d+%d+%d of %d", ErrRail, exeLen, dirLen, argLen, len(rest))
	}
	e.ExeOrFile = decodeUTF16(rest[:exeLen])
	e.WorkingDir = decodeUTF16(rest[exeLen : exeLen+dirLen])
	e.Arguments = decodeUTF16(rest[exeLen+dirLen : exeLen+dirLen+argLen])
	return e, nil
}

// EncodeRailExec builds a complete rail channel PDU (header included).
func EncodeRailExec(e RailExec) []byte {
	exe, dir, arg := encodeUTF16(e.ExeOrFile), encodeUTF16(e.WorkingDir), encodeUTF16(e.Arguments)
	n := 4 + 8 + len(exe) + len(dir) + len(arg)
	b := make([]byte, n)
	binary.LittleEndian.PutUint16(b, RailOrderExec)
	binary.LittleEndian.PutUint16(b[2:], uint16(n))
	binary.LittleEndian.PutUint16(b[4:], e.Flags)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(exe)))
	binary.LittleEndian.PutUint16(b[8:], uint16(len(dir)))
	binary.LittleEndian.PutUint16(b[10:], uint16(len(arg)))
	p := b[12:]
	p = p[copy(p, exe):]
	p = p[copy(p, dir):]
	copy(p, arg)
	return b
}

// RailExecResult is a TS_RAIL_ORDER_EXEC_RESULT: the server's verdict on a
// TS_RAIL_ORDER_EXEC.
type RailExecResult struct {
	Flags      uint16
	ExecResult uint16
	RawResult  uint32
	ExeOrFile  string
}

// DecodeRailExecResult parses the body of a TS_RAIL_ORDER_EXEC_RESULT.
func DecodeRailExecResult(body []byte) (RailExecResult, error) {
	var r RailExecResult
	if len(body) < 12 {
		return r, fmt.Errorf("%w: exec result %d bytes", ErrRail, len(body))
	}
	r.Flags = binary.LittleEndian.Uint16(body)
	r.ExecResult = binary.LittleEndian.Uint16(body[2:])
	r.RawResult = binary.LittleEndian.Uint32(body[4:])
	exeLen := int(binary.LittleEndian.Uint16(body[10:]))
	if exeLen%2 != 0 || exeLen > len(body)-12 {
		return r, fmt.Errorf("%w: exec result string %d of %d", ErrRail, exeLen, len(body)-12)
	}
	r.ExeOrFile = decodeUTF16(body[12 : 12+exeLen])
	return r, nil
}

// EncodeRailExecResult builds a complete rail channel PDU (header included).
func EncodeRailExecResult(r RailExecResult) []byte {
	exe := encodeUTF16(r.ExeOrFile)
	n := 4 + 12 + len(exe)
	b := make([]byte, n)
	binary.LittleEndian.PutUint16(b, RailOrderExecResult)
	binary.LittleEndian.PutUint16(b[2:], uint16(n))
	binary.LittleEndian.PutUint16(b[4:], r.Flags)
	binary.LittleEndian.PutUint16(b[6:], r.ExecResult)
	binary.LittleEndian.PutUint32(b[8:], r.RawResult)
	binary.LittleEndian.PutUint16(b[14:], uint16(len(exe)))
	copy(b[16:], exe)
	return b
}

// Alternate secondary drawing order types ([MS-RDPEGDI] 2.2.2.2.1.3.1.1).
const (
	altSecWindow uint8 = 0x0B
)

// Window order FieldsPresentFlags ([MS-RDPERP] 2.2.1.3.1.1 / 2.2.1.3.1.2.1).
const (
	WindowOrderTypeWindow   uint32 = 0x01000000
	WindowOrderTypeNotify   uint32 = 0x02000000
	WindowOrderTypeDesktop  uint32 = 0x04000000
	WindowOrderStateNew     uint32 = 0x10000000
	WindowOrderStateDeleted uint32 = 0x20000000
	WindowOrderIcon         uint32 = 0x40000000
	WindowOrderCachedIcon   uint32 = 0x80000000

	WindowFieldOwner            uint32 = 0x00000002
	WindowFieldStyle            uint32 = 0x00000008
	WindowFieldShow             uint32 = 0x00000010
	WindowFieldTitle            uint32 = 0x00000004
	WindowFieldClientAreaOffset uint32 = 0x00004000
	WindowFieldClientAreaSize   uint32 = 0x00010000
	WindowFieldResizeMarginX    uint32 = 0x00000080
	WindowFieldResizeMarginY    uint32 = 0x08000000
	WindowFieldRPContent        uint32 = 0x00020000
	WindowFieldRootParent       uint32 = 0x00040000
	WindowFieldWndOffset        uint32 = 0x00000800
	WindowFieldWndClientDelta   uint32 = 0x00008000
	WindowFieldWndSize          uint32 = 0x00000400
	WindowFieldWndRects         uint32 = 0x00000100
	WindowFieldVisOffset        uint32 = 0x00001000
	WindowFieldVisibility       uint32 = 0x00000200
	WindowFieldOverlayDesc      uint32 = 0x00400000
	WindowFieldTaskbarButton    uint32 = 0x00800000
	WindowFieldEnforceServerZ   uint32 = 0x00080000
	WindowFieldAppBarState      uint32 = 0x00000040
	WindowFieldAppBarEdge       uint32 = 0x00000001

	WindowFieldDesktopNone      uint32 = 0x00000001
	WindowFieldDesktopHooked    uint32 = 0x00000002
	WindowFieldDesktopArcDone   uint32 = 0x00000004
	WindowFieldDesktopArcBegan  uint32 = 0x00000008
	WindowFieldDesktopZOrder    uint32 = 0x00000010
	WindowFieldDesktopActiveWnd uint32 = 0x00000020
)

// WindowRect is a TS_RECTANGLE_16 relative to the window.
type WindowRect struct{ Left, Top, Right, Bottom uint16 }

// WindowOrder is one decoded Window alternate secondary order. Fields are
// only meaningful when the matching WindowField* bit is set in Fields.
type WindowOrder struct {
	Fields   uint32
	WindowID uint32 // TS_WINDOW_ORDER_HEADER.WindowId (not for desktop orders)
	Owner    uint32
	Style    uint32
	ExtStyle uint32
	Show     uint8
	Title    string
	// Window position and size on the server desktop.
	X, Y            int32
	Width, Height   uint32
	VisX, VisY      int32
	Rects, VisRects []WindowRect
	// Desktop orders: the active window and z-order.
	ActiveWindow uint32
	ZOrder       []uint32
}

// Type reports which of the WindowOrderType* bits is set.
func (w WindowOrder) Type() uint32 {
	return w.Fields & (WindowOrderTypeWindow | WindowOrderTypeNotify | WindowOrderTypeDesktop)
}

// Deleted reports a WINDOW_ORDER_STATE_DELETED order.
func (w WindowOrder) Deleted() bool { return w.Fields&WindowOrderStateDeleted != 0 }

// New reports a WINDOW_ORDER_STATE_NEW order.
func (w WindowOrder) New() bool { return w.Fields&WindowOrderStateNew != 0 }

// DecodeWindowOrders walks a fast-path or slow-path orders stream (after
// the numberOrders field) and returns the Window alternate secondary orders
// in it. Decoding stops at the first primary or secondary drawing order
// because their lengths cannot be known without a full order parser; the
// gateway disables those orders for monitored sessions, so in practice the
// stream holds only alternate secondary orders. Icon and notification-icon
// orders are skipped by size. Malformed input yields the orders decoded so
// far and an error.
func DecodeWindowOrders(data []byte) ([]WindowOrder, error) {
	var out []WindowOrder
	for len(data) > 0 {
		ctl := data[0]
		if ctl&0x03 != 0x02 { // TS_SECONDARY alone: alternate secondary order
			return out, nil
		}
		if len(data) < 3 {
			return out, fmt.Errorf("%w: altsec order %d bytes", ErrRail, len(data))
		}
		size := int(binary.LittleEndian.Uint16(data[1:]))
		if size < 3 || size > len(data) {
			return out, fmt.Errorf("%w: altsec order size %d of %d", ErrRail, size, len(data))
		}
		if ctl>>2 == altSecWindow && size >= 7 {
			w, err := decodeWindowOrder(data[3:size])
			if err != nil {
				return out, err
			}
			out = append(out, w)
		}
		data = data[size:]
	}
	return out, nil
}

func decodeWindowOrder(b []byte) (WindowOrder, error) {
	var w WindowOrder
	if len(b) < 4 {
		return w, fmt.Errorf("%w: window order %d bytes", ErrRail, len(b))
	}
	w.Fields = binary.LittleEndian.Uint32(b)
	b = b[4:]
	r := &railReader{b: b}
	switch w.Type() {
	case WindowOrderTypeDesktop:
		if w.Fields&WindowFieldDesktopNone != 0 {
			return w, nil
		}
		if w.Fields&WindowFieldDesktopActiveWnd != 0 {
			w.ActiveWindow = r.u32()
		}
		if w.Fields&WindowFieldDesktopZOrder != 0 {
			n := int(r.u8())
			if n > 64 {
				return w, fmt.Errorf("%w: desktop z-order %d windows", ErrRail, n)
			}
			for i := 0; i < n && r.err == nil; i++ {
				w.ZOrder = append(w.ZOrder, r.u32())
			}
		}
		return w, r.err
	case WindowOrderTypeWindow:
		w.WindowID = r.u32()
		if w.Fields&(WindowOrderIcon|WindowOrderCachedIcon) != 0 || w.Deleted() {
			return w, r.err
		}
		if w.Fields&WindowFieldOwner != 0 {
			w.Owner = r.u32()
		}
		if w.Fields&WindowFieldStyle != 0 {
			w.Style, w.ExtStyle = r.u32(), r.u32()
		}
		if w.Fields&WindowFieldShow != 0 {
			w.Show = r.u8()
		}
		if w.Fields&WindowFieldTitle != 0 {
			w.Title = r.str()
		}
		if w.Fields&WindowFieldClientAreaOffset != 0 {
			r.u32()
			r.u32()
		}
		if w.Fields&WindowFieldClientAreaSize != 0 {
			r.u32()
			r.u32()
		}
		if w.Fields&WindowFieldResizeMarginX != 0 {
			r.u32()
			r.u32()
		}
		if w.Fields&WindowFieldResizeMarginY != 0 {
			r.u32()
			r.u32()
		}
		if w.Fields&WindowFieldRPContent != 0 {
			r.u8()
		}
		if w.Fields&WindowFieldRootParent != 0 {
			r.u32()
		}
		if w.Fields&WindowFieldWndOffset != 0 {
			w.X, w.Y = int32(r.u32()), int32(r.u32())
		}
		if w.Fields&WindowFieldWndClientDelta != 0 {
			r.u32()
			r.u32()
		}
		if w.Fields&WindowFieldWndSize != 0 {
			w.Width, w.Height = r.u32(), r.u32()
		}
		if w.Fields&WindowFieldWndRects != 0 {
			w.Rects = r.rects()
		}
		if w.Fields&WindowFieldVisOffset != 0 {
			w.VisX, w.VisY = int32(r.u32()), int32(r.u32())
		}
		if w.Fields&WindowFieldVisibility != 0 {
			w.VisRects = r.rects()
		}
		return w, r.err
	default: // notification icon orders carry nothing the monitor logs
		w.WindowID = r.u32()
		return w, r.err
	}
}

type railReader struct {
	b   []byte
	err error
}

func (r *railReader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if len(r.b) < n {
		r.err = fmt.Errorf("%w: window order field needs %d bytes, %d left", ErrRail, n, len(r.b))
		return false
	}
	return true
}

func (r *railReader) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *railReader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *railReader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

// str reads a UNICODE_STRING ([MS-RDPERP] 2.2.1.2.1): cbString then bytes.
func (r *railReader) str() string {
	n := int(r.u16())
	if n%2 != 0 || !r.need(n) {
		if r.err == nil {
			r.err = fmt.Errorf("%w: odd unicode string length %d", ErrRail, n)
		}
		return ""
	}
	s := decodeUTF16(r.b[:n])
	r.b = r.b[n:]
	return s
}

func (r *railReader) rects() []WindowRect {
	n := int(r.u16())
	if n > 1024 {
		r.err = fmt.Errorf("%w: %d window rectangles", ErrRail, n)
		return nil
	}
	out := make([]WindowRect, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, WindowRect{r.u16(), r.u16(), r.u16(), r.u16()})
	}
	return out
}
