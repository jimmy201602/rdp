package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrInput is returned for malformed input PDUs.
var ErrInput = errors.New("invalid input PDU")

// Slow-path input event messageType values (TS_INPUT_EVENT, 2.2.8.1.1.3.1.1).
const (
	InputEventSync     uint16 = 0x0000
	InputEventUnused   uint16 = 0x0002
	InputEventScancode uint16 = 0x0004
	InputEventUnicode  uint16 = 0x0005
	InputEventMouse    uint16 = 0x8001
	InputEventMouseX   uint16 = 0x8002
)

// Fast-path input eventCode values (TS_FP_INPUT_EVENT, 2.2.8.1.2.2).
const (
	FastPathInputScancode uint8 = 0
	FastPathInputMouse    uint8 = 1
	FastPathInputMouseX   uint8 = 2
	FastPathInputSync     uint8 = 3
	FastPathInputUnicode  uint8 = 4
	FastPathInputQoE      uint8 = 6
)

// InputKind classifies a decoded input event independent of the path.
type InputKind uint8

const (
	InputKindSync InputKind = iota + 1
	InputKindScancode
	InputKindUnicode
	InputKindMouse
	InputKindMouseX
	InputKindQoE
	InputKindUnused
)

func (k InputKind) String() string {
	switch k {
	case InputKindSync:
		return "sync"
	case InputKindScancode:
		return "scancode"
	case InputKindUnicode:
		return "unicode"
	case InputKindMouse:
		return "mouse"
	case InputKindMouseX:
		return "mousex"
	case InputKindQoE:
		return "qoe"
	case InputKindUnused:
		return "unused"
	}
	return fmt.Sprintf("kind-%d", uint8(k))
}

// InputEvent is one keyboard / mouse / sync event. Flags and Code hold the
// path-specific flag word and key / character code; X, Y the mouse
// position. Relays must not log Code for keyboard events (keystrokes).
type InputEvent struct {
	Kind  InputKind
	Flags uint16
	Code  uint16
	X, Y  uint16
}

const (
	slowPathInputEventLen = 12
	maxInputEvents        = 1024
)

// DecodeInputPDU parses the body of a slow-path Input PDU
// (TS_INPUT_PDU_DATA after the Share Data Header).
func DecodeInputPDU(body []byte) ([]InputEvent, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("%w: body %d bytes", ErrInput, len(body))
	}
	n := int(binary.LittleEndian.Uint16(body))
	if n > maxInputEvents || len(body) != 4+n*slowPathInputEventLen {
		return nil, fmt.Errorf("%w: %d events in %d bytes", ErrInput, n, len(body))
	}
	events := make([]InputEvent, 0, n)
	for i := 0; i < n; i++ {
		e := body[4+i*slowPathInputEventLen:]
		typ := binary.LittleEndian.Uint16(e[4:])
		ev := InputEvent{}
		switch typ {
		case InputEventSync:
			ev.Kind = InputKindSync
			ev.Flags = uint16(binary.LittleEndian.Uint32(e[8:]))
		case InputEventUnused:
			ev.Kind = InputKindUnused
		case InputEventScancode:
			ev.Kind, ev.Flags, ev.Code = InputKindScancode, binary.LittleEndian.Uint16(e[6:]), binary.LittleEndian.Uint16(e[8:])
		case InputEventUnicode:
			ev.Kind, ev.Flags, ev.Code = InputKindUnicode, binary.LittleEndian.Uint16(e[6:]), binary.LittleEndian.Uint16(e[8:])
		case InputEventMouse, InputEventMouseX:
			ev.Kind = InputKindMouse
			if typ == InputEventMouseX {
				ev.Kind = InputKindMouseX
			}
			ev.Flags, ev.X, ev.Y = binary.LittleEndian.Uint16(e[6:]), binary.LittleEndian.Uint16(e[8:]), binary.LittleEndian.Uint16(e[10:])
		default:
			return nil, fmt.Errorf("%w: event %d has messageType 0x%04x", ErrInput, i, typ)
		}
		events = append(events, ev)
	}
	return events, nil
}

// DecodeFastPathInput parses a complete TS_FP_INPUT_PDU frame (as returned
// by ReadFastPathFrame).
func DecodeFastPathInput(frame []byte) ([]InputEvent, error) {
	if len(frame) < 2 {
		return nil, fmt.Errorf("%w: frame %d bytes", ErrInput, len(frame))
	}
	hdr := frame[0]
	if !IsFastPathHeader(hdr) {
		return nil, fmt.Errorf("%w: header 0x%02x", ErrInput, hdr)
	}
	if hdr>>6&FastPathOutputEncrypted != 0 {
		return nil, fmt.Errorf("%w: encrypted fast-path input", ErrInput)
	}
	size, p := int(frame[1]), frame[2:]
	if frame[1]&0x80 != 0 {
		if len(frame) < 3 {
			return nil, fmt.Errorf("%w: truncated length", ErrInput)
		}
		size, p = int(binary.BigEndian.Uint16(frame[1:])&0x7fff), frame[3:]
	}
	if size != len(frame) {
		return nil, fmt.Errorf("%w: length %d, frame %d bytes", ErrInput, size, len(frame))
	}
	n := int(hdr >> 2 & 0x0f)
	if n == 0 {
		if len(p) < 1 {
			return nil, fmt.Errorf("%w: missing numEvents", ErrInput)
		}
		n, p = int(p[0]), p[1:]
	}
	events := make([]InputEvent, 0, n)
	for i := 0; i < n; i++ {
		if len(p) < 1 {
			return nil, fmt.Errorf("%w: event %d truncated", ErrInput, i)
		}
		eh := p[0]
		flags, code := uint16(eh&0x1f), eh>>5
		p = p[1:]
		ev := InputEvent{Flags: flags}
		var need int
		switch code {
		case FastPathInputScancode:
			ev.Kind, need = InputKindScancode, 1
		case FastPathInputMouse:
			ev.Kind, need = InputKindMouse, 6
		case FastPathInputMouseX:
			ev.Kind, need = InputKindMouseX, 6
		case FastPathInputSync:
			ev.Kind, need = InputKindSync, 0
		case FastPathInputUnicode:
			ev.Kind, need = InputKindUnicode, 2
		case FastPathInputQoE:
			ev.Kind, need = InputKindQoE, 4
		default:
			return nil, fmt.Errorf("%w: event %d has eventCode %d", ErrInput, i, code)
		}
		if len(p) < need {
			return nil, fmt.Errorf("%w: event %d (%s) truncated", ErrInput, i, ev.Kind)
		}
		switch ev.Kind {
		case InputKindScancode:
			ev.Code = uint16(p[0])
		case InputKindUnicode:
			ev.Code = binary.LittleEndian.Uint16(p)
		case InputKindMouse, InputKindMouseX:
			ev.Flags, ev.X, ev.Y = binary.LittleEndian.Uint16(p), binary.LittleEndian.Uint16(p[2:]), binary.LittleEndian.Uint16(p[4:])
		}
		p = p[need:]
		events = append(events, ev)
	}
	if len(p) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrInput, len(p))
	}
	return events, nil
}

// EncodeInputPDU builds the body of a slow-path Input PDU from events
// (eventTime 0). Used by tests and by clients without fast-path input.
func EncodeInputPDU(events []InputEvent) ([]byte, error) {
	if len(events) == 0 || len(events) > maxInputEvents {
		return nil, fmt.Errorf("%w: %d events", ErrInput, len(events))
	}
	out := make([]byte, 4, 4+len(events)*slowPathInputEventLen)
	binary.LittleEndian.PutUint16(out, uint16(len(events)))
	for _, ev := range events {
		e := make([]byte, slowPathInputEventLen)
		switch ev.Kind {
		case InputKindSync:
			binary.LittleEndian.PutUint16(e[4:], InputEventSync)
			binary.LittleEndian.PutUint32(e[8:], uint32(ev.Flags))
		case InputKindScancode, InputKindUnicode:
			typ := InputEventScancode
			if ev.Kind == InputKindUnicode {
				typ = InputEventUnicode
			}
			binary.LittleEndian.PutUint16(e[4:], typ)
			binary.LittleEndian.PutUint16(e[6:], ev.Flags)
			binary.LittleEndian.PutUint16(e[8:], ev.Code)
		case InputKindMouse, InputKindMouseX:
			typ := InputEventMouse
			if ev.Kind == InputKindMouseX {
				typ = InputEventMouseX
			}
			binary.LittleEndian.PutUint16(e[4:], typ)
			binary.LittleEndian.PutUint16(e[6:], ev.Flags)
			binary.LittleEndian.PutUint16(e[8:], ev.X)
			binary.LittleEndian.PutUint16(e[10:], ev.Y)
		default:
			return nil, fmt.Errorf("%w: cannot encode %s on the slow path", ErrInput, ev.Kind)
		}
		out = append(out, e...)
	}
	return out, nil
}

// EncodeFastPathInput builds a TS_FP_INPUT_PDU frame from events.
func EncodeFastPathInput(events []InputEvent) ([]byte, error) {
	if len(events) == 0 || len(events) > 255 {
		return nil, fmt.Errorf("%w: %d events", ErrInput, len(events))
	}
	var body []byte
	for _, ev := range events {
		switch ev.Kind {
		case InputKindScancode:
			if ev.Code > 0xff {
				return nil, fmt.Errorf("%w: scancode 0x%04x does not fit fast-path", ErrInput, ev.Code)
			}
			body = append(body, byte(ev.Flags&0x1f)|FastPathInputScancode<<5, byte(ev.Code))
		case InputKindUnicode:
			body = append(body, byte(ev.Flags&0x1f)|FastPathInputUnicode<<5)
			body = binary.LittleEndian.AppendUint16(body, ev.Code)
		case InputKindSync:
			body = append(body, byte(ev.Flags&0x1f)|FastPathInputSync<<5)
		case InputKindMouse, InputKindMouseX:
			code := FastPathInputMouse
			if ev.Kind == InputKindMouseX {
				code = FastPathInputMouseX
			}
			body = append(body, code<<5)
			body = binary.LittleEndian.AppendUint16(body, ev.Flags)
			body = binary.LittleEndian.AppendUint16(body, ev.X)
			body = binary.LittleEndian.AppendUint16(body, ev.Y)
		default:
			return nil, fmt.Errorf("%w: cannot encode %s on the fast path", ErrInput, ev.Kind)
		}
	}
	hdr := byte(FastPathActionFastPath)
	if len(events) < 16 {
		hdr |= byte(len(events)) << 2
	} else {
		body = append([]byte{byte(len(events))}, body...)
	}
	size := 2 + len(body)
	if size > 0x7f {
		size++
	}
	out := []byte{hdr}
	if size <= 0x7f {
		out = append(out, byte(size))
	} else {
		out = binary.BigEndian.AppendUint16(out, uint16(size)|0x8000)
	}
	return append(out, body...), nil
}
