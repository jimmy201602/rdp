package form

// Keyboard flag bits. Slow-path TS_KEYBOARD_EVENT / TS_UNICODE_KEYBOARD_EVENT
// (MS-RDPBCGR 2.2.8.1.1.3.1.1.1 / .2) use keyboardFlags; fast-path
// TS_FP_KEYBOARD_EVENT / TS_FP_UNICODE_KEYBOARD_EVENT (2.2.8.1.2.2.1 / .2)
// pack the equivalent bits into the 5-bit eventFlags.
const (
	slowKbdExtended = 0x0100
	slowKbdRelease  = 0x8000
	fastKbdRelease  = 0x01
	fastKbdExtended = 0x02
)

// Pointer flag bits (TS_POINTER_EVENT, 2.2.8.1.1.3.1.1.3; identical on the
// fast path).
const (
	ptrFlagsMove    = 0x0800
	ptrFlagsDown    = 0x8000
	ptrFlagsButton1 = 0x1000
)

type keyKind int

const (
	keyNone keyKind = iota
	keyChar
	keyBackspace
	keyDelete
	keyTab
	keyEnter
	keyEscape
	keyLeft
	keyRight
	keyUp
	keyDown
	keyHome
	keyEnd
	keyShift
	keyCtrl
	keyAlt
	keyCapsLock
)

// Scan code set 1 keyCode values for the US layout (MS-RDPBCGR
// 2.2.8.1.1.3.1.1.1 keyCode, non-extended): {unshifted, shifted}.
var usScanChars = map[uint16][2]rune{
	0x02: {'1', '!'}, 0x03: {'2', '@'}, 0x04: {'3', '#'}, 0x05: {'4', '$'},
	0x06: {'5', '%'}, 0x07: {'6', '^'}, 0x08: {'7', '&'}, 0x09: {'8', '*'},
	0x0A: {'9', '('}, 0x0B: {'0', ')'}, 0x0C: {'-', '_'}, 0x0D: {'=', '+'},
	0x10: {'q', 'Q'}, 0x11: {'w', 'W'}, 0x12: {'e', 'E'}, 0x13: {'r', 'R'},
	0x14: {'t', 'T'}, 0x15: {'y', 'Y'}, 0x16: {'u', 'U'}, 0x17: {'i', 'I'},
	0x18: {'o', 'O'}, 0x19: {'p', 'P'}, 0x1A: {'[', '{'}, 0x1B: {']', '}'},
	0x1E: {'a', 'A'}, 0x1F: {'s', 'S'}, 0x20: {'d', 'D'}, 0x21: {'f', 'F'},
	0x22: {'g', 'G'}, 0x23: {'h', 'H'}, 0x24: {'j', 'J'}, 0x25: {'k', 'K'},
	0x26: {'l', 'L'}, 0x27: {';', ':'}, 0x28: {'\'', '"'}, 0x29: {'`', '~'},
	0x2B: {'\\', '|'}, 0x2C: {'z', 'Z'}, 0x2D: {'x', 'X'}, 0x2E: {'c', 'C'},
	0x2F: {'v', 'V'}, 0x30: {'b', 'B'}, 0x31: {'n', 'N'}, 0x32: {'m', 'M'},
	0x33: {',', '<'}, 0x34: {'.', '>'}, 0x35: {'/', '?'}, 0x39: {' ', ' '},
	// Numeric keypad with Num Lock on; the same codes with the extended
	// flag are the navigation cluster and handled in scanKey.
	0x37: {'*', '*'}, 0x4A: {'-', '-'}, 0x4E: {'+', '+'},
	0x47: {'7', '7'}, 0x48: {'8', '8'}, 0x49: {'9', '9'},
	0x4B: {'4', '4'}, 0x4C: {'5', '5'}, 0x4D: {'6', '6'},
	0x4F: {'1', '1'}, 0x50: {'2', '2'}, 0x51: {'3', '3'},
	0x52: {'0', '0'}, 0x53: {'.', '.'},
}

var usScanKeys = map[uint16]keyKind{
	0x01: keyEscape, 0x0E: keyBackspace, 0x0F: keyTab, 0x1C: keyEnter,
	0x1D: keyCtrl, 0x2A: keyShift, 0x36: keyShift, 0x38: keyAlt, 0x3A: keyCapsLock,
}

var usExtendedKeys = map[uint16]keyKind{
	0x1C: keyEnter, 0x1D: keyCtrl, 0x35: keyChar, 0x38: keyAlt,
	0x47: keyHome, 0x48: keyUp, 0x4B: keyLeft, 0x4D: keyRight,
	0x4F: keyEnd, 0x50: keyDown, 0x53: keyDelete,
}

// scanKey maps a scancode to a logical key. letters is true when Shift and
// Caps Lock disagree (letters upper-cased), symbols when Shift is held.
func scanKey(code uint16, extended, shift, caps bool) (keyKind, rune) {
	if extended {
		k, ok := usExtendedKeys[code]
		if !ok {
			return keyNone, 0
		}
		if k == keyChar {
			return keyChar, '/' // keypad divide
		}
		return k, 0
	}
	if k, ok := usScanKeys[code]; ok {
		return k, 0
	}
	pair, ok := usScanChars[code]
	if !ok {
		return keyNone, 0
	}
	r := pair[0]
	isLetter := pair[0] >= 'a' && pair[0] <= 'z'
	if (isLetter && shift != caps) || (!isLetter && shift) {
		r = pair[1]
	}
	return keyChar, r
}
