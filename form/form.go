// Package form draws a minimal RDP logon form (server address, user name,
// password, domain) into a 24bpp bitmap and turns decoded RDP keyboard and
// mouse events into edits, focus changes and a submit action. It has no
// protocol dependencies beyond wire.InputEvent so the gateway can present it
// over any activated server.Conn.
//
// Text is rendered from an embedded GNU Unifont subset (see
// glyphs_unifont.go and OFL-1.1.txt). The US keyboard layout is assumed for
// scancode input; clients that send Unicode keyboard events (IME, non-US
// layouts on some clients) are handled directly.
package form

import (
	"rdp.local/kernel/wire"
)

// Field identifies one input box.
type Field int

const (
	FieldAddress Field = iota
	FieldUser
	FieldPassword
	FieldDomain
	fieldCount
)

// Action is what the caller must do after an input event.
type Action int

const (
	ActionNone   Action = iota
	ActionSubmit        // Values() are complete; connect, then Fail or discard the form
	ActionCancel        // user pressed Esc; disconnect
)

// Values is a submitted form.
type Values struct {
	Address, UserName, Password, Domain string
}

// Maximum rune counts per field.
var fieldLimits = [fieldCount]int{253, 104, 127, 64}

var fieldLabels = [fieldCount]string{LabelAddress, LabelUser, LabelPass, LabelDomain}

var (
	colBackground = RGB{0x2b, 0x3a, 0x4a}
	colPanel      = RGB{0xf4, 0xf5, 0xf7}
	colText       = RGB{0x20, 0x20, 0x20}
	colMuted      = RGB{0x70, 0x78, 0x80}
	colBox        = RGB{0xff, 0xff, 0xff}
	colBorder     = RGB{0xb0, 0xb6, 0xbe}
	colFocus      = RGB{0x1e, 0x6f, 0xd9}
	colButton     = RGB{0x1e, 0x6f, 0xd9}
	colButtonBusy = RGB{0x9a, 0xa4, 0xb0}
	colButtonText = RGB{0xff, 0xff, 0xff}
	colError      = RGB{0xc0, 0x2a, 0x2a}
	colOK         = RGB{0x1f, 0x7a, 0x3c}
)

type fieldState struct {
	text   []rune
	cursor int
	scroll int // first visible rune
}

type layout struct {
	s                        int // pixel scale
	panel                    Rect
	title                    Rect
	labelX, boxX, boxW, rowH int
	boxes                    [fieldCount]Rect
	button                   Rect
	status, hint             Rect
}

// Form is a logon form bound to a canvas of fixed size. It is not safe for
// concurrent use.
type Form struct {
	c      *Canvas
	l      layout
	fields [fieldCount]fieldState
	focus  Field

	status    string
	statusCol RGB
	busy      bool

	shift, ctrl, alt, caps bool
	// Scan codes seen down while Ctrl/Alt were held are ignored on release
	// too; tracking exact state is unnecessary for a form.

	dirty Rect
}

// New creates a form for a width x height desktop and draws it.
func New(width, height int) *Form {
	f := &Form{c: newCanvas(width, height), statusCol: colMuted}
	f.l = computeLayout(width, height)
	f.drawAll()
	return f
}

func computeLayout(w, h int) layout {
	s := 1
	if w >= 1600 && h >= 1000 {
		s = 2
	}
	var l layout
	l.s = s
	pad, labelW, boxW, boxH, gap := 24*s, 96*s, 304*s, 28*s, 12*s
	l.rowH = boxH + gap
	contentW := labelW + 8*s + boxW
	panelW := contentW + 2*pad
	panelH := pad + 32*s + gap + int(fieldCount)*l.rowH + 32*s + 16*s + 20*s + 24*s + pad
	l.panel = Rect{(w - panelW) / 2, (h - panelH) / 2, panelW, panelH}
	if l.panel.X < 0 {
		l.panel.X = 0
	}
	if l.panel.Y < 0 {
		l.panel.Y = 0
	}
	x, y := l.panel.X+pad, l.panel.Y+pad
	l.title = Rect{x, y, contentW, 32 * s}
	y += 32*s + gap
	l.labelX, l.boxX, l.boxW = x, x+labelW+8*s, boxW
	for i := range l.boxes {
		l.boxes[i] = Rect{l.boxX, y, boxW, boxH}
		y += l.rowH
	}
	l.button = Rect{l.boxX + boxW - 96*s, y, 96 * s, 32 * s}
	y += 32*s + 16*s
	l.status = Rect{x, y, contentW, 20 * s}
	y += 20 * s
	l.hint = Rect{x, y, contentW, 24 * s}
	return l
}

// Canvas returns the backing bitmap; it is updated in place.
func (f *Form) Canvas() *Canvas { return f.c }

// Flush returns the bounding rectangle of everything repainted since the
// previous Flush (ok=false when nothing changed).
func (f *Form) Flush() (r Rect, ok bool) {
	r, f.dirty = f.dirty, Rect{}
	return r, r.W > 0 && r.H > 0
}

// Invalidate marks the whole canvas dirty (e.g. after a Refresh Rect PDU).
func (f *Form) Invalidate() {
	f.mark(Rect{0, 0, f.c.Width, f.c.Height})
}

// Values returns the current field contents.
func (f *Form) Values() Values {
	return Values{
		Address:  string(f.fields[FieldAddress].text),
		UserName: string(f.fields[FieldUser].text),
		Password: string(f.fields[FieldPassword].text),
		Domain:   string(f.fields[FieldDomain].text),
	}
}

// Prefill sets field contents (cursor at end) without changing focus.
func (f *Form) Prefill(v Values) {
	for i, s := range []string{v.Address, v.UserName, v.Password, v.Domain} {
		fs := &f.fields[i]
		fs.text = []rune(s)
		if len(fs.text) > fieldLimits[i] {
			fs.text = fs.text[:fieldLimits[i]]
		}
		fs.cursor, fs.scroll = len(fs.text), 0
		f.drawField(Field(i))
	}
}

// Focus returns the focused field.
func (f *Form) Focus() Field { return f.focus }

// Busy reports whether input is currently ignored (connection in progress).
func (f *Form) Busy() bool { return f.busy }

// Status returns the current status line.
func (f *Form) Status() string { return f.status }

// SetStatus replaces the status line. isError selects the error colour.
func (f *Form) SetStatus(msg string, isError bool) {
	f.status = msg
	f.statusCol = colMuted
	if isError {
		f.statusCol = colError
	}
	f.drawStatus()
}

// SetBusy disables input while the gateway connects (true) or re-enables it.
func (f *Form) SetBusy(busy bool) {
	if f.busy == busy {
		return
	}
	f.busy = busy
	f.drawButton()
	f.drawField(f.focus)
}

// Fail reports a failed connection attempt: shows msg as an error, clears the
// password, focuses the password field and re-enables input.
func (f *Form) Fail(msg string) {
	f.busy = false
	f.fields[FieldPassword] = fieldState{}
	f.setFocus(FieldPassword)
	f.drawButton()
	f.SetStatus(msg, true)
}

// Succeed shows a success status (the caller normally tears the form down
// right after).
func (f *Form) Succeed(msg string) {
	f.status, f.statusCol = msg, colOK
	f.drawStatus()
}

// HandleAll feeds events in order and returns the first non-ActionNone
// action, ignoring the remainder of the batch after it.
func (f *Form) HandleAll(evs []wire.InputEvent, fastPath bool) Action {
	for _, ev := range evs {
		if a := f.Handle(ev, fastPath); a != ActionNone {
			return a
		}
	}
	return ActionNone
}

// Handle applies one decoded input event. fastPath selects the flag
// encoding of ev (wire.DecodeFastPathInput vs wire.DecodeInputPDU).
func (f *Form) Handle(ev wire.InputEvent, fastPath bool) Action {
	switch ev.Kind {
	case wire.InputKindScancode:
		release, extended := ev.Flags&slowKbdRelease != 0, ev.Flags&slowKbdExtended != 0
		if fastPath {
			release, extended = ev.Flags&fastKbdRelease != 0, ev.Flags&fastKbdExtended != 0
		}
		return f.scancode(ev.Code, extended, release)
	case wire.InputKindUnicode:
		release := ev.Flags&slowKbdRelease != 0
		if fastPath {
			release = ev.Flags&fastKbdRelease != 0
		}
		if release || f.busy || f.ctrl || f.alt {
			return ActionNone
		}
		r := rune(ev.Code)
		if r >= 0x20 && r != 0x7f && r < 0xD800 {
			f.insert(r)
		}
		return ActionNone
	case wire.InputKindMouse:
		if ev.Flags&ptrFlagsDown != 0 && ev.Flags&ptrFlagsButton1 != 0 {
			return f.click(int(ev.X), int(ev.Y))
		}
	}
	return ActionNone
}

func (f *Form) scancode(code uint16, extended, release bool) Action {
	k, r := scanKey(code, extended, f.shift, f.caps)
	switch k {
	case keyShift:
		f.shift = !release
		return ActionNone
	case keyCtrl:
		f.ctrl = !release
		return ActionNone
	case keyAlt:
		f.alt = !release
		return ActionNone
	case keyCapsLock:
		if !release {
			f.caps = !f.caps
		}
		return ActionNone
	}
	if release || f.busy {
		return ActionNone
	}
	fs := &f.fields[f.focus]
	switch k {
	case keyChar:
		if !f.ctrl && !f.alt {
			f.insert(r)
		}
	case keyBackspace:
		if fs.cursor > 0 {
			fs.text = append(fs.text[:fs.cursor-1], fs.text[fs.cursor:]...)
			fs.cursor--
			f.drawField(f.focus)
		}
	case keyDelete:
		if fs.cursor < len(fs.text) {
			fs.text = append(fs.text[:fs.cursor], fs.text[fs.cursor+1:]...)
			f.drawField(f.focus)
		}
	case keyLeft:
		if fs.cursor > 0 {
			fs.cursor--
			f.drawField(f.focus)
		}
	case keyRight:
		if fs.cursor < len(fs.text) {
			fs.cursor++
			f.drawField(f.focus)
		}
	case keyHome:
		fs.cursor = 0
		f.drawField(f.focus)
	case keyEnd:
		fs.cursor = len(fs.text)
		f.drawField(f.focus)
	case keyTab:
		if f.shift {
			f.setFocus((f.focus + fieldCount - 1) % fieldCount)
		} else {
			f.setFocus((f.focus + 1) % fieldCount)
		}
	case keyUp:
		f.setFocus((f.focus + fieldCount - 1) % fieldCount)
	case keyDown:
		f.setFocus((f.focus + 1) % fieldCount)
	case keyEnter:
		return f.submit()
	case keyEscape:
		return ActionCancel
	}
	return ActionNone
}

func (f *Form) insert(r rune) {
	fs := &f.fields[f.focus]
	if len(fs.text) >= fieldLimits[f.focus] {
		return
	}
	fs.text = append(fs.text[:fs.cursor], append([]rune{r}, fs.text[fs.cursor:]...)...)
	fs.cursor++
	f.drawField(f.focus)
}

func (f *Form) click(x, y int) Action {
	if f.busy {
		return ActionNone
	}
	for i, b := range f.l.boxes {
		if b.contains(x, y) {
			f.setFocus(Field(i))
			f.fields[i].cursor = f.runeAt(Field(i), x)
			f.drawField(Field(i))
			return ActionNone
		}
	}
	if f.l.button.contains(x, y) {
		return f.submit()
	}
	return ActionNone
}

// runeAt maps a canvas x inside field i's box to the nearest rune boundary.
func (f *Form) runeAt(i Field, x int) int {
	fs := &f.fields[i]
	disp := f.display(i)
	px := f.l.boxes[i].X + 6*f.l.s
	for n := fs.scroll; n < len(disp); n++ {
		w := runeWidth(disp[n], f.l.s)
		if x < px+w/2 {
			return n
		}
		px += w
	}
	return len(disp)
}

func (f *Form) setFocus(i Field) {
	if i == f.focus {
		return
	}
	prev := f.focus
	f.focus = i
	f.drawField(prev)
	f.drawField(i)
}

func (f *Form) submit() Action {
	switch {
	case len(f.fields[FieldAddress].text) == 0:
		f.setFocus(FieldAddress)
		f.SetStatus(MsgNeedAddress, true)
		return ActionNone
	case len(f.fields[FieldUser].text) == 0:
		f.setFocus(FieldUser)
		f.SetStatus(MsgNeedUser, true)
		return ActionNone
	}
	f.busy = true
	f.drawButton()
	f.drawField(f.focus)
	f.SetStatus(MsgConnecting+string(f.fields[FieldAddress].text)+"…", false)
	return ActionSubmit
}

// display returns what is painted for field i (password masked).
func (f *Form) display(i Field) []rune {
	t := f.fields[i].text
	if i != FieldPassword {
		return t
	}
	m := make([]rune, len(t))
	for k := range m {
		m[k] = '*'
	}
	return m
}

func (f *Form) mark(r Rect) {
	x0, y0 := max(r.X, 0), max(r.Y, 0)
	x1, y1 := min(r.X+r.W, f.c.Width), min(r.Y+r.H, f.c.Height)
	if x0 >= x1 || y0 >= y1 {
		return
	}
	f.dirty = f.dirty.union(Rect{x0, y0, x1 - x0, y1 - y0})
}

func (f *Form) drawAll() {
	s := f.l.s
	f.c.fill(Rect{0, 0, f.c.Width, f.c.Height}, colBackground)
	f.c.fill(f.l.panel, colPanel)
	f.c.outline(f.l.panel, colBorder, s)
	f.c.drawText(f.l.title.X, f.l.title.Y, []rune(Title), 2*s, colText)
	for i := range f.fields {
		b := f.l.boxes[i]
		f.c.drawText(f.l.labelX, b.Y+6*s, []rune(fieldLabels[i]), s, colText)
		f.drawField(Field(i))
	}
	f.drawButton()
	f.drawStatus()
	f.c.drawText(f.l.hint.X, f.l.hint.Y+4*s, []rune(Hint), s, colMuted)
	f.mark(Rect{0, 0, f.c.Width, f.c.Height})
}

func (f *Form) drawField(i Field) {
	s, b, fs := f.l.s, f.l.boxes[i], &f.fields[i]
	f.c.fill(b, colBox)
	if i == f.focus && !f.busy {
		f.c.outline(b, colFocus, 2*s)
	} else {
		f.c.outline(b, colBorder, s)
	}
	inner := b.W - 12*s
	disp := f.display(i)
	if i == FieldDomain && len(disp) == 0 && i != f.focus {
		f.c.drawText(b.X+6*s, b.Y+6*s, []rune(HintOptional), s, colBorder)
	}
	if fs.cursor > len(disp) {
		fs.cursor = len(disp)
	}
	if fs.scroll > fs.cursor {
		fs.scroll = fs.cursor
	}
	for textWidth(disp[fs.scroll:fs.cursor], s) > inner {
		fs.scroll++
	}
	x, cx := b.X+6*s, b.X+6*s
	for n := fs.scroll; n < len(disp); n++ {
		w := runeWidth(disp[n], s)
		if x+w-b.X-6*s > inner {
			break
		}
		f.c.drawText(x, b.Y+6*s, disp[n:n+1], s, colText)
		x += w
		if n+1 == fs.cursor {
			cx = x
		}
	}
	if fs.cursor == fs.scroll {
		cx = b.X + 6*s
	}
	if i == f.focus && !f.busy {
		f.c.fill(Rect{cx, b.Y + 5*s, s, glyphHeight*s + 2*s}, colText)
	}
	f.mark(b)
}

func (f *Form) drawButton() {
	s, b := f.l.s, f.l.button
	col := colButton
	if f.busy {
		col = colButtonBusy
	}
	f.c.fill(b, col)
	label := []rune(LabelButton)
	w := textWidth(label, s)
	f.c.drawText(b.X+(b.W-w)/2, b.Y+(b.H-glyphHeight*s)/2, label, s, colButtonText)
	f.mark(b)
}

func (f *Form) drawStatus() {
	s, r := f.l.s, f.l.status
	f.c.fill(r, colPanel)
	f.c.drawText(r.X, r.Y+2*s, fitRunes([]rune(f.status), r.W, s), s, f.statusCol)
	f.mark(r)
}

// fitRunes truncates t with an ellipsis so it is at most maxW pixels wide.
func fitRunes(t []rune, maxW, scale int) []rune {
	if textWidth(t, scale) <= maxW {
		return t
	}
	ell := runeWidth('…', scale)
	w := 0
	for n, r := range t {
		rw := runeWidth(r, scale)
		if w+rw+ell > maxW {
			return append(append([]rune{}, t[:n]...), '…')
		}
		w += rw
	}
	return t
}
