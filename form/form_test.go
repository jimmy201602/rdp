package form

import (
	"testing"

	"rdp.local/kernel/wire"
)

func TestMessagesHaveGlyphs(t *testing.T) {
	for _, m := range allMessages {
		for _, r := range m {
			if !hasGlyph(r) {
				t.Errorf("%q: no glyph for U+%04X %q", m, r, string(r))
			}
		}
	}
	for r := rune(0x20); r <= 0x7e; r++ {
		if !hasGlyph(r) {
			t.Errorf("no glyph for ASCII U+%04X", r)
		}
	}
	if !hasGlyph('…') || !hasGlyph(0xFFFD) {
		t.Error("ellipsis / replacement glyph missing")
	}
	for r, g := range unifontGlyphs {
		if len(g) != 16 && len(g) != 32 {
			t.Errorf("U+%04X: glyph is %d bytes", r, len(g))
		}
	}
}

func press(f *Form, code uint16) Action {
	a := f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: code}, false)
	f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: code, Flags: slowKbdRelease}, false)
	return a
}

func pressExt(f *Form, code uint16) Action {
	a := f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: code, Flags: slowKbdExtended}, false)
	f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: code, Flags: slowKbdExtended | slowKbdRelease}, false)
	return a
}

var scanOf = func() map[rune]uint16 {
	m := map[rune]uint16{}
	for code, pair := range usScanChars {
		if code >= 0x47 || code == 0x37 { // prefer main-block keys over the keypad
			continue
		}
		m[pair[0]] = code
		m[pair[1]] = code
	}
	return m
}()

// typeText presses US-layout keys for s, holding Shift for shifted symbols.
func typeText(t *testing.T, f *Form, s string) {
	t.Helper()
	for _, r := range s {
		code, ok := scanOf[r]
		if !ok {
			t.Fatalf("no US scancode for %q", r)
		}
		shifted := usScanChars[code][1] == r && usScanChars[code][0] != r
		if shifted {
			f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: 0x2A}, false)
		}
		press(f, code)
		if shifted {
			f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: 0x2A, Flags: slowKbdRelease}, false)
		}
	}
}

func TestTypeTabSubmit(t *testing.T) {
	f := New(1024, 768)
	if _, ok := f.Flush(); !ok {
		t.Fatal("initial paint not marked dirty")
	}
	typeText(t, f, "10.0.0.5:3389")
	press(f, 0x0F) // Tab
	typeText(t, f, "Alice_W")
	press(f, 0x0F)
	// Password through Unicode keyboard events (IME / non-US layout).
	for _, r := range "p@ss 密码" {
		f.Handle(wire.InputEvent{Kind: wire.InputKindUnicode, Code: uint16(r)}, false)
		f.Handle(wire.InputEvent{Kind: wire.InputKindUnicode, Code: uint16(r), Flags: slowKbdRelease}, false)
	}
	press(f, 0x0F)
	typeText(t, f, "CORP")
	if f.Focus() != FieldDomain {
		t.Fatalf("focus = %d, want domain", f.Focus())
	}
	r, ok := f.Flush()
	if !ok || r.W == 0 || r.W > f.l.panel.W || r.H > f.l.panel.H {
		t.Fatalf("dirty rect after typing = %+v ok=%v, want within panel %+v", r, ok, f.l.panel)
	}
	if a := press(f, 0x1C); a != ActionSubmit {
		t.Fatalf("Enter → %v, want ActionSubmit", a)
	}
	want := Values{Address: "10.0.0.5:3389", UserName: "Alice_W", Password: "p@ss 密码", Domain: "CORP"}
	if got := f.Values(); got != want {
		t.Fatalf("Values = %+v, want %+v", got, want)
	}
	if !f.Busy() || f.Status() != MsgConnecting+"10.0.0.5:3389…" {
		t.Fatalf("busy=%v status=%q", f.Busy(), f.Status())
	}
	// Input is ignored while connecting.
	typeText(t, f, "x")
	if f.Values().Domain != "CORP" {
		t.Fatal("input accepted while busy")
	}
	f.Fail(MsgBadCredential)
	if f.Busy() || f.Focus() != FieldPassword || f.Values().Password != "" || f.Status() != MsgBadCredential {
		t.Fatalf("after Fail: busy=%v focus=%d values=%+v status=%q", f.Busy(), f.Focus(), f.Values(), f.Status())
	}
	typeText(t, f, "again")
	if a := press(f, 0x1C); a != ActionSubmit || f.Values().Password != "again" {
		t.Fatalf("retry: action=%v values=%+v", a, f.Values())
	}
}

func TestValidation(t *testing.T) {
	f := New(800, 600)
	if a := press(f, 0x1C); a != ActionNone || f.Status() != MsgNeedAddress || f.Focus() != FieldAddress {
		t.Fatalf("empty submit: %v %q focus=%d", a, f.Status(), f.Focus())
	}
	typeText(t, f, "host")
	if a := press(f, 0x1C); a != ActionNone || f.Status() != MsgNeedUser || f.Focus() != FieldUser {
		t.Fatalf("no-user submit: %v %q focus=%d", a, f.Status(), f.Focus())
	}
	if a := press(f, 0x01); a != ActionCancel {
		t.Fatalf("Esc → %v", a)
	}
}

func TestEditingKeys(t *testing.T) {
	f := New(1024, 768)
	typeText(t, f, "abd")
	pressExt(f, 0x4B) // Left
	typeText(t, f, "c")
	pressExt(f, 0x47) // Home
	press(f, 0x0E)    // Backspace at start: no-op
	pressExt(f, 0x53) // Delete 'a'
	pressExt(f, 0x4F) // End
	press(f, 0x0E)    // Backspace 'd'
	if got := f.Values().Address; got != "bc" {
		t.Fatalf("address = %q, want bc", got)
	}
	press(f, 0x3A) // Caps Lock
	typeText(t, f, "a1")
	press(f, 0x3A)
	if got := f.Values().Address; got != "bcA1" {
		t.Fatalf("caps: address = %q, want bcA1", got)
	}
	// Shift+Tab goes backwards, Up/Down cycle.
	f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: 0x2A}, false)
	press(f, 0x0F)
	f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: 0x2A, Flags: slowKbdRelease}, false)
	if f.Focus() != FieldDomain {
		t.Fatalf("Shift+Tab focus = %d", f.Focus())
	}
	pressExt(f, 0x50)
	if f.Focus() != FieldAddress {
		t.Fatalf("Down focus = %d", f.Focus())
	}
	// Ctrl-held letters are not inserted.
	press(f, 0x1D)
	f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: 0x1D}, false)
	press(f, 0x2F)
	f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: 0x1D, Flags: slowKbdRelease}, false)
	if got := f.Values().Address; got != "bcA1" {
		t.Fatalf("ctrl+v inserted: %q", got)
	}
	// Overlong input is capped.
	f.setFocus(FieldDomain)
	for i := 0; i < 100; i++ {
		typeText(t, f, "x")
	}
	if n := len(f.Values().Domain); n != fieldLimits[FieldDomain] {
		t.Fatalf("domain length %d, want %d", n, fieldLimits[FieldDomain])
	}
}

func TestFastPathFlags(t *testing.T) {
	f := New(1024, 768)
	fp := func(code uint16, flags uint16) {
		f.Handle(wire.InputEvent{Kind: wire.InputKindScancode, Code: code, Flags: flags}, true)
	}
	fp(0x1E, 0)              // a down
	fp(0x1E, fastKbdRelease) // a up
	fp(0x4B, fastKbdExtended)
	fp(0x4B, fastKbdExtended|fastKbdRelease) // Left
	fp(0x30, 0)
	fp(0x30, fastKbdRelease) // b inserted before a
	if got := f.Values().Address; got != "ba" {
		t.Fatalf("address = %q, want ba", got)
	}
	// Slow-path release flag (0x8000) must not be read as fast-path down.
	f.Handle(wire.InputEvent{Kind: wire.InputKindUnicode, Code: 'z', Flags: fastKbdRelease}, true)
	if got := f.Values().Address; got != "ba" {
		t.Fatalf("released unicode inserted: %q", got)
	}
}

func TestMouse(t *testing.T) {
	f := New(1024, 768)
	click := func(x, y int) Action {
		return f.Handle(wire.InputEvent{Kind: wire.InputKindMouse, Flags: ptrFlagsDown | ptrFlagsButton1, X: uint16(x), Y: uint16(y)}, true)
	}
	move := func(x, y int) {
		f.Handle(wire.InputEvent{Kind: wire.InputKindMouse, Flags: ptrFlagsMove, X: uint16(x), Y: uint16(y)}, true)
	}
	b := f.l.boxes[FieldUser]
	move(b.X+5, b.Y+5)
	if f.Focus() != FieldAddress {
		t.Fatal("mouse move changed focus")
	}
	if a := click(b.X+5, b.Y+5); a != ActionNone || f.Focus() != FieldUser {
		t.Fatalf("click user box: %v focus=%d", a, f.Focus())
	}
	typeText(t, f, "abc")
	// Click between 'a' and 'b' (each 8 px wide at scale 1, 6 px padding).
	click(b.X+6+8+1, b.Y+10)
	typeText(t, f, "X")
	if got := f.Values().UserName; got != "aXbc" {
		t.Fatalf("user = %q, want aXbc", got)
	}
	btn := f.l.button
	if a := click(btn.X+btn.W/2, btn.Y+btn.H/2); a != ActionNone || f.Status() != MsgNeedAddress {
		t.Fatalf("button without address: %v %q", a, f.Status())
	}
	typeText(t, f, "srv")
	if a := click(btn.X+1, btn.Y+1); a != ActionSubmit {
		t.Fatalf("button click → %v", a)
	}
	if a := click(b.X+5, b.Y+5); a != ActionNone || f.Focus() != FieldAddress {
		t.Fatal("click accepted while busy")
	}
}

func TestRenderMasksPassword(t *testing.T) {
	f := New(640, 480)
	f.Flush()
	press(f, 0x0F)
	press(f, 0x0F)
	typeText(t, f, "abc")
	star := New(640, 480)
	star.Flush()
	press(star, 0x0F)
	press(star, 0x0F)
	typeText(t, star, "***")
	if string(f.Canvas().BGR) != string(star.Canvas().BGR) {
		t.Fatal("password box does not render as asterisks")
	}
	plain := New(640, 480)
	press(plain, 0x0F)
	typeText(t, plain, "abc") // same text in the user box differs from the mask
	if string(plain.Canvas().BGR) == string(star.Canvas().BGR) {
		t.Fatal("canvases unexpectedly identical")
	}
	r, ok := f.Flush()
	if !ok || !r.contains(f.l.boxes[FieldPassword].X, f.l.boxes[FieldPassword].Y) {
		t.Fatalf("dirty rect %+v does not cover password box", r)
	}
}

func TestScaleAndSmallDesktop(t *testing.T) {
	big := New(1920, 1080)
	if big.l.s != 2 || big.l.panel.X <= 0 || big.l.panel.Y <= 0 {
		t.Fatalf("layout for 1920x1080: %+v", big.l.panel)
	}
	small := New(320, 200)
	small.Invalidate()
	if r, _ := small.Flush(); r.W != 320 || r.H != 200 {
		t.Fatalf("invalidate rect = %+v", r)
	}
	typeText(t, small, "x")
	small.SetStatus(MsgRefused+MsgRefused+MsgRefused, true)
	small.Succeed(MsgConnected)
	long := New(1024, 768)
	long.Prefill(Values{Address: string(make([]rune, 300)), Domain: "d"})
	if n := len(long.Values().Address); n != fieldLimits[FieldAddress] {
		t.Fatalf("prefill length %d", n)
	}
	typeText(t, long, "y")
}

func TestFitRunes(t *testing.T) {
	got := string(fitRunes([]rune("abcdefgh"), 8*5, 1))
	if got != "abcd…" {
		t.Fatalf("fitRunes = %q", got)
	}
	if got := string(fitRunes([]rune("ab"), 100, 1)); got != "ab" {
		t.Fatalf("fitRunes short = %q", got)
	}
}
