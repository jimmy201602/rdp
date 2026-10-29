package bitmap

import (
	"errors"
	"image/color"
	"testing"

	"rdp.local/kernel/wire"
)

var (
	opaqueBlack = color.RGBA{0, 0, 0, 0xFF}
	transparent = color.RGBA{}
)

func TestDecodeCursor24(t *testing.T) {
	// 2x2, 24bpp. Stored bottom-up: first XOR row is the visually lower one.
	p := wire.Pointer{Type: wire.PointerTypeColor, XorBpp: 24, Width: 2, Height: 2, HotSpotX: 1, HotSpotY: 1, CacheIndex: 4,
		XorMask: []byte{
			0, 0, 0xFF, 0xFF, 0xFF, 0xFF, // bottom row: red (B G R), white
			0, 0, 0, 0xFF, 0, 0, // top row: black, blue
		},
		// AND rows bottom-up, MSB first: bottom row bits 10 (red → inverted → black, white opaque);
		// top row bits 10 (black → transparent, blue opaque).
		AndMask: []byte{0x80, 0, 0x80, 0},
	}
	c, err := DecodeCursor(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.HotX != 1 || c.HotY != 1 || c.XorBpp != 24 || c.CacheIndex != 4 || c.Image.Rect.Dx() != 2 {
		t.Fatalf("%+v", c)
	}
	for xy, want := range map[[2]int]color.RGBA{
		{0, 0}: transparent, {1, 0}: {0, 0, 0xFF, 0xFF},
		{0, 1}: opaqueBlack, {1, 1}: {0xFF, 0xFF, 0xFF, 0xFF},
	} {
		if got := c.Image.RGBAAt(xy[0], xy[1]); got != want {
			t.Errorf("(%d,%d) = %v, want %v", xy[0], xy[1], got, want)
		}
	}
	if c.Hash() == "" {
		t.Fatal("hash")
	}
}

func TestDecodeCursorDepths(t *testing.T) {
	// 1bpp: bit set → white, AND mask absent → all opaque.
	c, err := DecodeCursor(wire.Pointer{Type: wire.PointerTypeNew, XorBpp: 1, Width: 2, Height: 1, XorMask: []byte{0x80, 0}}, nil)
	if err != nil || c.Image.RGBAAt(0, 0) != (color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}) || c.Image.RGBAAt(1, 0) != opaqueBlack {
		t.Fatalf("1bpp: %v %v", c, err)
	}
	// 8bpp through the palette.
	var pal [256]color.RGBA
	pal[7] = color.RGBA{1, 2, 3, 0}
	c, err = DecodeCursor(wire.Pointer{Type: wire.PointerTypeNew, XorBpp: 8, Width: 1, Height: 1, XorMask: []byte{7, 0}, AndMask: []byte{0, 0}}, &pal)
	if err != nil || c.Image.RGBAAt(0, 0) != (color.RGBA{1, 2, 3, 0xFF}) {
		t.Fatalf("8bpp: %v %v", c, err)
	}
	// 16bpp RGB565 red.
	c, err = DecodeCursor(wire.Pointer{Type: wire.PointerTypeNew, XorBpp: 16, Width: 1, Height: 1, XorMask: []byte{0x00, 0xF8}, AndMask: []byte{0, 0}}, nil)
	if err != nil || c.Image.RGBAAt(0, 0) != (color.RGBA{0xFF, 0, 0, 0xFF}) {
		t.Fatalf("16bpp: %v %v", c, err)
	}
	// 32bpp with alpha: alpha wins over the AND mask (which would hide the pixel).
	c, err = DecodeCursor(wire.Pointer{Type: wire.PointerTypeNew, XorBpp: 32, Width: 2, Height: 1,
		XorMask: []byte{0, 0, 0xFF, 0x80, 0, 0, 0, 0}, AndMask: []byte{0xC0, 0}}, nil)
	if err != nil || c.Image.RGBAAt(0, 0) != (color.RGBA{0x80, 0, 0, 0x80}) || c.Image.RGBAAt(1, 0) != transparent {
		t.Fatalf("32bpp alpha: %v %v", c.Image.RGBAAt(0, 0), err)
	}
	// 32bpp without alpha falls back to the AND mask.
	c, err = DecodeCursor(wire.Pointer{Type: wire.PointerTypeNew, XorBpp: 32, Width: 1, Height: 1,
		XorMask: []byte{0, 0, 0xFF, 0}, AndMask: []byte{0, 0}}, nil)
	if err != nil || c.Image.RGBAAt(0, 0) != (color.RGBA{0xFF, 0, 0, 0xFF}) {
		t.Fatalf("32bpp no alpha: %v %v", c, err)
	}
	for name, p := range map[string]wire.Pointer{
		"zero size":      {XorBpp: 24, Width: 0, Height: 1},
		"huge":           {XorBpp: 24, Width: 1000, Height: 1},
		"bad bpp":        {XorBpp: 12, Width: 1, Height: 1, XorMask: []byte{0, 0}},
		"xor short":      {XorBpp: 24, Width: 2, Height: 1, XorMask: []byte{0, 0, 0}},
		"xor not rows":   {XorBpp: 8, Width: 1, Height: 2, XorMask: []byte{0, 0, 0}},
		"and short":      {XorBpp: 8, Width: 9, Height: 1, XorMask: make([]byte, 10), AndMask: []byte{0}},
		"and not rows":   {XorBpp: 8, Width: 1, Height: 2, XorMask: []byte{0, 0}, AndMask: []byte{0, 0, 0}},
		"1bpp xor short": {XorBpp: 1, Width: 9, Height: 1, XorMask: []byte{0}},
	} {
		if _, err := DecodeCursor(p, nil); !errors.Is(err, ErrPointer) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPointerState(t *testing.T) {
	s := NewPointerState(2)
	if s.Current() != nil {
		t.Fatal("initial cursor")
	}
	if _, _, ok := s.Position(); ok {
		t.Fatal("initial position")
	}
	shape := wire.Pointer{Type: wire.PointerTypeNew, XorBpp: 24, Width: 1, Height: 1, CacheIndex: 1, HotSpotX: 0,
		XorMask: []byte{0, 0, 0xFF, 0}, AndMask: []byte{0, 0}}
	if err := s.Apply(shape, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(wire.Pointer{Type: wire.PointerTypePosition, X: 5, Y: 6}, nil); err != nil {
		t.Fatal(err)
	}
	if x, y, ok := s.Position(); !ok || x != 5 || y != 6 {
		t.Fatalf("position %d %d %t", x, y, ok)
	}
	if err := s.Apply(wire.Pointer{Type: wire.PointerTypeSystem, SystemType: wire.SystemPointerNull}, nil); err != nil || s.Current() != nil || s.Summary().Visible {
		t.Fatalf("null pointer: %v %+v", err, s.Summary())
	}
	if err := s.Apply(wire.Pointer{Type: wire.PointerTypeCached, CacheIndex: 1}, nil); err != nil || s.Current() == nil || !s.Summary().Visible {
		t.Fatalf("cached: %v", err)
	}
	if err := s.Apply(wire.Pointer{Type: wire.PointerTypeCached, CacheIndex: 0}, nil); !errors.Is(err, ErrPointer) {
		t.Fatalf("cache miss: %v", err)
	}
	if err := s.Apply(wire.Pointer{Type: wire.PointerTypeCached, CacheIndex: 9}, nil); !errors.Is(err, ErrPointer) {
		t.Fatalf("cache out of range: %v", err)
	}
	shape.CacheIndex = 7 // beyond the cache: shown but not cached
	if err := s.Apply(shape, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(wire.Pointer{Type: wire.PointerTypeSystem, SystemType: wire.SystemPointerDefault}, nil); err != nil || s.Current() != nil || !s.Summary().Visible {
		t.Fatalf("default pointer: %v", err)
	}
	if err := s.Apply(wire.Pointer{Type: wire.PointerTypeSystem, SystemType: 0x1234}, nil); err != nil || s.Summary().System != "0x00001234" {
		t.Fatalf("other system pointer: %v %+v", err, s.Summary())
	}
	if err := s.Apply(wire.Pointer{Type: 0x99}, nil); !errors.Is(err, ErrPointer) {
		t.Fatalf("unknown type: %v", err)
	}
	if err := s.Apply(wire.Pointer{Type: wire.PointerTypeColor, XorBpp: 24, Width: 1, Height: 1}, nil); !errors.Is(err, ErrPointer) {
		t.Fatalf("bad shape: %v", err)
	}
	st := s.Summary()
	if st.Decoded != 2 || st.CacheHits != 1 || st.CacheMisses != 2 || st.Errors != 4 || st.FirstError == "" || st.Current != nil || *st.X != 5 || st.System != "0x00001234" {
		t.Fatalf("%+v", st)
	}
	if err := s.Apply(wire.Pointer{Type: wire.PointerTypeCached, CacheIndex: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if st := s.Summary(); st.Current == nil || st.Current.Width != 1 || st.Current.CacheIndex != 1 || st.Current.Hash == "" {
		t.Fatalf("%+v", st.Current)
	}
}

func TestComposite(t *testing.T) {
	f := New(4, 4)
	c, err := DecodeCursor(wire.Pointer{Type: wire.PointerTypeNew, XorBpp: 24, Width: 2, Height: 1, HotSpotX: 1, HotSpotY: 0,
		XorMask: []byte{0, 0, 0xFF, 0, 0xFF, 0}, AndMask: []byte{0x40, 0}}, nil) // red opaque, green hidden
	if err != nil {
		t.Fatal(err)
	}
	out := f.Composite(c, 2, 3) // hotspot at (2,3) → cursor origin (1,3)
	if out.RGBAAt(1, 3) != (color.RGBA{0xFF, 0, 0, 0xFF}) || out.RGBAAt(2, 3) != opaqueBlack || out.RGBAAt(0, 0) != opaqueBlack {
		t.Fatalf("%v %v", out.RGBAAt(1, 3), out.RGBAAt(2, 3))
	}
	if f.Image().RGBAAt(1, 3) != opaqueBlack {
		t.Fatal("composite modified the framebuffer")
	}
	// Partly off screen and nil cursor are fine.
	if out := f.Composite(c, 0, 0); out.RGBAAt(0, 0) != opaqueBlack || out.RGBAAt(1, 0) != opaqueBlack {
		t.Fatal("off-screen composite")
	}
	if out := f.Composite(nil, 0, 0); out.Rect != f.Image().Rect {
		t.Fatal("nil cursor")
	}
}
