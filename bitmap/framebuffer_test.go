package bitmap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image/color"
	"image/png"
	"testing"

	"rdp.local/kernel/wire"
)

// rect builds one TS_BITMAP_DATA through wire.DecodeUpdate.
func rect(t *testing.T, left, top, right, bottom, w, h, bpp, flags uint16, data []byte) wire.BitmapData {
	t.Helper()
	body := make([]byte, 0, 32+len(data))
	for _, v := range []uint16{wire.UpdateTypeBitmap, 1, left, top, right, bottom, w, h, bpp, flags, uint16(len(data))} {
		body = binary.LittleEndian.AppendUint16(body, v)
	}
	u, err := wire.DecodeUpdate(append(body, data...))
	if err != nil {
		t.Fatal(err)
	}
	return u.Bitmaps[0]
}

func TestDrawUncompressedBottomUp(t *testing.T) {
	f := New(4, 4)
	// 2x2 24bpp, bottom-up: first stored row is the visually lower one.
	data := []byte{
		0, 0, 0xFF, 0, 0xFF, 0, // bottom row: red, green (B G R)
		0xFF, 0, 0, 0xFF, 0xFF, 0xFF, // top row: blue, white
	}
	if err := f.Draw(rect(t, 1, 1, 2, 2, 2, 2, 24, 0, data)); err != nil {
		t.Fatal(err)
	}
	want := map[[2]int]color.RGBA{
		{1, 1}: {0, 0, 0xFF, 0xFF}, {2, 1}: {0xFF, 0xFF, 0xFF, 0xFF},
		{1, 2}: {0xFF, 0, 0, 0xFF}, {2, 2}: {0, 0xFF, 0, 0xFF},
		{0, 0}: {0, 0, 0, 0xFF}, {3, 3}: {0, 0, 0, 0xFF},
	}
	for xy, c := range want {
		if got := f.Image().RGBAAt(xy[0], xy[1]); got != c {
			t.Errorf("(%d,%d) = %v, want %v", xy[0], xy[1], got, c)
		}
	}
	s := f.Summary()
	if s.Rects != 1 || s.Pixels != 4 || s.Covered != 4 || s.Clipped != 0 || s.Decompressed != 0 || s.Depths["24"] != 1 || *s.Dirty != [4]int{1, 1, 3, 3} || s.Hash == "" {
		t.Fatalf("%+v", s)
	}
	var buf bytes.Buffer
	if err := f.WritePNG(&buf); err != nil {
		t.Fatal(err)
	}
	if img, err := png.Decode(&buf); err != nil || img.Bounds().Dx() != 4 {
		t.Fatalf("png: %v", err)
	}
}

func TestDrawClipsToDestRectAndScreen(t *testing.T) {
	f := New(4, 4)
	// 4x1 bitmap declared for a 2-pixel wide destination (padding), at the right edge.
	data := []byte{1, 1, 2, 2, 3, 3, 4, 4}
	if err := f.Draw(rect(t, 3, 0, 4, 0, 4, 1, 16, 0, data)); err != nil {
		t.Fatal(err)
	}
	s := f.Summary()
	if s.Clipped != 1 || s.Pixels != 1 || s.Covered != 1 || *s.Dirty != [4]int{3, 0, 4, 1} {
		t.Fatalf("%+v", s)
	}
	if f.Image().RGBAAt(3, 0) == (color.RGBA{0, 0, 0, 0xFF}) {
		t.Fatal("pixel (3,0) not drawn")
	}
	// Entirely off screen: counted, nothing drawn.
	if err := f.Draw(rect(t, 10, 10, 11, 10, 2, 1, 16, 0, data[:4])); err != nil {
		t.Fatal(err)
	}
	if s := f.Summary(); s.Rects != 2 || s.Clipped != 2 || s.Pixels != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestDrawCompressedAndPalette(t *testing.T) {
	f := New(4, 2)
	// 8bpp before palette: indices resolve to black and are counted as unpaletted.
	if err := f.Draw(rect(t, 0, 0, 3, 0, 4, 1, 8, wire.BitmapCompression|wire.BitmapNoCompressionHdr, []byte{0x64, 0x01})); err != nil {
		t.Fatal(err)
	}
	if s := f.Summary(); s.Unpaletted != 1 || s.Decompressed != 1 || f.Image().RGBAAt(0, 0) != (color.RGBA{0, 0, 0, 0xFF}) {
		t.Fatalf("%+v", s)
	}
	f.SetPalette([][3]uint8{{0, 0, 0}, {10, 20, 30}})
	hdr := binary.LittleEndian.AppendUint16(nil, 0)
	hdr = binary.LittleEndian.AppendUint16(hdr, 2) // cbCompMainBodySize
	hdr = binary.LittleEndian.AppendUint16(hdr, 4)
	hdr = binary.LittleEndian.AppendUint16(hdr, 4)
	if err := f.Draw(rect(t, 0, 1, 3, 1, 4, 1, 8, wire.BitmapCompression, append(hdr, 0x64, 0x01))); err != nil {
		t.Fatal(err)
	}
	if got := f.Image().RGBAAt(2, 1); got != (color.RGBA{10, 20, 30, 0xFF}) {
		t.Fatalf("palette pixel %v", got)
	}
	if s := f.Summary(); !s.PaletteSet || s.Unpaletted != 1 || s.Decompressed != 2 || s.Covered != 8 {
		t.Fatalf("%+v", s)
	}
}

func TestDrawHighColorConversion(t *testing.T) {
	f := New(2, 1)
	// 16bpp RGB565 0xF800 (red) and 15bpp RGB555 0x03E0 (green).
	if err := f.Draw(rect(t, 0, 0, 0, 0, 1, 1, 16, 0, []byte{0x00, 0xF8})); err != nil {
		t.Fatal(err)
	}
	if err := f.Draw(rect(t, 1, 0, 1, 0, 1, 1, 15, 0, []byte{0xE0, 0x03})); err != nil {
		t.Fatal(err)
	}
	if r, g := f.Image().RGBAAt(0, 0), f.Image().RGBAAt(1, 0); r != (color.RGBA{0xFF, 0, 0, 0xFF}) || g != (color.RGBA{0, 0xFF, 0, 0xFF}) {
		t.Fatalf("%v %v", r, g)
	}
	// 32bpp BGRX.
	if err := f.Draw(rect(t, 0, 0, 0, 0, 1, 1, 32, 0, []byte{1, 2, 3, 0x80})); err != nil {
		t.Fatal(err)
	}
	if got := f.Image().RGBAAt(0, 0); got != (color.RGBA{3, 2, 1, 0xFF}) {
		t.Fatalf("32bpp %v", got)
	}
	if s := f.Summary(); s.Depths["16"] != 1 || s.Depths["15"] != 1 || s.Depths["32"] != 1 || s.Covered != 2 || s.Pixels != 3 {
		t.Fatalf("%+v", s)
	}
}

func TestDrawRejects(t *testing.T) {
	f := New(4, 4)
	// Corrupt RLE: colour run overflowing the 2x1 bitmap.
	err := f.Draw(rect(t, 0, 0, 1, 0, 2, 1, 24, wire.BitmapCompression|wire.BitmapNoCompressionHdr, []byte{0x65, 1, 2, 3}))
	if !errors.Is(err, ErrDraw) || !errors.Is(err, ErrRLE) {
		t.Fatalf("%v", err)
	}
	// Inverted destination rectangle.
	if err := f.Draw(rect(t, 2, 0, 1, 0, 2, 1, 24, 0, make([]byte, 6))); !errors.Is(err, ErrDraw) {
		t.Fatalf("%v", err)
	}
	s := f.Summary()
	if s.Errors != 2 || s.FirstError == "" || s.Rects != 0 || s.Dirty != nil {
		t.Fatalf("%+v", s)
	}
	if f.Hash() != New(4, 4).Hash() {
		t.Fatal("rejected rectangles changed the framebuffer")
	}
}
