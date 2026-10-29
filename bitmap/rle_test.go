package bitmap

import (
	"bytes"
	"errors"
	"testing"
)

func TestExtractCode(t *testing.T) {
	for hdr, want := range map[byte]int{
		0x04: regularBGRun, 0x24: regularFGRun, 0x41: regularFGBGImage, 0x64: regularColorRun, 0x84: regularColorImg,
		0xC2: liteSetFGFGRun, 0xD1: liteSetFGFGBGImage, 0xE2: liteDitheredRun,
		0xF0: megaBGRun, 0xF4: megaColorImg, 0xF8: megaDitheredRun, 0xF9: specialFGBG1, 0xFE: specialBlack,
	} {
		if got := extractCode(hdr); got != want {
			t.Errorf("0x%02x: code 0x%x, want 0x%x", hdr, got, want)
		}
	}
}

func TestDecompress8bpp(t *testing.T) {
	cases := []struct {
		name string
		w, h int
		src  []byte
		want []byte
	}{
		{"color run then fg run xor on second line", 4, 2,
			[]byte{0x64, 0x11, 0x24},
			[]byte{0x11, 0x11, 0x11, 0x11, 0xEE, 0xEE, 0xEE, 0xEE}},
		{"bg runs insert fg pel between them on first line", 8, 1,
			[]byte{0x03, 0x05},
			[]byte{0, 0, 0, 0xFF, 0, 0, 0, 0}},
		{"bg run on second line copies row below; no insert across lines", 4, 2,
			[]byte{0x64, 0x22, 0x04},
			[]byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}},
		{"bg run insert on second line xors row below", 4, 2,
			[]byte{0x64, 0x22, 0x02, 0x02},
			[]byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0xDD, 0x22}},
		{"fgbg image first line", 8, 1,
			[]byte{0x41, 0xA5},
			[]byte{0xFF, 0, 0xFF, 0, 0, 0xFF, 0, 0xFF}},
		{"fgbg image extended length 3", 3, 1,
			[]byte{0x40, 0x02, 0x05},
			[]byte{0xFF, 0, 0xFF}},
		{"fgbg image second line xors row below", 2, 2,
			[]byte{0x62, 0x0F, 0x40, 0x01, 0x01},
			[]byte{0x0F, 0x0F, 0xF0, 0x0F}},
		{"lite set fg + fgbg image", 8, 1,
			[]byte{0xD1, 0x0F, 0x01},
			[]byte{0x0F, 0, 0, 0, 0, 0, 0, 0}},
		{"lite set fg + fg run keeps fg for later fg run", 4, 1,
			[]byte{0xC2, 0x33, 0x22},
			[]byte{0x33, 0x33, 0x33, 0x33}},
		{"dithered run", 4, 1,
			[]byte{0xE2, 0x01, 0x02},
			[]byte{1, 2, 1, 2}},
		{"color image", 4, 1,
			[]byte{0x84, 9, 8, 7, 6},
			[]byte{9, 8, 7, 6}},
		{"mega mega color run", 4, 1,
			[]byte{0xF3, 0x04, 0x00, 0x33},
			[]byte{0x33, 0x33, 0x33, 0x33}},
		{"mega mega fgbg image 9 pixels", 9, 1,
			[]byte{0xF2, 0x09, 0x00, 0xFF, 0x01},
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"regular run extended length 32+1", 33, 1,
			[]byte{0x60, 0x01, 0x07},
			bytes.Repeat([]byte{7}, 33)},
		{"special fgbg 1 and 2, white, black", 18, 1,
			[]byte{0xF9, 0xFA, 0xFD, 0xFE},
			[]byte{0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0xFF, 0, 0xFF, 0, 0, 0, 0, 0, 0xFF, 0}},
	}
	for _, c := range cases {
		got, err := Decompress(c.src, c.w, c.h, 8)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s:\n got  % x\n want % x", c.name, got, c.want)
		}
	}
}

func TestDecompressPelSizes(t *testing.T) {
	// 16bpp: LITE_SET_FG_FG_RUN with pel 0x1234, then FG_RUN on line 2 XORs
	// the same foreground with the row below, giving zero.
	got, err := Decompress([]byte{0xC2, 0x34, 0x12, 0x22}, 2, 2, 16)
	if err != nil || !bytes.Equal(got, []byte{0x34, 0x12, 0x34, 0x12, 0, 0, 0, 0}) {
		t.Fatalf("16bpp: % x %v", got, err)
	}
	// 15bpp white is 0xFFFF as well (reference decoder behaviour).
	if got, err := Decompress([]byte{0xFD}, 1, 1, 15); err != nil || !bytes.Equal(got, []byte{0xFF, 0xFF}) {
		t.Fatalf("15bpp white: % x %v", got, err)
	}
	// 24bpp colour run, B G R order preserved.
	if got, err := Decompress([]byte{0x62, 1, 2, 3}, 2, 1, 24); err != nil || !bytes.Equal(got, []byte{1, 2, 3, 1, 2, 3}) {
		t.Fatalf("24bpp: % x %v", got, err)
	}
	// 32bpp white.
	if got, err := Decompress([]byte{0xFD}, 1, 1, 32); err != nil || !bytes.Equal(got, []byte{0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Fatalf("32bpp white: % x %v", got, err)
	}
}

func TestDecompressErrors(t *testing.T) {
	for name, c := range map[string]struct {
		src  []byte
		w, h int
		bpp  int
	}{
		"bad bpp":                 {[]byte{0xFD}, 1, 1, 12},
		"zero size":               {[]byte{0xFD}, 0, 1, 8},
		"truncated pel":           {[]byte{0x64}, 4, 1, 8},
		"truncated mask":          {[]byte{0x41}, 8, 1, 8},
		"truncated mega length":   {[]byte{0xF3, 0x04}, 4, 1, 8},
		"truncated extended len":  {[]byte{0x60}, 4, 1, 8},
		"overflow":                {[]byte{0x65, 0x01}, 4, 1, 8},
		"underfill":               {[]byte{0x62, 0x01}, 4, 1, 8},
		"unknown order":           {[]byte{0xFB}, 1, 1, 8},
		"fgbg overflow":           {[]byte{0x41, 0xFF}, 4, 1, 8},
		"dithered overflow":       {[]byte{0xE3, 1, 2}, 4, 1, 8},
		"empty stream, unfilled":  {nil, 1, 1, 8},
		"mega color image 2 of 4": {[]byte{0xF4, 0x02, 0x00, 1, 2}, 4, 1, 8},
	} {
		if _, err := Decompress(c.src, c.w, c.h, c.bpp); !errors.Is(err, ErrRLE) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzDecompress(f *testing.F) {
	f.Add([]byte{0x64, 0x11, 0x24}, 4, 2, 8)
	f.Add([]byte{0xC2, 0x34, 0x12, 0x22}, 2, 2, 16)
	f.Add([]byte{0x41, 0xA5, 0xF9, 0xFA}, 8, 3, 24)
	f.Fuzz(func(t *testing.T, src []byte, w, h, bpp int) {
		if w < 0 || h < 0 || w > 64 || h > 64 {
			return
		}
		out, err := Decompress(src, w, h, bpp)
		if err == nil && len(out) != w*h*PelSize(bpp) {
			t.Fatalf("%d bytes for %dx%dx%d", len(out), w, h, bpp)
		}
	})
}
