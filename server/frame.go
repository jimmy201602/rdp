package server

import "fmt"

// Frame is a top-down 24bpp (B, G, R) desktop image.
type Frame struct {
	Width, Height uint16
	BGR           []byte
}

// NewFrame allocates a black frame.
func NewFrame(w, h uint16) *Frame {
	return &Frame{Width: w, Height: h, BGR: make([]byte, int(w)*int(h)*3)}
}

// Set writes one pixel.
func (f *Frame) Set(x, y int, r, g, b uint8) {
	if x < 0 || y < 0 || x >= int(f.Width) || y >= int(f.Height) {
		return
	}
	i := (y*int(f.Width) + x) * 3
	f.BGR[i], f.BGR[i+1], f.BGR[i+2] = b, g, r
}

// Fill paints a rectangle (clipped).
func (f *Frame) Fill(x0, y0, w, h int, r, g, b uint8) {
	for y := y0; y < y0+h; y++ {
		for x := x0; x < x0+w; x++ {
			f.Set(x, y, r, g, b)
		}
	}
}

func (f *Frame) validate() error {
	if f.Width == 0 || f.Height == 0 || len(f.BGR) != int(f.Width)*int(f.Height)*3 {
		return fmt.Errorf("%w: frame %dx%d with %d bytes", ErrConfig, f.Width, f.Height, len(f.BGR))
	}
	return nil
}

// TestPattern returns a frame with eight colour bars, a white border and a
// grey box, easy to recognise in a client screenshot.
func TestPattern(w, h uint16) *Frame {
	f := NewFrame(w, h)
	bars := [8][3]uint8{{255, 255, 255}, {255, 255, 0}, {0, 255, 255}, {0, 255, 0}, {255, 0, 255}, {255, 0, 0}, {0, 0, 255}, {0, 0, 0}}
	bw := (int(w) + 7) / 8
	for i, c := range bars {
		f.Fill(i*bw, 0, bw, int(h)*2/3, c[0], c[1], c[2])
	}
	f.Fill(0, int(h)*2/3, int(w), int(h)-int(h)*2/3, 32, 32, 96)
	f.Fill(int(w)/4, int(h)*3/4, int(w)/2, int(h)/8, 200, 200, 200)
	for x := 0; x < int(w); x++ {
		f.Set(x, 0, 255, 255, 255)
		f.Set(x, int(h)-1, 255, 255, 255)
	}
	for y := 0; y < int(h); y++ {
		f.Set(0, y, 255, 255, 255)
		f.Set(int(w)-1, y, 255, 255, 255)
	}
	return f
}

// rows converts frame rows [y0, y1) to a bottom-up TS_BITMAP_DATA payload
// at the given depth (16, 24 or 32 bpp).
func (f *Frame) rows(y0, y1 int, bpp uint16) []byte {
	w := int(f.Width)
	bytesPP := int(bpp) / 8
	stride := w * bytesPP
	out := make([]byte, (y1-y0)*stride)
	for y := y1 - 1; y >= y0; y-- {
		dst := out[(y1-1-y)*stride:]
		src := f.BGR[y*w*3:]
		for x := 0; x < w; x++ {
			b, g, r := src[3*x], src[3*x+1], src[3*x+2]
			switch bpp {
			case 16:
				v := uint16(r>>3)<<11 | uint16(g>>2)<<5 | uint16(b>>3)
				dst[2*x], dst[2*x+1] = byte(v), byte(v>>8)
			case 24:
				dst[3*x], dst[3*x+1], dst[3*x+2] = b, g, r
			case 32:
				dst[4*x], dst[4*x+1], dst[4*x+2], dst[4*x+3] = b, g, r, 0
			}
		}
	}
	return out
}

// Pointer is a 24bpp colour pointer (TS_COLORPOINTERATTRIBUTE) with a 1bpp
// AND mask; both masks are top-down here and flipped on the wire.
type Pointer struct {
	Width, Height      uint16
	HotSpotX, HotSpotY uint16
	XorBGR             []byte // Width*Height*3
	And                []byte // ceil(Width/8) bytes per row (even stride applied on the wire)
}

// DefaultPointer returns a 32x32 black arrow with a white outline.
func DefaultPointer() *Pointer {
	const n = 32
	p := &Pointer{Width: n, Height: n, XorBGR: make([]byte, n*n*3), And: make([]byte, n*n/8)}
	for i := range p.And {
		p.And[i] = 0xff // transparent everywhere
	}
	// Arrow: rows 0..19, width grows with y, white outline, black fill.
	for y := 0; y < 20; y++ {
		w := y/2 + 1
		if y > 12 {
			w = 7 - (y-12)/2
		}
		for x := 0; x < w+2 && x < n; x++ {
			idx := y*n + x
			p.And[idx/8] &^= 0x80 >> (idx % 8)
			shade := uint8(0)
			if x == w+1 || x == 0 || y == 19 || y == 0 {
				shade = 255
			}
			p.XorBGR[3*idx], p.XorBGR[3*idx+1], p.XorBGR[3*idx+2] = shade, shade, shade
		}
	}
	return p
}

func (p *Pointer) validate() error {
	if p.Width == 0 || p.Height == 0 || p.Width > 32 || p.Height > 32 ||
		len(p.XorBGR) != int(p.Width)*int(p.Height)*3 || len(p.And) != int(p.Height)*((int(p.Width)+7)/8) {
		return fmt.Errorf("%w: pointer %dx%d masks %d/%d", ErrConfig, p.Width, p.Height, len(p.XorBGR), len(p.And))
	}
	return nil
}

// wireMasks returns bottom-up XOR (24bpp, even stride) and AND (1bpp, even
// stride) masks.
func (p *Pointer) wireMasks() (xor, and []byte) {
	w, h := int(p.Width), int(p.Height)
	xs := w * 3
	if xs%2 != 0 {
		xs++
	}
	as := (w + 7) / 8
	srcAs := as
	if as%2 != 0 {
		as++
	}
	xor = make([]byte, xs*h)
	and = make([]byte, as*h)
	for y := 0; y < h; y++ {
		dy := h - 1 - y
		copy(xor[dy*xs:], p.XorBGR[y*w*3:(y+1)*w*3])
		copy(and[dy*as:], p.And[y*srcAs:(y+1)*srcAs])
	}
	return xor, and
}
