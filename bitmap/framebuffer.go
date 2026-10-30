package bitmap

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"

	"rdp.local/kernel/wire"
)

// ErrDraw wraps failures to apply a TS_BITMAP_DATA to a Framebuffer.
var ErrDraw = errors.New("bitmap: draw")

// Stats summarises what a Framebuffer has received.
type Stats struct {
	Width  int `json:"width"`
	Height int `json:"height"`

	Rects        int            `json:"rects"`             // rectangles applied
	Decompressed int            `json:"decompressed"`      // of which Interleaved RLE
	Clipped      int            `json:"clipped,omitempty"` // rectangles partly outside the destination rectangle or screen
	Pixels       int            `json:"pixels"`            // pixels written (including overwrites)
	Covered      int            `json:"covered"`           // distinct pixels written at least once
	Depths       map[string]int `json:"depths,omitempty"`  // bitsPerPixel values seen, e.g. "24"
	PaletteSet   bool           `json:"palette_set,omitempty"`
	Unpaletted   int            `json:"unpaletted_rects,omitempty"` // 8bpp rectangles drawn before any Palette Update

	// Dirty is the bounding box of everything written, as [left top right bottom)
	// in screen coordinates; nil when nothing was drawn.
	Dirty *[4]int `json:"dirty,omitempty"`

	Errors     int    `json:"errors,omitempty"` // rectangles rejected (decode or format error)
	FirstError string `json:"first_error,omitempty"`

	// Hash is the SHA-256 of the RGBA pixel buffer, filled by Summary.
	Hash string `json:"sha256,omitempty"`
}

// Framebuffer is a top-down RGBA screen that Slow-Path Bitmap Updates are
// painted on. It is not safe for concurrent use.
type Framebuffer struct {
	img     *image.RGBA
	drawn   []bool
	palette [256]color.RGBA
	stats   Stats
}

// New returns a black framebuffer of the given desktop size.
func New(width, height int) *Framebuffer {
	f := &Framebuffer{img: image.NewRGBA(image.Rect(0, 0, width, height)), drawn: make([]bool, width*height)}
	f.stats.Width, f.stats.Height = width, height
	for i := 3; i < len(f.img.Pix); i += 4 {
		f.img.Pix[i] = 0xFF
	}
	return f
}

// Image returns the backing image (not a copy).
func (f *Framebuffer) Image() *image.RGBA { return f.img }

// SetPalette installs the entries of a Palette Update (2.2.9.1.1.3.1.1),
// each as red, green, blue.
func (f *Framebuffer) SetPalette(entries [][3]uint8) {
	for i, e := range entries {
		if i >= 256 {
			break
		}
		f.palette[i] = color.RGBA{e[0], e[1], e[2], 0xFF}
	}
	f.stats.PaletteSet = true
}

// Summary returns the statistics with the pixel hash filled in.
func (f *Framebuffer) Summary() Stats {
	s := f.stats
	if s.Depths != nil {
		s.Depths = make(map[string]int, len(f.stats.Depths))
		for k, v := range f.stats.Depths {
			s.Depths[k] = v
		}
	}
	if s.Dirty != nil {
		d := *s.Dirty
		s.Dirty = &d
	}
	s.Hash = f.Hash()
	return s
}

// Hash is the SHA-256 (hex) of the RGBA pixel buffer.
func (f *Framebuffer) Hash() string {
	sum := sha256.Sum256(f.img.Pix)
	return hex.EncodeToString(sum[:])
}

// WritePNG encodes the framebuffer as PNG.
func (f *Framebuffer) WritePNG(w io.Writer) error { return png.Encode(w, f.img) }

func (f *Framebuffer) reject(err error) error {
	f.stats.Errors++
	if f.stats.FirstError == "" {
		f.stats.FirstError = err.Error()
	}
	return err
}

// Draw applies one TS_BITMAP_DATA: the bitmap (width x height, bottom-up)
// is placed at (destLeft, destTop) and clipped to the inclusive destination
// rectangle and the screen. Compressed data is decoded with Decompress.
// Rejected rectangles are counted in Stats.Errors and leave the screen
// unchanged.
func (f *Framebuffer) Draw(b wire.BitmapData) error {
	bpp := int(b.BitsPerPixel)
	ps := PelSize(bpp)
	if ps == 0 {
		return f.reject(fmt.Errorf("%w: bitsPerPixel %d", ErrDraw, bpp))
	}
	w, h := int(b.Width), int(b.Height)
	if w == 0 || h == 0 || int(b.DestRight) < int(b.DestLeft) || int(b.DestBottom) < int(b.DestTop) {
		return f.reject(fmt.Errorf("%w: rectangle %dx%d at (%d,%d)-(%d,%d)", ErrDraw, w, h, b.DestLeft, b.DestTop, b.DestRight, b.DestBottom))
	}
	pix := b.Data()
	if b.Compressed {
		var err error
		if pix, err = decompress(pix, w, h, bpp); err != nil {
			return f.reject(fmt.Errorf("%w: %dx%dx%d at (%d,%d): %w", ErrDraw, w, h, bpp, b.DestLeft, b.DestTop, err))
		}
		f.stats.Decompressed++
	} else if len(pix) != w*h*ps {
		return f.reject(fmt.Errorf("%w: uncompressed %dx%dx%d needs %d bytes, got %d", ErrDraw, w, h, bpp, w*h*ps, len(pix)))
	}
	if bpp == 8 && !f.stats.PaletteSet {
		f.stats.Unpaletted++
	}

	bounds := f.img.Bounds()
	dst := image.Rect(int(b.DestLeft), int(b.DestTop), int(b.DestRight)+1, int(b.DestBottom)+1)
	full := image.Rect(int(b.DestLeft), int(b.DestTop), int(b.DestLeft)+w, int(b.DestTop)+h)
	clip := full.Intersect(dst).Intersect(bounds)
	if clip != full {
		f.stats.Clipped++
	}
	f.stats.Rects++
	if f.stats.Depths == nil {
		f.stats.Depths = map[string]int{}
	}
	f.stats.Depths[fmt.Sprint(bpp)]++
	if clip.Empty() {
		return nil
	}

	stride := w * ps
	for y := clip.Min.Y; y < clip.Max.Y; y++ {
		srcRow := (h - 1 - (y - full.Min.Y)) * stride
		off := f.img.PixOffset(clip.Min.X, y)
		di := y*bounds.Dx() + clip.Min.X
		for x := clip.Min.X; x < clip.Max.X; x++ {
			c := pelRGBA(pix[srcRow+(x-full.Min.X)*ps:], bpp, &f.palette)
			p := f.img.Pix[off : off+4 : off+4]
			p[0], p[1], p[2], p[3] = c.R, c.G, c.B, 0xFF
			off += 4
			if !f.drawn[di] {
				f.drawn[di] = true
				f.stats.Covered++
			}
			di++
		}
	}
	f.stats.Pixels += clip.Dx() * clip.Dy()
	if f.stats.Dirty == nil {
		f.stats.Dirty = &[4]int{clip.Min.X, clip.Min.Y, clip.Max.X, clip.Max.Y}
	} else {
		d := f.stats.Dirty
		d[0], d[1] = min(d[0], clip.Min.X), min(d[1], clip.Min.Y)
		d[2], d[3] = max(d[2], clip.Max.X), max(d[3], clip.Max.Y)
	}
	return nil
}

func scale5(v uint32) uint8 { return uint8(v<<3 | v>>2) }
func scale6(v uint32) uint8 { return uint8(v<<2 | v>>4) }

// Palette returns the current 8bpp palette (entries from Palette Updates).
func (f *Framebuffer) Palette() *[256]color.RGBA { return &f.palette }

// pelRGBA converts one little-endian pixel at p to RGBA; palette resolves
// 8bpp indices (nil means black).
func pelRGBA(p []byte, bpp int, palette *[256]color.RGBA) color.RGBA {
	switch bpp {
	case 8:
		if palette == nil {
			return color.RGBA{0, 0, 0, 0xFF}
		}
		c := palette[p[0]]
		c.A = 0xFF
		return c
	case 15:
		v := uint32(p[0]) | uint32(p[1])<<8
		return color.RGBA{scale5(v >> 10 & 0x1F), scale5(v >> 5 & 0x1F), scale5(v & 0x1F), 0xFF}
	case 16:
		v := uint32(p[0]) | uint32(p[1])<<8
		return color.RGBA{scale5(v >> 11 & 0x1F), scale6(v >> 5 & 0x3F), scale5(v & 0x1F), 0xFF}
	default: // 24, 32: B G R [X]
		return color.RGBA{p[2], p[1], p[0], 0xFF}
	}
}
