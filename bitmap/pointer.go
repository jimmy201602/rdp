package bitmap

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"

	"rdp.local/kernel/wire"
)

// ErrPointer wraps cursor decoding failures.
var ErrPointer = errors.New("bitmap: pointer")

// Cursor is a decoded colour pointer: an RGBA image with its hotspot.
type Cursor struct {
	Image      *image.RGBA
	HotX, HotY int
	XorBpp     int
	CacheIndex int
}

// DecodeCursor renders the XOR and AND masks of a Color, New or Large
// pointer (2.2.9.1.1.4.4–2.2.9.1.1.4.5, 2.2.9.1.2.1.11) into RGBA. Masks are
// bottom-up; scan-line strides are taken from the mask lengths. AND bit 1
// with a black XOR pixel is transparent; AND bit 1 with any other XOR pixel
// (screen inversion) is approximated as opaque black. A 32bpp XOR mask with
// any non-zero alpha uses that alpha instead of the AND mask. 8bpp XOR
// pixels are looked up in palette (nil means black).
func DecodeCursor(p wire.Pointer, palette *[256]color.RGBA) (*Cursor, error) {
	w, h, bpp := int(p.Width), int(p.Height), int(p.XorBpp)
	if w == 0 || h == 0 || w > 384 || h > 384 {
		return nil, fmt.Errorf("%w: size %dx%d", ErrPointer, w, h)
	}
	ps := PelSize(bpp)
	if bpp != 1 && ps == 0 {
		return nil, fmt.Errorf("%w: xorBpp %d", ErrPointer, bpp)
	}
	xorStride, andStride := len(p.XorMask)/h, len(p.AndMask)/h
	if xorStride*h != len(p.XorMask) || xorStride*8 < w*bpp {
		return nil, fmt.Errorf("%w: xor mask %d bytes for %dx%dx%d", ErrPointer, len(p.XorMask), w, h, bpp)
	}
	if len(p.AndMask) != 0 && (andStride*h != len(p.AndMask) || andStride*8 < w) {
		return nil, fmt.Errorf("%w: and mask %d bytes for %dx%d", ErrPointer, len(p.AndMask), w, h)
	}
	useAlpha := false
	if bpp == 32 {
		for i := 3; i < len(p.XorMask); i += 4 {
			if p.XorMask[i] != 0 {
				useAlpha = true
				break
			}
		}
	}
	c := &Cursor{Image: image.NewRGBA(image.Rect(0, 0, w, h)), HotX: int(p.HotSpotX), HotY: int(p.HotSpotY), XorBpp: bpp, CacheIndex: int(p.CacheIndex)}
	for y := 0; y < h; y++ {
		xorRow := p.XorMask[(h-1-y)*xorStride:]
		var andRow []byte
		if len(p.AndMask) != 0 {
			andRow = p.AndMask[(h-1-y)*andStride:]
		}
		for x := 0; x < w; x++ {
			var px color.RGBA
			switch bpp {
			case 1:
				if xorRow[x/8]&(0x80>>(x%8)) != 0 {
					px = color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
				} else {
					px = color.RGBA{0, 0, 0, 0xFF}
				}
			case 32:
				px = pelRGBA(xorRow[x*4:], 32, palette)
				if useAlpha {
					px.A = xorRow[x*4+3]
					px = color.RGBA{premul(px.R, px.A), premul(px.G, px.A), premul(px.B, px.A), px.A}
				}
			default:
				px = pelRGBA(xorRow[x*ps:], bpp, palette)
			}
			if !useAlpha && andRow != nil && andRow[x/8]&(0x80>>(x%8)) != 0 {
				if px.R == 0 && px.G == 0 && px.B == 0 {
					px = color.RGBA{}
				} else {
					px = color.RGBA{0, 0, 0, 0xFF}
				}
			}
			c.Image.SetRGBA(x, y, px)
		}
	}
	return c, nil
}

func premul(v, a uint8) uint8 { return uint8(uint32(v) * uint32(a) / 0xFF) }

// Hash is the SHA-256 (hex) of the cursor's RGBA pixels.
func (c *Cursor) Hash() string {
	sum := sha256.Sum256(c.Image.Pix)
	return hex.EncodeToString(sum[:])
}

// CursorInfo describes a cursor in reports.
type CursorInfo struct {
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	HotX       int    `json:"hot_x"`
	HotY       int    `json:"hot_y"`
	XorBpp     int    `json:"xor_bpp"`
	CacheIndex int    `json:"cache_index"`
	Hash       string `json:"sha256"`
}

func (c *Cursor) info() *CursorInfo {
	return &CursorInfo{Width: c.Image.Rect.Dx(), Height: c.Image.Rect.Dy(), HotX: c.HotX, HotY: c.HotY, XorBpp: c.XorBpp, CacheIndex: c.CacheIndex, Hash: c.Hash()}
}

// PointerStats summarises pointer updates applied to a PointerState.
type PointerStats struct {
	Decoded     int    `json:"decoded"` // Color/New/Large cursors rendered
	CacheHits   int    `json:"cache_hits"`
	CacheMisses int    `json:"cache_misses,omitempty"`
	Errors      int    `json:"errors,omitempty"`
	FirstError  string `json:"first_error,omitempty"`

	Visible bool   `json:"visible"`
	System  string `json:"system,omitempty"` // last system pointer: "null", "default" or hex
	// X, Y is the last Pointer Position, nil when none was received.
	X       *int        `json:"x,omitempty"`
	Y       *int        `json:"y,omitempty"`
	Current *CursorInfo `json:"current,omitempty"`
}

// PointerState tracks the server's pointer: cache, current shape, position
// and visibility.
type PointerState struct {
	cache   []*Cursor
	current *Cursor
	stats   PointerStats
}

// NewPointerState returns a state with a cache of cacheSize slots (the
// colorPointerCacheSize advertised in the Pointer Capability Set).
func NewPointerState(cacheSize int) *PointerState {
	return &PointerState{cache: make([]*Cursor, cacheSize), stats: PointerStats{Visible: true}}
}

// Current returns the current cursor shape, nil when none or hidden.
func (s *PointerState) Current() *Cursor {
	if !s.stats.Visible {
		return nil
	}
	return s.current
}

// Position returns the last Pointer Position, ok false when none was received.
func (s *PointerState) Position() (x, y int, ok bool) {
	if s.stats.X == nil {
		return 0, 0, false
	}
	return *s.stats.X, *s.stats.Y, true
}

// Summary returns the statistics.
func (s *PointerState) Summary() PointerStats {
	st := s.stats
	if st.X != nil {
		x, y := *st.X, *st.Y
		st.X, st.Y = &x, &y
	}
	if s.current != nil {
		st.Current = s.current.info()
	}
	return st
}

func (s *PointerState) reject(err error) error {
	s.stats.Errors++
	if s.stats.FirstError == "" {
		s.stats.FirstError = err.Error()
	}
	return err
}

// Apply handles one pointer update. palette resolves 8bpp cursors.
func (s *PointerState) Apply(p wire.Pointer, palette *[256]color.RGBA) error {
	switch p.Type {
	case wire.PointerTypeSystem:
		switch p.SystemType {
		case wire.SystemPointerNull:
			s.stats.System, s.stats.Visible = "null", false
		case wire.SystemPointerDefault:
			s.stats.System, s.stats.Visible = "default", true
			s.current = nil
		default:
			s.stats.System = fmt.Sprintf("0x%08x", p.SystemType)
		}
	case wire.PointerTypePosition:
		x, y := int(p.X), int(p.Y)
		s.stats.X, s.stats.Y = &x, &y
	case wire.PointerTypeCached:
		idx := int(p.CacheIndex)
		if idx >= len(s.cache) || s.cache[idx] == nil {
			s.stats.CacheMisses++
			return s.reject(fmt.Errorf("%w: cached pointer %d not in cache of %d", ErrPointer, idx, len(s.cache)))
		}
		s.stats.CacheHits++
		s.current, s.stats.Visible = s.cache[idx], true
	case wire.PointerTypeColor, wire.PointerTypeNew, wire.PointerTypeLarge:
		c, err := DecodeCursor(p, palette)
		if err != nil {
			return s.reject(err)
		}
		s.stats.Decoded++
		if idx := int(p.CacheIndex); idx < len(s.cache) {
			s.cache[idx] = c
		}
		s.current, s.stats.Visible = c, true
	default:
		return s.reject(fmt.Errorf("%w: messageType 0x%04x", ErrPointer, p.Type))
	}
	return nil
}

// Composite returns a copy of the framebuffer with the cursor drawn so that
// its hotspot lands on (x, y).
func (f *Framebuffer) Composite(c *Cursor, x, y int) *image.RGBA {
	out := image.NewRGBA(f.img.Rect)
	copy(out.Pix, f.img.Pix)
	if c == nil {
		return out
	}
	r := c.Image.Rect.Add(image.Pt(x-c.HotX, y-c.HotY))
	draw.Draw(out, r, c.Image, image.Point{}, draw.Over)
	return out
}
