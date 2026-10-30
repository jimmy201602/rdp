package bitmap

import (
	"errors"
	"fmt"
)

// ErrPlanar reports a malformed RDP 6.0 planar bitmap.
var ErrPlanar = errors.New("bitmap: planar")

// RDP 6.0 bitmap compression format header (MS-RDPEGDI 2.2.2.5.1).
const (
	planarCLLMask = 0x07 // color loss level
	planarCS      = 0x08 // chroma subsampling
	planarRLE     = 0x10
	planarNA      = 0x20 // no alpha plane
)

// DecompressPlanar decodes an RDP 6.0 planar bitmap (the codec Windows uses
// for compressed 32bpp bitmaps) into 32bpp BGRA pels, scanlines in stream
// order like Decompress.
func DecompressPlanar(src []byte, width, height int) ([]byte, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("%w: empty stream", ErrPlanar)
	}
	hdr := src[0]
	if hdr&0xC0 != 0 {
		return nil, fmt.Errorf("%w: reserved header bits in %#02x", ErrPlanar, hdr)
	}
	cll := int(hdr & planarCLLMask)
	cs := hdr&planarCS != 0
	if cs && cll == 0 {
		return nil, fmt.Errorf("%w: chroma subsampling without color loss", ErrPlanar)
	}
	cw, ch := width, height
	if cs {
		cw, ch = (width+1)/2, (height+1)/2
	}
	type dim struct{ w, h int }
	dims := []dim{{width, height}, {width, height}, {cw, ch}, {cw, ch}} // A, Y/R, Co/G, Cg/B
	alpha := hdr&planarNA == 0
	if !alpha {
		dims = dims[1:]
	}
	planes := make([][]byte, 0, 4)
	if !alpha {
		planes = append(planes, nil)
	}
	p := src[1:]
	for i, d := range dims {
		var plane []byte
		if hdr&planarRLE != 0 {
			var err error
			if plane, p, err = planarRLEPlane(p, d.w, d.h); err != nil {
				return nil, fmt.Errorf("%w: plane %d: %w", ErrPlanar, i, err)
			}
		} else {
			n := d.w * d.h
			if len(p) < n {
				return nil, fmt.Errorf("%w: raw plane %d needs %d bytes, got %d", ErrPlanar, i, n, len(p))
			}
			plane, p = p[:n], p[n:]
		}
		planes = append(planes, plane)
	}

	out := make([]byte, width*height*4)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			i := y*width + x
			a := byte(0xFF)
			if alpha {
				a = planes[0][i]
			}
			var r, g, b byte
			if cll == 0 {
				r, g, b = planes[1][i], planes[2][i], planes[3][i]
			} else {
				ci := i
				if cs {
					ci = (y/2)*cw + x/2
				}
				// Co and Cg are stored right-shifted by the color loss level;
				// shifting back by one less yields half their value. Windows
				// computes Co as B - R (verified against Server 2016).
				luma := int(planes[1][i])
				co := int(int8(planes[2][ci] << (cll - 1)))
				cg := int(int8(planes[3][ci] << (cll - 1)))
				t := luma - cg
				r, g, b = clamp8(t-co), clamp8(luma+cg), clamp8(t+co)
			}
			o := i * 4
			out[o], out[o+1], out[o+2], out[o+3] = b, g, r, a
		}
	}
	return out, nil
}

// planarRLEPlane decodes one RLE color plane (MS-RDPEGDI 2.2.2.5.1.1): the
// first scanline holds absolute values, later ones deltas to the scanline
// before. It returns the plane and the rest of src.
func planarRLEPlane(src []byte, w, h int) ([]byte, []byte, error) {
	out := make([]byte, w*h)
	pos := 0
	for y := 0; y < h; y++ {
		row := out[y*w : (y+1)*w]
		var above []byte
		if y > 0 {
			above = out[(y-1)*w : y*w]
		}
		last := 0
		put := func(x int) {
			if above == nil {
				row[x] = byte(last)
			} else {
				row[x] = byte(int(above[x]) + last)
			}
		}
		for x := 0; x < w; {
			if pos >= len(src) {
				return nil, nil, fmt.Errorf("scanline %d: truncated stream", y)
			}
			ctl := src[pos]
			pos++
			run, raw := int(ctl&0x0F), int(ctl>>4)
			switch run {
			case 1:
				run, raw = raw+16, 0
			case 2:
				run, raw = raw+32, 0
			}
			if x+raw+run > w {
				return nil, nil, fmt.Errorf("scanline %d: segment of %d+%d at %d exceeds width %d", y, raw, run, x, w)
			}
			if pos+raw > len(src) {
				return nil, nil, fmt.Errorf("scanline %d: truncated raw values", y)
			}
			for k := 0; k < raw; k++ {
				v := src[pos]
				pos++
				if above == nil {
					last = int(v)
				} else if v&1 != 0 {
					last = -(int(v>>1) + 1)
				} else {
					last = int(v >> 1)
				}
				put(x)
				x++
			}
			for k := 0; k < run; k++ {
				put(x)
				x++
			}
		}
	}
	return out, src[pos:], nil
}

func clamp8(v int) byte {
	return byte(min(max(v, 0), 255))
}

// decompress decodes compressed TS_BITMAP_DATA: 32bpp bitmaps use the planar
// codec, with interleaved RLE as a fallback.
func decompress(src []byte, width, height, bitsPerPixel int) ([]byte, error) {
	if bitsPerPixel == 32 {
		out, err := DecompressPlanar(src, width, height)
		if err == nil {
			return out, nil
		}
		if out, rerr := Decompress(src, width, height, bitsPerPixel); rerr == nil {
			return out, nil
		}
		return nil, err
	}
	return Decompress(src, width, height, bitsPerPixel)
}
