// Package bitmap renders basic server output: Interleaved RLE decompression
// (MS-RDPBCGR 3.1.9), a software framebuffer that applies TS_BITMAP_DATA
// rectangles (2.2.9.1.1.3.1.2.2) from slow- or fast-path Bitmap Updates,
// and pointer (cursor) decoding from XOR/AND masks (2.2.9.1.1.4). It
// depends only on the standard library and package wire.
package bitmap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrRLE wraps every Interleaved RLE decoding failure.
var ErrRLE = errors.New("bitmap: interleaved rle")

// Order codes (3.1.9.1). Regular orders carry a 3-bit code and 5-bit run
// length, lite orders a 4-bit code and 4-bit run length, MEGA_MEGA orders a
// full byte code and a 16-bit run length; special orders have no length.
const (
	regularBGRun     = 0x0
	regularFGRun     = 0x1
	regularFGBGImage = 0x2
	regularColorRun  = 0x3
	regularColorImg  = 0x4

	liteSetFGFGRun     = 0xC
	liteSetFGFGBGImage = 0xD
	liteDitheredRun    = 0xE

	megaBGRun        = 0xF0
	megaFGRun        = 0xF1
	megaFGBGImage    = 0xF2
	megaColorRun     = 0xF3
	megaColorImg     = 0xF4
	megaSetFGFGRun   = 0xF6
	megaSetFGBGImage = 0xF7
	megaDitheredRun  = 0xF8

	specialFGBG1 = 0xF9
	specialFGBG2 = 0xFA
	specialWhite = 0xFD
	specialBlack = 0xFE
)

// PelSize returns the bytes per pixel for a TS_BITMAP_DATA bitsPerPixel, or
// 0 when the depth is not one of 8, 15, 16, 24, 32.
func PelSize(bitsPerPixel int) int {
	switch bitsPerPixel {
	case 8:
		return 1
	case 15, 16:
		return 2
	case 24:
		return 3
	case 32:
		return 4
	}
	return 0
}

// whitePel is the initial foreground colour (3.1.9.3): all colour bits set.
// 15bpp uses the 16-bit value, as the reference decoders do.
func whitePel(bitsPerPixel int) uint32 {
	switch PelSize(bitsPerPixel) {
	case 1:
		return 0xFF
	case 2:
		return 0xFFFF
	case 3:
		return 0xFFFFFF
	}
	return 0xFFFFFFFF
}

type decoder struct {
	src []byte
	pos int

	dst      []byte
	out      int
	ps       int // bytes per pixel
	rowDelta int // bytes per scanline

	fg          uint32
	firstLine   bool
	insertFGPel bool
}

func (d *decoder) fail(format string, a ...any) error {
	return fmt.Errorf("%w: at byte %d: %s", ErrRLE, d.pos, fmt.Sprintf(format, a...))
}

func (d *decoder) readPel() (uint32, error) {
	if d.pos+d.ps > len(d.src) {
		return 0, d.fail("truncated pixel")
	}
	var v uint32
	for i := d.ps - 1; i >= 0; i-- {
		v = v<<8 | uint32(d.src[d.pos+i])
	}
	d.pos += d.ps
	return v, nil
}

func (d *decoder) readByte() (byte, error) {
	if d.pos >= len(d.src) {
		return 0, d.fail("truncated stream")
	}
	b := d.src[d.pos]
	d.pos++
	return b, nil
}

func (d *decoder) writePel(v uint32) error {
	if d.out+d.ps > len(d.dst) {
		return d.fail("output overflow (%d bytes)", len(d.dst))
	}
	for i := 0; i < d.ps; i++ {
		d.dst[d.out+i] = byte(v >> (8 * i))
	}
	d.out += d.ps
	return nil
}

// above returns the pixel one scanline before the write position (the
// previous decoded row; rows are bottom-up so it is visually below).
func (d *decoder) above() uint32 {
	var v uint32
	p := d.out - d.rowDelta
	for i := d.ps - 1; i >= 0; i-- {
		v = v<<8 | uint32(d.dst[p+i])
	}
	return v
}

// prev is the pixel from the previous row, or black on the first line.
func (d *decoder) prev() uint32 {
	if d.firstLine {
		return 0
	}
	return d.above()
}

func extractCode(hdr byte) int {
	switch {
	case hdr&0xC0 != 0xC0:
		return int(hdr >> 5)
	case hdr&0xF0 == 0xF0:
		return int(hdr)
	}
	return int(hdr >> 4)
}

// runLength implements ExtractRunLength (3.1.9.3): it consumes the order
// header and any extended length bytes.
func (d *decoder) runLength(code int) (int, error) {
	hdr, err := d.readByte()
	if err != nil {
		return 0, err
	}
	ext := func(add int) (int, error) {
		b, err := d.readByte()
		if err != nil {
			return 0, err
		}
		return int(b) + add, nil
	}
	switch code {
	case regularFGBGImage:
		if n := int(hdr & 0x1F); n != 0 {
			return n * 8, nil
		}
		return ext(1)
	case liteSetFGFGBGImage:
		if n := int(hdr & 0x0F); n != 0 {
			return n * 8, nil
		}
		return ext(1)
	case regularBGRun, regularFGRun, regularColorRun, regularColorImg:
		if n := int(hdr & 0x1F); n != 0 {
			return n, nil
		}
		return ext(32)
	case liteSetFGFGRun, liteDitheredRun:
		if n := int(hdr & 0x0F); n != 0 {
			return n, nil
		}
		return ext(16)
	case megaBGRun, megaFGRun, megaFGBGImage, megaColorRun, megaColorImg,
		megaSetFGFGRun, megaSetFGBGImage, megaDitheredRun:
		if d.pos+2 > len(d.src) {
			return 0, d.fail("truncated MEGA_MEGA length")
		}
		n := int(binary.LittleEndian.Uint16(d.src[d.pos:]))
		d.pos += 2
		return n, nil
	}
	return 0, nil // special orders
}

// fgBgImage writes count pixels selected by the bits of mask (LSB first):
// a set bit is the foreground XORed with the previous row's pixel (black on
// the first line), a clear bit is the previous row's pixel itself.
func (d *decoder) fgBgImage(mask byte, count int) error {
	for i := 0; i < count; i++ {
		v := d.prev()
		if mask&(1<<i) != 0 {
			v ^= d.fg
		}
		if err := d.writePel(v); err != nil {
			return err
		}
	}
	return nil
}

// Decompress decodes an Interleaved RLE stream (the bitmapDataStream of a
// TS_BITMAP_DATA with BITMAP_COMPRESSION, after any TS_CD_HEADER) into a
// bottom-up pixel buffer of width*height pixels at bitsPerPixel. The whole
// buffer must be produced and the whole stream consumed.
func Decompress(src []byte, width, height, bitsPerPixel int) ([]byte, error) {
	ps := PelSize(bitsPerPixel)
	if ps == 0 {
		return nil, fmt.Errorf("%w: bitsPerPixel %d", ErrRLE, bitsPerPixel)
	}
	if width <= 0 || height <= 0 || width*height*ps > 64<<20 {
		return nil, fmt.Errorf("%w: bitmap %dx%d", ErrRLE, width, height)
	}
	d := &decoder{
		src: src, dst: make([]byte, width*height*ps),
		ps: ps, rowDelta: width * ps,
		fg: whitePel(bitsPerPixel), firstLine: true,
	}
	for d.pos < len(d.src) {
		if d.firstLine && d.out >= d.rowDelta {
			d.firstLine = false
			d.insertFGPel = false
		}
		code := extractCode(d.src[d.pos])
		n, err := d.runLength(code)
		if err != nil {
			return nil, err
		}
		switch code {
		case regularBGRun, megaBGRun:
			if d.insertFGPel && n > 0 {
				if err := d.writePel(d.prev() ^ d.fg); err != nil {
					return nil, err
				}
				n--
			}
			for ; n > 0; n-- {
				if err := d.writePel(d.prev()); err != nil {
					return nil, err
				}
			}
			d.insertFGPel = true
			continue

		case regularFGRun, megaFGRun, liteSetFGFGRun, megaSetFGFGRun:
			if code == liteSetFGFGRun || code == megaSetFGFGRun {
				if d.fg, err = d.readPel(); err != nil {
					return nil, err
				}
			}
			for ; n > 0; n-- {
				if err := d.writePel(d.prev() ^ d.fg); err != nil {
					return nil, err
				}
			}

		case liteDitheredRun, megaDitheredRun:
			a, err := d.readPel()
			if err != nil {
				return nil, err
			}
			b, err := d.readPel()
			if err != nil {
				return nil, err
			}
			for ; n > 0; n-- {
				if err := d.writePel(a); err != nil {
					return nil, err
				}
				if err := d.writePel(b); err != nil {
					return nil, err
				}
			}

		case regularColorRun, megaColorRun:
			v, err := d.readPel()
			if err != nil {
				return nil, err
			}
			for ; n > 0; n-- {
				if err := d.writePel(v); err != nil {
					return nil, err
				}
			}

		case regularFGBGImage, megaFGBGImage, liteSetFGFGBGImage, megaSetFGBGImage:
			if code == liteSetFGFGBGImage || code == megaSetFGBGImage {
				if d.fg, err = d.readPel(); err != nil {
					return nil, err
				}
			}
			for ; n > 8; n -= 8 {
				mask, err := d.readByte()
				if err != nil {
					return nil, err
				}
				if err := d.fgBgImage(mask, 8); err != nil {
					return nil, err
				}
			}
			if n > 0 {
				mask, err := d.readByte()
				if err != nil {
					return nil, err
				}
				if err := d.fgBgImage(mask, n); err != nil {
					return nil, err
				}
			}

		case regularColorImg, megaColorImg:
			for ; n > 0; n-- {
				v, err := d.readPel()
				if err != nil {
					return nil, err
				}
				if err := d.writePel(v); err != nil {
					return nil, err
				}
			}

		case specialFGBG1:
			if err := d.fgBgImage(0x03, 8); err != nil {
				return nil, err
			}
		case specialFGBG2:
			if err := d.fgBgImage(0x05, 8); err != nil {
				return nil, err
			}
		case specialWhite:
			if err := d.writePel(whitePel(bitsPerPixel)); err != nil {
				return nil, err
			}
		case specialBlack:
			if err := d.writePel(0); err != nil {
				return nil, err
			}
		default:
			d.pos--
			return nil, d.fail("unknown order 0x%02x", d.src[d.pos])
		}
		d.insertFGPel = false
	}
	if d.out != len(d.dst) {
		return nil, d.fail("decoded %d of %d bytes", d.out, len(d.dst))
	}
	return d.dst, nil
}
