package wire

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Server output after Connection Finalization: Save Session Info (2.2.10.1),
// Slow-Path Graphics Update (2.2.9.1.1.3) and Slow-Path Pointer Update
// (2.2.9.1.1.4); fast-path framing is in fastpath.go. Bitmap and pointer
// data are described, not decoded: RLE decompression and cursor rendering
// live in package bitmap, bulk compression is never negotiated.

// Save Session Info infoType values (2.2.10.1.1).
const (
	InfoTypeLogon         uint32 = 0x00000000
	InfoTypeLogonLong     uint32 = 0x00000001
	InfoTypeLogonPlain    uint32 = 0x00000002
	InfoTypeLogonExtended uint32 = 0x00000003

	logonExAutoReconnectCookie uint32 = 0x00000001
	logonExLogonErrors         uint32 = 0x00000002
)

// SaveSessionInfo is TS_SAVE_SESSION_INFO_PDU_DATA. UserName/Domain come
// from the server's logon notification; the auto-reconnect cookie is only
// kept in AutoReconnect for a client that wants to rejoin the session.
type SaveSessionInfo struct {
	InfoType  uint32 `json:"info_type"`
	SessionID uint32 `json:"session_id"`
	Domain    string `json:"domain"`
	UserName  string `json:"user_name"`

	HasAutoReconnectCookie bool       `json:"has_auto_reconnect_cookie"`
	AutoReconnect          *ARCCookie `json:"-"`
	HasLogonErrors         bool       `json:"has_logon_errors"`
	ErrorNotificationType  uint32     `json:"error_notification_type"`
	ErrorNotificationData  uint32     `json:"error_notification_data"`
}

func utf16zString(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// DecodeSaveSessionInfo parses the body of a Save Session Info Data PDU.
func DecodeSaveSessionInfo(body []byte) (SaveSessionInfo, error) {
	var s SaveSessionInfo
	if len(body) < 4 {
		return s, fmt.Errorf("%w: save session info body %d bytes", ErrShare, len(body))
	}
	s.InfoType = binary.LittleEndian.Uint32(body)
	rest := body[4:]
	switch s.InfoType {
	case InfoTypeLogon: // TS_LOGON_INFO: 4+52+4+512+4
		if len(rest) < 576 {
			return s, fmt.Errorf("%w: logon info %d bytes", ErrShare, len(rest))
		}
		cbDomain, cbUser := binary.LittleEndian.Uint32(rest), binary.LittleEndian.Uint32(rest[56:])
		if cbDomain > 52 || cbUser > 512 {
			return s, fmt.Errorf("%w: logon info cbDomain %d cbUserName %d", ErrShare, cbDomain, cbUser)
		}
		s.Domain = utf16zString(rest[4:56], int(cbDomain))
		s.UserName = utf16zString(rest[60:572], int(cbUser))
		s.SessionID = binary.LittleEndian.Uint32(rest[572:])
	case InfoTypeLogonLong: // TS_LOGON_INFO_VERSION_2
		if len(rest) < 576 {
			return s, fmt.Errorf("%w: logon info v2 %d bytes", ErrShare, len(rest))
		}
		if v := binary.LittleEndian.Uint16(rest); v != 1 {
			return s, fmt.Errorf("%w: logon info v2 version %d", ErrShare, v)
		}
		s.SessionID = binary.LittleEndian.Uint32(rest[6:])
		cbDomain, cbUser := binary.LittleEndian.Uint32(rest[10:]), binary.LittleEndian.Uint32(rest[14:])
		strs := rest[576:]
		if cbDomain > 52 || cbUser > 512 || uint64(cbDomain)+uint64(cbUser) > uint64(len(strs)) {
			return s, fmt.Errorf("%w: logon info v2 cbDomain %d cbUserName %d (%d bytes)", ErrShare, cbDomain, cbUser, len(strs))
		}
		s.Domain = utf16zString(strs[:cbDomain], int(cbDomain))
		s.UserName = utf16zString(strs[cbDomain:cbDomain+cbUser], int(cbUser))
	case InfoTypeLogonPlain: // TS_PLAIN_NOTIFY: 576 pad bytes
		if len(rest) < 576 {
			return s, fmt.Errorf("%w: plain notify %d bytes", ErrShare, len(rest))
		}
	case InfoTypeLogonExtended: // TS_LOGON_INFO_EXTENDED
		if len(rest) < 6 {
			return s, fmt.Errorf("%w: logon info extended %d bytes", ErrShare, len(rest))
		}
		fields := binary.LittleEndian.Uint32(rest[2:])
		p := rest[6:]
		for _, f := range []uint32{logonExAutoReconnectCookie, logonExLogonErrors} {
			if fields&f == 0 {
				continue
			}
			if len(p) < 4 {
				return s, fmt.Errorf("%w: logon info extended field truncated", ErrShare)
			}
			n := binary.LittleEndian.Uint32(p)
			p = p[4:]
			if uint64(n) > uint64(len(p)) {
				return s, fmt.Errorf("%w: logon info extended field %d bytes, %d available", ErrShare, n, len(p))
			}
			switch f {
			case logonExAutoReconnectCookie:
				s.HasAutoReconnectCookie = true
				if c, err := decodeARCCookie(p[:n]); err == nil {
					s.AutoReconnect = c
				}
			case logonExLogonErrors:
				if n < 8 {
					return s, fmt.Errorf("%w: logon errors info %d bytes", ErrShare, n)
				}
				s.HasLogonErrors = true
				s.ErrorNotificationType = binary.LittleEndian.Uint32(p)
				s.ErrorNotificationData = binary.LittleEndian.Uint32(p[4:])
			}
			p = p[n:]
		}
	default:
		return s, fmt.Errorf("%w: save session info infoType 0x%08x", ErrShare, s.InfoType)
	}
	return s, nil
}

// Slow-path updateType values (2.2.9.1.1.3.1).
const (
	UpdateTypeOrders      uint16 = 0x0000
	UpdateTypeBitmap      uint16 = 0x0001
	UpdateTypePalette     uint16 = 0x0002
	UpdateTypeSynchronize uint16 = 0x0003

	BitmapCompression        uint16 = 0x0001
	BitmapNoCompressionHdr   uint16 = 0x0400
	bitmapCompressionHdrSize        = 8
)

// BitmapData is TS_BITMAP_DATA (2.2.9.1.1.3.1.2.2) without the pixel data.
type BitmapData struct {
	DestLeft, DestTop, DestRight, DestBottom uint16
	Width, Height, BitsPerPixel, Flags       uint16
	Compressed                               bool
	DataLength                               int // bitmap bytes (after any compression header)
	data                                     []byte
}

// Data returns the raw bitmap bytes (RLE-compressed when Compressed).
func (b BitmapData) Data() []byte { return b.data }

// Update is a decoded Slow-Path Graphics Update PDU body.
type Update struct {
	Type         uint16
	NumOrders    uint16       // UpdateTypeOrders; the order stream is not parsed
	Bitmaps      []BitmapData // UpdateTypeBitmap
	PaletteSize  uint32       // UpdateTypePalette
	Palette      [][3]uint8   // UpdateTypePalette entries as red, green, blue
	OrdersStream []byte
}

// DecodeUpdate parses the body of an Update Data PDU (pduType2 Update).
func DecodeUpdate(body []byte) (Update, error) {
	var u Update
	if len(body) < 2 {
		return u, fmt.Errorf("%w: update body %d bytes", ErrShare, len(body))
	}
	u.Type = binary.LittleEndian.Uint16(body)
	rest := body[2:]
	switch u.Type {
	case UpdateTypeOrders: // pad2, numberOrders, pad2, orders
		if len(rest) < 6 {
			return u, fmt.Errorf("%w: orders update header", ErrShare)
		}
		u.NumOrders = binary.LittleEndian.Uint16(rest[2:])
		u.OrdersStream = rest[6:]
	case UpdateTypeBitmap:
		if len(rest) < 2 {
			return u, fmt.Errorf("%w: bitmap update header", ErrShare)
		}
		n := int(binary.LittleEndian.Uint16(rest))
		rest = rest[2:]
		for i := 0; i < n; i++ {
			if len(rest) < 18 {
				return u, fmt.Errorf("%w: bitmap data %d/%d truncated", ErrShare, i, n)
			}
			var b BitmapData
			for j, f := range []*uint16{&b.DestLeft, &b.DestTop, &b.DestRight, &b.DestBottom, &b.Width, &b.Height, &b.BitsPerPixel, &b.Flags} {
				*f = binary.LittleEndian.Uint16(rest[2*j:])
			}
			length := int(binary.LittleEndian.Uint16(rest[16:]))
			rest = rest[18:]
			if length > len(rest) {
				return u, fmt.Errorf("%w: bitmap data %d/%d: %d bytes declared, %d available", ErrShare, i, n, length, len(rest))
			}
			data := rest[:length]
			rest = rest[length:]
			b.Compressed = b.Flags&BitmapCompression != 0
			if b.Compressed && b.Flags&BitmapNoCompressionHdr == 0 {
				if len(data) < bitmapCompressionHdrSize {
					return u, fmt.Errorf("%w: bitmap data %d/%d lacks compression header", ErrShare, i, n)
				}
				if mainBody := int(binary.LittleEndian.Uint16(data[2:])); mainBody != len(data)-bitmapCompressionHdrSize {
					return u, fmt.Errorf("%w: bitmap data %d/%d cbCompMainBodySize %d vs %d", ErrShare, i, n, mainBody, len(data)-bitmapCompressionHdrSize)
				}
				data = data[bitmapCompressionHdrSize:]
			}
			switch b.BitsPerPixel {
			case 8, 15, 16, 24, 32:
			default:
				return u, fmt.Errorf("%w: bitmap data %d/%d bitsPerPixel %d", ErrShare, i, n, b.BitsPerPixel)
			}
			if !b.Compressed {
				bpp := (int(b.BitsPerPixel) + 7) / 8
				if want := int(b.Width) * int(b.Height) * bpp; want != len(data) {
					return u, fmt.Errorf("%w: bitmap data %d/%d uncompressed %dx%dx%d = %d bytes, got %d", ErrShare, i, n, b.Width, b.Height, bpp, want, len(data))
				}
			}
			b.DataLength = len(data)
			b.data = data
			u.Bitmaps = append(u.Bitmaps, b)
		}
		if len(rest) != 0 {
			return u, fmt.Errorf("%w: %d trailing bytes after bitmap update", ErrShare, len(rest))
		}
	case UpdateTypePalette: // pad2, numberColors, entries
		if len(rest) < 6 {
			return u, fmt.Errorf("%w: palette update header", ErrShare)
		}
		u.PaletteSize = binary.LittleEndian.Uint32(rest[2:])
		if u.PaletteSize > 256 || len(rest[6:]) < int(u.PaletteSize)*3 {
			return u, fmt.Errorf("%w: palette with %d colors in %d bytes", ErrShare, u.PaletteSize, len(rest)-6)
		}
		u.Palette = make([][3]uint8, u.PaletteSize)
		for i := range u.Palette {
			copy(u.Palette[i][:], rest[6+3*i:])
		}
	case UpdateTypeSynchronize:
	default:
		return u, fmt.Errorf("%w: updateType 0x%04x", ErrShare, u.Type)
	}
	return u, nil
}

// Slow-path pointer messageType values (2.2.9.1.1.4).
const (
	PointerTypeSystem   uint16 = 0x0001
	PointerTypePosition uint16 = 0x0003
	PointerTypeColor    uint16 = 0x0006
	PointerTypeCached   uint16 = 0x0007
	PointerTypeNew      uint16 = 0x0008
	PointerTypeLarge    uint16 = 0x0009
)

// System pointer types (2.2.9.1.1.4.3).
const (
	SystemPointerNull    uint32 = 0x00000000
	SystemPointerDefault uint32 = 0x00007F00
)

// Pointer is a decoded Slow-Path Pointer Update PDU body (or a fast-path
// pointer update, see DecodeFastPathPointer).
type Pointer struct {
	Type       uint16
	SystemType uint32 // PointerTypeSystem
	X, Y       uint16 // PointerTypePosition
	CacheIndex uint16 // Color, Cached, New, Large
	Width      uint16 // Color, New, Large
	Height     uint16
	XorBpp     uint16 // 24 for Color; New, Large carry it
	HotSpotX   uint16
	HotSpotY   uint16
	// XorMask and AndMask are the raw bottom-up mask bitmaps (Color, New,
	// Large): XorMask at XorBpp bits per pixel, AndMask 1 bit per pixel,
	// each scan-line padded as sent (see bitmap.DecodeCursor).
	XorMask []byte
	AndMask []byte
}

// DecodePointer parses the body of a Pointer Data PDU (pduType2 Pointer).
// Pointer bitmaps are length-checked and kept as raw masks, not interpreted.
func DecodePointer(body []byte) (Pointer, error) {
	if len(body) < 4 {
		return Pointer{}, fmt.Errorf("%w: pointer body %d bytes", ErrShare, len(body))
	}
	return decodePointer(binary.LittleEndian.Uint16(body), body[4:])
}

func decodePointer(typ uint16, rest []byte) (Pointer, error) {
	p := Pointer{Type: typ}
	need := func(n int) error {
		if len(rest) < n {
			return fmt.Errorf("%w: pointer type 0x%04x body %d bytes", ErrShare, p.Type, len(rest))
		}
		return nil
	}
	colorAttr := func(off int, large bool) error {
		// cacheIndex, hotSpot(4), width, height, lengthAndMask, lengthXorMask, masks
		hdr, maskLen := 14, 2
		if large {
			hdr, maskLen = 18, 4
		}
		if err := need(off + hdr); err != nil {
			return err
		}
		p.CacheIndex = binary.LittleEndian.Uint16(rest[off:])
		p.HotSpotX = binary.LittleEndian.Uint16(rest[off+2:])
		p.HotSpotY = binary.LittleEndian.Uint16(rest[off+4:])
		p.Width = binary.LittleEndian.Uint16(rest[off+6:])
		p.Height = binary.LittleEndian.Uint16(rest[off+8:])
		var andLen, xorLen int
		if large {
			andLen = int(binary.LittleEndian.Uint32(rest[off+10:]))
			xorLen = int(binary.LittleEndian.Uint32(rest[off+14:]))
		} else {
			andLen = int(binary.LittleEndian.Uint16(rest[off+10:]))
			xorLen = int(binary.LittleEndian.Uint16(rest[off+12:]))
		}
		_ = maskLen
		if total := off + hdr + xorLen + andLen; len(rest) < total || len(rest) > total+1 {
			return fmt.Errorf("%w: pointer masks %d+%d bytes in %d", ErrShare, xorLen, andLen, len(rest)-off-hdr)
		}
		p.XorMask = rest[off+hdr : off+hdr+xorLen]
		p.AndMask = rest[off+hdr+xorLen : off+hdr+xorLen+andLen]
		return nil
	}
	switch p.Type {
	case PointerTypeSystem:
		if err := need(4); err != nil {
			return p, err
		}
		p.SystemType = binary.LittleEndian.Uint32(rest)
	case PointerTypePosition:
		if err := need(4); err != nil {
			return p, err
		}
		p.X, p.Y = binary.LittleEndian.Uint16(rest), binary.LittleEndian.Uint16(rest[2:])
	case PointerTypeCached:
		if err := need(2); err != nil {
			return p, err
		}
		p.CacheIndex = binary.LittleEndian.Uint16(rest)
	case PointerTypeColor:
		p.XorBpp = 24
		return p, colorAttr(0, false)
	case PointerTypeNew, PointerTypeLarge:
		if err := need(2); err != nil {
			return p, err
		}
		p.XorBpp = binary.LittleEndian.Uint16(rest)
		return p, colorAttr(2, p.Type == PointerTypeLarge)
	default:
		return p, fmt.Errorf("%w: pointer messageType 0x%04x", ErrShare, p.Type)
	}
	return p, nil
}

// --- Server side -----------------------------------------------------------

// NewBitmapData describes an uncompressed (or, with compressed set,
// RLE-compressed, no compression header) bitmap rectangle for
// EncodeBitmapUpdate. data must hold width*height*bytesPerPixel bytes when
// not compressed; rows are bottom-up as in TS_BITMAP_DATA.
func NewBitmapData(left, top, width, height, bpp uint16, compressed bool, data []byte) (BitmapData, error) {
	switch bpp {
	case 8, 15, 16, 24, 32:
	default:
		return BitmapData{}, fmt.Errorf("%w: bitsPerPixel %d", ErrShare, bpp)
	}
	if width == 0 || height == 0 {
		return BitmapData{}, fmt.Errorf("%w: empty bitmap", ErrShare)
	}
	if !compressed {
		if want := int(width) * int(height) * ((int(bpp) + 7) / 8); want != len(data) {
			return BitmapData{}, fmt.Errorf("%w: %dx%dx%d needs %d bytes, got %d", ErrShare, width, height, bpp, want, len(data))
		}
	}
	b := BitmapData{
		DestLeft: left, DestTop: top, DestRight: left + width - 1, DestBottom: top + height - 1,
		Width: width, Height: height, BitsPerPixel: bpp, Compressed: compressed,
		DataLength: len(data), data: data,
	}
	if compressed {
		b.Flags = BitmapCompression | BitmapNoCompressionHdr
	}
	return b, nil
}

// EncodeBitmapUpdate builds the body of a slow-path Update Data PDU
// (TS_UPDATE_BITMAP_DATA, 2.2.9.1.1.3.1.2) for the given rectangles.
func EncodeBitmapUpdate(rects []BitmapData) ([]byte, error) {
	if len(rects) == 0 || len(rects) > 0xffff {
		return nil, fmt.Errorf("%w: %d bitmap rectangles", ErrShare, len(rects))
	}
	out := binary.LittleEndian.AppendUint16(nil, UpdateTypeBitmap)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(rects)))
	for _, b := range rects {
		if len(b.data) > 0xffff {
			return nil, fmt.Errorf("%w: bitmap data %d bytes too large", ErrShare, len(b.data))
		}
		for _, v := range []uint16{b.DestLeft, b.DestTop, b.DestRight, b.DestBottom, b.Width, b.Height, b.BitsPerPixel, b.Flags} {
			out = binary.LittleEndian.AppendUint16(out, v)
		}
		out = binary.LittleEndian.AppendUint16(out, uint16(len(b.data)))
		out = append(out, b.data...)
	}
	return out, nil
}

// EncodeUpdatePDU wraps an update body in a Share Data PDU (pduType2 Update)
// from the server channel.
func EncodeUpdatePDU(shareID uint32, body []byte) ([]byte, error) {
	return EncodeShareData(shareID, ServerChannelID, PDUType2Update, body)
}

// EncodePointer builds the body of a slow-path Pointer Update PDU
// (TS_POINTER_PDU, 2.2.9.1.1.4) from a Pointer; System, Position, Cached,
// Color and New pointers are supported (Large needs the large pointer
// capability and is refused).
func EncodePointer(p Pointer) ([]byte, error) {
	out := binary.LittleEndian.AppendUint16(nil, p.Type)
	out = binary.LittleEndian.AppendUint16(out, 0) // pad2Octets
	switch p.Type {
	case PointerTypeSystem:
		return binary.LittleEndian.AppendUint32(out, p.SystemType), nil
	case PointerTypePosition:
		out = binary.LittleEndian.AppendUint16(out, p.X)
		return binary.LittleEndian.AppendUint16(out, p.Y), nil
	case PointerTypeCached:
		return binary.LittleEndian.AppendUint16(out, p.CacheIndex), nil
	case PointerTypeColor, PointerTypeNew:
		if p.Type == PointerTypeNew {
			out = binary.LittleEndian.AppendUint16(out, p.XorBpp)
		} else if p.XorBpp != 24 {
			return nil, fmt.Errorf("%w: color pointer must be 24bpp", ErrShare)
		}
		if p.Width == 0 || p.Height == 0 || p.Width > 96 || p.Height > 96 || len(p.XorMask) > 0xffff || len(p.AndMask) > 0xffff {
			return nil, fmt.Errorf("%w: pointer %dx%d masks %d/%d", ErrShare, p.Width, p.Height, len(p.XorMask), len(p.AndMask))
		}
		out = binary.LittleEndian.AppendUint16(out, p.CacheIndex)
		out = binary.LittleEndian.AppendUint16(out, p.HotSpotX)
		out = binary.LittleEndian.AppendUint16(out, p.HotSpotY)
		out = binary.LittleEndian.AppendUint16(out, p.Width)
		out = binary.LittleEndian.AppendUint16(out, p.Height)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(p.AndMask)))
		out = binary.LittleEndian.AppendUint16(out, uint16(len(p.XorMask)))
		out = append(out, p.XorMask...)
		out = append(out, p.AndMask...)
		return append(out, 0), nil // pad
	}
	return nil, fmt.Errorf("%w: pointer messageType 0x%04x cannot be encoded", ErrShare, p.Type)
}

// EncodePointerPDU wraps a pointer body in a Share Data PDU (pduType2 Pointer).
func EncodePointerPDU(shareID uint32, body []byte) ([]byte, error) {
	return EncodeShareData(shareID, ServerChannelID, PDUType2Pointer, body)
}
