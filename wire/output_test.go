package wire

import (
	"encoding/binary"
	"errors"
	"testing"
)

func le16(v ...uint16) []byte {
	b := make([]byte, 0, 2*len(v))
	for _, x := range v {
		b = binary.LittleEndian.AppendUint16(b, x)
	}
	return b
}

func TestDecodeSaveSessionInfo(t *testing.T) {
	// TS_LOGON_INFO: cbDomain=2*"D", Domain[52], cbUserName, UserName[512], SessionId.
	v1 := binary.LittleEndian.AppendUint32(nil, InfoTypeLogon)
	v1 = binary.LittleEndian.AppendUint32(v1, 4)
	v1 = append(v1, append([]byte{'D', 0, 0, 0}, make([]byte, 48)...)...)
	v1 = binary.LittleEndian.AppendUint32(v1, 12)
	v1 = append(v1, append([]byte{'u', 0, 's', 0, 'e', 0, 'r', 0, '1', 0, 0, 0}, make([]byte, 500)...)...)
	v1 = binary.LittleEndian.AppendUint32(v1, 7)
	s, err := DecodeSaveSessionInfo(v1)
	if err != nil || s.Domain != "D" || s.UserName != "user1" || s.SessionID != 7 {
		t.Fatalf("v1: %+v %v", s, err)
	}

	// TS_LOGON_INFO_VERSION_2.
	v2 := binary.LittleEndian.AppendUint32(nil, InfoTypeLogonLong)
	v2 = append(v2, 1, 0)                             // Version
	v2 = binary.LittleEndian.AppendUint32(v2, 576+22) // Size
	v2 = binary.LittleEndian.AppendUint32(v2, 9)      // SessionId
	v2 = binary.LittleEndian.AppendUint32(v2, 6)      // cbDomain
	v2 = binary.LittleEndian.AppendUint32(v2, 16)     // cbUserName
	v2 = append(v2, make([]byte, 558)...)             // Pad
	v2 = append(v2, 'a', 0, 'b', 0, 0, 0)
	v2 = append(v2, 'r', 0, 'd', 0, 'p', 0, 't', 0, 'e', 0, 's', 0, 't', 0, 0, 0)
	if s, err = DecodeSaveSessionInfo(v2); err != nil || s.Domain != "ab" || s.UserName != "rdptest" || s.SessionID != 9 {
		t.Fatalf("v2: %+v %v", s, err)
	}

	plain := append(binary.LittleEndian.AppendUint32(nil, InfoTypeLogonPlain), make([]byte, 576)...)
	if s, err = DecodeSaveSessionInfo(plain); err != nil || s.InfoType != InfoTypeLogonPlain {
		t.Fatalf("plain: %+v %v", s, err)
	}

	// TS_LOGON_INFO_EXTENDED with both fields.
	ext := binary.LittleEndian.AppendUint32(nil, InfoTypeLogonExtended)
	ext = append(ext, 0, 0) // Length (ignored)
	ext = binary.LittleEndian.AppendUint32(ext, logonExAutoReconnectCookie|logonExLogonErrors)
	ext = binary.LittleEndian.AppendUint32(ext, 28)
	ext = append(ext, make([]byte, 28)...)
	ext = binary.LittleEndian.AppendUint32(ext, 8)
	ext = binary.LittleEndian.AppendUint32(ext, 0xFFFFFFFC) // LOGON_WARNING
	ext = binary.LittleEndian.AppendUint32(ext, 0x00000005)
	ext = append(ext, make([]byte, 570)...)
	s, err = DecodeSaveSessionInfo(ext)
	if err != nil || !s.HasAutoReconnectCookie || !s.HasLogonErrors || s.ErrorNotificationType != 0xFFFFFFFC || s.ErrorNotificationData != 5 {
		t.Fatalf("extended: %+v %v", s, err)
	}

	for name, bad := range map[string][]byte{
		"short":         v1[:3],
		"unknown type":  binary.LittleEndian.AppendUint32(nil, 9),
		"v1 truncated":  v1[:100],
		"v1 cbDomain":   append(binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, InfoTypeLogon), 60), make([]byte, 572)...),
		"v2 version":    append(binary.LittleEndian.AppendUint32(nil, InfoTypeLogonLong), append([]byte{2, 0}, make([]byte, 574)...)...),
		"ext truncated": ext[:20],
	} {
		if _, err := DecodeSaveSessionInfo(bad); !errors.Is(err, ErrShare) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDecodeUpdateBitmap(t *testing.T) {
	// Two rectangles: one uncompressed 4x2x16bpp, one compressed with header.
	raw := le16(0, 0, 3, 1, 4, 2, 16, 0, 16)
	raw = append(raw, make([]byte, 16)...)
	comp := le16(10, 20, 13, 21, 4, 2, 24, BitmapCompression, 8+5)
	comp = append(comp, le16(0, 5, 12, 2)...) // cbCompFirstRowSize=0, cbCompMainBodySize=5, cbScanWidth, cbUncompressedSize
	comp = append(comp, 1, 2, 3, 4, 5)
	body := append(le16(UpdateTypeBitmap, 2), append(raw, comp...)...)
	u, err := DecodeUpdate(body)
	if err != nil || u.Type != UpdateTypeBitmap || len(u.Bitmaps) != 2 {
		t.Fatalf("%+v %v", u, err)
	}
	if b := u.Bitmaps[0]; b.Compressed || b.Width != 4 || b.Height != 2 || b.BitsPerPixel != 16 || b.DataLength != 16 {
		t.Fatalf("raw rect %+v", b)
	}
	if b := u.Bitmaps[1]; !b.Compressed || b.DestLeft != 10 || b.DataLength != 5 || b.Data()[0] != 1 {
		t.Fatalf("compressed rect %+v", b)
	}

	noHdr := le16(0, 0, 3, 1, 4, 2, 24, BitmapCompression|BitmapNoCompressionHdr, 3)
	noHdr = append(noHdr, 9, 9, 9)
	if u, err := DecodeUpdate(append(le16(UpdateTypeBitmap, 1), noHdr...)); err != nil || u.Bitmaps[0].DataLength != 3 {
		t.Fatalf("no hdr: %+v %v", u, err)
	}

	pal := append(le16(UpdateTypePalette, 0), binary.LittleEndian.AppendUint32(nil, 2)...)
	pal = append(pal, 1, 2, 3, 4, 5, 6)
	if u, err := DecodeUpdate(pal); err != nil || u.PaletteSize != 2 {
		t.Fatalf("palette: %+v %v", u, err)
	}
	orders := append(le16(UpdateTypeOrders, 0, 3, 0), 0xaa)
	if u, err := DecodeUpdate(orders); err != nil || u.NumOrders != 3 || len(u.OrdersStream) != 1 {
		t.Fatalf("orders: %+v %v", u, err)
	}
	if u, err := DecodeUpdate(le16(UpdateTypeSynchronize, 0)); err != nil || u.Type != UpdateTypeSynchronize {
		t.Fatalf("sync: %+v %v", u, err)
	}

	for name, bad := range map[string][]byte{
		"short":         {1},
		"unknown":       le16(7),
		"rect count":    le16(UpdateTypeBitmap, 3),
		"rect length":   append(le16(UpdateTypeBitmap, 1), le16(0, 0, 3, 1, 4, 2, 16, 0, 99)...),
		"bpp":           append(le16(UpdateTypeBitmap, 1), append(le16(0, 0, 3, 1, 4, 2, 7, 0, 8), make([]byte, 8)...)...),
		"size mismatch": append(le16(UpdateTypeBitmap, 1), append(le16(0, 0, 3, 1, 4, 2, 16, 0, 15), make([]byte, 15)...)...),
		"comp hdr":      append(le16(UpdateTypeBitmap, 1), append(le16(0, 0, 3, 1, 4, 2, 24, BitmapCompression, 4), 1, 2, 3, 4)...),
		"trailing":      append(body, 0),
		"palette big":   append(le16(UpdateTypePalette, 0), binary.LittleEndian.AppendUint32(nil, 300)...),
	} {
		if _, err := DecodeUpdate(bad); !errors.Is(err, ErrShare) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDecodePointer(t *testing.T) {
	sys := append(le16(PointerTypeSystem, 0), binary.LittleEndian.AppendUint32(nil, 0x7F00)...)
	if p, err := DecodePointer(sys); err != nil || p.SystemType != 0x7F00 {
		t.Fatalf("system: %+v %v", p, err)
	}
	if p, err := DecodePointer(le16(PointerTypePosition, 0, 30, 40)); err != nil || p.X != 30 || p.Y != 40 {
		t.Fatalf("position: %+v %v", p, err)
	}
	if p, err := DecodePointer(le16(PointerTypeCached, 0, 5)); err != nil || p.CacheIndex != 5 {
		t.Fatalf("cached: %+v %v", p, err)
	}
	// Color pointer 2x1: xor 24bpp = 6 bytes (scanline padded to 4 -> 8), and mask 1 row padded -> 2 bytes.
	color := le16(PointerTypeColor, 0, 3, 1, 0, 2, 1, 2, 8)
	color = append(color, make([]byte, 10)...)
	if p, err := DecodePointer(color); err != nil || p.CacheIndex != 3 || p.Width != 2 || p.XorBpp != 24 {
		t.Fatalf("color: %+v %v", p, err)
	}
	newPtr := le16(PointerTypeNew, 0, 32, 4, 1, 0, 2, 1, 2, 8)
	newPtr = append(newPtr, make([]byte, 10)...)
	if p, err := DecodePointer(newPtr); err != nil || p.XorBpp != 32 || p.CacheIndex != 4 {
		t.Fatalf("new: %+v %v", p, err)
	}
	large := le16(PointerTypeLarge, 0, 32, 1, 0, 0, 2, 1)
	large = binary.LittleEndian.AppendUint32(large, 2)
	large = binary.LittleEndian.AppendUint32(large, 8)
	large = append(large, make([]byte, 10)...)
	if p, err := DecodePointer(large); err != nil || p.Type != PointerTypeLarge || p.Height != 1 {
		t.Fatalf("large: %+v %v", p, err)
	}
	for name, bad := range map[string][]byte{
		"short":   {1, 0},
		"unknown": le16(2, 0),
		"masks":   color[:len(color)-3],
		"sys":     le16(PointerTypeSystem, 0, 1),
	} {
		if _, err := DecodePointer(bad); !errors.Is(err, ErrShare) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzDecodeOutput(f *testing.F) {
	f.Add(uint8(0), le16(UpdateTypeBitmap, 1, 0, 0, 3, 1, 4, 2, 16, 0, 16))
	f.Add(uint8(1), le16(PointerTypePosition, 0, 1, 2))
	f.Add(uint8(2), append(binary.LittleEndian.AppendUint32(nil, InfoTypeLogonPlain), make([]byte, 576)...))
	f.Fuzz(func(t *testing.T, kind uint8, p []byte) {
		switch kind % 3 {
		case 0:
			_, _ = DecodeUpdate(p)
		case 1:
			_, _ = DecodePointer(p)
		default:
			_, _ = DecodeSaveSessionInfo(p)
		}
	})
}
