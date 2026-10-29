package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// fpUpdate encodes one TS_FP_UPDATE.
func fpUpdate(code, frag uint8, compressed bool, data []byte) []byte {
	hdr := code | frag<<4
	if compressed {
		hdr |= 0x80
	}
	b := []byte{hdr}
	if compressed {
		b = append(b, 0x20) // compressionFlags (PACKET_COMPRESSED)
	}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// fpPDU frames updates in a TS_FP_UPDATE_PDU with the given flags.
func fpPDU(flags uint8, updates ...[]byte) []byte {
	body := bytes.Join(updates, nil)
	size := 2 + len(body)
	if size+1 > 0x7F {
		size++
	}
	pdu := []byte{flags << 6}
	if size > 0x7F {
		pdu = append(pdu, byte(size>>8)|0x80, byte(size))
	} else {
		pdu = append(pdu, byte(size))
	}
	return append(pdu, body...)
}

func TestIsFastPathHeader(t *testing.T) {
	for b, want := range map[byte]bool{0x00: true, 0x80: true, 0x40: true, 0x03: false, 0x01: false} {
		if got := IsFastPathHeader(b); got != want {
			t.Errorf("0x%02x: %t", b, got)
		}
	}
}

func TestDecodeFastPathPDU(t *testing.T) {
	bitmap := append(le16(UpdateTypeBitmap, 1, 0, 0, 3, 1, 4, 2, 16, 0, 16), make([]byte, 16)...)
	pdu := fpPDU(0, fpUpdate(FastPathUpdateBitmap, FastPathFragmentSingle, false, bitmap),
		fpUpdate(FastPathUpdatePtrPosition, FastPathFragmentSingle, false, le16(7, 9)),
		fpUpdate(FastPathUpdateSynchronize, FastPathFragmentSingle, false, nil))
	fp, err := DecodeFastPathPDU(pdu)
	if err != nil || fp.Flags != 0 || len(fp.Updates) != 3 {
		t.Fatalf("%+v %v", fp, err)
	}
	if u := fp.Updates[0]; u.Code != FastPathUpdateBitmap || u.Fragmentation != FastPathFragmentSingle || u.Compressed || !bytes.Equal(u.Data, bitmap) {
		t.Fatalf("bitmap update %+v", u)
	}
	if u := fp.Updates[1]; u.Code != FastPathUpdatePtrPosition || !bytes.Equal(u.Data, le16(7, 9)) {
		t.Fatalf("position update %+v", u)
	}
	if u := fp.Updates[2]; u.Code != FastPathUpdateSynchronize || len(u.Data) != 0 {
		t.Fatalf("synchronize update %+v", u)
	}

	// Long length form, fragments and the compression flag.
	big := make([]byte, 300)
	pdu = fpPDU(FastPathOutputSecureChecksum,
		fpUpdate(FastPathUpdateOrders, FastPathFragmentFirst, false, big),
		fpUpdate(FastPathUpdateOrders, FastPathFragmentLast, true, []byte{1, 2}))
	if pdu[1]&0x80 == 0 || len(pdu) != int(pdu[1]&0x7F)<<8|int(pdu[2]) {
		t.Fatalf("long length encoding % x", pdu[:3])
	}
	fp, err = DecodeFastPathPDU(pdu)
	if err != nil || fp.Flags != FastPathOutputSecureChecksum || len(fp.Updates) != 2 {
		t.Fatalf("%+v %v", fp, err)
	}
	if u := fp.Updates[0]; u.Fragmentation != FastPathFragmentFirst || len(u.Data) != 300 {
		t.Fatalf("first fragment %+v", u)
	}
	if u := fp.Updates[1]; u.Fragmentation != FastPathFragmentLast || !u.Compressed || u.CompressionFlags != 0x20 || !bytes.Equal(u.Data, []byte{1, 2}) {
		t.Fatalf("last fragment %+v", u)
	}

	// ReadFastPathPDU consumes exactly one PDU and leaves the rest.
	r := bytes.NewReader(append(append([]byte(nil), pdu...), 3, 0, 0, 7))
	first, _ := r.ReadByte()
	fp2, err := ReadFastPathPDU(r, first, 0)
	if err != nil || len(fp2.Updates) != 2 || r.Len() != 4 {
		t.Fatalf("%+v %v remaining %d", fp2, err, r.Len())
	}

	for name, bad := range map[string][]byte{
		"empty":            {},
		"x224 action":      {0x03, 0x02},
		"encrypted":        {0x80, 0x02},
		"length mismatch":  {0x00, 0x06, 0x01, 0x00, 0x00},
		"no updates":       {0x00, 0x02},
		"truncated size":   {0x00, 0x03, 0x01},
		"size overflow":    {0x00, 0x05, 0x01, 0x05, 0x00},
		"truncated cflags": {0x00, 0x03, 0x81},
	} {
		if _, err := DecodeFastPathPDU(bad); !errors.Is(err, ErrFastPath) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ReadFastPathPDU(bytes.NewReader([]byte{0x05}), 0, 0); err == nil {
		t.Error("truncated stream accepted")
	}
	if _, err := ReadFastPathPDU(bytes.NewReader([]byte{0x90, 0x00}), 0, 0x100); !errors.Is(err, ErrFastPath) {
		t.Errorf("oversize: %v", err)
	}
}

func TestDecodeFastPathPointer(t *testing.T) {
	if p, err := DecodeFastPathPointer(FastPathUpdatePtrNull, nil); err != nil || p.Type != PointerTypeSystem || p.SystemType != SystemPointerNull {
		t.Fatalf("null: %+v %v", p, err)
	}
	if p, err := DecodeFastPathPointer(FastPathUpdatePtrDefault, nil); err != nil || p.SystemType != SystemPointerDefault {
		t.Fatalf("default: %+v %v", p, err)
	}
	if p, err := DecodeFastPathPointer(FastPathUpdatePtrPosition, le16(30, 40)); err != nil || p.Type != PointerTypePosition || p.X != 30 || p.Y != 40 {
		t.Fatalf("position: %+v %v", p, err)
	}
	if p, err := DecodeFastPathPointer(FastPathUpdateCached, le16(5)); err != nil || p.Type != PointerTypeCached || p.CacheIndex != 5 {
		t.Fatalf("cached: %+v %v", p, err)
	}
	// 2x1 24bpp colour pointer: xor 6 bytes, and 2 bytes.
	color := le16(3, 1, 0, 2, 1, 2, 6)
	color = append(color, 1, 2, 3, 4, 5, 6, 0x80, 0)
	p, err := DecodeFastPathPointer(FastPathUpdateColor, color)
	if err != nil || p.Type != PointerTypeColor || p.XorBpp != 24 || p.HotSpotX != 1 || p.HotSpotY != 0 || p.Width != 2 ||
		!bytes.Equal(p.XorMask, []byte{1, 2, 3, 4, 5, 6}) || !bytes.Equal(p.AndMask, []byte{0x80, 0}) {
		t.Fatalf("color: %+v %v", p, err)
	}
	if p, err := DecodeFastPathPointer(FastPathUpdatePointer, append(le16(32), color...)); err != nil || p.Type != PointerTypeNew || p.XorBpp != 32 {
		t.Fatalf("new: %+v %v", p, err)
	}
	if _, err := DecodeFastPathPointer(FastPathUpdateLargePointer, []byte{1}); !errors.Is(err, ErrShare) {
		t.Fatalf("large truncated: %v", err)
	}
	if _, err := DecodeFastPathPointer(FastPathUpdateBitmap, nil); !errors.Is(err, ErrFastPath) {
		t.Fatalf("non-pointer: %v", err)
	}
	if n, err := FastPathOrdersCount([]byte{4, 0, 9}); err != nil || n != 4 {
		t.Fatalf("orders: %d %v", n, err)
	}
	if _, err := FastPathOrdersCount([]byte{4}); !errors.Is(err, ErrFastPath) {
		t.Fatalf("orders truncated: %v", err)
	}
	for _, c := range []uint8{FastPathUpdatePtrNull, FastPathUpdatePtrDefault, FastPathUpdatePtrPosition, FastPathUpdateColor, FastPathUpdateCached, FastPathUpdatePointer, FastPathUpdateLargePointer} {
		if !IsFastPathPointer(c) {
			t.Errorf("0x%x not a pointer", c)
		}
	}
	if IsFastPathPointer(FastPathUpdateBitmap) || FastPathUpdateName(FastPathUpdateCached) != "ptr-cached" || FastPathUpdateName(0xF) != "0xf" {
		t.Error("names")
	}
}

func FuzzDecodeFastPathPDU(f *testing.F) {
	f.Add(fpPDU(0, fpUpdate(FastPathUpdateSynchronize, 0, false, nil)))
	f.Add(fpPDU(0, fpUpdate(FastPathUpdatePtrPosition, 0, false, []byte{1, 0, 2, 0})))
	f.Fuzz(func(t *testing.T, b []byte) {
		fp, err := DecodeFastPathPDU(b)
		if err == nil {
			for _, u := range fp.Updates {
				if IsFastPathPointer(u.Code) {
					_, _ = DecodeFastPathPointer(u.Code, u.Data)
				}
			}
		}
	})
}
