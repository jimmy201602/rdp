package wire

import (
	"encoding/binary"
	"testing"
)

func TestChannelRejectsMalformedChunks(t *testing.T) {
	chunk := func(n, flags uint32, p []byte) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b, n)
		binary.LittleEndian.PutUint32(b[4:], flags)
		return append(b, p...)
	}
	for _, p := range [][]byte{nil, {0}, chunk(MaxChannelMessage+1, 3, nil), chunk(2, 3, []byte{1}), chunk(0, 3, []byte{1}), chunk(1, 2, []byte{1})} {
		var r ChannelReassembler
		if _, _, _, err := r.Add(p); err == nil {
			t.Fatalf("accepted malformed %x", p)
		}
		if len(r.buf) != 0 || r.active {
			t.Fatal("malformed state retained")
		}
	}
	var r ChannelReassembler
	if _, _, _, err := r.Add(chunk(2, 1, []byte{1})); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := r.Add(chunk(3, 2, []byte{2})); err == nil {
		t.Fatal("changed message length accepted")
	}
	if _, _, comp, err := r.Add(chunk(1, 3|ChannelPacketCompressed, nil)); err != nil || !comp {
		t.Fatal("compression not reported")
	}
}
func TestRDPEFSWireLayoutsAndBounds(t *testing.T) {
	p := EncodeSetDisposition(1, 2, 3)
	if len(p) != 56 || binary.LittleEndian.Uint32(p[24:]) != 13 || binary.LittleEndian.Uint32(p[28:]) != 0 {
		t.Fatal("disposition must have empty SetBuffer per MS-RDPEFS")
	}
	p = EncodeQueryDirectory(1, 2, 3, 1, true, "\\*")
	if binary.LittleEndian.Uint32(p[29:]) != 6 || p[len(p)-1] != 0 || p[len(p)-2] != 0 {
		t.Fatal("initial path not UTF16z")
	}
	if _, err := DecodeDevicelistRemove([]byte{255, 255, 255, 255}); err == nil {
		t.Fatal("remove overflow accepted")
	}
	if _, err := ParseReadResponse([]byte{9, 0, 0, 0, 1}); err == nil {
		t.Fatal("truncated read accepted")
	}
	if _, _, err := DecodeClipHeader([]byte{5, 0, 1, 0, 9, 0, 0, 0}); err == nil {
		t.Fatal("truncated clipboard accepted")
	}
	tail := make([]byte, 4+66)
	binary.LittleEndian.PutUint32(tail, 66)
	binary.LittleEndian.PutUint32(tail[4+60:], 2)
	copy(tail[4+64:], []byte{'a', 0})
	files, err := ParseDirectoryEntries(tail, 1)
	if err != nil || len(files) != 1 || files[0].Name != "a" {
		t.Fatalf("directory %v %v", files, err)
	}
	binary.LittleEndian.PutUint32(tail[4:], 1)
	if _, err := ParseDirectoryEntries(tail, 1); err == nil {
		t.Fatal("overlapping directory entries accepted")
	}
}
func FuzzRedirectedWire(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add(EncodeCreate(1, 2, "\\test", AccessReadFile, FileOpen, OptionsFile))
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 8192 {
			return
		}
		_, _ = DecodeIORequest(p)
		_, _ = DecodeIOCompletion(p)
		_, _ = DecodeDeviceAnnounce(p)
		_, _ = DecodeDevicelistRemove(p)
		_, _ = ParseDirectoryEntries(p, 1)
		_, _ = ParseDirectoryResponse(p)
		_, _ = ParseReadResponse(p)
		_, _, _ = DecodeClipHeader(p)
		_, _ = DecodeFileList(p)
		_ = DecodeFormatList(p, true)
		_ = DecodeFormatList(p, false)
		var r ChannelReassembler
		_, _, _, _ = r.Add(p)
	})
}
