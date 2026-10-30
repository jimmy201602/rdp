package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestChannelReassembly(t *testing.T) {
	msg := bytes.Repeat([]byte("abcdefgh"), 500) // 4000 bytes, > chunk size
	chunks := SplitChannelPDU(msg, 1600)
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	var ra ChannelReassembler
	var got []byte
	for i, c := range chunks {
		m, done, comp, err := ra.Add(c)
		if err != nil || comp {
			t.Fatalf("chunk %d: comp %v err %v", i, comp, err)
		}
		if done {
			got = m
		}
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("reassembled %d bytes, want %d", len(got), len(msg))
	}
}

func ioReq(t *testing.T, full []byte) IORequest {
	t.Helper()
	h, body, err := DecodeRDPDRHeader(full)
	if err != nil || h.PacketID != PakidCoreDeviceIORequest {
		t.Fatalf("header %+v err %v", h, err)
	}
	req, err := DecodeIORequest(body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestCreateRoundTrip(t *testing.T) {
	req := ioReq(t, EncodeCreate(7, 42, `\sub\file.txt`, AccessReadFile, FileOpen, OptionsFile))
	if req.DeviceID != 7 || req.CompletionID != 42 || req.Major != IRPMJCreate {
		t.Fatalf("header %+v", req)
	}
	if req.Path != `\sub\file.txt` || req.CreateDisposition != FileOpen {
		t.Fatalf("path %q disp %d", req.Path, req.CreateDisposition)
	}
}

func TestReadWriteRoundTrip(t *testing.T) {
	r := ioReq(t, EncodeRead(1, 2, 3, 4096, 1<<20))
	if r.Major != IRPMJRead || r.Length != 4096 || r.Offset != 1<<20 {
		t.Fatalf("read %+v", r)
	}
	data := []byte("payload")
	w := ioReq(t, EncodeWrite(1, 2, 3, 8, data))
	if w.Major != IRPMJWrite || w.Length != uint32(len(data)) || w.Offset != 8 {
		t.Fatalf("write %+v", w)
	}
}

func TestQueryDirectoryRoundTrip(t *testing.T) {
	q := ioReq(t, EncodeQueryDirectory(1, 2, 3, FileBothDirectoryInformation, true, "*"))
	if q.Major != IRPMJDirectoryControl || q.Minor != IRPMNQueryDirectory {
		t.Fatalf("%+v", q)
	}
	if q.FsInformationClass != FileBothDirectoryInformation || q.Path != "*" {
		t.Fatalf("class %d path %q", q.FsInformationClass, q.Path)
	}
}

func TestDeviceAnnounce(t *testing.T) {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint32(1)) // one device
	binary.Write(&b, binary.LittleEndian, uint32(RDPDRDtypFilesystem))
	binary.Write(&b, binary.LittleEndian, uint32(5)) // device id
	name := make([]byte, 8)
	copy(name, "C:")
	b.Write(name)
	label := encodeUTF16z("OS")
	binary.Write(&b, binary.LittleEndian, uint32(len(label)))
	b.Write(label)
	devs, err := DecodeDeviceAnnounce(b.Bytes())
	if err != nil || len(devs) != 1 {
		t.Fatalf("devs %v err %v", devs, err)
	}
	if devs[0].Type != RDPDRDtypFilesystem || devs[0].ID != 5 || devs[0].DosName != "C:" || devs[0].Label != "OS" {
		t.Fatalf("device %+v", devs[0])
	}
}

func TestDirectoryResponse(t *testing.T) {
	entry := make([]byte, 93)
	binary.LittleEndian.PutUint32(entry[0:], 0)                    // NextEntryOffset (last)
	binary.LittleEndian.PutUint64(entry[24:], 131000000000000000)  // LastWriteTime (>1601 epoch)
	binary.LittleEndian.PutUint64(entry[40:], 5)                   // EndOfFile (size)
	binary.LittleEndian.PutUint32(entry[56:], fileAttributeNormal) // attributes
	name := encodeUTF16("hello.txt")
	binary.LittleEndian.PutUint32(entry[60:], uint32(len(name)))
	entry = append(entry, name...)

	tail := make([]byte, 4)
	binary.LittleEndian.PutUint32(tail, uint32(len(entry)))
	tail = append(tail, entry...)

	files, err := ParseDirectoryResponse(tail)
	if err != nil || len(files) != 1 {
		t.Fatalf("files %v err %v", files, err)
	}
	f := files[0]
	if f.Name != "hello.txt" || f.Size != 5 || f.IsDir || f.Modified.IsZero() {
		t.Fatalf("entry %+v", f)
	}
}

func TestCompletionParsers(t *testing.T) {
	create := make([]byte, 5)
	binary.LittleEndian.PutUint32(create, 99)
	create[4] = 1
	if id, info, err := ParseCreateResponse(create); err != nil || id != 99 || info != 1 {
		t.Fatalf("create %d %d %v", id, info, err)
	}
	read := append([]byte{3, 0, 0, 0}, []byte("abc")...)
	if d, err := ParseReadResponse(read); err != nil || string(d) != "abc" {
		t.Fatalf("read %q %v", d, err)
	}
	write := []byte{7, 0, 0, 0}
	if n, err := ParseWriteResponse(write); err != nil || n != 7 {
		t.Fatalf("write %d %v", n, err)
	}
}

func TestClipFormatList(t *testing.T) {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint32(CFUnicodeText))
	b.Write(encodeUTF16z("")) // standard format, empty long name
	binary.Write(&b, binary.LittleEndian, uint32(49161))
	b.Write(encodeUTF16z("FileGroupDescriptorW"))

	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint16(hdr, CBFormatList)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(b.Len()))
	h, body, err := DecodeClipHeader(append(hdr, b.Bytes()...))
	if err != nil || h.MsgType != CBFormatList {
		t.Fatalf("header %+v err %v", h, err)
	}
	formats := DecodeFormatList(body, true)
	if len(formats) != 2 || !HasText(formats) || !HasFileList(formats) {
		t.Fatalf("formats %+v", formats)
	}
}

func TestClipFileList(t *testing.T) {
	desc := make([]byte, 592)
	binary.LittleEndian.PutUint32(desc[64:], 0) // size high
	binary.LittleEndian.PutUint32(desc[68:], 1234)
	copy(desc[72:], encodeUTF16("report.pdf"))
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body, 1)
	body = append(body, desc...)
	files, err := DecodeFileList(body)
	if err != nil || len(files) != 1 || files[0].Name != "report.pdf" || files[0].Size != 1234 {
		t.Fatalf("files %+v err %v", files, err)
	}
}
