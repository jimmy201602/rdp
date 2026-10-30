package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"rdp.local/kernel/wire"
)

func TestWebClipText(t *testing.T) {
	var sent [][]byte
	got := make(chan string, 1)
	c := &webClip{send: func(m []byte) error { sent = append(sent, m); return nil }, onText: func(cc ClipContent) { got <- cc.Text }}
	caps := make([]byte, 16)
	binary.LittleEndian.PutUint16(caps, 1)
	binary.LittleEndian.PutUint16(caps[4:], 1)
	binary.LittleEndian.PutUint16(caps[6:], 12)
	binary.LittleEndian.PutUint32(caps[8:], 2)
	binary.LittleEndian.PutUint32(caps[12:], 2)
	must(t, c.handle(clipPDU(wire.CBClipCaps, 0, caps)))
	must(t, c.handle(clipPDU(wire.CBMonitorReady, 0, nil)))
	if len(sent) != 2 || binary.LittleEndian.Uint16(sent[1]) != wire.CBFormatList {
		t.Fatalf("handshake sent %d messages", len(sent))
	}
	must(t, c.set(ClipContent{Text: "你好 hello"}))
	list := sent[len(sent)-1]
	if binary.LittleEndian.Uint32(list[8:]) != wire.CFUnicodeText {
		t.Fatalf("format list %x", list)
	}
	must(t, c.handle(clipPDU(wire.CBFormatDataRequest, 0, binary.LittleEndian.AppendUint32(nil, wire.CFUnicodeText))))
	resp := sent[len(sent)-1]
	if fromUTF16le(resp[8:]) != "你好 hello" {
		t.Fatalf("data response %x", resp)
	}
	remote := binary.LittleEndian.AppendUint32(nil, wire.CFUnicodeText)
	remote = append(remote, 0, 0)
	must(t, c.handle(clipPDU(wire.CBFormatList, 0, remote)))
	if binary.LittleEndian.Uint16(sent[len(sent)-1]) != wire.CBFormatDataRequest {
		t.Fatal("no data request for remote text")
	}
	must(t, c.handle(clipPDU(wire.CBFormatDataResponse, wire.CBResponseOK, utf16le("remote", true))))
	if s := <-got; s != "remote" {
		t.Fatalf("remote text %q", s)
	}
}

func TestWebClipRich(t *testing.T) {
	var sent [][]byte
	got := make(chan ClipContent, 1)
	c := &webClip{send: func(m []byte) error { sent = append(sent, m); return nil }, onText: func(cc ClipContent) { got <- cc }, longNames: true, ready: true}
	img := image.NewNRGBA(image.Rect(0, 0, 3, 2))
	img.SetNRGBA(2, 1, color.NRGBA{R: 200, G: 10, B: 20, A: 255})
	var pb bytes.Buffer
	must(t, png.Encode(&pb, img))
	must(t, c.set(ClipContent{Text: "t", HTML: "<b>粗</b>", PNG: pb.Bytes()}))
	ids := map[uint32]string{}
	for _, f := range wire.DecodeFormatList(sent[len(sent)-1][8:], true) {
		ids[f.ID] = f.Name
	}
	if ids[cfLocalHTML] != "HTML Format" || ids[cfLocalPNG] != "PNG" || len(ids) != 4 {
		t.Fatalf("formats %v", ids)
	}
	must(t, c.handle(clipPDU(wire.CBFormatDataRequest, 0, binary.LittleEndian.AppendUint32(nil, cfLocalHTML))))
	if h := decodeCFHTML(sent[len(sent)-1][8:]); h != "<b>粗</b>" {
		t.Fatalf("html round trip %q", h)
	}
	must(t, c.handle(clipPDU(wire.CBFormatDataRequest, 0, binary.LittleEndian.AppendUint32(nil, cfDIB))))
	dib := sent[len(sent)-1][8:]
	back, err := dibToPNG(dib)
	must(t, err)
	bi, err := png.Decode(bytes.NewReader(back))
	must(t, err)
	if r, g, _, _ := bi.At(2, 1).RGBA(); r>>8 != 200 || g>>8 != 10 {
		t.Fatalf("dib pixel %v", bi.At(2, 1))
	}

	// Remote list: text, HTML and a DIB are fetched one after another.
	var list []byte
	list = c.appendFormat(list, wire.CFUnicodeText, "")
	list = c.appendFormat(list, 0xC123, "HTML Format")
	list = c.appendFormat(list, cfDIB, "")
	must(t, c.handle(clipPDU(wire.CBFormatList, 0, list)))
	for _, body := range [][]byte{utf16le("hi", true), append(encodeCFHTML("<i>x</i>"), 0), dib} {
		if binary.LittleEndian.Uint16(sent[len(sent)-1]) != wire.CBFormatDataRequest {
			t.Fatal("expected a data request")
		}
		must(t, c.handle(clipPDU(wire.CBFormatDataResponse, wire.CBResponseOK, body)))
	}
	cc := <-got
	if cc.Text != "hi" || cc.HTML != "<i>x</i>" || len(cc.PNG) == 0 {
		t.Fatalf("remote content %+v", cc)
	}
}

func TestDIB16(t *testing.T) {
	dib := make([]byte, 40)
	binary.LittleEndian.PutUint32(dib, 40)
	binary.LittleEndian.PutUint32(dib[4:], 2)
	binary.LittleEndian.PutUint32(dib[8:], 1)
	binary.LittleEndian.PutUint16(dib[14:], 16)
	binary.LittleEndian.PutUint32(dib[16:], 3)
	for _, m := range []uint32{0xF800, 0x07E0, 0x001F} {
		dib = binary.LittleEndian.AppendUint32(dib, m)
	}
	dib = binary.LittleEndian.AppendUint16(dib, 0xF800)
	dib = binary.LittleEndian.AppendUint16(dib, 0x001F)
	p, err := dibToPNG(dib)
	must(t, err)
	img, err := png.Decode(bytes.NewReader(p))
	must(t, err)
	if r, _, _, _ := img.At(0, 0).RGBA(); r>>8 != 255 {
		t.Fatalf("pixel 0 %v", img.At(0, 0))
	}
	if _, _, b, _ := img.At(1, 0).RGBA(); b>>8 != 255 {
		t.Fatalf("pixel 1 %v", img.At(1, 0))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type memFS struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
}

func (m *memFS) Stat(_ context.Context, p string) (FSEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dirs[p] {
		return FSEntry{Name: p, Dir: true}, nil
	}
	if b, ok := m.files[p]; ok {
		return FSEntry{Name: p, Size: int64(len(b))}, nil
	}
	return FSEntry{}, FSErrNotFound
}
func (m *memFS) List(_ context.Context, dir string) ([]FSEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []FSEntry
	for p, b := range m.files {
		if parentOf(p) == dir {
			out = append(out, FSEntry{Name: p[strings.LastIndex(p, "/")+1:], Size: int64(len(b))})
		}
	}
	for p := range m.dirs {
		if p != "" && parentOf(p) == dir {
			out = append(out, FSEntry{Name: p[strings.LastIndex(p, "/")+1:], Dir: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func parentOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}
func (m *memFS) Read(_ context.Context, p string, off int64, n int) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := m.files[p]
	if off >= int64(len(b)) {
		return nil, nil
	}
	end := min(int(off)+n, len(b))
	return b[off:end], nil
}
func (m *memFS) Write(_ context.Context, p string, off int64, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := m.files[p]
	for int64(len(b)) < off+int64(len(data)) {
		b = append(b, 0)
	}
	copy(b[off:], data)
	m.files[p] = b
	return nil
}
func (m *memFS) Create(_ context.Context, p string, dir bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if dir {
		m.dirs[p] = true
	} else {
		m.files[p] = nil
	}
	return nil
}
func (m *memFS) Truncate(_ context.Context, p string, size int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[p] = m.files[p][:size]
	return nil
}
func (m *memFS) Remove(_ context.Context, p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, p)
	delete(m.dirs, p)
	return nil
}
func (m *memFS) Rename(_ context.Context, from, to string, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[to] = m.files[from]
	delete(m.files, from)
	return nil
}

func ioRequest(fileID, completion, major, minor uint32, args []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, webDriveID)
	b = binary.LittleEndian.AppendUint32(b, fileID)
	b = binary.LittleEndian.AppendUint32(b, completion)
	b = binary.LittleEndian.AppendUint32(b, major)
	b = binary.LittleEndian.AppendUint32(b, minor)
	return rdpdrPDU(wire.PakidCoreDeviceIORequest, append(b, args...))
}

func TestWebDrive(t *testing.T) {
	out := make(chan []byte, 64)
	d := newWebDrive(func(m []byte) error { out <- m; return nil })
	defer d.close()
	next := func() (uint16, []byte) {
		select {
		case m := <-out:
			return binary.LittleEndian.Uint16(m[2:]), m[4:]
		case <-time.After(2 * time.Second):
			t.Fatal("no reply")
			return 0, nil
		}
	}
	fs := &memFS{files: map[string][]byte{"a.txt": []byte("hello"), "sub/b.txt": nil}, dirs: map[string]bool{"sub": true}}
	must(t, d.mount("Docs", fs))
	announce := rdpdrPDU(wire.PakidCoreServerAnnounce, []byte{1, 0, 0x0d, 0, 9, 0, 0, 0})
	must(t, d.handle(announce))
	if id, body := next(); id != wire.PakidCoreClientidConfirm || binary.LittleEndian.Uint16(body[2:]) != 0x0c {
		t.Fatalf("announce reply %x %x", id, body)
	}
	if id, _ := next(); id != wire.PakidCoreClientName {
		t.Fatalf("client name %x", id)
	}
	must(t, d.handle(rdpdrPDU(wire.PakidCoreUserLoggedon, nil)))
	id, body := next()
	devs, err := wire.DecodeDeviceAnnounce(body)
	if id != wire.PakidCoreDevicelistAnnounce || err != nil || len(devs) != 1 || devs[0].DosName != "DOCS" {
		t.Fatalf("device list %x %+v %v", id, devs, err)
	}
	completion := func() wire.IOCompletion {
		id, body := next()
		c, err := wire.DecodeIOCompletion(body)
		if id != wire.PakidCoreDeviceIOCompletion || err != nil {
			t.Fatalf("completion %x %v", id, err)
		}
		return c
	}
	create := func(p string, disp, opts uint32) wire.IOCompletion {
		name := utf16le(p, true)
		args := make([]byte, 32)
		binary.LittleEndian.PutUint32(args[20:], disp)
		binary.LittleEndian.PutUint32(args[24:], opts)
		binary.LittleEndian.PutUint32(args[28:], uint32(len(name)))
		must(t, d.handle(ioRequest(0, 1, wire.IRPMJCreate, 0, append(args, name...))))
		return completion()
	}
	c := create(`\a.txt`, wire.FileOpen, createNonDirectory)
	file, _, _ := wire.ParseCreateResponse(c.Tail)
	if c.IoStatus != 0 {
		t.Fatalf("open status %x", c.IoStatus)
	}
	rd := make([]byte, 32)
	binary.LittleEndian.PutUint32(rd, 100)
	must(t, d.handle(ioRequest(file, 2, wire.IRPMJRead, 0, rd)))
	if data, err := wire.ParseReadResponse(completion().Tail); err != nil || string(data) != "hello" {
		t.Fatalf("read %q %v", data, err)
	}
	if c := create(`\missing.txt`, wire.FileOpen, 0); c.IoStatus != ntNameNotFound {
		t.Fatalf("missing status %x", c.IoStatus)
	}
	c = create(`\new.txt`, wire.FileCreate, createNonDirectory)
	nf, info, _ := wire.ParseCreateResponse(c.Tail)
	if c.IoStatus != 0 || info != 2 {
		t.Fatalf("create %x info %d", c.IoStatus, info)
	}
	wr := make([]byte, 32)
	binary.LittleEndian.PutUint32(wr, 3)
	must(t, d.handle(ioRequest(nf, 3, wire.IRPMJWrite, 0, append(wr, "xyz"...))))
	if c := completion(); c.IoStatus != 0 || string(fs.files["new.txt"]) != "xyz" {
		t.Fatalf("write %x %q", c.IoStatus, fs.files["new.txt"])
	}
	c = create(`\`, wire.FileOpen, createDirectory)
	root, _, _ := wire.ParseCreateResponse(c.Tail)
	pattern := utf16le(`\*`, true)
	q := make([]byte, 32)
	binary.LittleEndian.PutUint32(q, wire.FileBothDirectoryInformation)
	q[4] = 1
	binary.LittleEndian.PutUint32(q[5:], uint32(len(pattern)))
	var names []string
	must(t, d.handle(ioRequest(root, 4, wire.IRPMJDirectoryControl, wire.IRPMNQueryDirectory, append(q, pattern...))))
	for {
		c := completion()
		if c.IoStatus == ntNoMoreFiles {
			break
		}
		entries, err := wire.ParseDirectoryResponse(c.Tail)
		if err != nil || len(entries) != 1 {
			t.Fatalf("dir entry %v %v", entries, err)
		}
		names = append(names, entries[0].Name)
		q[4] = 0
		must(t, d.handle(ioRequest(root, 5, wire.IRPMJDirectoryControl, wire.IRPMNQueryDirectory, q)))
	}
	if strings.Join(names, ",") != "a.txt,new.txt,sub" {
		t.Fatalf("listing %v", names)
	}
}
