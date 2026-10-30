package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"rdp.local/kernel/wire"
)

// WebFS is a folder the browser shared with a web session (File System
// Access API). Paths are slash-separated and relative to the folder root
// ("" is the root). Implementations return the FSError* sentinels so the
// drive can map them to NTSTATUS.
type WebFS interface {
	Stat(ctx context.Context, p string) (FSEntry, error)
	List(ctx context.Context, dir string) ([]FSEntry, error)
	Read(ctx context.Context, p string, off int64, n int) ([]byte, error)
	Write(ctx context.Context, p string, off int64, data []byte) error
	Create(ctx context.Context, p string, dir bool) error
	Truncate(ctx context.Context, p string, size int64) error
	Remove(ctx context.Context, p string) error
	Rename(ctx context.Context, from, to string, replace bool) error
}

// FSEntry describes one file or folder.
type FSEntry struct {
	Name     string    `json:"name"`
	Dir      bool      `json:"dir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"-"`
}

var (
	FSErrNotFound = errors.New("not found")
	FSErrExists   = errors.New("already exists")
	FSErrNotEmpty = errors.New("folder not empty")
	FSErrDenied   = errors.New("access denied")
	FSErrOffline  = errors.New("browser not connected")
)

// NTSTATUS values used by the emulated drive.
const (
	ntSuccess            = 0x00000000
	ntNoMoreFiles        = 0x80000006
	ntUnsuccessful       = 0xC0000001
	ntNotImplemented     = 0xC0000002
	ntInvalidDevReq      = 0xC0000010
	ntAccessDenied       = 0xC0000022
	ntObjectNameInvalid  = 0xC0000033
	ntNameNotFound       = 0xC0000034
	ntNameCollision      = 0xC0000035
	ntFileIsDirectory    = 0xC00000BA
	ntNotSupported       = 0xC00000BB
	ntDeviceNotConnected = 0xC000009D
	ntNotADirectory      = 0xC0000103
	ntDirNotEmpty        = 0xC0000101
	ntInvalidHandle      = 0xC0000008
)

func ntStatus(err error) uint32 {
	switch {
	case err == nil:
		return ntSuccess
	case errors.Is(err, FSErrNotFound):
		return ntNameNotFound
	case errors.Is(err, FSErrExists):
		return ntNameCollision
	case errors.Is(err, FSErrNotEmpty):
		return ntDirNotEmpty
	case errors.Is(err, FSErrDenied):
		return ntAccessDenied
	case errors.Is(err, FSErrOffline), errors.Is(err, context.DeadlineExceeded):
		return ntDeviceNotConnected
	}
	return ntUnsuccessful
}

const webDriveID = 1

type webFile struct {
	path          string
	dir           bool
	deleteOnClose bool
	entries       []FSEntry // QUERY_DIRECTORY results not yet returned
}

// webDrive is the client side of rdpdr for a web session: it announces one
// file system device backed by a WebFS and answers the server's I/O
// requests itself.
type webDrive struct {
	send func([]byte) error

	mu        sync.Mutex
	fs        WebFS
	name      string
	loggedOn  bool
	announced bool
	files     map[uint32]*webFile
	nextFile  uint32
	queue     chan []byte
	stop      chan struct{}
	once      sync.Once
}

func newWebDrive(send func([]byte) error) *webDrive {
	d := &webDrive{send: send, files: map[uint32]*webFile{}, queue: make(chan []byte, 512), stop: make(chan struct{})}
	go d.worker()
	return d
}

func (d *webDrive) close() { d.once.Do(func() { close(d.stop) }) }

func rdpdrPDU(packetID uint16, body []byte) []byte {
	b := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint16(b, wire.RDPDRCtypCore)
	binary.LittleEndian.PutUint16(b[2:], packetID)
	return append(b, body...)
}

func dosName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
		if b.Len() == 7 {
			break
		}
	}
	if b.Len() == 0 {
		return "BROWSER"
	}
	return b.String()
}

func (d *webDrive) announce() error {
	dn := make([]byte, 8)
	copy(dn, dosName(d.name))
	data := append([]byte(d.name), 0)
	body := binary.LittleEndian.AppendUint32(nil, 1)
	body = binary.LittleEndian.AppendUint32(body, wire.RDPDRDtypFilesystem)
	body = binary.LittleEndian.AppendUint32(body, webDriveID)
	body = append(body, dn...)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(data)))
	body = append(body, data...)
	d.announced = true
	return d.send(rdpdrPDU(wire.PakidCoreDevicelistAnnounce, body))
}

func (d *webDrive) remove() error {
	d.announced = false
	d.files = map[uint32]*webFile{}
	body := binary.LittleEndian.AppendUint32(nil, 1)
	body = binary.LittleEndian.AppendUint32(body, webDriveID)
	return d.send(rdpdrPDU(wire.PakidCoreDevicelistRemove, body))
}

// mount shares fs under name, replacing a previous folder.
func (d *webDrive) mount(name string, fs WebFS) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.announced {
		if err := d.remove(); err != nil {
			return err
		}
	}
	d.fs, d.name = fs, name
	if d.loggedOn {
		return d.announce()
	}
	return nil
}

func (d *webDrive) unmount() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fs = nil
	if d.announced {
		return d.remove()
	}
	return nil
}

func (d *webDrive) mountedFS() (string, WebFS) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.name, d.fs
}

func (d *webDrive) mounted() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fs == nil {
		return ""
	}
	return d.name
}

// handle processes one reassembled message from the server. I/O requests
// are queued: they wait on the browser and run one at a time.
func (d *webDrive) handle(msg []byte) error {
	h, body, err := wire.DecodeRDPDRHeader(msg)
	if err != nil || h.Component != wire.RDPDRCtypCore {
		return nil
	}
	switch h.PacketID {
	case wire.PakidCoreServerAnnounce:
		if len(body) < 8 {
			return nil
		}
		minor := binary.LittleEndian.Uint16(body[2:])
		if minor > 0x000C {
			minor = 0x000C
		}
		reply := binary.LittleEndian.AppendUint16(nil, 1)
		reply = binary.LittleEndian.AppendUint16(reply, minor)
		reply = append(reply, body[4:8]...)
		if err := d.send(rdpdrPDU(wire.PakidCoreClientidConfirm, reply)); err != nil {
			return err
		}
		name := utf16le(webClientName, true)
		nb := binary.LittleEndian.AppendUint32(nil, 1)
		nb = binary.LittleEndian.AppendUint32(nb, 0)
		nb = binary.LittleEndian.AppendUint32(nb, uint32(len(name)))
		return d.send(rdpdrPDU(wire.PakidCoreClientName, append(nb, name...)))
	case wire.PakidCoreServerCapability:
		caps := binary.LittleEndian.AppendUint16(nil, 2)
		caps = binary.LittleEndian.AppendUint16(caps, 0)
		// CAP_GENERAL_TYPE, version 2.
		gen := make([]byte, 44)
		binary.LittleEndian.PutUint16(gen, 1)
		binary.LittleEndian.PutUint16(gen[2:], 44)
		binary.LittleEndian.PutUint32(gen[4:], 2)
		binary.LittleEndian.PutUint16(gen[16:], 1)      // protocolMajorVersion
		binary.LittleEndian.PutUint16(gen[18:], 0x000C) // protocolMinorVersion
		binary.LittleEndian.PutUint32(gen[20:], 0xFFFF) // ioCode1: all IRPs
		binary.LittleEndian.PutUint32(gen[28:], 0x7)    // device remove, display name, user logged on PDUs
		caps = append(caps, gen...)
		drive := make([]byte, 8)
		binary.LittleEndian.PutUint16(drive, 4)
		binary.LittleEndian.PutUint16(drive[2:], 8)
		binary.LittleEndian.PutUint32(drive[4:], 2)
		caps = append(caps, drive...)
		return d.send(rdpdrPDU(wire.PakidCoreClientCapability, caps))
	case wire.PakidCoreUserLoggedon:
		d.mu.Lock()
		defer d.mu.Unlock()
		d.loggedOn = true
		if d.fs != nil && !d.announced {
			return d.announce()
		}
	case wire.PakidCoreDeviceIORequest:
		select {
		case d.queue <- append([]byte(nil), body...):
		default:
			return d.complete(body, ntUnsuccessful, make([]byte, 4))
		}
	}
	return nil
}

func (d *webDrive) worker() {
	for {
		select {
		case <-d.stop:
			return
		case body := <-d.queue:
			_ = d.io(body)
		}
	}
}

// complete answers the request whose DR_DEVICE_IOREQUEST body is req.
var driveDebug = os.Getenv("RDPGW_DRIVE_DEBUG") != ""

func (d *webDrive) complete(req []byte, status uint32, tail []byte) error {
	if driveDebug && len(req) >= 20 {
		log.Printf("webdrive: file %d major %#x minor %#x args % x -> status %#08x tail %d bytes",
			binary.LittleEndian.Uint32(req[4:]), binary.LittleEndian.Uint32(req[12:]), binary.LittleEndian.Uint32(req[16:]),
			req[20:min(len(req), 20+48)], status, len(tail))
	}
	b := make([]byte, 12, 12+len(tail))
	copy(b, req[0:4])      // DeviceId
	copy(b[4:], req[8:12]) // CompletionId
	binary.LittleEndian.PutUint32(b[8:], status)
	return d.send(rdpdrPDU(wire.PakidCoreDeviceIOCompletion, append(b, tail...)))
}

// winPath turns a drive-relative Windows path into a WebFS path.
func winPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = path.Clean("/" + p)
	return strings.TrimPrefix(p, "/")
}

func fileTimeOf(t time.Time) uint64 {
	if t.IsZero() {
		t = time.Unix(0, 0)
	}
	return uint64(t.UnixNano()/100) + 116444736000000000
}

func attrsOf(e FSEntry) uint32 {
	if e.Dir {
		return 0x10
	}
	return 0x20 // FILE_ATTRIBUTE_ARCHIVE
}

func (d *webDrive) io(body []byte) error {
	if len(body) < 20 {
		return nil
	}
	major := binary.LittleEndian.Uint32(body[12:])
	minor := binary.LittleEndian.Uint32(body[16:])
	fileID := binary.LittleEndian.Uint32(body[4:])
	args := body[20:]
	d.mu.Lock()
	fs := d.fs
	f := d.files[fileID]
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	u32 := func(off int) uint32 {
		if len(args) < off+4 {
			return 0
		}
		return binary.LittleEndian.Uint32(args[off:])
	}
	u64 := func(off int) uint64 {
		if len(args) < off+8 {
			return 0
		}
		return binary.LittleEndian.Uint64(args[off:])
	}
	if fs == nil {
		return d.complete(body, ntDeviceNotConnected, make([]byte, 5))
	}
	if major != wire.IRPMJCreate && f == nil {
		return d.complete(body, ntInvalidHandle, make([]byte, 5))
	}
	switch major {
	case wire.IRPMJCreate:
		disp, opts := u32(20), u32(24)
		n := u32(28)
		var name string
		if len(args) >= 32+int(n) {
			name = fromUTF16le(args[32 : 32+n])
		}
		id, info, status := d.create(ctx, fs, winPath(name), disp, opts)
		if driveDebug {
			log.Printf("webdrive: create %q disp %d opts %#x -> id %d status %#08x", name, disp, opts, id, status)
		}
		tail := binary.LittleEndian.AppendUint32(nil, id)
		return d.complete(body, status, append(tail, info))
	case wire.IRPMJClose:
		d.mu.Lock()
		delete(d.files, fileID)
		d.mu.Unlock()
		if f.deleteOnClose {
			_ = fs.Remove(ctx, f.path)
		}
		return d.complete(body, ntSuccess, make([]byte, 5))
	case wire.IRPMJRead:
		n, off := u32(0), u64(4)
		if n > 1<<20 {
			n = 1 << 20
		}
		if f.dir {
			return d.complete(body, ntFileIsDirectory, make([]byte, 4))
		}
		data, err := fs.Read(ctx, f.path, int64(off), int(n))
		if err != nil {
			return d.complete(body, ntStatus(err), make([]byte, 4))
		}
		tail := binary.LittleEndian.AppendUint32(nil, uint32(len(data)))
		return d.complete(body, ntSuccess, append(tail, data...))
	case wire.IRPMJWrite:
		n, off := u32(0), u64(4)
		if len(args) < 32+int(n) {
			return d.complete(body, ntUnsuccessful, make([]byte, 5))
		}
		if err := fs.Write(ctx, f.path, int64(off), args[32:32+n]); err != nil {
			return d.complete(body, ntStatus(err), make([]byte, 5))
		}
		return d.complete(body, ntSuccess, append(binary.LittleEndian.AppendUint32(nil, n), 0))
	case wire.IRPMJQueryInformation:
		e, err := fs.Stat(ctx, f.path)
		if err != nil {
			return d.complete(body, ntStatus(err), make([]byte, 4))
		}
		var buf []byte
		switch u32(0) {
		case 4: // FileBasicInformation
			t := fileTimeOf(e.Modified)
			buf = make([]byte, 36)
			for i := 0; i < 4; i++ {
				binary.LittleEndian.PutUint64(buf[8*i:], t)
			}
			binary.LittleEndian.PutUint32(buf[32:], attrsOf(e))
		case 5: // FileStandardInformation
			buf = make([]byte, 22)
			binary.LittleEndian.PutUint64(buf, uint64(alloc(e.Size)))
			binary.LittleEndian.PutUint64(buf[8:], uint64(e.Size))
			binary.LittleEndian.PutUint32(buf[16:], 1)
			if f.deleteOnClose {
				buf[20] = 1
			}
			if e.Dir {
				buf[21] = 1
			}
		case 35: // FileAttributeTagInformation
			buf = make([]byte, 8)
			binary.LittleEndian.PutUint32(buf, attrsOf(e))
		default:
			return d.complete(body, ntNotSupported, make([]byte, 4))
		}
		return d.complete(body, ntSuccess, append(binary.LittleEndian.AppendUint32(nil, uint32(len(buf))), buf...))
	case wire.IRPMJSetInformation:
		class, n := u32(0), u32(4)
		var set []byte
		if len(args) >= 32+int(n) {
			set = args[32 : 32+n]
		}
		status := uint32(ntSuccess)
		switch class {
		case 4, 19: // basic, allocation: accepted, not stored
		case 20: // FileEndOfFileInformation
			if len(set) >= 8 {
				status = ntStatus(fs.Truncate(ctx, f.path, int64(binary.LittleEndian.Uint64(set))))
			}
		case 13: // FileDispositionInformation
			del := len(set) == 0 || set[0] != 0
			if del && f.dir {
				if list, err := fs.List(ctx, f.path); err == nil && len(list) > 0 {
					status = ntDirNotEmpty
					break
				}
			}
			d.mu.Lock()
			f.deleteOnClose = del
			d.mu.Unlock()
		case 10: // FileRenameInformation
			if len(set) < 6 {
				status = ntUnsuccessful
				break
			}
			l := binary.LittleEndian.Uint32(set[2:])
			if len(set) < 6+int(l) {
				status = ntUnsuccessful
				break
			}
			to := winPath(fromUTF16le(set[6 : 6+l]))
			if err := fs.Rename(ctx, f.path, to, set[0] != 0); err != nil {
				status = ntStatus(err)
			} else {
				d.mu.Lock()
				f.path = to
				d.mu.Unlock()
			}
		default:
			status = ntNotSupported
		}
		return d.complete(body, status, append(binary.LittleEndian.AppendUint32(nil, n), 0))
	case wire.IRPMJQueryVolumeInformation:
		var buf []byte
		const total, free = 1 << 26, 1 << 25 // allocation units of 4 KiB: 256 GiB / 128 GiB
		switch u32(0) {
		case 1: // FileFsVolumeInformation
			// RDP omits FILE_FS_VOLUME_INFORMATION's trailing Reserved byte
			// (FreeRDP: "Reserved(1), MUST NOT be added!").
			label := utf16le(d.mounted(), false)
			buf = make([]byte, 17, 17+len(label))
			binary.LittleEndian.PutUint64(buf, fileTimeOf(time.Now()))
			binary.LittleEndian.PutUint32(buf[8:], 0x52445057)
			binary.LittleEndian.PutUint32(buf[12:], uint32(len(label)))
			buf = append(buf, label...)
		case 3: // FileFsSizeInformation
			buf = make([]byte, 24)
			binary.LittleEndian.PutUint64(buf, total)
			binary.LittleEndian.PutUint64(buf[8:], free)
			binary.LittleEndian.PutUint32(buf[16:], 8)
			binary.LittleEndian.PutUint32(buf[20:], 512)
		case 4: // FileFsDeviceInformation
			buf = make([]byte, 8)
			binary.LittleEndian.PutUint32(buf, 7) // FILE_DEVICE_DISK
		case 5: // FileFsAttributeInformation
			name := utf16le("NTFS", false)
			buf = make([]byte, 12, 12+len(name))
			binary.LittleEndian.PutUint32(buf, 0x00000003) // case sensitive search, case preserved names
			binary.LittleEndian.PutUint32(buf[4:], 255)
			binary.LittleEndian.PutUint32(buf[8:], uint32(len(name)))
			buf = append(buf, name...)
		case 7: // FileFsFullSizeInformation
			buf = make([]byte, 32)
			binary.LittleEndian.PutUint64(buf, total)
			binary.LittleEndian.PutUint64(buf[8:], free)
			binary.LittleEndian.PutUint64(buf[16:], free)
			binary.LittleEndian.PutUint32(buf[24:], 8)
			binary.LittleEndian.PutUint32(buf[28:], 512)
		default:
			return d.complete(body, ntNotSupported, make([]byte, 4))
		}
		return d.complete(body, ntSuccess, append(binary.LittleEndian.AppendUint32(nil, uint32(len(buf))), buf...))
	case wire.IRPMJDirectoryControl:
		if minor != wire.IRPMNQueryDirectory {
			return d.complete(body, ntNotSupported, make([]byte, 5))
		}
		class := u32(0)
		if len(args) > 4 && args[4] != 0 {
			n := binary.LittleEndian.Uint32(args[5:])
			var pattern string
			if len(args) >= 32+int(n) {
				pattern = fromUTF16le(args[32 : 32+n])
			}
			dir, glob := f.path, "*"
			if p := winPath(pattern); pattern != "" && strings.ContainsAny(path.Base(p), "*?") {
				dir, glob = path.Dir(p), path.Base(p)
				if dir == "." {
					dir = ""
				}
			} else if pattern != "" && p != f.path {
				dir, glob = path.Dir(p), path.Base(p)
				if dir == "." {
					dir = ""
				}
			}
			list, err := fs.List(ctx, dir)
			if err != nil {
				return d.complete(body, ntStatus(err), make([]byte, 5))
			}
			var keep []FSEntry
			for _, e := range list {
				if wildMatch(strings.ToLower(glob), strings.ToLower(e.Name)) {
					keep = append(keep, e)
				}
			}
			d.mu.Lock()
			f.entries = keep
			d.mu.Unlock()
			if len(keep) == 0 {
				return d.complete(body, wire.StatusNoSuchFile, make([]byte, 5))
			}
		}
		d.mu.Lock()
		if len(f.entries) == 0 {
			d.mu.Unlock()
			return d.complete(body, ntNoMoreFiles, make([]byte, 5))
		}
		e := f.entries[0]
		f.entries = f.entries[1:]
		d.mu.Unlock()
		buf, ok := dirEntry(class, e)
		if !ok {
			return d.complete(body, ntNotSupported, make([]byte, 5))
		}
		return d.complete(body, ntSuccess, append(binary.LittleEndian.AppendUint32(nil, uint32(len(buf))), buf...))
	case wire.IRPMJDeviceControl:
		return d.complete(body, ntInvalidDevReq, make([]byte, 4))
	case 0x11: // IRP_MJ_LOCK_CONTROL
		return d.complete(body, ntSuccess, make([]byte, 5))
	}
	return d.complete(body, ntNotImplemented, make([]byte, 5))
}

func alloc(size int64) int64 { return (size + 4095) &^ 4095 }

func dirEntry(class uint32, e FSEntry) ([]byte, bool) {
	name := utf16le(e.Name, false)
	if class == 12 { // FileNamesInformation
		b := make([]byte, 12, 12+len(name))
		binary.LittleEndian.PutUint32(b[8:], uint32(len(name)))
		return append(b, name...), true
	}
	base := 0
	switch class {
	case 1:
		base = 64
	case 2:
		base = 68
	case 3:
		base = 93
	default:
		return nil, false
	}
	b := make([]byte, base, base+len(name))
	t := fileTimeOf(e.Modified)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(b[8+8*i:], t)
	}
	binary.LittleEndian.PutUint64(b[40:], uint64(e.Size))
	binary.LittleEndian.PutUint64(b[48:], uint64(alloc(e.Size)))
	binary.LittleEndian.PutUint32(b[56:], attrsOf(e))
	binary.LittleEndian.PutUint32(b[60:], uint32(len(name)))
	return append(b, name...), true
}

// wildMatch implements the * and ? subset of Windows wildcards.
func wildMatch(pattern, name string) bool {
	if pattern == "*" || pattern == "*.*" {
		return true
	}
	p, n := []rune(pattern), []rune(name)
	var match func(i, j int) bool
	match = func(i, j int) bool {
		for i < len(p) {
			switch p[i] {
			case '*':
				for k := j; k <= len(n); k++ {
					if match(i+1, k) {
						return true
					}
				}
				return false
			case '?':
				if j >= len(n) {
					return false
				}
			default:
				if j >= len(n) || n[j] != p[i] {
					return false
				}
			}
			i++
			j++
		}
		return j == len(n)
	}
	return match(0, 0)
}

const (
	createDirectory     = 0x00000001
	createNonDirectory  = 0x00000040
	createDeleteOnClose = 0x00001000
)

func (d *webDrive) create(ctx context.Context, fs WebFS, p string, disp, opts uint32) (uint32, uint8, uint32) {
	// "file:stream" names an NTFS alternate data stream (Explorer probes
	// Zone.Identifier); browser folders have none and reject ':' in names.
	if strings.Contains(p, ":") {
		if disp == wire.FileOpen || disp == wire.FileOverwrite {
			return 0, 0, ntNameNotFound
		}
		return 0, 0, ntObjectNameInvalid
	}
	e, err := fs.Stat(ctx, p)
	exists := err == nil
	if err != nil && !errors.Is(err, FSErrNotFound) {
		return 0, 0, ntStatus(err)
	}
	if p == "" {
		exists, e.Dir = true, true
	}
	info := uint8(1) // FILE_OPENED
	wantDir := opts&createDirectory != 0
	switch {
	case exists && e.Dir && opts&createNonDirectory != 0:
		return 0, 0, ntFileIsDirectory
	case exists && !e.Dir && wantDir:
		return 0, 0, ntNotADirectory
	}
	switch disp {
	case wire.FileOpen:
		if !exists {
			return 0, 0, ntNameNotFound
		}
	case wire.FileCreate:
		if exists {
			return 0, 0, ntNameCollision
		}
	case wire.FileOverwrite:
		if !exists {
			return 0, 0, ntNameNotFound
		}
	}
	if !exists {
		if err := fs.Create(ctx, p, wantDir); err != nil {
			return 0, 0, ntStatus(err)
		}
		e, info = FSEntry{Dir: wantDir}, 2 // FILE_CREATED
	} else if !e.Dir && (disp == wire.FileOverwrite || disp == wire.FileOverwriteIf || disp == wire.FileSupersede) {
		if err := fs.Truncate(ctx, p, 0); err != nil {
			return 0, 0, ntStatus(err)
		}
		info = 3 // FILE_OVERWRITTEN
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nextFile++
	d.files[d.nextFile] = &webFile{path: p, dir: e.Dir, deleteOnClose: opts&createDeleteOnClose != 0}
	return d.nextFile, info, ntSuccess
}
