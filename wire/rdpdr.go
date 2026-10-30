package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"
)

// ErrRDPDR is returned for malformed device redirection (rdpdr) messages.
var ErrRDPDR = errors.New("invalid rdpdr pdu")

// RDPDR_HEADER components and packet ids (MS-RDPEFS 2.2.1.1).
const (
	RDPDRCtypCore = 0x4472
	RDPDRCtypPrn  = 0x5052

	PakidCoreServerAnnounce     = 0x496E
	PakidCoreClientidConfirm    = 0x4343
	PakidCoreClientName         = 0x434E
	PakidCoreDevicelistAnnounce = 0x4441
	PakidCoreDeviceReply        = 0x6472
	PakidCoreDeviceIORequest    = 0x4952
	PakidCoreDeviceIOCompletion = 0x4943
	PakidCoreServerCapability   = 0x5350
	PakidCoreClientCapability   = 0x4350
	PakidCoreDevicelistRemove   = 0x444D
	PakidCoreUserLoggedon       = 0x554C
)

// Device types (MS-RDPEFS 2.2.1.3).
const (
	RDPDRDtypSerial     = 0x00000001
	RDPDRDtypParallel   = 0x00000002
	RDPDRDtypPrint      = 0x00000004
	RDPDRDtypFilesystem = 0x00000008
	RDPDRDtypSmartcard  = 0x00000020
)

// Major functions (MS-RDPEFS 2.2.1.4).
const (
	IRPMJCreate                 = 0x00
	IRPMJClose                  = 0x02
	IRPMJRead                   = 0x03
	IRPMJWrite                  = 0x04
	IRPMJQueryInformation       = 0x05
	IRPMJSetInformation         = 0x06
	IRPMJQueryVolumeInformation = 0x0A
	IRPMJDirectoryControl       = 0x0C
	IRPMJDeviceControl          = 0x0E
)

// Minor function for IRP_MJ_DIRECTORY_CONTROL.
const (
	IRPMNQueryDirectory        = 0x01
	IRPMNNotifyChangeDirectory = 0x02
)

// CreateDisposition values (used in CREATE requests).
const (
	FileSupersede   = 0x00000000
	FileOpen        = 0x00000001
	FileCreate      = 0x00000002
	FileOpenIf      = 0x00000003
	FileOverwrite   = 0x00000004
	FileOverwriteIf = 0x00000005
)

// A subset of DesiredAccess / CreateOptions / attributes we use.
const (
	accessFileReadData       = 0x00000001
	accessFileListDirectory  = 0x00000001
	accessFileWriteData      = 0x00000002
	accessFileReadAttributes = 0x00000080
	accessDelete             = 0x00010000
	accessGenericRead        = 0x80000000
	accessSynchronize        = 0x00100000

	optionDirectoryFile         = 0x00000001
	optionSynchronousIONonalert = 0x00000020
	optionNonDirectoryFile      = 0x00000040
	optionDeleteOnClose         = 0x00001000

	fileAttributeDirectory = 0x00000010
	fileAttributeNormal    = 0x00000080
)

// FsInformationClass values we use.
const (
	FileDirectoryInformation     = 1
	FileFullDirectoryInformation = 2
	FileBothDirectoryInformation = 3
	FileNamesInformation         = 12
	FileDispositionInformation   = 13
)

// NTSTATUS values we check.
const (
	StatusSuccess     = 0x00000000
	StatusNoMoreFiles = 0x80000006
	StatusNoSuchFile  = 0xC000000F
)

// RDPDRHeader is the shared component/packet id.
type RDPDRHeader struct {
	Component uint16
	PacketID  uint16
}

// DecodeRDPDRHeader reads the shared header and returns the rest.
func DecodeRDPDRHeader(p []byte) (RDPDRHeader, []byte, error) {
	if len(p) < 4 {
		return RDPDRHeader{}, nil, fmt.Errorf("%w: header of %d bytes", ErrRDPDR, len(p))
	}
	return RDPDRHeader{
		Component: binary.LittleEndian.Uint16(p),
		PacketID:  binary.LittleEndian.Uint16(p[2:]),
	}, p[4:], nil
}

func encodeRDPDRHeader(packetID uint16) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b, RDPDRCtypCore)
	binary.LittleEndian.PutUint16(b[2:], uint16(packetID))
	return b
}

// RDPDRDevice is one announced device.
type RDPDRDevice struct {
	Type    uint32
	ID      uint32
	DosName string // trimmed PreferredDosName (e.g. "C:" or "PRN1")
	Label   string // filesystem volume label, when present
}

// DecodeDeviceAnnounce parses a DEVICELIST_ANNOUNCE body (after the header).
func DecodeDeviceAnnounce(p []byte) ([]RDPDRDevice, error) {
	if len(p) < 4 {
		return nil, fmt.Errorf("%w: device list of %d bytes", ErrRDPDR, len(p))
	}
	count := binary.LittleEndian.Uint32(p)
	p = p[4:]
	var out []RDPDRDevice
	for i := uint32(0); i < count; i++ {
		if len(p) < 20 {
			return nil, fmt.Errorf("%w: device %d truncated", ErrRDPDR, i)
		}
		d := RDPDRDevice{
			Type:    binary.LittleEndian.Uint32(p),
			ID:      binary.LittleEndian.Uint32(p[4:]),
			DosName: trimZ(string(p[8:16])),
		}
		dataLen := binary.LittleEndian.Uint32(p[16:])
		p = p[20:]
		if uint32(len(p)) < dataLen {
			return nil, fmt.Errorf("%w: device %d data truncated", ErrRDPDR, i)
		}
		data := p[:dataLen]
		p = p[dataLen:]
		if d.Type == RDPDRDtypFilesystem && len(data) >= 2 {
			d.Label = decodeUTF16(data)
		}
		out = append(out, d)
	}
	return out, nil
}

// DecodeDevicelistRemove parses the device ids a DEVICELIST_REMOVE drops.
func DecodeDevicelistRemove(p []byte) ([]uint32, error) {
	if len(p) < 4 {
		return nil, fmt.Errorf("%w: remove list of %d bytes", ErrRDPDR, len(p))
	}
	count := binary.LittleEndian.Uint32(p)
	p = p[4:]
	if count > uint32(len(p)/4) {
		return nil, fmt.Errorf("%w: remove list truncated", ErrRDPDR)
	}
	out := make([]uint32, count)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(p[i*4:])
	}
	return out, nil
}

// IORequest is a decoded DR_DEVICE_IOREQUEST with the fields of the functions
// we care about.
type IORequest struct {
	DeviceID, FileID, CompletionID uint32
	Major, Minor                   uint32
	Path                           string // CREATE, QUERY_DIRECTORY
	CreateDisposition              uint32
	Length                         uint32 // READ, WRITE
	Offset                         uint64
	FsInformationClass             uint32 // DIRECTORY_CONTROL, SET_INFORMATION
}

// DecodeIORequest parses a DR_DEVICE_IOREQUEST body (after the header).
func DecodeIORequest(p []byte) (IORequest, error) {
	if len(p) < 20 {
		return IORequest{}, fmt.Errorf("%w: io request of %d bytes", ErrRDPDR, len(p))
	}
	r := IORequest{
		DeviceID:     binary.LittleEndian.Uint32(p),
		FileID:       binary.LittleEndian.Uint32(p[4:]),
		CompletionID: binary.LittleEndian.Uint32(p[8:]),
		Major:        binary.LittleEndian.Uint32(p[12:]),
		Minor:        binary.LittleEndian.Uint32(p[16:]),
	}
	body := p[20:]
	switch r.Major {
	case IRPMJCreate:
		if len(body) < 32 {
			return r, nil
		}
		r.CreateDisposition = binary.LittleEndian.Uint32(body[20:])
		pathLen := binary.LittleEndian.Uint32(body[28:])
		if int(pathLen) <= len(body)-32 {
			r.Path = decodeUTF16(body[32 : 32+pathLen])
		}
	case IRPMJRead, IRPMJWrite:
		if len(body) >= 12 {
			r.Length = binary.LittleEndian.Uint32(body)
			r.Offset = binary.LittleEndian.Uint64(body[4:])
		}
	case IRPMJDirectoryControl:
		if r.Minor == IRPMNQueryDirectory && len(body) >= 32 {
			r.FsInformationClass = binary.LittleEndian.Uint32(body)
			pathLen := binary.LittleEndian.Uint32(body[5:])
			if int(pathLen) <= len(body)-32 {
				r.Path = decodeUTF16(body[32 : 32+pathLen])
			}
		}
	case IRPMJSetInformation:
		if len(body) >= 4 {
			r.FsInformationClass = binary.LittleEndian.Uint32(body)
		}
	}
	return r, nil
}

// IOCompletion is a decoded DR_DEVICE_IOCOMPLETION header; Tail is the
// function-specific remainder, interpreted against the matching request.
type IOCompletion struct {
	DeviceID, CompletionID, IoStatus uint32
	Tail                             []byte
}

// DecodeIOCompletion parses a DR_DEVICE_IOCOMPLETION body (after the header).
func DecodeIOCompletion(p []byte) (IOCompletion, error) {
	if len(p) < 12 {
		return IOCompletion{}, fmt.Errorf("%w: io completion of %d bytes", ErrRDPDR, len(p))
	}
	return IOCompletion{
		DeviceID:     binary.LittleEndian.Uint32(p),
		CompletionID: binary.LittleEndian.Uint32(p[4:]),
		IoStatus:     binary.LittleEndian.Uint32(p[8:]),
		Tail:         p[12:],
	}, nil
}

// ParseCreateResponse reads a CREATE completion tail (FileId, Information).
func ParseCreateResponse(tail []byte) (fileID uint32, information uint8, err error) {
	if len(tail) < 4 {
		return 0, 0, fmt.Errorf("%w: create response of %d bytes", ErrRDPDR, len(tail))
	}
	fileID = binary.LittleEndian.Uint32(tail)
	if len(tail) >= 5 {
		information = tail[4]
	}
	return fileID, information, nil
}

// ParseReadResponse reads a READ completion tail (Length, ReadData).
func ParseReadResponse(tail []byte) ([]byte, error) {
	if len(tail) < 4 {
		return nil, fmt.Errorf("%w: read response of %d bytes", ErrRDPDR, len(tail))
	}
	n := binary.LittleEndian.Uint32(tail)
	if uint64(n) > uint64(len(tail)-4) {
		return nil, ErrRDPDR
	}
	return tail[4 : 4+n], nil
}

// ParseWriteResponse reads a WRITE completion tail (Length).
func ParseWriteResponse(tail []byte) (uint32, error) {
	if len(tail) < 4 {
		return 0, fmt.Errorf("%w: write response of %d bytes", ErrRDPDR, len(tail))
	}
	return binary.LittleEndian.Uint32(tail), nil
}

// FileEntry is one directory entry from a QUERY_DIRECTORY completion.
type FileEntry struct {
	Name       string
	Size       int64
	Attributes uint32
	IsDir      bool
	Modified   time.Time
}

// ParseDirectoryResponse reads a QUERY_DIRECTORY completion tail of
// FILE_BOTH_DIR_INFORMATION entries (FsInformationClass 3).
func ParseDirectoryResponse(tail []byte) ([]FileEntry, error) {
	return ParseDirectoryEntries(tail, FileBothDirectoryInformation)
}

func ParseDirectoryEntries(tail []byte, class uint32) ([]FileEntry, error) {
	base := 64
	if class == FileBothDirectoryInformation {
		base = 93
	} else if class != FileDirectoryInformation {
		return nil, ErrRDPDR
	}
	if len(tail) < 4 {
		return nil, fmt.Errorf("%w: directory response of %d bytes", ErrRDPDR, len(tail))
	}
	n := binary.LittleEndian.Uint32(tail)
	buf := tail[4:]
	if uint64(n) > uint64(len(buf)) {
		return nil, ErrRDPDR
	}
	buf = buf[:n]
	var out []FileEntry
	for off := 0; off < len(buf); {
		e := buf[off:]
		if len(e) < base {
			return nil, ErrRDPDR
		}
		next := binary.LittleEndian.Uint32(e)
		writeTime := int64(binary.LittleEndian.Uint64(e[24:]))
		size := int64(binary.LittleEndian.Uint64(e[40:]))
		attrs := binary.LittleEndian.Uint32(e[56:])
		nameLen := binary.LittleEndian.Uint32(e[60:])
		if nameLen%2 != 0 || uint64(nameLen) > uint64(len(e)-base) {
			return nil, ErrRDPDR
		}
		if next != 0 && (uint64(next) < uint64(base)+uint64(nameLen) || uint64(next) >= uint64(len(e))) {
			return nil, ErrRDPDR
		}
		name := decodeUTF16(e[base : base+int(nameLen)])
		if name != "." && name != ".." {
			out = append(out, FileEntry{
				Name:       name,
				Size:       size,
				Attributes: attrs,
				IsDir:      attrs&fileAttributeDirectory != 0,
				Modified:   fileTime(writeTime),
			})
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
	return out, nil
}

// --- encoders for requests the gateway injects towards the client ---

func encodeIOHeader(packetID uint16, deviceID, fileID, completionID, major, minor uint32) []byte {
	b := append(encodeRDPDRHeader(packetID), make([]byte, 20)...)
	binary.LittleEndian.PutUint32(b[4:], deviceID)
	binary.LittleEndian.PutUint32(b[8:], fileID)
	binary.LittleEndian.PutUint32(b[12:], completionID)
	binary.LittleEndian.PutUint32(b[16:], major)
	binary.LittleEndian.PutUint32(b[20:], minor)
	return b
}

// EncodeCreate builds an IRP_MJ_CREATE request (FileId is 0, the client
// assigns it in the reply). The path is relative to the device root and
// starts with a backslash (e.g. "\\dir\\file.txt").
func EncodeCreate(deviceID, completionID uint32, path string, desiredAccess, disposition, options uint32) []byte {
	name := encodeUTF16z(path)
	// DR_CREATE_REQ: DesiredAccess u32, AllocationSize u64, FileAttributes
	// u32, SharedAccess u32, CreateDisposition u32, CreateOptions u32,
	// PathLength u32, Path[PathLength].
	body := make([]byte, 32+len(name))
	binary.LittleEndian.PutUint32(body[0:], desiredAccess)
	binary.LittleEndian.PutUint32(body[16:], 0x00000007) // FILE_SHARE_READ|WRITE|DELETE
	binary.LittleEndian.PutUint32(body[20:], disposition)
	binary.LittleEndian.PutUint32(body[24:], options)
	binary.LittleEndian.PutUint32(body[28:], uint32(len(name)))
	copy(body[32:], name)
	return append(encodeIOHeader(PakidCoreDeviceIORequest, deviceID, 0, completionID, IRPMJCreate, 0), body...)
}

// EncodeRead builds an IRP_MJ_READ request.
func EncodeRead(deviceID, fileID, completionID, length uint32, offset uint64) []byte {
	body := make([]byte, 32)
	binary.LittleEndian.PutUint32(body, length)
	binary.LittleEndian.PutUint64(body[4:], offset)
	return append(encodeIOHeader(PakidCoreDeviceIORequest, deviceID, fileID, completionID, IRPMJRead, 0), body...)
}

// EncodeWrite builds an IRP_MJ_WRITE request carrying data.
func EncodeWrite(deviceID, fileID, completionID uint32, offset uint64, data []byte) []byte {
	body := make([]byte, 32+len(data))
	binary.LittleEndian.PutUint32(body, uint32(len(data)))
	binary.LittleEndian.PutUint64(body[4:], offset)
	copy(body[32:], data)
	return append(encodeIOHeader(PakidCoreDeviceIORequest, deviceID, fileID, completionID, IRPMJWrite, 0), body...)
}

// EncodeClose builds an IRP_MJ_CLOSE request.
func EncodeClose(deviceID, fileID, completionID uint32) []byte {
	return append(encodeIOHeader(PakidCoreDeviceIORequest, deviceID, fileID, completionID, IRPMJClose, 0), make([]byte, 32)...)
}

// EncodeQueryDirectory builds an IRP_MJ_DIRECTORY_CONTROL / QUERY_DIRECTORY
// request. On the first call for a handle initial is true and path is the
// search pattern (e.g. "*"); later calls repeat with initial false.
func EncodeQueryDirectory(deviceID, fileID, completionID, infoClass uint32, initial bool, path string) []byte {
	var name []byte
	if initial {
		name = encodeUTF16z(path)
	}
	body := make([]byte, 32+len(name))
	binary.LittleEndian.PutUint32(body, infoClass)
	if initial {
		body[4] = 1
	}
	binary.LittleEndian.PutUint32(body[5:], uint32(len(name)))
	copy(body[32:], name)
	return append(encodeIOHeader(PakidCoreDeviceIORequest, deviceID, fileID, completionID, IRPMJDirectoryControl, IRPMNQueryDirectory), body...)
}

// EncodeSetDisposition builds an IRP_MJ_SET_INFORMATION /
// FileDispositionInformation request that marks the open file for deletion.
func EncodeSetDisposition(deviceID, fileID, completionID uint32) []byte {
	// MS-RDPEFS 2.2.3.3.9: an empty SetBuffer implies DeletePending=1.
	body := make([]byte, 32)
	binary.LittleEndian.PutUint32(body, FileDispositionInformation)
	return append(encodeIOHeader(PakidCoreDeviceIORequest, deviceID, fileID, completionID, IRPMJSetInformation, 0), body...)
}

// DirectoryAccess and friends are the argument bundles the drive manager uses
// so callers don't repeat the flag maths.
const (
	AccessListDir  = accessFileListDirectory | accessFileReadAttributes | accessSynchronize
	AccessReadFile = accessGenericRead | accessSynchronize
	AccessWriteNew = accessFileWriteData | accessFileReadAttributes | accessSynchronize
	AccessDelete   = accessDelete | accessFileReadAttributes | accessSynchronize

	OptionsDir        = optionDirectoryFile | optionSynchronousIONonalert
	OptionsFile       = optionNonDirectoryFile | optionSynchronousIONonalert
	OptionsDeleteFile = optionNonDirectoryFile | optionSynchronousIONonalert | optionDeleteOnClose
)

// --- helpers ---

func trimZ(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return s[:i]
		}
	}
	return s
}

func decodeUTF16(b []byte) string {
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

func encodeUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

func encodeUTF16z(s string) []byte {
	return append(encodeUTF16(s), 0, 0)
}

func fileTime(ft int64) time.Time {
	const unixEpochTicks = 116444736000000000 // 100ns intervals from 1601 to 1970
	if ft <= unixEpochTicks {
		return time.Time{}
	}
	ticks := ft - unixEpochTicks
	return time.Unix(ticks/10000000, (ticks%10000000)*100).UTC()
}
