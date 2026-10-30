package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrClip is returned for malformed clipboard (cliprdr) messages.
var ErrClip = errors.New("invalid cliprdr pdu")

// CLIPRDR_HEADER msgType values (MS-RDPECLIP 2.2.1).
const (
	CBMonitorReady         = 0x0001
	CBFormatList           = 0x0002
	CBFormatListResponse   = 0x0003
	CBFormatDataRequest    = 0x0004
	CBFormatDataResponse   = 0x0005
	CBTempDirectory        = 0x0006
	CBClipCaps             = 0x0007
	CBFilecontentsRequest  = 0x0008
	CBFilecontentsResponse = 0x0009
	CBLockClipdata         = 0x000A
	CBUnlockClipdata       = 0x000B
)

// CLIPRDR_HEADER msgFlags.
const (
	CBResponseOK   = 0x0001
	CBResponseFail = 0x0002
	CBASCIINames   = 0x0004
)

// Standard clipboard format ids.
const (
	CFText        = 1
	CFUnicodeText = 13
)

// ClipHeader is the shared CLIPRDR_HEADER.
type ClipHeader struct {
	MsgType  uint16
	MsgFlags uint16
	DataLen  uint32
}

// DecodeClipHeader reads a CLIPRDR_HEADER and returns the payload bytes
// (clamped to DataLen when present).
func DecodeClipHeader(p []byte) (ClipHeader, []byte, error) {
	if len(p) < 8 {
		return ClipHeader{}, nil, fmt.Errorf("%w: header of %d bytes", ErrClip, len(p))
	}
	h := ClipHeader{
		MsgType:  binary.LittleEndian.Uint16(p),
		MsgFlags: binary.LittleEndian.Uint16(p[2:]),
		DataLen:  binary.LittleEndian.Uint32(p[4:]),
	}
	body := p[8:]
	if uint64(h.DataLen) > uint64(len(body)) {
		return ClipHeader{}, nil, ErrClip
	}
	body = body[:h.DataLen]
	return h, body, nil
}

// ClipFormat is one offered clipboard format.
type ClipFormat struct {
	ID   uint32
	Name string
}

// DecodeFormatList parses a CB_FORMAT_LIST body. longNames selects the
// CLIPRDR_LONG_FORMAT_NAMES layout (formatId u32 + null-terminated unicode
// name); otherwise the short layout (formatId u32 + 32-byte name). Parsing is
// lenient: it returns the formats decoded so far on a short read.
func DecodeFormatList(body []byte, longNames bool) []ClipFormat {
	var out []ClipFormat
	for len(body) >= 4 {
		id := binary.LittleEndian.Uint32(body)
		body = body[4:]
		var name string
		if longNames {
			var n int
			name, n = readUTF16z(body)
			if n > len(body) {
				break
			}
			body = body[n:]
		} else {
			if len(body) < 32 {
				break
			}
			name = decodeUTF16(body[:32])
			body = body[32:]
		}
		out = append(out, ClipFormat{ID: id, Name: name})
	}
	return out
}

// HasFileList reports whether a format list offers a file descriptor group.
func HasFileList(formats []ClipFormat) bool {
	for _, f := range formats {
		if f.Name == "FileGroupDescriptorW" || f.Name == "FileGroupDescriptor" {
			return true
		}
	}
	return false
}

// HasText reports whether a format list offers plain or unicode text.
func HasText(formats []ClipFormat) bool {
	for _, f := range formats {
		if f.ID == CFText || f.ID == CFUnicodeText {
			return true
		}
	}
	return false
}

// DecodeFormatDataRequest reads the requested format id.
func DecodeFormatDataRequest(body []byte) (uint32, error) {
	if len(body) < 4 {
		return 0, fmt.Errorf("%w: data request of %d bytes", ErrClip, len(body))
	}
	return binary.LittleEndian.Uint32(body), nil
}

// ClipFile is one entry of a copied file group.
type ClipFile struct {
	Name string
	Size int64
}

// DecodeFileList parses a CLIPRDR_FILELIST (the data of a FileGroupDescriptorW
// format data response): cItems u32 then that many 592-byte descriptors.
func DecodeFileList(body []byte) ([]ClipFile, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("%w: file list of %d bytes", ErrClip, len(body))
	}
	count := binary.LittleEndian.Uint32(body)
	body = body[4:]
	const descLen = 592
	var out []ClipFile
	for i := uint32(0); i < count && len(body) >= descLen; i++ {
		d := body[:descLen]
		body = body[descLen:]
		hi := uint64(binary.LittleEndian.Uint32(d[64:]))
		lo := uint64(binary.LittleEndian.Uint32(d[68:]))
		out = append(out, ClipFile{
			Name: decodeUTF16(d[72 : 72+520]),
			Size: int64(hi<<32 | lo),
		})
	}
	return out, nil
}

// readUTF16z decodes a null-terminated UTF-16LE string and returns the bytes
// consumed (including the two-byte terminator).
func readUTF16z(b []byte) (string, int) {
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			return decodeUTF16(b[:i]), i + 2
		}
	}
	return decodeUTF16(b), len(b)
}
