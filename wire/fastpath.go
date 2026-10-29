package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Fast-Path output (2.2.9.1.2): TS_FP_UPDATE_PDU carrying TS_FP_UPDATE
// structures. Only the unencrypted form used with Enhanced RDP Security is
// accepted; bulk-compressed updates are reported, not decompressed, because
// the client never advertises compression.

// ErrFastPath wraps fast-path framing failures.
var ErrFastPath = errors.New("invalid fast-path PDU")

// fpOutputHeader action and flags (2.2.9.1.2).
const (
	FastPathActionFastPath = 0x0
	FastPathActionX224     = 0x3

	FastPathOutputSecureChecksum = 0x1
	FastPathOutputEncrypted      = 0x2
)

// TS_FP_UPDATE updateCode values (2.2.9.1.2.1).
const (
	FastPathUpdateOrders       uint8 = 0x0
	FastPathUpdateBitmap       uint8 = 0x1
	FastPathUpdatePalette      uint8 = 0x2
	FastPathUpdateSynchronize  uint8 = 0x3
	FastPathUpdateSurfCmds     uint8 = 0x4
	FastPathUpdatePtrNull      uint8 = 0x5
	FastPathUpdatePtrDefault   uint8 = 0x6
	FastPathUpdatePtrPosition  uint8 = 0x8
	FastPathUpdateColor        uint8 = 0x9
	FastPathUpdateCached       uint8 = 0xA
	FastPathUpdatePointer      uint8 = 0xB
	FastPathUpdateLargePointer uint8 = 0xC

	FastPathFragmentSingle uint8 = 0
	FastPathFragmentLast   uint8 = 1
	FastPathFragmentFirst  uint8 = 2
	FastPathFragmentNext   uint8 = 3

	fastPathCompressionUsed = 0x2 // compression field of updateHeader
)

// MaxFastPathPDUSize is the largest encodable TS_FP_UPDATE_PDU (15-bit length).
const MaxFastPathPDUSize = 0x7FFF

// FastPathUpdate is one TS_FP_UPDATE. Data is the updateData, still
// fragmented and (if Compressed) still bulk-compressed.
type FastPathUpdate struct {
	Code             uint8
	Fragmentation    uint8
	Compressed       bool
	CompressionFlags uint8
	Data             []byte
}

// FastPathPDU is a decoded TS_FP_UPDATE_PDU.
type FastPathPDU struct {
	Flags   uint8 // fpOutputHeader flags (FastPathOutput*)
	Updates []FastPathUpdate
}

// IsFastPathHeader reports whether a first byte read from the server starts
// a fast-path PDU (action FASTPATH_OUTPUT_ACTION_FASTPATH) rather than a
// TPKT header (version 3, which doubles as FASTPATH_OUTPUT_ACTION_X224).
func IsFastPathHeader(b byte) bool { return b&0x03 == FastPathActionFastPath }

// ReadFastPathPDU reads the rest of a TS_FP_UPDATE_PDU whose fpOutputHeader
// byte has already been consumed, bounding the whole PDU by maxSize (zero
// means MaxFastPathPDUSize), and decodes it.
func ReadFastPathPDU(r io.Reader, header byte, maxSize int) (FastPathPDU, error) {
	if maxSize <= 0 || maxSize > MaxFastPathPDUSize {
		maxSize = MaxFastPathPDUSize
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:1]); err != nil {
		return FastPathPDU{}, fmt.Errorf("read fast-path length: %w", err)
	}
	size, hdr := int(l[0]), 2
	if l[0]&0x80 != 0 {
		if _, err := io.ReadFull(r, l[1:]); err != nil {
			return FastPathPDU{}, fmt.Errorf("read fast-path length: %w", err)
		}
		size, hdr = int(l[0]&0x7F)<<8|int(l[1]), 3
	}
	if size < hdr || size > maxSize {
		return FastPathPDU{}, fmt.Errorf("%w: length %d outside [%d, %d]", ErrFastPath, size, hdr, maxSize)
	}
	pdu := make([]byte, size)
	pdu[0] = header
	copy(pdu[1:], l[:hdr-1])
	if _, err := io.ReadFull(r, pdu[hdr:]); err != nil {
		return FastPathPDU{}, fmt.Errorf("read fast-path payload: %w", err)
	}
	return DecodeFastPathPDU(pdu)
}

// DecodeFastPathPDU parses a complete TS_FP_UPDATE_PDU.
func DecodeFastPathPDU(pdu []byte) (FastPathPDU, error) {
	var fp FastPathPDU
	if len(pdu) < 2 {
		return fp, fmt.Errorf("%w: %d bytes", ErrFastPath, len(pdu))
	}
	if action := pdu[0] & 0x03; action != FastPathActionFastPath {
		return fp, fmt.Errorf("%w: action %d", ErrFastPath, action)
	}
	fp.Flags = pdu[0] >> 6
	if fp.Flags&FastPathOutputEncrypted != 0 {
		return fp, fmt.Errorf("%w: FASTPATH_OUTPUT_ENCRYPTED set under TLS", ErrFastPath)
	}
	size, hdr := int(pdu[1]), 2
	if pdu[1]&0x80 != 0 {
		if len(pdu) < 3 {
			return fp, fmt.Errorf("%w: truncated length", ErrFastPath)
		}
		size, hdr = int(pdu[1]&0x7F)<<8|int(pdu[2]), 3
	}
	if size != len(pdu) {
		return fp, fmt.Errorf("%w: length %d, got %d bytes", ErrFastPath, size, len(pdu))
	}
	rest := pdu[hdr:]
	for len(rest) > 0 {
		var u FastPathUpdate
		u.Code = rest[0] & 0x0F
		u.Fragmentation = rest[0] >> 4 & 0x03
		u.Compressed = rest[0]>>6 == fastPathCompressionUsed
		rest = rest[1:]
		if u.Compressed {
			if len(rest) < 1 {
				return fp, fmt.Errorf("%w: update 0x%x truncated compressionFlags", ErrFastPath, u.Code)
			}
			u.CompressionFlags, rest = rest[0], rest[1:]
		}
		if len(rest) < 2 {
			return fp, fmt.Errorf("%w: update 0x%x truncated size", ErrFastPath, u.Code)
		}
		n := int(binary.LittleEndian.Uint16(rest))
		rest = rest[2:]
		if n > len(rest) {
			return fp, fmt.Errorf("%w: update 0x%x declares %d bytes, %d available", ErrFastPath, u.Code, n, len(rest))
		}
		u.Data, rest = rest[:n], rest[n:]
		fp.Updates = append(fp.Updates, u)
	}
	if len(fp.Updates) == 0 {
		return fp, fmt.Errorf("%w: no updates", ErrFastPath)
	}
	return fp, nil
}

// FastPathUpdateName names an updateCode for reports.
func FastPathUpdateName(code uint8) string {
	switch code {
	case FastPathUpdateOrders:
		return "orders"
	case FastPathUpdateBitmap:
		return "bitmap"
	case FastPathUpdatePalette:
		return "palette"
	case FastPathUpdateSynchronize:
		return "synchronize"
	case FastPathUpdateSurfCmds:
		return "surfcmds"
	case FastPathUpdatePtrNull:
		return "ptr-null"
	case FastPathUpdatePtrDefault:
		return "ptr-default"
	case FastPathUpdatePtrPosition:
		return "ptr-position"
	case FastPathUpdateColor:
		return "ptr-color"
	case FastPathUpdateCached:
		return "ptr-cached"
	case FastPathUpdatePointer:
		return "ptr-new"
	case FastPathUpdateLargePointer:
		return "ptr-large"
	}
	return fmt.Sprintf("0x%x", code)
}

// IsFastPathPointer reports whether an updateCode is a pointer update.
func IsFastPathPointer(code uint8) bool {
	switch code {
	case FastPathUpdatePtrNull, FastPathUpdatePtrDefault, FastPathUpdatePtrPosition,
		FastPathUpdateColor, FastPathUpdateCached, FastPathUpdatePointer, FastPathUpdateLargePointer:
		return true
	}
	return false
}

// DecodeFastPathPointer converts a fast-path pointer update (2.2.9.1.2.1.5
// to 2.2.9.1.2.1.11) into the slow-path Pointer representation.
func DecodeFastPathPointer(code uint8, data []byte) (Pointer, error) {
	switch code {
	case FastPathUpdatePtrNull:
		return Pointer{Type: PointerTypeSystem, SystemType: SystemPointerNull}, nil
	case FastPathUpdatePtrDefault:
		return Pointer{Type: PointerTypeSystem, SystemType: SystemPointerDefault}, nil
	case FastPathUpdatePtrPosition:
		return decodePointer(PointerTypePosition, data)
	case FastPathUpdateColor:
		return decodePointer(PointerTypeColor, data)
	case FastPathUpdateCached:
		return decodePointer(PointerTypeCached, data)
	case FastPathUpdatePointer:
		return decodePointer(PointerTypeNew, data)
	case FastPathUpdateLargePointer:
		return decodePointer(PointerTypeLarge, data)
	}
	return Pointer{}, fmt.Errorf("%w: updateCode 0x%x is not a pointer update", ErrFastPath, code)
}

// FastPathOrdersCount returns numberOrders of a TS_FP_UPDATE_ORDERS
// (2.2.9.1.2.1.1); the order stream itself is not parsed.
func FastPathOrdersCount(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("%w: orders update %d bytes", ErrFastPath, len(data))
	}
	return binary.LittleEndian.Uint16(data), nil
}
