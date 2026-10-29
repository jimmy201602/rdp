package wire

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// ReadFastPathFrame reads one complete fast-path PDU (input or output) from
// r and returns its raw bytes including the header and length octets, so
// that a relay can forward it unchanged. The caller must have peeked that
// the next byte is a fast-path header (IsFastPathHeader). Encrypted PDUs
// (FASTPATH_*_ENCRYPTED) are refused: Enhanced RDP Security never sets them.
func ReadFastPathFrame(r *bufio.Reader, maxSize int) ([]byte, error) {
	if maxSize <= 0 || maxSize > MaxFastPathPDUSize {
		maxSize = MaxFastPathPDUSize
	}
	hdr, err := r.Peek(2)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrFastPath, err)
	}
	if !IsFastPathHeader(hdr[0]) {
		return nil, fmt.Errorf("%w: header byte 0x%02x is not fast-path", ErrFastPath, hdr[0])
	}
	if hdr[0]>>6&FastPathOutputEncrypted != 0 {
		return nil, fmt.Errorf("%w: encrypted fast-path PDU", ErrFastPath)
	}
	size, lenOctets := int(hdr[1]), 1
	if hdr[1]&0x80 != 0 {
		if hdr, err = r.Peek(3); err != nil {
			return nil, fmt.Errorf("%w: length: %v", ErrFastPath, err)
		}
		size, lenOctets = int(binary.BigEndian.Uint16(hdr[1:])&0x7fff), 2
	}
	if size < 1+lenOctets || size > maxSize {
		return nil, fmt.Errorf("%w: length %d outside [%d, %d]", ErrFastPath, size, 1+lenOctets, maxSize)
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrFastPath, err)
	}
	return frame, nil
}
