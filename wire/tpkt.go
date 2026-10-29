package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	TPKTHeaderSize = 4
	MinTPKTSize    = 7
	MaxTPKTSize    = 65535
)

var ErrTPKT = errors.New("invalid TPKT")

// ReadTPKT reads exactly one TPDU, leaving any following packet unread.
// maxSize bounds the entire packet before allocation; zero uses the protocol limit.
func ReadTPKT(r io.Reader, maxSize int) ([]byte, error) {
	if maxSize == 0 {
		maxSize = MaxTPKTSize
	}
	if maxSize < MinTPKTSize || maxSize > MaxTPKTSize {
		return nil, fmt.Errorf("%w: invalid size limit %d", ErrTPKT, maxSize)
	}
	var header [TPKTHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read TPKT header: %w", err)
	}
	if header[0] != 3 {
		return nil, fmt.Errorf("%w: version %d", ErrTPKT, header[0])
	}
	size := int(binary.BigEndian.Uint16(header[2:]))
	if size < MinTPKTSize || size > maxSize {
		return nil, fmt.Errorf("%w: size %d outside [%d, %d]", ErrTPKT, size, MinTPKTSize, maxSize)
	}
	payload := make([]byte, size-TPKTHeaderSize)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read TPKT payload: %w", err)
	}
	return payload, nil
}

func EncodeTPKT(payload []byte) ([]byte, error) {
	if len(payload) < MinTPKTSize-TPKTHeaderSize || len(payload) > MaxTPKTSize-TPKTHeaderSize {
		return nil, fmt.Errorf("%w: payload size %d", ErrTPKT, len(payload))
	}
	packet := make([]byte, TPKTHeaderSize+len(payload))
	packet[0] = 3
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[TPKTHeaderSize:], payload)
	return packet, nil
}

func WriteTPKT(w io.Writer, payload []byte) error {
	packet, err := EncodeTPKT(payload)
	if err != nil {
		return err
	}
	for len(packet) > 0 {
		n, err := w.Write(packet)
		if n < 0 || n > len(packet) {
			return io.ErrShortWrite
		}
		if err != nil {
			return fmt.Errorf("write TPKT: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}
