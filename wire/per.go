package wire

import (
	"errors"
	"fmt"
)

// Helpers for the ALIGNED variant of BASIC-PER (ITU-T X.691) as used by the
// T.124 GCC connect data and the T.125 domain PDUs. Only unfragmented length
// determinants (< 16384) are supported; RDP connection PDUs never exceed that.

var ErrPER = errors.New("invalid PER")

func perLength(n int) ([]byte, error) {
	switch {
	case n < 0:
		return nil, fmt.Errorf("%w: negative length", ErrPER)
	case n < 0x80:
		return []byte{byte(n)}, nil
	case n < 0x4000:
		return []byte{0x80 | byte(n>>8), byte(n)}, nil
	default:
		return nil, fmt.Errorf("%w: length %d requires fragmentation", ErrPER, n)
	}
}

func perReadLength(p []byte) (int, []byte, error) {
	if len(p) == 0 {
		return 0, nil, fmt.Errorf("%w: missing length", ErrPER)
	}
	if p[0]&0x80 == 0 {
		return int(p[0]), p[1:], nil
	}
	if p[0]&0x40 != 0 {
		return 0, nil, fmt.Errorf("%w: fragmented length not supported", ErrPER)
	}
	if len(p) < 2 {
		return 0, nil, fmt.Errorf("%w: truncated length", ErrPER)
	}
	return int(p[0]&0x3f)<<8 | int(p[1]), p[2:], nil
}

func perReadBytes(p []byte, n int) ([]byte, []byte, error) {
	if n < 0 || n > len(p) {
		return nil, nil, fmt.Errorf("%w: need %d bytes, have %d", ErrPER, n, len(p))
	}
	return p[:n], p[n:], nil
}
