package wire

import (
	"errors"
	"fmt"
)

// Minimal ITU-T X.690 BER helpers for the definite-length encodings used by
// the T.125 Connect-Initial / Connect-Response PDUs.

var ErrBER = errors.New("invalid BER")

const (
	berBoolean     = 0x01
	berInteger     = 0x02
	berOctetString = 0x04
	berEnumerated  = 0x0a
	berSequence    = 0x30
)

func berLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xff:
		return []byte{0x81, byte(n)}
	case n <= 0xffff:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func berElement(tag []byte, value []byte) []byte {
	out := make([]byte, 0, len(tag)+4+len(value))
	out = append(out, tag...)
	out = append(out, berLength(len(value))...)
	return append(out, value...)
}

// berInt encodes v as an unsigned INTEGER without a sign-padding octet, the
// form used by the MS-RDPBCGR 4.1.3 Connect-Initial dump (e.g. 65535 as
// 02 02 ff ff). berReadUint accepts both this and the sign-padded form.
func berInt(v uint32) []byte {
	var raw [5]byte
	n := 0
	for i := 3; i >= 0; i-- {
		b := byte(v >> (8 * i))
		if n == 0 && b == 0 && i > 0 {
			continue
		}
		raw[n] = b
		n++
	}
	return berElement([]byte{berInteger}, raw[:n])
}

// berRead parses one TLV at the start of p, requiring the given tag bytes.
func berRead(p []byte, tag []byte) (value, rest []byte, err error) {
	if len(p) < len(tag)+1 {
		return nil, nil, fmt.Errorf("%w: truncated element", ErrBER)
	}
	for i, b := range tag {
		if p[i] != b {
			return nil, nil, fmt.Errorf("%w: expected tag %x, got %x", ErrBER, tag, p[:len(tag)])
		}
	}
	p = p[len(tag):]
	first := int(p[0])
	p = p[1:]
	length := first
	if first&0x80 != 0 {
		n := first & 0x7f
		if n == 0 || n > 3 || len(p) < n {
			return nil, nil, fmt.Errorf("%w: unsupported length form 0x%02x", ErrBER, first)
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | int(p[i])
		}
		p = p[n:]
	}
	if length > len(p) {
		return nil, nil, fmt.Errorf("%w: length %d exceeds %d available bytes", ErrBER, length, len(p))
	}
	return p[:length], p[length:], nil
}

func berReadUint(p []byte, tag byte) (uint32, []byte, error) {
	value, rest, err := berRead(p, []byte{tag})
	if err != nil {
		return 0, nil, err
	}
	if len(value) == 0 || len(value) > 5 || (len(value) == 5 && value[0] != 0) {
		return 0, nil, fmt.Errorf("%w: integer length %d", ErrBER, len(value))
	}
	var v uint32
	for _, b := range value {
		v = v<<8 | uint32(b)
	}
	return v, rest, nil
}

// berIntCanonical encodes v as a canonical X.690 INTEGER (a leading zero
// octet when the top bit is set), the form Windows servers use in the MCS
// Connect-Response (MS-RDPBCGR 4.1.4 encodes 65528 as 02 03 00 ff f8).
func berIntCanonical(v uint32) []byte {
	var b []byte
	for v > 0x7f {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	b = append([]byte{byte(v)}, b...)
	return berElement([]byte{berInteger}, b)
}
