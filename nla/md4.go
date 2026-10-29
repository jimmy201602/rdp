package nla

import (
	"encoding/binary"
	"math/bits"
)

// md4Sum implements RFC 1320 solely for NTLM's password-derived key.
// MD4 must not be used as a general-purpose cryptographic hash.
func md4Sum(p []byte) [16]byte {
	n := len(p)
	data := make([]byte, (n+9+63)/64*64)
	copy(data, p)
	data[n] = 0x80
	binary.LittleEndian.PutUint64(data[len(data)-8:], uint64(n)*8)
	h := [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}
	for off := 0; off < len(data); off += 64 {
		var x [16]uint32
		for i := range x {
			x[i] = binary.LittleEndian.Uint32(data[off+4*i:])
		}
		a, b, c, d := h[0], h[1], h[2], h[3]
		for i := 0; i < 48; i++ {
			var f, k, add uint32
			var shift int
			switch {
			case i < 16:
				f, k = (b&c)|(^b&d), uint32(i)
				shift = [4]int{3, 7, 11, 19}[i%4]
			case i < 32:
				j := i - 16
				f, k, add = (b&c)|(b&d)|(c&d), uint32(j%4*4+j/4), 0x5a827999
				shift = [4]int{3, 5, 9, 13}[i%4]
			default:
				j := i - 32
				f, k, add = b^c^d, [16]uint32{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}[j], 0x6ed9eba1
				shift = [4]int{3, 9, 11, 15}[i%4]
			}
			a = bits.RotateLeft32(a+f+x[k]+add, shift)
			a, b, c, d = d, a, b, c
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
	}
	var sum [16]byte
	for i, v := range h {
		binary.LittleEndian.PutUint32(sum[4*i:], v)
	}
	return sum
}
