package transport

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

const ntlmFlags uint32 = 0xe2888235
const ntlmRequired uint32 = 0x60088231 // Unicode, sign/seal, NTLM, ESS, 128-bit, key exchange

var ntlmSignature = []byte("NTLMSSP\x00")

func ntlmUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func ntlmHMAC(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func ntlmResponseKey(user, domain, password string) []byte {
	hash := md4Sum(ntlmUTF16(password))
	return ntlmHMAC(hash[:], ntlmUTF16(strings.ToUpper(user)+domain))
}

func ntlmNegotiate() []byte {
	p := make([]byte, 40)
	copy(p, ntlmSignature)
	binary.LittleEndian.PutUint32(p[8:], 1)
	binary.LittleEndian.PutUint32(p[12:], ntlmFlags)
	copy(p[32:], []byte{6, 1, 0xb1, 0x1d, 0, 0, 0, 15})
	return p
}

func ntlmBuffer(p []byte, at, minimum int) ([]byte, error) {
	if at+8 > len(p) {
		return nil, errors.New("short NTLM security buffer")
	}
	n := int(binary.LittleEndian.Uint16(p[at:]))
	off := uint64(binary.LittleEndian.Uint32(p[at+4:]))
	if n == 0 {
		return nil, nil
	}
	if off < uint64(minimum) || off+uint64(n) > uint64(len(p)) {
		return nil, errors.New("invalid NTLM security buffer")
	}
	return p[int(off) : int(off)+n], nil
}

func ntlmAppendAV(out []byte, id uint16, value []byte) []byte {
	var h [4]byte
	binary.LittleEndian.PutUint16(h[:], id)
	binary.LittleEndian.PutUint16(h[2:], uint16(len(value)))
	out = append(out, h[:]...)
	return append(out, value...)
}

// ntlmTargetInfo preserves server AV pairs and binds the response to this
// TLS endpoint and SPN; MsvAvFlags advertises the authenticate-message MIC.
func ntlmTargetInfo(info, binding []byte, spn string, now time.Time) ([]byte, []byte, bool, error) {
	if len(binding) != 16 || len(ntlmUTF16(spn)) > 65535 {
		return nil, nil, false, errors.New("invalid NTLM channel binding or SPN")
	}
	stamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(stamp, uint64(now.Unix()+11644473600)*10000000+uint64(now.Nanosecond()/100))
	var out []byte
	var flags uint32
	haveStamp, ended := false, false
	seen := map[uint16]bool{}
	for len(info) >= 4 {
		id, n := binary.LittleEndian.Uint16(info), int(binary.LittleEndian.Uint16(info[2:]))
		info = info[4:]
		if n > len(info) || seen[id] {
			return nil, nil, false, errors.New("invalid NTLM target info")
		}
		seen[id] = true
		value := info[:n]
		info = info[n:]
		if id == 0 {
			ended = n == 0 && len(info) == 0
			break
		}
		switch id {
		case 6:
			if n != 4 {
				return nil, nil, false, errors.New("invalid NTLM AV flags")
			}
			flags = binary.LittleEndian.Uint32(value)
		case 7:
			if n != 8 {
				return nil, nil, false, errors.New("invalid NTLM timestamp")
			}
			copy(stamp, value)
			haveStamp = true
			out = ntlmAppendAV(out, id, value)
		case 9, 10: // replaced with the intended target and authenticated TLS binding
		default:
			out = ntlmAppendAV(out, id, value)
		}
	}
	if !ended {
		return nil, nil, false, errors.New("unterminated NTLM target info")
	}
	var f [4]byte
	binary.LittleEndian.PutUint32(f[:], flags|2)
	out = ntlmAppendAV(out, 6, f[:])
	out = ntlmAppendAV(out, 9, ntlmUTF16(spn))
	out = ntlmAppendAV(out, 10, binding)
	out = ntlmAppendAV(out, 0, nil)
	return out, stamp, haveStamp, nil
}

func ntlmAuthenticate(negotiate, challenge, binding []byte, user, domain, password, spn string) ([]byte, *ntlmSecurity, error) {
	if len(challenge) < 48 || !bytes.Equal(challenge[:8], ntlmSignature) || binary.LittleEndian.Uint32(challenge[8:]) != 2 {
		return nil, nil, errors.New("expected NTLM challenge")
	}
	flags := binary.LittleEndian.Uint32(challenge[20:]) & ntlmFlags
	if flags&ntlmRequired != ntlmRequired || flags&0x00800000 == 0 {
		return nil, nil, errors.New("NTLM challenge lacks required NTLMv2 session security")
	}
	minimum := 48
	if flags&0x02000000 != 0 {
		minimum = 56
	}
	if len(challenge) < minimum {
		return nil, nil, errors.New("short NTLM version")
	}
	info, err := ntlmBuffer(challenge, 40, minimum)
	if err != nil {
		return nil, nil, err
	}
	info, stamp, haveStamp, err := ntlmTargetInfo(info, binding, spn, time.Now())
	if err != nil {
		return nil, nil, err
	}
	if len(ntlmUTF16(user)) > 65535 || len(ntlmUTF16(domain)) > 65535 || len(info) > 65487 {
		return nil, nil, errors.New("NTLM field too large")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	blob := make([]byte, 28)
	blob[0], blob[1] = 1, 1
	copy(blob[8:], stamp)
	copy(blob[16:], nonce[:])
	blob = append(blob, info...)
	blob = append(blob, 0, 0, 0, 0)
	key := ntlmResponseKey(user, domain, password)
	proof := ntlmHMAC(key, challenge[24:32], blob)
	ntResponse := append(append([]byte{}, proof...), blob...)
	lmResponse := make([]byte, 24)
	if !haveStamp {
		copy(lmResponse, ntlmHMAC(key, challenge[24:32], nonce[:]))
		copy(lmResponse[16:], nonce[:])
	}
	baseKey := ntlmHMAC(key, proof)
	exported := make([]byte, 16)
	if _, err := rand.Read(exported); err != nil {
		return nil, nil, err
	}
	rc, err := rc4.NewCipher(baseKey)
	if err != nil {
		return nil, nil, err
	}
	encryptedKey := make([]byte, 16)
	rc.XORKeyStream(encryptedKey, exported)
	micOffset := 64
	if flags&0x02000000 != 0 {
		micOffset = 72
	}
	auth := make([]byte, micOffset+16)
	copy(auth, ntlmSignature)
	binary.LittleEndian.PutUint32(auth[8:], 3)
	binary.LittleEndian.PutUint32(auth[60:], flags)
	if micOffset == 72 {
		copy(auth[64:], negotiate[32:40])
	}
	for i, field := range [][]byte{lmResponse, ntResponse, ntlmUTF16(domain), ntlmUTF16(user), nil, encryptedKey} {
		at := 12 + 8*i
		binary.LittleEndian.PutUint16(auth[at:], uint16(len(field)))
		binary.LittleEndian.PutUint16(auth[at+2:], uint16(len(field)))
		binary.LittleEndian.PutUint32(auth[at+4:], uint32(len(auth)))
		auth = append(auth, field...)
	}
	copy(auth[micOffset:], ntlmHMAC(exported, negotiate, challenge, auth))
	security, err := newNTLMSecurity(exported)
	return auth, security, err
}

type ntlmDirection struct {
	sign []byte
	seal *rc4.Cipher
	seq  uint32
}

type ntlmSecurity struct {
	client, server *ntlmDirection
}

func newNTLMSecurity(key []byte) (*ntlmSecurity, error) {
	if len(key) != 16 {
		return nil, errors.New("invalid NTLM session key")
	}
	makeDirection := func(direction string) (*ntlmDirection, error) {
		derive := func(kind string) [16]byte {
			data := append(append([]byte{}, key...), []byte("session key to "+direction+" "+kind+" key magic constant\x00")...)
			return md5.Sum(data)
		}
		sign, seal := derive("signing"), derive("sealing")
		rc, err := rc4.NewCipher(seal[:])
		return &ntlmDirection{sign: sign[:], seal: rc}, err
	}
	client, err := makeDirection("client-to-server")
	if err != nil {
		return nil, err
	}
	server, err := makeDirection("server-to-client")
	if err != nil {
		return nil, err
	}
	return &ntlmSecurity{client: client, server: server}, nil
}

func (d *ntlmDirection) wrap(plain []byte) []byte {
	out := make([]byte, 16+len(plain))
	binary.LittleEndian.PutUint32(out, 1)
	binary.LittleEndian.PutUint32(out[12:], d.seq)
	mac := ntlmHMAC(d.sign, out[12:16], plain)[:8]
	d.seal.XORKeyStream(out[16:], plain)
	d.seal.XORKeyStream(out[4:12], mac)
	d.seq++
	return out
}

func (d *ntlmDirection) unwrap(sealed []byte) ([]byte, error) {
	if len(sealed) < 16 || binary.LittleEndian.Uint32(sealed) != 1 || binary.LittleEndian.Uint32(sealed[12:]) != d.seq {
		return nil, errors.New("invalid NTLM message signature or sequence")
	}
	plain := make([]byte, len(sealed)-16)
	d.seal.XORKeyStream(plain, sealed[16:])
	mac := ntlmHMAC(d.sign, sealed[12:16], plain)[:8]
	d.seal.XORKeyStream(mac, mac)
	if !hmac.Equal(mac, sealed[4:12]) {
		return nil, fmt.Errorf("NTLM message integrity check failed")
	}
	d.seq++
	return plain, nil
}
