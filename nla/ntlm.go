package nla

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

// NTLM negotiate flags (MS-NLMP 2.2.2.5).
const (
	flagUnicode          uint32 = 0x00000001
	flagRequestTarget    uint32 = 0x00000004
	flagSign             uint32 = 0x00000010
	flagSeal             uint32 = 0x00000020
	flagNTLM             uint32 = 0x00000200
	flagAlwaysSign       uint32 = 0x00008000
	flagTargetTypeDomain uint32 = 0x00010000
	flagTargetTypeServer uint32 = 0x00020000
	flagESS              uint32 = 0x00080000
	flagTargetInfo       uint32 = 0x00800000
	flagVersion          uint32 = 0x02000000
	flag128              uint32 = 0x20000000
	flagKeyExchange      uint32 = 0x40000000
	flag56               uint32 = 0x80000000
)

// ntlmFlags is what the client offers; ntlmRequired is the subset both sides
// must agree on: Unicode, NTLMv2 session security, sign/seal, 128-bit keys
// and key exchange. Anything weaker is refused.
const ntlmFlags = flag56 | flagKeyExchange | flag128 | flagVersion | flagTargetInfo | flagESS | flagAlwaysSign | flagNTLM | flagSeal | flagSign | flagRequestTarget | flagUnicode
const ntlmRequired = flagKeyExchange | flag128 | flagESS | flagAlwaysSign | flagNTLM | flagSeal | flagSign | flagUnicode

// AV pair ids (MS-NLMP 2.2.2.1).
const (
	avEOL             uint16 = 0
	avNbComputerName  uint16 = 1
	avNbDomainName    uint16 = 2
	avDnsComputerName uint16 = 3
	avDnsDomainName   uint16 = 4
	avFlags           uint16 = 6
	avTimestamp       uint16 = 7
	avTargetName      uint16 = 9
	avChannelBindings uint16 = 10
)

var ntlmSignature = []byte("NTLMSSP\x00")
var ntlmVersion = []byte{6, 1, 0xb1, 0x1d, 0, 0, 0, 15}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func fromUTF16LE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", errors.New("odd UTF-16 length")
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u)), nil
}

func hmacMD5(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

// ntowfV2 derives the NTLMv2 response key (MS-NLMP 3.3.2).
func ntowfV2(user, domain, password string) []byte {
	hash := md4Sum(utf16LE(password))
	return hmacMD5(hash[:], utf16LE(strings.ToUpper(user)+domain))
}

func fileTime(now time.Time) []byte {
	stamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(stamp, uint64(now.Unix()+11644473600)*10000000+uint64(now.Nanosecond()/100))
	return stamp
}

func ntlmNegotiate() []byte {
	p := make([]byte, 40)
	copy(p, ntlmSignature)
	binary.LittleEndian.PutUint32(p[8:], 1)
	binary.LittleEndian.PutUint32(p[12:], ntlmFlags)
	copy(p[32:], ntlmVersion)
	return p
}

// ntlmField reads a security buffer whose payload must start at or after
// minimum (the end of the fixed header).
func ntlmField(p []byte, at, minimum int) ([]byte, error) {
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

func putField(p []byte, at int, payload *[]byte, base int, value []byte) {
	binary.LittleEndian.PutUint16(p[at:], uint16(len(value)))
	binary.LittleEndian.PutUint16(p[at+2:], uint16(len(value)))
	binary.LittleEndian.PutUint32(p[at+4:], uint32(base+len(*payload)))
	*payload = append(*payload, value...)
}

func appendAV(out []byte, id uint16, value []byte) []byte {
	var h [4]byte
	binary.LittleEndian.PutUint16(h[:], id)
	binary.LittleEndian.PutUint16(h[2:], uint16(len(value)))
	out = append(out, h[:]...)
	return append(out, value...)
}

type avPair struct {
	id    uint16
	value []byte
}

// parseAV decodes AV pairs up to and including MsvAvEOL and returns the
// pairs and the bytes after the terminator.
func parseAV(info []byte) ([]avPair, []byte, error) {
	var pairs []avPair
	seen := map[uint16]bool{}
	for len(info) >= 4 {
		id, n := binary.LittleEndian.Uint16(info), int(binary.LittleEndian.Uint16(info[2:]))
		info = info[4:]
		if n > len(info) || seen[id] {
			return nil, nil, errors.New("invalid NTLM target info")
		}
		seen[id] = true
		if id == avEOL {
			if n != 0 {
				return nil, nil, errors.New("invalid NTLM target info terminator")
			}
			return pairs, info, nil
		}
		pairs = append(pairs, avPair{id, info[:n]})
		info = info[n:]
	}
	return nil, nil, errors.New("unterminated NTLM target info")
}

// clientTargetInfo preserves server AV pairs and binds the response to this
// TLS endpoint and SPN; MsvAvFlags advertises the authenticate-message MIC.
func clientTargetInfo(info, binding []byte, spn string, now time.Time) ([]byte, []byte, bool, error) {
	if len(binding) != 16 || len(utf16LE(spn)) > 65535 {
		return nil, nil, false, errors.New("invalid NTLM channel binding or SPN")
	}
	pairs, rest, err := parseAV(info)
	if err != nil {
		return nil, nil, false, err
	}
	if len(rest) != 0 {
		return nil, nil, false, errors.New("trailing bytes after NTLM target info")
	}
	stamp := fileTime(now)
	var out []byte
	var flags uint32
	haveStamp := false
	for _, p := range pairs {
		switch p.id {
		case avFlags:
			if len(p.value) != 4 {
				return nil, nil, false, errors.New("invalid NTLM AV flags")
			}
			flags = binary.LittleEndian.Uint32(p.value)
		case avTimestamp:
			if len(p.value) != 8 {
				return nil, nil, false, errors.New("invalid NTLM timestamp")
			}
			copy(stamp, p.value)
			haveStamp = true
			out = appendAV(out, p.id, p.value)
		case avTargetName, avChannelBindings: // replaced with the intended target and authenticated TLS binding
		default:
			out = appendAV(out, p.id, p.value)
		}
	}
	var f [4]byte
	binary.LittleEndian.PutUint32(f[:], flags|2)
	out = appendAV(out, avFlags, f[:])
	out = appendAV(out, avTargetName, utf16LE(spn))
	out = appendAV(out, avChannelBindings, binding)
	out = appendAV(out, avEOL, nil)
	return out, stamp, haveStamp, nil
}

// ntlmAuthenticate answers a CHALLENGE with an NTLMv2 AUTHENTICATE message
// carrying a MIC and returns the negotiated session security.
func ntlmAuthenticate(negotiate, challenge, binding []byte, user, domain, password, spn string) ([]byte, *ntlmSecurity, error) {
	if len(challenge) < 48 || !bytes.Equal(challenge[:8], ntlmSignature) || binary.LittleEndian.Uint32(challenge[8:]) != 2 {
		return nil, nil, errors.New("expected NTLM challenge")
	}
	flags := binary.LittleEndian.Uint32(challenge[20:]) & ntlmFlags
	if flags&ntlmRequired != ntlmRequired || flags&flagTargetInfo == 0 {
		return nil, nil, errors.New("NTLM challenge lacks required NTLMv2 session security")
	}
	minimum := 48
	if flags&flagVersion != 0 {
		minimum = 56
	}
	if len(challenge) < minimum {
		return nil, nil, errors.New("short NTLM version")
	}
	info, err := ntlmField(challenge, 40, minimum)
	if err != nil {
		return nil, nil, err
	}
	info, stamp, haveStamp, err := clientTargetInfo(info, binding, spn, time.Now())
	if err != nil {
		return nil, nil, err
	}
	if len(utf16LE(user)) > 65535 || len(utf16LE(domain)) > 65535 || len(info) > 65487 {
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
	key := ntowfV2(user, domain, password)
	proof := hmacMD5(key, challenge[24:32], blob)
	ntResponse := append(append([]byte{}, proof...), blob...)
	lmResponse := make([]byte, 24)
	if !haveStamp {
		copy(lmResponse, hmacMD5(key, challenge[24:32], nonce[:]))
		copy(lmResponse[16:], nonce[:])
	}
	baseKey := hmacMD5(key, proof)
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
	if flags&flagVersion != 0 {
		micOffset = 72
	}
	auth := make([]byte, micOffset+16)
	copy(auth, ntlmSignature)
	binary.LittleEndian.PutUint32(auth[8:], 3)
	binary.LittleEndian.PutUint32(auth[60:], flags)
	if micOffset == 72 {
		copy(auth[64:], negotiate[32:40])
	}
	var payload []byte
	base := len(auth)
	for i, field := range [][]byte{lmResponse, ntResponse, utf16LE(domain), utf16LE(user), nil, encryptedKey} {
		putField(auth, 12+8*i, &payload, base, field)
	}
	auth = append(auth, payload...)
	copy(auth[micOffset:], hmacMD5(exported, negotiate, challenge, auth))
	security, err := newNTLMSecurity(exported)
	return auth, security, err
}

// --- server side ----------------------------------------------------------

// challengeState is what the server remembers between CHALLENGE and
// AUTHENTICATE.
type challengeState struct {
	negotiate []byte
	challenge []byte
	flags     uint32
	nonce     [8]byte
	stamp     []byte
}

// ntlmChallenge validates a NEGOTIATE message and builds the CHALLENGE
// advertising target info with a server timestamp.
func ntlmChallenge(negotiate []byte, domain, computer string, now time.Time) (*challengeState, error) {
	if len(negotiate) < 32 || !bytes.Equal(negotiate[:8], ntlmSignature) || binary.LittleEndian.Uint32(negotiate[8:]) != 1 {
		return nil, errors.New("expected NTLM negotiate")
	}
	offered := binary.LittleEndian.Uint32(negotiate[12:])
	flags := offered&ntlmFlags | flagTargetInfo | flagTargetTypeServer
	if flags&ntlmRequired != ntlmRequired {
		return nil, fmt.Errorf("client NTLM flags 0x%08x lack NTLMv2 session security", offered)
	}
	st := &challengeState{negotiate: append([]byte{}, negotiate...), flags: flags, stamp: fileTime(now)}
	if _, err := rand.Read(st.nonce[:]); err != nil {
		return nil, err
	}
	var info []byte
	info = appendAV(info, avNbDomainName, utf16LE(strings.ToUpper(domain)))
	info = appendAV(info, avNbComputerName, utf16LE(strings.ToUpper(computer)))
	info = appendAV(info, avDnsDomainName, utf16LE(strings.ToLower(domain)))
	info = appendAV(info, avDnsComputerName, utf16LE(strings.ToLower(computer)))
	info = appendAV(info, avTimestamp, st.stamp)
	info = appendAV(info, avEOL, nil)
	header := 48
	if flags&flagVersion != 0 {
		header = 56
	}
	msg := make([]byte, header)
	copy(msg, ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:], 2)
	binary.LittleEndian.PutUint32(msg[20:], flags)
	copy(msg[24:], st.nonce[:])
	if header == 56 {
		copy(msg[48:], ntlmVersion)
	}
	var payload []byte
	putField(msg, 12, &payload, header, utf16LE(strings.ToUpper(computer)))
	putField(msg, 40, &payload, header, info)
	st.challenge = append(msg, payload...)
	return st, nil
}

// Identity is the account proven by NTLMv2.
type Identity struct {
	User, Domain string
}

type verified struct {
	identity     Identity
	security     *ntlmSecurity
	channelBound bool
}

// ntlmVerify checks an AUTHENTICATE message against the challenge: NTLMv2
// proof with the password from lookup, MIC when advertised, and the TLS
// channel binding when the client supplied one. On success it returns the
// session security keyed by the exchanged session key.
func (st *challengeState) verify(auth, binding []byte, lookup func(user, domain string) (string, bool)) (*verified, error) {
	if len(auth) < 64 || !bytes.Equal(auth[:8], ntlmSignature) || binary.LittleEndian.Uint32(auth[8:]) != 3 {
		return nil, errors.New("expected NTLM authenticate")
	}
	flags := binary.LittleEndian.Uint32(auth[60:])
	if flags&ntlmRequired != ntlmRequired {
		return nil, errors.New("NTLM authenticate downgraded session security")
	}
	minimum := len(auth)
	for i := 0; i < 6; i++ {
		if n := binary.LittleEndian.Uint16(auth[12+8*i:]); n != 0 {
			if off := int(binary.LittleEndian.Uint32(auth[16+8*i:])); off < minimum {
				minimum = off
			}
		}
	}
	if minimum < 64 {
		return nil, errors.New("invalid NTLM authenticate payload offset")
	}
	field := func(i int) ([]byte, error) { return ntlmField(auth, 12+8*i, minimum) }
	nt, err := field(1)
	if err != nil {
		return nil, err
	}
	domainRaw, err := field(2)
	if err != nil {
		return nil, err
	}
	userRaw, err := field(3)
	if err != nil {
		return nil, err
	}
	encKey, err := field(5)
	if err != nil {
		return nil, err
	}
	if len(nt) < 16+28+4 || nt[16] != 1 || nt[17] != 1 || len(encKey) != 16 {
		return nil, errors.New("expected an NTLMv2 response with key exchange")
	}
	user, err := fromUTF16LE(userRaw)
	if err != nil {
		return nil, err
	}
	domain, err := fromUTF16LE(domainRaw)
	if err != nil {
		return nil, err
	}
	if user == "" {
		return nil, errors.New("NTLM authenticate without a user name")
	}
	proof, blob := nt[:16], nt[16:]
	pairs, _, err := parseAV(blob[28:])
	if err != nil {
		return nil, err
	}
	micRequired, channelBound := false, false
	for _, p := range pairs {
		switch p.id {
		case avFlags:
			micRequired = len(p.value) == 4 && binary.LittleEndian.Uint32(p.value)&2 != 0
		case avChannelBindings:
			if len(p.value) != 16 {
				return nil, errors.New("invalid NTLM channel binding")
			}
			if !bytes.Equal(p.value, make([]byte, 16)) {
				if len(binding) != 0 && !hmac.Equal(p.value, binding) {
					return nil, errors.New("NTLM channel binding does not match this TLS endpoint")
				}
				channelBound = len(binding) != 0
			}
		}
	}
	password, ok := lookup(user, domain)
	if !ok {
		// Burn the same work as a real check so unknown users are not
		// distinguishable by timing, then deny.
		password = string(st.nonce[:])
	}
	key := ntowfV2(user, domain, password)
	expected := hmacMD5(key, st.nonce[:], blob)
	if !ok || !hmac.Equal(proof, expected) {
		return nil, ErrLogonFailure
	}
	baseKey := hmacMD5(key, proof)
	rc, err := rc4.NewCipher(baseKey)
	if err != nil {
		return nil, err
	}
	exported := make([]byte, 16)
	rc.XORKeyStream(exported, encKey)
	if micRequired {
		if minimum < 88 {
			return nil, errors.New("NTLM authenticate advertises a MIC but has none")
		}
		zeroed := append([]byte{}, auth...)
		copy(zeroed[72:88], make([]byte, 16))
		if !hmac.Equal(auth[72:88], hmacMD5(exported, st.negotiate, st.challenge, zeroed)) {
			return nil, errors.New("NTLM authenticate MIC mismatch")
		}
	}
	security, err := newNTLMSecurity(exported)
	if err != nil {
		return nil, err
	}
	return &verified{identity: Identity{User: user, Domain: domain}, security: security, channelBound: channelBound}, nil
}

// --- session security (MS-NLMP 3.4) ----------------------------------------

type ntlmDirection struct {
	sign    []byte
	sealKey []byte
	seal    *rc4.Cipher
	seq     uint32
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
		d := &ntlmDirection{sign: sign[:], sealKey: seal[:]}
		return d, d.reset()
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

// reset restarts the RC4 key stream while keeping the sequence number, as
// Windows and FreeRDP do after the SPNEGO mechListMIC exchange.
func (d *ntlmDirection) reset() error {
	rc, err := rc4.NewCipher(d.sealKey)
	d.seal = rc
	return err
}

func (s *ntlmSecurity) resetCiphers() error {
	if err := s.client.reset(); err != nil {
		return err
	}
	return s.server.reset()
}

// signature computes the NTLMSSP_MESSAGE_SIGNATURE for plain, consuming
// eight bytes of key stream for the checksum.
func (d *ntlmDirection) signature(plain []byte) []byte {
	sig := make([]byte, 16)
	binary.LittleEndian.PutUint32(sig, 1)
	binary.LittleEndian.PutUint32(sig[12:], d.seq)
	mac := hmacMD5(d.sign, sig[12:16], plain)[:8]
	d.seal.XORKeyStream(sig[4:12], mac)
	d.seq++
	return sig
}

// verify checks a detached signature (GSS_VerifyMIC).
func (d *ntlmDirection) verify(plain, sig []byte) error {
	if len(sig) != 16 || binary.LittleEndian.Uint32(sig) != 1 || binary.LittleEndian.Uint32(sig[12:]) != d.seq {
		return errors.New("invalid NTLM message signature or sequence")
	}
	mac := hmacMD5(d.sign, sig[12:16], plain)[:8]
	d.seal.XORKeyStream(mac, mac)
	d.seq++
	if !hmac.Equal(mac, sig[4:12]) {
		return errors.New("NTLM message integrity check failed")
	}
	return nil
}

// wrap seals plain and prefixes the signature (GSS_WrapEx).
func (d *ntlmDirection) wrap(plain []byte) []byte {
	out := make([]byte, 16+len(plain))
	binary.LittleEndian.PutUint32(out, 1)
	binary.LittleEndian.PutUint32(out[12:], d.seq)
	mac := hmacMD5(d.sign, out[12:16], plain)[:8]
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
	mac := hmacMD5(d.sign, sealed[12:16], plain)[:8]
	d.seal.XORKeyStream(mac, mac)
	if !hmac.Equal(mac, sealed[4:12]) {
		return nil, errors.New("NTLM message integrity check failed")
	}
	d.seq++
	return plain, nil
}
