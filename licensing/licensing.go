// Package licensing implements the client side of the RDP licensing exchange
// (MS-RDPELE) as far as needed to reach the Capability Exchange: it answers a
// Server License Request with a Client New License Request, a Server Platform
// Challenge with a Client Platform Challenge Response, verifies the MAC of a
// Server New License / Upgrade License and accepts the STATUS_VALID_CLIENT
// error alert. No license is stored; every connection asks for a new one.
//
// Layouts: MS-RDPBCGR 2.2.1.12 (preamble, binary blob, error message),
// MS-RDPELE 2.2.2.1 - 2.2.2.7 (messages) and 5.1 (key derivation, RC4, MAC).
// The server certificate is taken from the License Request; its proprietary
// signature is not verified because the transport already authenticates the
// server through TLS and the licensing keys protect nothing beyond licensing.
package licensing

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

var ErrLicense = errors.New("invalid licensing PDU")

// Preamble message types (MS-RDPBCGR 2.2.1.12.1.1).
const (
	MsgLicenseRequest            uint8 = 0x01
	MsgPlatformChallenge         uint8 = 0x02
	MsgNewLicense                uint8 = 0x03
	MsgUpgradeLicense            uint8 = 0x04
	MsgLicenseInfo               uint8 = 0x12
	MsgNewLicenseRequest         uint8 = 0x13
	MsgPlatformChallengeResponse uint8 = 0x15
	MsgErrorAlert                uint8 = 0xFF

	preambleVersion2    uint8 = 0x02
	preambleVersion3    uint8 = 0x03
	preambleExtendedErr uint8 = 0x80
	preambleVersionMask uint8 = 0x0F
	preambleLen               = 4
	clientPreambleFlags       = preambleVersion3 | preambleExtendedErr
)

// Binary blob types (MS-RDPBCGR 2.2.1.12.1.2).
const (
	BlobData              uint16 = 0x0001
	BlobRandom            uint16 = 0x0002
	BlobCertificate       uint16 = 0x0003
	BlobError             uint16 = 0x0004
	BlobEncryptedData     uint16 = 0x0009
	BlobKeyExchangeAlg    uint16 = 0x000D
	BlobScope             uint16 = 0x000E
	BlobClientUserName    uint16 = 0x000F
	BlobClientMachineName uint16 = 0x0010
)

// Error codes and state transitions (MS-RDPBCGR 2.2.1.12.1.3).
const (
	ErrInvalidServerCertificate uint32 = 0x00000001
	ErrNoLicense                uint32 = 0x00000002
	ErrInvalidMAC               uint32 = 0x00000003
	ErrInvalidScope             uint32 = 0x00000004
	ErrNoLicenseServer          uint32 = 0x00000006
	StatusValidClient           uint32 = 0x00000007
	ErrInvalidClient            uint32 = 0x00000008
	ErrInvalidProductID         uint32 = 0x0000000B
	ErrInvalidMessageLen        uint32 = 0x0000000C

	StateTotalAbort        uint32 = 0x00000001
	StateNoTransition      uint32 = 0x00000002
	StateResetPhaseToStart uint32 = 0x00000003
	StateResendLastMessage uint32 = 0x00000004
)

const (
	keyExchangeAlgRSA uint32 = 0x00000001

	// DefaultPlatformID is CLIENT_OS_ID_WINNT_POST_52 | CLIENT_IMAGE_ID_MICROSOFT
	// (MS-RDPELE 2.2.2.2); the value only labels the client for the server.
	DefaultPlatformID uint32 = 0x04000000 | 0x00010000

	challengeVersion     uint16 = 0x0100
	challengeTypeOther   uint16 = 0xFF00
	licenseDetailDetail  uint16 = 0x0003
	serverRandomLen             = 32
	clientRandomLen             = 32
	preMasterSecretLen          = 48
	macLen                      = 16
	hardwareIDLen               = 20
	maxLicensingMessage         = 0xffff
	maxStrLen                   = 256
	maxScopes                   = 16
	rsaPublicKeyMagic    uint32 = 0x31415352
	certChainVersion1    uint32 = 0x00000001
	certChainVersion2    uint32 = 0x00000002
	blobTypeRSAKey       uint16 = 0x0006
	blobTypeRSASignature uint16 = 0x0008
)

// ErrorAlert is a decoded LICENSE_ERROR_MESSAGE other than STATUS_VALID_CLIENT.
type ErrorAlert struct {
	Code            uint32
	StateTransition uint32
}

func (e *ErrorAlert) Error() string {
	return fmt.Sprintf("server licensing error alert (dwErrorCode 0x%08x, dwStateTransition 0x%08x)", e.Code, e.StateTransition)
}

// Client drives the licensing exchange for one connection.
type Client struct {
	UserName    string
	MachineName string
	PlatformID  uint32   // zero selects DefaultPlatformID
	HardwareID  [16]byte // Data1..Data4 of CLIENT_HARDWARE_ID
	Rand        io.Reader

	serverRandom [serverRandomLen]byte
	clientRandom [clientRandomLen]byte
	preMaster    [preMasterSecretLen]byte
	macSaltKey   []byte
	encKey       []byte
	state        state

	// Populated from the Server License Request.
	ProductVersion uint32
	CompanyName    string
	ProductID      string
	Scopes         []string
	// Outcome is "valid-client", "new-license" or "upgrade-license" once Done.
	Outcome string
}

type state int

const (
	stateInitial state = iota
	stateAwaitChallengeOrLicense
	stateAwaitLicense
	stateDone
)

// Done reports whether the exchange finished successfully.
func (c *Client) Done() bool { return c.state == stateDone }

// Handle consumes one licensing PDU (preamble + message, security header
// already removed) and returns the reply to send, if any. done is true once
// the server accepted the client (Valid Client alert or a New License).
func (c *Client) Handle(msg []byte) (reply []byte, done bool, err error) {
	typ, body, err := decodePreamble(msg)
	if err != nil {
		return nil, false, err
	}
	switch typ {
	case MsgErrorAlert:
		if err := c.handleErrorAlert(body); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	case MsgLicenseRequest:
		if c.state != stateInitial {
			return nil, false, fmt.Errorf("%w: unexpected License Request in state %d", ErrLicense, c.state)
		}
		reply, err = c.handleLicenseRequest(body)
		if err != nil {
			return nil, false, err
		}
		c.state = stateAwaitChallengeOrLicense
		return reply, false, nil
	case MsgPlatformChallenge:
		if c.state != stateAwaitChallengeOrLicense {
			return nil, false, fmt.Errorf("%w: unexpected Platform Challenge in state %d", ErrLicense, c.state)
		}
		reply, err = c.handlePlatformChallenge(body)
		if err != nil {
			return nil, false, err
		}
		c.state = stateAwaitLicense
		return reply, false, nil
	case MsgNewLicense, MsgUpgradeLicense:
		if c.state != stateAwaitChallengeOrLicense && c.state != stateAwaitLicense {
			return nil, false, fmt.Errorf("%w: unexpected New/Upgrade License in state %d", ErrLicense, c.state)
		}
		if err := c.handleNewLicense(body); err != nil {
			return nil, false, err
		}
		c.state = stateDone
		c.Outcome = "new-license"
		if typ == MsgUpgradeLicense {
			c.Outcome = "upgrade-license"
		}
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("%w: unexpected message type 0x%02x", ErrLicense, typ)
	}
}

func decodePreamble(msg []byte) (uint8, []byte, error) {
	if len(msg) < preambleLen {
		return 0, nil, fmt.Errorf("%w: %d bytes, need preamble", ErrLicense, len(msg))
	}
	size := int(binary.LittleEndian.Uint16(msg[2:]))
	if size != len(msg) {
		return 0, nil, fmt.Errorf("%w: wMsgSize %d, PDU has %d bytes", ErrLicense, size, len(msg))
	}
	if v := msg[1] & preambleVersionMask; v != preambleVersion3 && v != preambleVersion2 {
		return 0, nil, fmt.Errorf("%w: preamble version %d", ErrLicense, v)
	}
	return msg[0], msg[preambleLen:], nil
}

func encodeMessage(typ uint8, body []byte) ([]byte, error) {
	if preambleLen+len(body) > maxLicensingMessage {
		return nil, fmt.Errorf("%w: message of %d bytes too large", ErrLicense, len(body))
	}
	out := make([]byte, preambleLen, preambleLen+len(body))
	out[0] = typ
	out[1] = clientPreambleFlags
	binary.LittleEndian.PutUint16(out[2:], uint16(preambleLen+len(body)))
	return append(out, body...), nil
}

func (c *Client) handleErrorAlert(body []byte) error {
	if len(body) < 12 {
		return fmt.Errorf("%w: error alert body %d bytes", ErrLicense, len(body))
	}
	code := binary.LittleEndian.Uint32(body)
	transition := binary.LittleEndian.Uint32(body[4:])
	typ, blob, rest, err := readBlob(body[8:])
	if err != nil {
		return err
	}
	// wBlobType is ignored when wBlobLen is 0 (MS-RDPBCGR 2.2.1.12.1.3);
	// xrdp's fixed STATUS_VALID_CLIENT message carries 0x1428 there.
	if (len(blob) != 0 && typ != BlobError) || len(rest) != 0 {
		return fmt.Errorf("%w: error alert blob type 0x%04x, %d trailing bytes", ErrLicense, typ, len(rest))
	}
	if code == StatusValidClient && transition == StateNoTransition {
		c.state = stateDone
		c.Outcome = "valid-client"
		return nil
	}
	return &ErrorAlert{Code: code, StateTransition: transition}
}

// --- Server License Request -> Client New License Request -----------------

func (c *Client) handleLicenseRequest(body []byte) ([]byte, error) {
	if len(body) < serverRandomLen+8 {
		return nil, fmt.Errorf("%w: license request body %d bytes", ErrLicense, len(body))
	}
	copy(c.serverRandom[:], body)
	rest := body[serverRandomLen:]

	// PRODUCT_INFO
	c.ProductVersion = binary.LittleEndian.Uint32(rest)
	company, rest, err := readU32String(rest[4:], "pbCompanyName")
	if err != nil {
		return nil, err
	}
	product, rest, err := readU32String(rest, "pbProductId")
	if err != nil {
		return nil, err
	}
	c.CompanyName, c.ProductID = company, product

	// KeyExchangeList
	typ, algs, rest, err := readBlob(rest)
	if err != nil {
		return nil, err
	}
	if typ != BlobKeyExchangeAlg || len(algs) == 0 || len(algs)%4 != 0 {
		return nil, fmt.Errorf("%w: KeyExchangeList blob type 0x%04x, %d bytes", ErrLicense, typ, len(algs))
	}
	rsaOffered := false
	for i := 0; i < len(algs); i += 4 {
		if binary.LittleEndian.Uint32(algs[i:]) == keyExchangeAlgRSA {
			rsaOffered = true
		}
	}
	if !rsaOffered {
		return nil, fmt.Errorf("%w: server does not offer KEY_EXCHANGE_ALG_RSA", ErrLicense)
	}

	// ServerCertificate
	typ, cert, rest, err := readBlob(rest)
	if err != nil {
		return nil, err
	}
	if typ != BlobCertificate {
		return nil, fmt.Errorf("%w: ServerCertificate blob type 0x%04x", ErrLicense, typ)
	}
	pub, err := ParseServerCertificate(cert)
	if err != nil {
		return nil, err
	}

	// ScopeList
	if len(rest) < 4 {
		return nil, fmt.Errorf("%w: scope list truncated", ErrLicense)
	}
	count := binary.LittleEndian.Uint32(rest)
	rest = rest[4:]
	if count > maxScopes {
		return nil, fmt.Errorf("%w: %d scopes", ErrLicense, count)
	}
	c.Scopes = c.Scopes[:0]
	for i := uint32(0); i < count; i++ {
		var scope []byte
		typ, scope, rest, err = readBlob(rest)
		if err != nil {
			return nil, err
		}
		if typ != BlobScope {
			return nil, fmt.Errorf("%w: scope blob type 0x%04x", ErrLicense, typ)
		}
		c.Scopes = append(c.Scopes, strings.TrimRight(string(scope), "\x00"))
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after scope list", ErrLicense, len(rest))
	}

	r := c.Rand
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, c.clientRandom[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, c.preMaster[:]); err != nil {
		return nil, err
	}
	c.macSaltKey, c.encKey = DeriveKeys(c.preMaster[:], c.clientRandom[:], c.serverRandom[:])

	encrypted, err := EncryptWithServerKey(pub, c.preMaster[:])
	if err != nil {
		return nil, err
	}
	user, err := ansiZ(c.UserName, "user name")
	if err != nil {
		return nil, err
	}
	machine, err := ansiZ(c.MachineName, "machine name")
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 128+len(encrypted))
	out = binary.LittleEndian.AppendUint32(out, keyExchangeAlgRSA)
	out = binary.LittleEndian.AppendUint32(out, c.platformID())
	out = append(out, c.clientRandom[:]...)
	out = appendBlob(out, BlobRandom, encrypted)
	out = appendBlob(out, BlobClientUserName, user)
	out = appendBlob(out, BlobClientMachineName, machine)
	return encodeMessage(MsgNewLicenseRequest, out)
}

func (c *Client) platformID() uint32 {
	if c.PlatformID == 0 {
		return DefaultPlatformID
	}
	return c.PlatformID
}

// --- Server Platform Challenge -> Client Platform Challenge Response ------

func (c *Client) handlePlatformChallenge(body []byte) ([]byte, error) {
	if len(body) < 4+4+macLen {
		return nil, fmt.Errorf("%w: platform challenge body %d bytes", ErrLicense, len(body))
	}
	// ConnectFlags are reserved. The blob's wBlobType is not defined for this
	// message and the MS-RDPELE 4.4 sample carries an arbitrary value there,
	// so only wBlobLen is used.
	_, encrypted, rest, err := readBlob(body[4:])
	if err != nil {
		return nil, err
	}
	if len(rest) != macLen {
		return nil, fmt.Errorf("%w: platform challenge has %d bytes after blob, want %d-byte MAC", ErrLicense, len(rest), macLen)
	}
	challenge, err := c.crypt(encrypted)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(c.mac(challenge), rest) {
		return nil, fmt.Errorf("%w: platform challenge MAC mismatch", ErrLicense)
	}
	if len(challenge) > 0xffff {
		return nil, fmt.Errorf("%w: challenge too long", ErrLicense)
	}

	response := make([]byte, 0, 8+len(challenge))
	response = binary.LittleEndian.AppendUint16(response, challengeVersion)
	response = binary.LittleEndian.AppendUint16(response, challengeTypeOther)
	response = binary.LittleEndian.AppendUint16(response, licenseDetailDetail)
	response = binary.LittleEndian.AppendUint16(response, uint16(len(challenge)))
	response = append(response, challenge...)

	hwid := make([]byte, 0, hardwareIDLen)
	hwid = binary.LittleEndian.AppendUint32(hwid, c.platformID())
	hwid = append(hwid, c.HardwareID[:]...)

	encResponse, err := c.crypt(response)
	if err != nil {
		return nil, err
	}
	encHWID, err := c.crypt(hwid)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 8+len(encResponse)+len(encHWID)+macLen)
	out = appendBlob(out, BlobEncryptedData, encResponse)
	out = appendBlob(out, BlobEncryptedData, encHWID)
	out = append(out, c.mac(append(append([]byte{}, response...), hwid...))...)
	return encodeMessage(MsgPlatformChallengeResponse, out)
}

// --- Server New License / Upgrade License ---------------------------------

func (c *Client) handleNewLicense(body []byte) error {
	typ, encrypted, rest, err := readBlob(body)
	if err != nil {
		return err
	}
	if typ != BlobEncryptedData {
		return fmt.Errorf("%w: new license blob type 0x%04x", ErrLicense, typ)
	}
	if len(rest) != macLen {
		return fmt.Errorf("%w: new license has %d bytes after blob, want %d-byte MAC", ErrLicense, len(rest), macLen)
	}
	info, err := c.crypt(encrypted)
	if err != nil {
		return err
	}
	if !bytes.Equal(c.mac(info), rest) {
		return fmt.Errorf("%w: new license MAC mismatch", ErrLicense)
	}
	return nil
}

// --- Cryptography (MS-RDPELE 5.1) ------------------------------------------

func saltedHash(salt, input, r1, r2 []byte) []byte {
	inner := sha1.New()
	inner.Write(input)
	inner.Write(salt)
	inner.Write(r1)
	inner.Write(r2)
	outer := md5.New()
	outer.Write(salt)
	outer.Write(inner.Sum(nil))
	return outer.Sum(nil)
}

// DeriveKeys implements MS-RDPELE 5.1.2 and returns the MAC salt key and the
// licensing encryption key.
func DeriveKeys(preMaster, clientRandom, serverRandom []byte) (macSalt, encKey []byte) {
	var master []byte
	for _, in := range []string{"A", "BB", "CCC"} {
		master = append(master, saltedHash(preMaster, []byte(in), clientRandom, serverRandom)...)
	}
	var blob []byte
	for _, in := range []string{"A", "BB", "CCC"} {
		blob = append(blob, saltedHash(master, []byte(in), serverRandom, clientRandom)...)
	}
	final := md5.New()
	final.Write(blob[16:32])
	final.Write(clientRandom)
	final.Write(serverRandom)
	return blob[:16], final.Sum(nil)
}

// crypt applies RC4 with the licensing encryption key. Every blob is
// encrypted independently, so a fresh key stream is used each time.
func (c *Client) crypt(data []byte) ([]byte, error) {
	if c.encKey == nil {
		return nil, fmt.Errorf("%w: licensing keys not derived yet", ErrLicense)
	}
	return RC4(c.encKey, data)
}

// RC4 encrypts or decrypts data with key (MS-RDPELE 5.1.3).
func RC4(key, data []byte) ([]byte, error) {
	ciph, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	ciph.XORKeyStream(out, data)
	return out, nil
}

// MAC implements MS-RDPELE 5.1.5.
func MAC(macSalt, data []byte) []byte {
	pad1 := bytes.Repeat([]byte{0x36}, 40)
	pad2 := bytes.Repeat([]byte{0x5c}, 48)
	inner := sha1.New()
	inner.Write(macSalt)
	inner.Write(pad1)
	inner.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(data))))
	inner.Write(data)
	outer := md5.New()
	outer.Write(macSalt)
	outer.Write(pad2)
	outer.Write(inner.Sum(nil))
	return outer.Sum(nil)
}

func (c *Client) mac(data []byte) []byte { return MAC(c.macSaltKey, data) }

// EncryptWithServerKey implements MS-RDPBCGR 5.3.4.1 for the premaster secret
// (MS-RDPELE 5.1.1.1): the plaintext is a little-endian integer, c = m^e mod
// n, written little-endian into a zeroed buffer of modulus length + 8.
func EncryptWithServerKey(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	modLen := (pub.N.BitLen() + 7) / 8
	if len(plaintext) >= modLen {
		return nil, fmt.Errorf("%w: %d-byte plaintext does not fit %d-byte modulus", ErrLicense, len(plaintext), modLen)
	}
	m := new(big.Int).SetBytes(Reverse(plaintext))
	c := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	out := make([]byte, modLen+8)
	copy(out, Reverse(c.Bytes()))
	return out, nil
}

// Reverse returns b in reverse byte order (big-endian <-> little-endian).
func Reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, x := range b {
		out[len(b)-1-i] = x
	}
	return out
}

// --- Server certificate (MS-RDPBCGR 2.2.1.4.3.1, 2.2.1.4.3.1.1, 5.3.3.2) ----

// ParseServerCertificate extracts the RSA public key from a SERVER_CERTIFICATE
// (proprietary certificate or X.509 chain whose leaf is last).
func ParseServerCertificate(p []byte) (*rsa.PublicKey, error) {
	if len(p) < 4 {
		return nil, fmt.Errorf("%w: server certificate too short", ErrLicense)
	}
	version := binary.LittleEndian.Uint32(p) & 0x7fffffff
	rest := p[4:]
	switch version {
	case certChainVersion1:
		return parseProprietaryCertificate(rest)
	case certChainVersion2:
		return parseX509Chain(rest)
	default:
		return nil, fmt.Errorf("%w: certificate chain version %d", ErrLicense, version)
	}
}

func parseProprietaryCertificate(p []byte) (*rsa.PublicKey, error) {
	if len(p) < 12 {
		return nil, fmt.Errorf("%w: proprietary certificate too short", ErrLicense)
	}
	if binary.LittleEndian.Uint32(p) != 1 || binary.LittleEndian.Uint32(p[4:]) != keyExchangeAlgRSA {
		return nil, fmt.Errorf("%w: proprietary certificate algorithms % x", ErrLicense, p[:8])
	}
	typ := binary.LittleEndian.Uint16(p[8:])
	n := int(binary.LittleEndian.Uint16(p[10:]))
	if typ != blobTypeRSAKey || n > len(p)-12 {
		return nil, fmt.Errorf("%w: public key blob type 0x%04x length %d", ErrLicense, typ, n)
	}
	key := p[12 : 12+n]
	if len(key) < 20 || binary.LittleEndian.Uint32(key) != rsaPublicKeyMagic {
		return nil, fmt.Errorf("%w: RSA_PUBLIC_KEY magic", ErrLicense)
	}
	keylen := int(binary.LittleEndian.Uint32(key[4:]))
	bitlen := int(binary.LittleEndian.Uint32(key[8:]))
	exp := binary.LittleEndian.Uint32(key[16:])
	if bitlen%8 != 0 || bitlen < 512 || bitlen > 8192 || keylen != bitlen/8+8 || 20+keylen != len(key) {
		return nil, fmt.Errorf("%w: RSA_PUBLIC_KEY keylen %d bitlen %d (%d bytes)", ErrLicense, keylen, bitlen, len(key))
	}
	modulus := new(big.Int).SetBytes(Reverse(key[20 : 20+bitlen/8]))
	// keylen/bitlen are validated above; the modulus itself may have unset
	// top bits (xrdp's built-in proprietary certificate declares 512 bits
	// but carries a 511-bit modulus), so only reject truly degenerate keys.
	if modulus.BitLen() <= bitlen-8 || exp < 3 {
		return nil, fmt.Errorf("%w: degenerate RSA public key", ErrLicense)
	}
	return &rsa.PublicKey{N: modulus, E: int(exp)}, nil
}

func parseX509Chain(p []byte) (*rsa.PublicKey, error) {
	if len(p) < 4 {
		return nil, fmt.Errorf("%w: X.509 chain too short", ErrLicense)
	}
	count := binary.LittleEndian.Uint32(p)
	rest := p[4:]
	// NumCertBlobs MUST be between 2 and 200 (MS-RDPELE 2.2.1.4.2).
	if count < 2 || count > 200 {
		return nil, fmt.Errorf("%w: X.509 chain with %d certificates", ErrLicense, count)
	}
	var leaf []byte
	for i := uint32(0); i < count; i++ {
		if len(rest) < 4 {
			return nil, fmt.Errorf("%w: X.509 chain truncated", ErrLicense)
		}
		n := int(binary.LittleEndian.Uint32(rest))
		rest = rest[4:]
		if n > len(rest) {
			return nil, fmt.Errorf("%w: certificate %d length %d exceeds %d", ErrLicense, i, n, len(rest))
		}
		leaf = rest[:n]
		rest = rest[n:]
	}
	// X509_CERTIFICATE_CHAIN ends with 8 + 4*NumCertBlobs padding bytes
	// (MS-RDPELE 2.2.1.4.2); the MS-RDPELE 4.1 sample carries them.
	if pad := 8 + 4*int(count); len(rest) != pad && len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after X.509 chain, want %d padding", ErrLicense, len(rest), pad)
	}
	return leafRSAPublicKey(leaf)
}

// leafRSAPublicKey extracts the RSA public key from a DER certificate. Only
// the SubjectPublicKeyInfo is decoded: licensing certificates issued by
// Terminal Services (the MS-RDPELE 4.1 sample included) use non-standard
// extensions and a legacy public key algorithm OID that crypto/x509 rejects,
// and the chain is not used for authentication (TLS already did that).
func leafRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	var cert, tbs asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &cert); err != nil || len(rest) != 0 || cert.Tag != asn1.TagSequence || !cert.IsCompound {
		return nil, fmt.Errorf("%w: leaf certificate is not a DER SEQUENCE", ErrLicense)
	}
	if _, err := asn1.Unmarshal(cert.Bytes, &tbs); err != nil || tbs.Tag != asn1.TagSequence || !tbs.IsCompound {
		return nil, fmt.Errorf("%w: leaf certificate tbsCertificate", ErrLicense)
	}
	// tbsCertificate: [0] version OPTIONAL, serialNumber, signature, issuer,
	// validity, subject, subjectPublicKeyInfo, ...
	p := tbs.Bytes
	var field asn1.RawValue
	for i := 0; i < 7; i++ {
		rest, err := asn1.Unmarshal(p, &field)
		if err != nil {
			return nil, fmt.Errorf("%w: leaf certificate field %d: %v", ErrLicense, i, err)
		}
		if i == 0 && (field.Class != asn1.ClassContextSpecific || field.Tag != 0) {
			i++ // no explicit version: this field was the serial number
		}
		p = rest
		if i == 6 {
			break
		}
	}
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(field.FullBytes, &spki); err != nil {
		return nil, fmt.Errorf("%w: subjectPublicKeyInfo: %v", ErrLicense, err)
	}
	if spki.PublicKey.BitLength%8 != 0 {
		return nil, fmt.Errorf("%w: subjectPublicKey bit length %d", ErrLicense, spki.PublicKey.BitLength)
	}
	pub, err := x509.ParsePKCS1PublicKey(spki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: leaf certificate key is not RSA: %v", ErrLicense, err)
	}
	if pub.N.BitLen() < 512 || pub.E < 3 {
		return nil, fmt.Errorf("%w: degenerate RSA public key", ErrLicense)
	}
	return pub, nil
}

// --- helpers ----------------------------------------------------------------

func readBlob(p []byte) (typ uint16, data, rest []byte, err error) {
	if len(p) < 4 {
		return 0, nil, nil, fmt.Errorf("%w: blob header truncated", ErrLicense)
	}
	typ = binary.LittleEndian.Uint16(p)
	n := int(binary.LittleEndian.Uint16(p[2:]))
	if n > len(p)-4 {
		return 0, nil, nil, fmt.Errorf("%w: blob 0x%04x length %d exceeds %d", ErrLicense, typ, n, len(p)-4)
	}
	return typ, p[4 : 4+n], p[4+n:], nil
}

func appendBlob(out []byte, typ uint16, data []byte) []byte {
	out = binary.LittleEndian.AppendUint16(out, typ)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(data)))
	return append(out, data...)
}

func readU32String(p []byte, name string) (string, []byte, error) {
	if len(p) < 4 {
		return "", nil, fmt.Errorf("%w: %s length truncated", ErrLicense, name)
	}
	n := int(binary.LittleEndian.Uint32(p))
	p = p[4:]
	if n == 0 || n%2 != 0 || n > len(p) || n > 2*maxStrLen {
		return "", nil, fmt.Errorf("%w: %s length %d", ErrLicense, name, n)
	}
	var sb strings.Builder
	for i := 0; i+1 < n; i += 2 {
		u := binary.LittleEndian.Uint16(p[i:])
		if u == 0 {
			break
		}
		sb.WriteRune(rune(u))
	}
	return sb.String(), p[n:], nil
}

func ansiZ(s, name string) ([]byte, error) {
	if s == "" || len(s) > maxStrLen || strings.ContainsRune(s, 0) {
		return nil, fmt.Errorf("%w: %s must be 1..%d bytes without NUL", ErrLicense, name, maxStrLen)
	}
	for _, r := range s {
		if r > 0x7f {
			return nil, fmt.Errorf("%w: %s must be ASCII", ErrLicense, name)
		}
	}
	return append([]byte(s), 0), nil
}
