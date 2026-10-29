package licensing

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadHex(tb testing.TB, name string) []byte {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "wire", "testdata", name))
	if err != nil {
		tb.Fatal(err)
	}
	b, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// MS-RDPELE 4.1 Server License Request: the client must parse it and answer
// with a well-formed Client New License Request (compare with 4.2).
func TestLicenseRequestSample(t *testing.T) {
	msg := loadHex(t, "ele-4.1-license-request.hex")
	c := &Client{UserName: "user", MachineName: "machine", Rand: zeroReader{}}
	reply, done, err := c.Handle(msg)
	if err != nil {
		t.Fatal(err)
	}
	if done || c.Done() {
		t.Fatal("done after license request")
	}
	if c.CompanyName != "Microsoft Corporation" || c.ProductID != "A02" || c.ProductVersion == 0 {
		t.Fatalf("product info %q %q 0x%x", c.CompanyName, c.ProductID, c.ProductVersion)
	}
	if len(c.Scopes) != 1 || c.Scopes[0] != "microsoft.com" {
		t.Fatalf("scopes %q", c.Scopes)
	}

	sample := loadHex(t, "ele-4.2-new-license-request.hex")
	if reply[0] != MsgNewLicenseRequest || reply[1] != sample[1] || int(binary.LittleEndian.Uint16(reply[2:])) != len(reply) {
		t.Fatalf("reply preamble % x", reply[:4])
	}
	body := reply[4:]
	if binary.LittleEndian.Uint32(body) != keyExchangeAlgRSA || binary.LittleEndian.Uint32(body[4:]) != DefaultPlatformID {
		t.Fatalf("alg/platform % x", body[:8])
	}
	typ, enc, rest, err := readBlob(body[8+clientRandomLen:])
	if err != nil || typ != BlobRandom {
		t.Fatalf("premaster blob %#x %v", typ, err)
	}
	sampleTyp, sampleEnc, _, _ := readBlob(sample[4+8+clientRandomLen:])
	if sampleTyp != BlobRandom || len(enc) != len(sampleEnc) {
		t.Fatalf("encrypted premaster %d bytes, sample %d", len(enc), len(sampleEnc))
	}
	typ, user, rest, err := readBlob(rest)
	if err != nil || typ != BlobClientUserName || string(user) != "user\x00" {
		t.Fatalf("user blob %#x %q %v", typ, user, err)
	}
	typ, machine, rest, err := readBlob(rest)
	if err != nil || typ != BlobClientMachineName || string(machine) != "machine\x00" || len(rest) != 0 {
		t.Fatalf("machine blob %#x %q %d %v", typ, machine, len(rest), err)
	}
}

// Structure of the remaining MS-RDPELE samples (keys are not published, so
// only framing can be checked).
func TestSampleFraming(t *testing.T) {
	pc := loadHex(t, "ele-4.4-platform-challenge.hex")
	typ, body, err := decodePreamble(pc)
	if err != nil || typ != MsgPlatformChallenge {
		t.Fatalf("platform challenge %#x %v", typ, err)
	}
	// wBlobType is arbitrary in the sample (0xf750) and must be ignored.
	bt, blob, rest, err := readBlob(body[4:])
	if err != nil || bt != 0xf750 || len(blob) != 10 || len(rest) != macLen {
		t.Fatalf("platform challenge blob %#x %d %d %v", bt, len(blob), len(rest), err)
	}
	resp := loadHex(t, "ele-4.5-platform-challenge-response.hex")
	typ, body, err = decodePreamble(resp)
	if err != nil || typ != MsgPlatformChallengeResponse {
		t.Fatalf("response %#x %v", typ, err)
	}
	// The sample annotates both wBlobType fields as ignored (they hold
	// BB_DATA_BLOB although 2.2.2.5 specifies BB_ENCRYPTED_DATA_BLOB).
	bt, blob, rest, err = readBlob(body)
	if err != nil || bt != BlobData || len(blob) != 18 {
		t.Fatalf("response blob %#x %d %v", bt, len(blob), err)
	}
	bt, blob, rest, err = readBlob(rest)
	if err != nil || bt != BlobData || len(blob) != hardwareIDLen || len(rest) != macLen {
		t.Fatalf("hwid blob %#x %d %d %v", bt, len(blob), len(rest), err)
	}
	nl := loadHex(t, "ele-4.6-new-license.hex")
	typ, body, err = decodePreamble(nl)
	if err != nil || typ != MsgNewLicense {
		t.Fatalf("new license %#x %v", typ, err)
	}
	bt, _, rest, err = readBlob(body)
	if err != nil || bt != BlobEncryptedData || len(rest) != macLen {
		t.Fatalf("new license blob %#x %d %v", bt, len(rest), err)
	}
	// Without the session keys the client must refuse it (MAC mismatch) and
	// must not accept it before a License Request.
	c := &Client{}
	if _, _, err := c.Handle(nl); !errors.Is(err, ErrLicense) {
		t.Fatalf("new license before request: %v", err)
	}
}

// MS-RDPBCGR 4.1.11 Server License Error PDU - Valid Client (decrypted body).
func TestValidClientAndErrorAlerts(t *testing.T) {
	valid := []byte{0xff, 0x03, 0x10, 0x00, 0x07, 0, 0, 0, 0x02, 0, 0, 0, 0x04, 0x00, 0x00, 0x00}
	c := &Client{}
	reply, done, err := c.Handle(valid)
	if err != nil || !done || reply != nil || !c.Done() || c.Outcome != "valid-client" {
		t.Fatalf("valid client: %v %v % x %q", err, done, reply, c.Outcome)
	}
	bad := append([]byte{}, valid...)
	bad[4] = byte(ErrInvalidClient)
	bad[8] = byte(StateTotalAbort)
	var ea *ErrorAlert
	if _, _, err := (&Client{}).Handle(bad); !errors.As(err, &ea) || ea.Code != ErrInvalidClient || ea.StateTransition != StateTotalAbort {
		t.Fatalf("error alert: %v", err)
	}
	cases := map[string][]byte{
		"size mismatch": append([]byte{0xff, 0x03, 0x11, 0x00}, valid[4:]...),
		"bad version":   append([]byte{0xff, 0x05, 0x10, 0x00}, valid[4:]...),
		"short":         valid[:3],
		"wrong blob":    append(append([]byte{0xff, 0x03, 0x11, 0x00}, valid[4:12]...), 0x01, 0x00, 0x01, 0x00, 0x00),
		"trailing":      append(append([]byte{0xff, 0x03, 0x11, 0x00}, valid[4:]...), 0x00),
		"unknown type":  append([]byte{0x12, 0x03, 0x10, 0x00}, valid[4:]...),
	}
	for name, msg := range cases {
		if _, _, err := (&Client{}).Handle(msg); !errors.Is(err, ErrLicense) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A fake server with its own RSA key exercises the complete exchange: it
// decrypts the premaster secret, derives the same keys, issues a platform
// challenge and a new license and checks every client MAC.
func TestFullExchangeAgainstFakeServer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var serverRandom [32]byte
	for i := range serverRandom {
		serverRandom[i] = byte(0xa0 + i)
	}
	request := buildLicenseRequest(t, serverRandom[:], proprietaryCertificate(&key.PublicKey))
	c := &Client{UserName: "tester", MachineName: "rdpkernel", HardwareID: [16]byte{1, 2, 3, 4}}
	reply, done, err := c.Handle(request)
	if err != nil || done {
		t.Fatalf("license request: %v %v", err, done)
	}

	// Server side: recover the premaster secret and derive the keys.
	body := reply[4:]
	clientRandom := body[8 : 8+32]
	_, enc, rest, err := readBlob(body[40:])
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != key.Size()+8 || !bytes.Equal(enc[key.Size():], make([]byte, 8)) {
		t.Fatalf("encrypted premaster %d bytes, padding % x", len(enc), enc[key.Size():])
	}
	cInt := new(big.Int).SetBytes(Reverse(enc[:key.Size()]))
	mInt := new(big.Int).Exp(cInt, key.D, key.N)
	preMaster := Reverse(mInt.Bytes())
	for len(preMaster) < preMasterSecretLen {
		preMaster = append(preMaster, 0)
	}
	if !bytes.Equal(preMaster, c.preMaster[:]) {
		t.Fatalf("premaster mismatch\n% x\n% x", preMaster, c.preMaster[:])
	}
	macSalt, encKey := DeriveKeys(preMaster, clientRandom, serverRandom[:])
	if !bytes.Equal(macSalt, c.macSaltKey) || !bytes.Equal(encKey, c.encKey) {
		t.Fatal("server-side key derivation differs")
	}
	_, user, rest, _ := readBlob(rest)
	_, machine, _, _ := readBlob(rest)
	if string(user) != "tester\x00" || string(machine) != "rdpkernel\x00" {
		t.Fatalf("names %q %q", user, machine)
	}

	// Platform challenge.
	challenge := []byte("TEST\x00")
	encChallenge, _ := RC4(encKey, challenge)
	pcBody := binary.LittleEndian.AppendUint32(nil, 0)
	pcBody = appendBlob(pcBody, BlobEncryptedData, encChallenge)
	pcBody = append(pcBody, MAC(macSalt, challenge)...)
	pc := serverMessage(MsgPlatformChallenge, pcBody)
	reply, done, err = c.Handle(pc)
	if err != nil || done || reply[0] != MsgPlatformChallengeResponse {
		t.Fatalf("platform challenge: %v %v", err, done)
	}
	_, encResp, rest, err := readBlob(reply[4:])
	if err != nil {
		t.Fatal(err)
	}
	_, encHWID, mac, err := readBlob(rest)
	if err != nil || len(mac) != macLen {
		t.Fatalf("response framing %v %d", err, len(mac))
	}
	resp, _ := RC4(encKey, encResp)
	hwid, _ := RC4(encKey, encHWID)
	if !bytes.Equal(MAC(macSalt, append(append([]byte{}, resp...), hwid...)), mac) {
		t.Fatal("client response MAC does not verify")
	}
	if binary.LittleEndian.Uint16(resp) != challengeVersion || binary.LittleEndian.Uint16(resp[2:]) != challengeTypeOther ||
		binary.LittleEndian.Uint16(resp[4:]) != licenseDetailDetail || int(binary.LittleEndian.Uint16(resp[6:])) != len(challenge) ||
		!bytes.Equal(resp[8:], challenge) {
		t.Fatalf("response data % x", resp)
	}
	if binary.LittleEndian.Uint32(hwid) != DefaultPlatformID || !bytes.Equal(hwid[4:], c.HardwareID[:]) {
		t.Fatalf("hwid % x", hwid)
	}

	// Tampered challenge MAC must be refused.
	bad := append([]byte{}, pc...)
	bad[len(bad)-1] ^= 1
	c2 := *c
	c2.state = stateAwaitChallengeOrLicense
	if _, _, err := c2.Handle(bad); !errors.Is(err, ErrLicense) {
		t.Fatalf("tampered challenge: %v", err)
	}

	// New license.
	info := bytes.Repeat([]byte{0x5a}, 40)
	encInfo, _ := RC4(encKey, info)
	nlBody := appendBlob(nil, BlobEncryptedData, encInfo)
	nlBody = append(nlBody, MAC(macSalt, info)...)
	reply, done, err = c.Handle(serverMessage(MsgNewLicense, nlBody))
	if err != nil || !done || reply != nil || c.Outcome != "new-license" {
		t.Fatalf("new license: %v %v % x %q", err, done, reply, c.Outcome)
	}
	if _, _, err := c.Handle(request); !errors.Is(err, ErrLicense) {
		t.Fatalf("license request after completion: %v", err)
	}
}

func TestLicenseRequestRejections(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cert := proprietaryCertificate(&key.PublicKey)
	good := buildLicenseRequest(t, make([]byte, 32), cert)
	noRSA := append([]byte{}, good...)
	// KeyExchangeList follows random(32) + version(4) + company + product.
	idx := bytes.Index(noRSA, []byte{0x0d, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00})
	if idx < 0 {
		t.Fatal("key exchange list not found")
	}
	noRSA[idx+4] = 0x02
	cases := map[string][]byte{
		"truncated":    good[:len(good)-3],
		"no RSA":       noRSA,
		"bad preamble": append([]byte{0x01, 0x03, 0x00, 0x00}, good[4:]...),
	}
	for name, msg := range cases {
		if _, _, err := (&Client{UserName: "u", MachineName: "m"}).Handle(msg); !errors.Is(err, ErrLicense) {
			t.Errorf("%s: %v", name, err)
		}
	}
	badCert := append([]byte{}, cert...)
	binary.LittleEndian.PutUint32(badCert, 7)
	if _, _, err := (&Client{UserName: "u", MachineName: "m"}).Handle(buildLicenseRequest(t, make([]byte, 32), badCert)); !errors.Is(err, ErrLicense) {
		t.Errorf("bad certificate version: %v", err)
	}
	if _, _, err := (&Client{UserName: "", MachineName: "m"}).Handle(good); !errors.Is(err, ErrLicense) {
		t.Errorf("empty user name: %v", err)
	}
	if _, _, err := (&Client{UserName: "\u00fc", MachineName: "m"}).Handle(good); !errors.Is(err, ErrLicense) {
		t.Errorf("non-ASCII user name: %v", err)
	}
}

func TestEncryptWithServerKeyRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte{0x01, 0x80, 0xff}, 16)
	enc, err := EncryptWithServerKey(&key.PublicKey, plain)
	if err != nil || len(enc) != key.Size()+8 {
		t.Fatalf("%d bytes %v", len(enc), err)
	}
	m := new(big.Int).Exp(new(big.Int).SetBytes(Reverse(enc[:key.Size()])), key.D, key.N)
	got := Reverse(m.Bytes())
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypted % x", got)
	}
	if _, err := EncryptWithServerKey(&key.PublicKey, make([]byte, key.Size())); !errors.Is(err, ErrLicense) {
		t.Fatalf("oversized plaintext: %v", err)
	}
}

func FuzzHandle(f *testing.F) {
	f.Add(loadHex(f, "ele-4.1-license-request.hex"))
	f.Add(loadHex(f, "ele-4.4-platform-challenge.hex"))
	f.Add(loadHex(f, "ele-4.6-new-license.hex"))
	f.Add([]byte{0xff, 0x03, 0x10, 0x00, 0x07, 0, 0, 0, 0x02, 0, 0, 0, 0x04, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, p []byte) {
		c := &Client{UserName: "u", MachineName: "m", Rand: zeroReader{}}
		_, _, _ = c.Handle(p)
	})
}

// --- test helpers -----------------------------------------------------------

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0x11
	}
	return len(p), nil
}

func serverMessage(typ uint8, body []byte) []byte {
	out := []byte{typ, preambleVersion3, 0, 0}
	binary.LittleEndian.PutUint16(out[2:], uint16(4+len(body)))
	return append(out, body...)
}

func utf16z(s string) []byte {
	var out []byte
	for _, r := range s {
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return append(out, 0, 0)
}

func buildLicenseRequest(t *testing.T, serverRandom, cert []byte) []byte {
	t.Helper()
	body := append([]byte{}, serverRandom...)
	body = binary.LittleEndian.AppendUint32(body, 0x00060000)
	company := utf16z("Test Corp")
	body = binary.LittleEndian.AppendUint32(body, uint32(len(company)))
	body = append(body, company...)
	product := utf16z("A02")
	body = binary.LittleEndian.AppendUint32(body, uint32(len(product)))
	body = append(body, product...)
	body = appendBlob(body, BlobKeyExchangeAlg, binary.LittleEndian.AppendUint32(nil, keyExchangeAlgRSA))
	body = appendBlob(body, BlobCertificate, cert)
	body = binary.LittleEndian.AppendUint32(body, 1)
	body = appendBlob(body, BlobScope, []byte("test.local\x00"))
	return serverMessage(MsgLicenseRequest, body)
}

func proprietaryCertificate(pub *rsa.PublicKey) []byte {
	modulus := Reverse(pub.N.Bytes())
	bitlen := uint32(len(modulus) * 8)
	key := binary.LittleEndian.AppendUint32(nil, rsaPublicKeyMagic)
	key = binary.LittleEndian.AppendUint32(key, bitlen/8+8)
	key = binary.LittleEndian.AppendUint32(key, bitlen)
	key = binary.LittleEndian.AppendUint32(key, bitlen/8-1)
	key = binary.LittleEndian.AppendUint32(key, uint32(pub.E))
	key = append(key, modulus...)
	key = append(key, make([]byte, 8)...)

	cert := binary.LittleEndian.AppendUint32(nil, certChainVersion1)
	cert = binary.LittleEndian.AppendUint32(cert, 1)
	cert = binary.LittleEndian.AppendUint32(cert, keyExchangeAlgRSA)
	cert = appendBlob(cert, blobTypeRSAKey, key)
	cert = appendBlob(cert, blobTypeRSASignature, make([]byte, 72))
	return cert
}

// xrdp answers any Client New License Request with a fixed STATUS_VALID_CLIENT
// Licensing Error Message whose zero-length blob has wBlobType 0x1428; the
// type is ignored when wBlobLen is 0 (MS-RDPBCGR 2.2.1.12.1.3).
func TestXrdpValidClientBlobTypeIgnored(t *testing.T) {
	msg := []byte{0xff, 0x02, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x28, 0x14, 0x00, 0x00}
	c := &Client{UserName: "u", MachineName: "m"}
	reply, done, err := c.Handle(msg)
	if err != nil || !done || reply != nil || c.Outcome != "valid-client" {
		t.Fatalf("reply=%x done=%v outcome=%q err=%v", reply, done, c.Outcome, err)
	}
	// A non-empty blob must still be BB_ERROR_BLOB.
	bad := append(msg[:12:12], 0x28, 0x14, 0x01, 0x00, 0x00)
	bad[2] = 0x11
	if _, _, err := (&Client{}).Handle(bad); err == nil {
		t.Fatal("non-empty blob with wrong type accepted")
	}
}

func TestEncodeValidClientAlert(t *testing.T) {
	msg := EncodeValidClientAlert()
	c := &Client{UserName: "u", MachineName: "m"}
	reply, done, err := c.Handle(msg)
	if err != nil || !done || reply != nil || c.Outcome != "valid-client" {
		t.Fatalf("reply %x done %v err %v outcome %q", reply, done, err, c.Outcome)
	}
	if len(msg) != 16 || msg[0] != MsgErrorAlert || msg[1] != 0x03 {
		t.Fatalf("alert %x", msg)
	}
}
