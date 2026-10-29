package transport

import (
	"bytes"
	"crypto/rc4"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMD4Vectors(t *testing.T) {
	for in, want := range map[string]string{
		"":                              "31d6cfe0d16ae931b73c59d7e0c089c0",
		"abc":                           "a448017aaf21d8525fc10ae87aa6729d",
		"message digest":                "d9130a8164549fe818874806e1c7014b",
		strings.Repeat("1234567890", 8): "e33b4ddc9c38f2199c3e7b164fcc0536",
	} {
		if got := md4Sum([]byte(in)); hex.EncodeToString(got[:]) != want {
			t.Errorf("md4(%q) = %x", in, got)
		}
	}
}

func TestNTOWFv2Vector(t *testing.T) {
	// MS-NLMP 4.2.4.1.1
	if got := hex.EncodeToString(ntlmResponseKey("User", "Domain", "Password")); got != "0c868a403bfd7a93a3001ef22ef02e3f" {
		t.Fatal(got)
	}
}

// TestCredSSPExchange runs the client against an in-memory server that
// checks the NTLMv2 proof, MIC, channel binding and public-key binding,
// then decrypts the delegated credentials.
func TestCredSSPExchange(t *testing.T) {
	publicKey := []byte("subject-public-key")
	binding := bytes.Repeat([]byte{0x5a}, 16)
	client, srv := net.Pipe()
	defer func() { _ = client.Close() }()
	done := make(chan error, 1)
	var delegated []string
	go func() { done <- fakeCredSSPServer(srv, publicKey, publicKey, binding, &delegated) }()
	var res Result
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := credsspExchange(client, publicKey, binding, "TERMSRV/host", "alice", "CORP", "s3cret", &res); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !res.NLA || res.CredSSPVersion != 6 || strings.Join(delegated, "|") != "CORP|alice|s3cret" {
		t.Fatalf("res %+v delegated %v", res, delegated)
	}
}

func TestCredSSPRejectsWrongServerBinding(t *testing.T) {
	client, srv := net.Pipe()
	defer func() { _ = client.Close() }()
	binding := bytes.Repeat([]byte{1}, 16)
	go func() { _ = fakeCredSSPServer(srv, []byte("real-key"), []byte("other-key"), binding, new([]string)) }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	err := credsspExchange(client, []byte("real-key"), binding, "TERMSRV/host", "alice", "CORP", "s3cret", &Result{})
	if err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("got %v, want public-key binding mismatch", err)
	}
}

func TestReadTSRequestErrorCode(t *testing.T) {
	var buf bytes.Buffer
	if err := writeTSRequest(&buf, tsRequest{Version: 6, ErrorCode: int64(int32(-1073741715))}); err != nil {
		t.Fatal(err)
	}
	if _, err := readTSRequest(&buf); err == nil || !strings.Contains(err.Error(), "0xc000006d") {
		t.Fatal(err)
	}
}

func fakeCredSSPServer(conn net.Conn, publicKey, replyKey, binding []byte, delegated *[]string) error {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	first, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	negotiate := first.Tokens[0].Token
	challenge := make([]byte, 56)
	copy(challenge, ntlmSignature)
	binary.LittleEndian.PutUint32(challenge[8:], 2)
	binary.LittleEndian.PutUint32(challenge[20:], ntlmFlags)
	copy(challenge[24:], "8bytes!!")
	info := ntlmAppendAV(nil, 2, ntlmUTF16("CORP"))
	stamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(stamp, 1)
	info = ntlmAppendAV(info, 7, stamp)
	info = ntlmAppendAV(info, 0, nil)
	binary.LittleEndian.PutUint16(challenge[40:], uint16(len(info)))
	binary.LittleEndian.PutUint16(challenge[42:], uint16(len(info)))
	binary.LittleEndian.PutUint32(challenge[44:], 56)
	challenge = append(challenge, info...)
	if err := writeTSRequest(conn, tsRequest{Version: 6, Tokens: []negoToken{{Token: challenge}}}); err != nil {
		return err
	}
	second, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	auth := second.Tokens[0].Token
	field := func(i int) []byte { b, _ := ntlmBuffer(auth, 12+8*i, 88); return b }
	nt, domain, user, encKey := field(1), field(2), field(3), field(5)
	key := ntlmResponseKey("alice", "CORP", "s3cret")
	if !bytes.Equal(nt[:16], ntlmHMAC(key, challenge[24:32], nt[16:])) {
		return errorString("bad NT proof")
	}
	if !bytes.Contains(nt, ntlmAppendAV(nil, 10, binding)) || !bytes.Contains(nt, ntlmAppendAV(nil, 9, ntlmUTF16("TERMSRV/host"))) {
		return errorString("missing channel binding or SPN")
	}
	if !bytes.Equal(field(0), make([]byte, 24)) || !bytes.Equal(domain, ntlmUTF16("CORP")) || !bytes.Equal(user, ntlmUTF16("alice")) {
		return errorString("bad authenticate fields")
	}
	rc, _ := rc4.NewCipher(ntlmHMAC(key, nt[:16]))
	exported := make([]byte, 16)
	rc.XORKeyStream(exported, encKey)
	mic := append([]byte{}, auth[72:88]...)
	zeroed := append([]byte{}, auth...)
	copy(zeroed[72:88], make([]byte, 16))
	if !bytes.Equal(mic, ntlmHMAC(exported, negotiate, challenge, zeroed)) {
		return errorString("bad MIC")
	}
	security, _ := newNTLMSecurity(exported)
	proof, err := security.client.unwrap(second.PubKeyAuth)
	if err != nil {
		return err
	}
	if !bytes.Equal(proof, credsspBinding("Client-To-Server", second.Nonce, publicKey)) {
		return errorString("bad client binding")
	}
	reply := security.server.wrap(credsspBinding("Server-To-Client", second.Nonce, replyKey))
	if err := writeTSRequest(conn, tsRequest{Version: 6, PubKeyAuth: reply}); err != nil {
		return err
	}
	third, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	plain, err := security.client.unwrap(third.AuthInfo)
	if err != nil {
		return err
	}
	var creds struct {
		Type int    `asn1:"explicit,tag:0"`
		Data []byte `asn1:"explicit,tag:1"`
	}
	var pw struct {
		Domain   []byte `asn1:"explicit,tag:0"`
		User     []byte `asn1:"explicit,tag:1"`
		Password []byte `asn1:"explicit,tag:2"`
	}
	if _, err := asn1.Unmarshal(plain, &creds); err != nil {
		return err
	}
	if _, err := asn1.Unmarshal(creds.Data, &pw); err != nil {
		return err
	}
	for _, b := range [][]byte{pw.Domain, pw.User, pw.Password} {
		*delegated = append(*delegated, string(bytes.ReplaceAll(b, []byte{0}, nil)))
	}
	return nil
}

type errorString string

func (e errorString) Error() string { return string(e) }
