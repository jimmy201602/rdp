package transport

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// ErrCredSSP means NLA failed before the RDP Basic Settings Exchange.
var ErrCredSSP = errors.New("CredSSP authentication failed")

type negoToken struct {
	Token []byte `asn1:"explicit,tag:0"`
}

type tsRequest struct {
	Version    int         `asn1:"explicit,tag:0"`
	Tokens     []negoToken `asn1:"optional,explicit,tag:1"`
	AuthInfo   []byte      `asn1:"optional,explicit,tag:2"`
	PubKeyAuth []byte      `asn1:"optional,explicit,tag:3"`
	ErrorCode  int64       `asn1:"optional,explicit,tag:4"`
	Nonce      []byte      `asn1:"optional,explicit,tag:5"`
}

func writeTSRequest(w io.Writer, request tsRequest) error {
	data, err := asn1.Marshal(request)
	if err != nil {
		return err
	}
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func readTSRequest(r io.Reader) (tsRequest, error) {
	var request tsRequest
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return request, err
	}
	if header[0] != 0x30 {
		return request, errors.New("expected TSRequest sequence")
	}
	n := int(header[1])
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 3 {
			return request, errors.New("invalid TSRequest length")
		}
		length := make([]byte, count)
		if _, err := io.ReadFull(r, length); err != nil {
			return request, err
		}
		header = append(header, length...)
		n = 0
		for _, b := range length {
			n = n<<8 | int(b)
		}
	}
	if n > 1<<20 {
		return request, errors.New("TSRequest exceeds size limit")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return request, err
	}
	rest, err := asn1.Unmarshal(append(header, body...), &request)
	if err != nil || len(rest) != 0 {
		return request, errors.New("invalid TSRequest encoding")
	}
	if request.ErrorCode != 0 {
		return request, fmt.Errorf("server NTSTATUS 0x%08x", uint32(request.ErrorCode))
	}
	// Older versions lack the nonce-bound public-key proof (CVE-2018-0886).
	if request.Version < 5 || request.Version > 6 {
		return request, errors.New("server must support CredSSP version 5 or 6")
	}
	return request, nil
}

func credsspPublicKey(cert *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
	if err != nil || len(rest) != 0 || spki.Key.BitLength%8 != 0 || len(spki.Key.Bytes) == 0 {
		return nil, errors.New("invalid TLS subject public key")
	}
	return spki.Key.Bytes, nil
}

// tlsServerEndPoint uses RFC 5929's certificate hash in a GSS channel binding
// structure (MS-NLMP MsvAvChannelBindings), independently of pubKeyAuth.
func tlsServerEndPoint(cert *x509.Certificate) []byte {
	var digest []byte
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h := sha512.Sum384(cert.Raw)
		digest = h[:]
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h := sha512.Sum512(cert.Raw)
		digest = h[:]
	default:
		h := sha256.Sum256(cert.Raw)
		digest = h[:]
	}
	app := append([]byte("tls-server-end-point:"), digest...)
	binding := make([]byte, 20)
	binary.LittleEndian.PutUint32(binding[16:], uint32(len(app)))
	h := md5.Sum(append(binding, app...))
	return h[:]
}

func credsspBinding(direction string, nonce, key []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("CredSSP " + direction + " Binding Hash\x00"))
	_, _ = h.Write(nonce)
	_, _ = h.Write(key)
	return h.Sum(nil)
}

func authenticateNLA(conn *tls.Conn, address string, opts Options, res *Result) error {
	if !opts.NLA {
		return nil
	}
	err := credsspClient(conn, address, opts, res)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCredSSP, err)
	}
	return nil
}

func credsspClient(conn *tls.Conn, address string, opts Options, res *Result) error {
	if opts.UserName == "" || opts.Password == "" {
		return errors.New("NLA requires a user and password")
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return errors.New("TLS peer certificate missing")
	}
	key, err := credsspPublicKey(certs[0])
	if err != nil {
		return err
	}
	name := opts.ServerName
	if name == "" {
		name, _, err = net.SplitHostPort(address)
		if err != nil {
			return err
		}
	}
	user, domain := opts.UserName, opts.Domain
	if domain == "" {
		if parts := strings.SplitN(user, "\\", 2); len(parts) == 2 {
			domain, user = parts[0], parts[1]
		}
	}
	return credsspExchange(conn, key, tlsServerEndPoint(certs[0]), "TERMSRV/"+name, user, domain, opts.Password, res)
}

func credsspExchange(conn io.ReadWriter, publicKey, binding []byte, spn, user, domain, password string, res *Result) error {
	negotiate := ntlmNegotiate()
	if err := writeTSRequest(conn, tsRequest{Version: 6, Tokens: []negoToken{{Token: negotiate}}}); err != nil {
		return err
	}
	challenge, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if len(challenge.Tokens) != 1 || len(challenge.PubKeyAuth) != 0 || len(challenge.AuthInfo) != 0 {
		return errors.New("expected one NTLM challenge token")
	}
	auth, security, err := ntlmAuthenticate(negotiate, challenge.Tokens[0].Token, binding, user, domain, password, spn)
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	proof := security.client.wrap(credsspBinding("Client-To-Server", nonce, publicKey))
	if err := writeTSRequest(conn, tsRequest{Version: 6, Tokens: []negoToken{{Token: auth}}, PubKeyAuth: proof, Nonce: nonce}); err != nil {
		return err
	}
	reply, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if reply.Version != challenge.Version || len(reply.AuthInfo) != 0 {
		return errors.New("unexpected CredSSP public-key reply")
	}
	plain, err := security.server.unwrap(reply.PubKeyAuth)
	if err != nil {
		return err
	}
	if !hmac.Equal(plain, credsspBinding("Server-To-Client", nonce, publicKey)) {
		return errors.New("server TLS public-key binding mismatch")
	}
	passwordCreds := struct {
		Domain   []byte `asn1:"explicit,tag:0"`
		User     []byte `asn1:"explicit,tag:1"`
		Password []byte `asn1:"explicit,tag:2"`
	}{ntlmUTF16(domain), ntlmUTF16(user), ntlmUTF16(password)}
	encoded, err := asn1.Marshal(passwordCreds)
	if err != nil {
		return err
	}
	credentials := struct {
		Type int    `asn1:"explicit,tag:0"`
		Data []byte `asn1:"explicit,tag:1"`
	}{1, encoded}
	encoded, err = asn1.Marshal(credentials)
	if err != nil {
		return err
	}
	if err := writeTSRequest(conn, tsRequest{Version: 6, AuthInfo: security.client.wrap(encoded)}); err != nil {
		return err
	}
	res.NLA = true
	res.CredSSPVersion = challenge.Version
	return nil
}
