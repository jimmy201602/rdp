// Package nla implements CredSSP (MS-CSSP) over NTLMv2 (MS-NLMP) for RDP
// Network Level Authentication, for both the client and the server role.
//
// Only CredSSP versions 5 and 6 are spoken: the public key of the TLS
// server is bound to the exchange through the nonce-based hash, so a
// man-in-the-middle TLS endpoint cannot relay the authentication. NTLM is
// restricted to NTLMv2 with extended session security, 128-bit signing and
// sealing and key exchange; LM, NTLMv1 and unsigned exchanges are refused.
// Kerberos is not implemented. Servers accept the raw NTLM tokens FreeRDP
// sends as well as SPNEGO-wrapped NTLM from mstsc.
package nla

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ErrLogonFailure is returned by Server when the client's credentials are
// unknown or its NTLMv2 proof does not match. The client receives
// STATUS_LOGON_FAILURE.
var ErrLogonFailure = errors.New("NTLM logon failure")

// STATUS_LOGON_FAILURE (0xC000006D) as the signed INTEGER TSRequest carries.
const statusLogonFailure int64 = -1073741715

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

type tsPasswordCreds struct {
	Domain   []byte `asn1:"explicit,tag:0"`
	User     []byte `asn1:"explicit,tag:1"`
	Password []byte `asn1:"explicit,tag:2"`
}

type tsCredentials struct {
	Type int    `asn1:"explicit,tag:0"`
	Data []byte `asn1:"explicit,tag:1"`
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

// readTSRequest reads one DER TSRequest. A non-zero ErrorCode is returned
// as an error naming the NTSTATUS.
func readTSRequest(r io.Reader) (tsRequest, error) {
	var request tsRequest
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return request, err
	}
	if header[0] != tagSequence {
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
		return request, fmt.Errorf("peer NTSTATUS 0x%08x", uint32(request.ErrorCode))
	}
	return request, nil
}

// PublicKey returns the subjectPublicKey bytes of cert, the value both
// CredSSP peers bind to.
func PublicKey(cert *x509.Certificate) ([]byte, error) {
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

// TLSServerEndPoint is the MsvAvChannelBindings value for cert: the MD5 of
// a GSS channel binding structure carrying RFC 5929's
// tls-server-end-point certificate hash.
func TLSServerEndPoint(cert *x509.Certificate) []byte {
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

// SplitUser separates a DOMAIN\user name when no explicit domain is given.
func SplitUser(user, domain string) (string, string) {
	if domain == "" {
		if parts := strings.SplitN(user, "\\", 2); len(parts) == 2 {
			return parts[1], parts[0]
		}
	}
	return user, domain
}

// marshalPasswordCreds encodes TSCredentials{credType 1, TSPasswordCreds}.
func marshalPasswordCreds(domain, user, password string) ([]byte, error) {
	encoded, err := asn1.Marshal(tsPasswordCreds{utf16LE(domain), utf16LE(user), utf16LE(password)})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(tsCredentials{1, encoded})
}

func bindingHash(direction string, nonce, key []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("CredSSP " + direction + " Binding Hash\x00"))
	_, _ = h.Write(nonce)
	_, _ = h.Write(key)
	return h.Sum(nil)
}

// --- client -------------------------------------------------------------------

// ClientConfig drives Client. PublicKey and Binding come from the TLS
// server certificate (PublicKey, TLSServerEndPoint); SPN is usually
// "TERMSRV/" + host.
type ClientConfig struct {
	PublicKey []byte
	Binding   []byte
	SPN       string
	User      string
	Domain    string
	Password  string
}

// ClientResult reports a completed client exchange.
type ClientResult struct {
	Version int // CredSSP version the server used (5 or 6)
}

// Client authenticates to a CredSSP server over an established TLS stream
// and delegates the password credentials.
func Client(conn io.ReadWriter, cfg ClientConfig) (ClientResult, error) {
	if cfg.User == "" || cfg.Password == "" {
		return ClientResult{}, errors.New("NLA requires a user and password")
	}
	if len(cfg.PublicKey) == 0 || len(cfg.Binding) != 16 {
		return ClientResult{}, errors.New("NLA requires the server public key and TLS binding")
	}
	negotiate := ntlmNegotiate()
	if err := writeTSRequest(conn, tsRequest{Version: 6, Tokens: []negoToken{{Token: negotiate}}}); err != nil {
		return ClientResult{}, err
	}
	challenge, err := readTSRequest(conn)
	if err != nil {
		return ClientResult{}, err
	}
	// Older versions lack the nonce-bound public-key proof (CVE-2018-0886).
	if challenge.Version < 5 || challenge.Version > 6 {
		return ClientResult{}, errors.New("server must support CredSSP version 5 or 6")
	}
	if len(challenge.Tokens) != 1 || len(challenge.PubKeyAuth) != 0 || len(challenge.AuthInfo) != 0 {
		return ClientResult{}, errors.New("expected one NTLM challenge token")
	}
	auth, security, err := ntlmAuthenticate(negotiate, challenge.Tokens[0].Token, cfg.Binding, cfg.User, cfg.Domain, cfg.Password, cfg.SPN)
	if err != nil {
		return ClientResult{}, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return ClientResult{}, err
	}
	proof := security.client.wrap(bindingHash("Client-To-Server", nonce, cfg.PublicKey))
	if err := writeTSRequest(conn, tsRequest{Version: 6, Tokens: []negoToken{{Token: auth}}, PubKeyAuth: proof, Nonce: nonce}); err != nil {
		return ClientResult{}, err
	}
	reply, err := readTSRequest(conn)
	if err != nil {
		return ClientResult{}, err
	}
	if reply.Version != challenge.Version || len(reply.AuthInfo) != 0 {
		return ClientResult{}, errors.New("unexpected CredSSP public-key reply")
	}
	plain, err := security.server.unwrap(reply.PubKeyAuth)
	if err != nil {
		return ClientResult{}, err
	}
	if !hmac.Equal(plain, bindingHash("Server-To-Client", nonce, cfg.PublicKey)) {
		return ClientResult{}, errors.New("server TLS public-key binding mismatch")
	}
	encoded, err := marshalPasswordCreds(cfg.Domain, cfg.User, cfg.Password)
	if err != nil {
		return ClientResult{}, err
	}
	if err := writeTSRequest(conn, tsRequest{Version: 6, AuthInfo: security.client.wrap(encoded)}); err != nil {
		return ClientResult{}, err
	}
	return ClientResult{Version: challenge.Version}, nil
}

// --- server -------------------------------------------------------------------

// ServerConfig drives Server.
type ServerConfig struct {
	// PublicKey is the subjectPublicKey of the certificate this TLS
	// endpoint presented; Binding its TLSServerEndPoint value (optional:
	// when set, a client-supplied channel binding must match it).
	PublicKey []byte
	Binding   []byte
	// Lookup returns the password of user (domain as sent by the client,
	// often empty or the client's workgroup); ok=false denies the logon.
	Lookup func(user, domain string) (password string, ok bool)
	// DomainName and ComputerName are advertised in the NTLM challenge
	// (defaults WORKGROUP / RDPGW).
	DomainName   string
	ComputerName string
	// Now supplies the challenge timestamp (default time.Now).
	Now func() time.Time
}

// Credentials are the TSPasswordCreds the client delegated.
type Credentials struct {
	Domain, User, Password string
}

// ServerResult reports a completed server exchange.
type ServerResult struct {
	Version  int
	Identity Identity // proven by the NTLMv2 response
	// Credentials delegated by the client; nil when it delegated nothing
	// (restricted admin / remote credential guard). When present the user
	// and password are those that passed NTLM.
	Credentials  *Credentials
	SPNEGO       bool // tokens were SPNEGO-wrapped (mstsc)
	ChannelBound bool // client bound its response to this TLS certificate
}

// Server authenticates a CredSSP client over an established TLS stream.
// On a credential failure it reports STATUS_LOGON_FAILURE to the client and
// returns ErrLogonFailure.
func Server(conn io.ReadWriter, cfg ServerConfig) (*ServerResult, error) {
	if len(cfg.PublicKey) == 0 || cfg.Lookup == nil {
		return nil, errors.New("nla: server public key and Lookup required")
	}
	if cfg.DomainName == "" {
		cfg.DomainName = "WORKGROUP"
	}
	if cfg.ComputerName == "" {
		cfg.ComputerName = "RDPGW"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	req, err := readTSRequest(conn)
	if err != nil {
		return nil, err
	}
	peerVersion := req.Version
	version := min(peerVersion, 6)
	fail := func(err error) (*ServerResult, error) {
		if peerVersion >= 3 && peerVersion != 5 {
			_ = writeTSRequest(conn, tsRequest{Version: version, ErrorCode: statusLogonFailure})
		}
		return nil, err
	}
	if peerVersion < 5 {
		return fail(fmt.Errorf("client CredSSP version %d lacks the nonce-bound public-key proof", peerVersion))
	}
	acc := &acceptor{cfg: cfg}
	var out []byte
	for {
		if len(req.Tokens) != 1 {
			return fail(errors.New("expected one authentication token"))
		}
		var done bool
		if out, done, err = acc.step(req.Tokens[0].Token); err != nil {
			return fail(err)
		}
		if done {
			break
		}
		if err := writeTSRequest(conn, tsRequest{Version: version, Tokens: []negoToken{{Token: out}}}); err != nil {
			return nil, err
		}
		if req, err = readTSRequest(conn); err != nil {
			return nil, err
		}
		if req.Version != peerVersion {
			return fail(errors.New("client changed its CredSSP version"))
		}
	}
	if len(req.PubKeyAuth) == 0 && len(out) > 0 {
		// The final mechanism token was answered without the proof.
		if err := writeTSRequest(conn, tsRequest{Version: version, Tokens: []negoToken{{Token: out}}}); err != nil {
			return nil, err
		}
		out = nil
		if req, err = readTSRequest(conn); err != nil {
			return nil, err
		}
	}
	if len(req.Nonce) != 32 || len(req.PubKeyAuth) == 0 {
		return fail(errors.New("expected the client nonce and public-key proof"))
	}
	sec := acc.result.security
	plain, err := sec.client.unwrap(req.PubKeyAuth)
	if err != nil {
		return fail(err)
	}
	if !hmac.Equal(plain, bindingHash("Client-To-Server", req.Nonce, cfg.PublicKey)) {
		return fail(errors.New("client TLS public-key binding mismatch"))
	}
	reply := tsRequest{Version: version, PubKeyAuth: sec.server.wrap(bindingHash("Server-To-Client", req.Nonce, cfg.PublicKey))}
	if len(out) > 0 {
		reply.Tokens = []negoToken{{Token: out}}
	}
	if err := writeTSRequest(conn, reply); err != nil {
		return nil, err
	}
	if req, err = readTSRequest(conn); err != nil {
		return nil, err
	}
	if req.Version != peerVersion || len(req.AuthInfo) == 0 {
		return nil, errors.New("expected delegated credentials")
	}
	if plain, err = sec.client.unwrap(req.AuthInfo); err != nil {
		return nil, err
	}
	var creds tsCredentials
	if rest, err := asn1.Unmarshal(plain, &creds); err != nil || len(rest) != 0 {
		return nil, errors.New("invalid TSCredentials")
	}
	if creds.Type != 1 {
		return nil, fmt.Errorf("unsupported TSCredentials type %d (only password credentials)", creds.Type)
	}
	var pw tsPasswordCreds
	if rest, err := asn1.Unmarshal(creds.Data, &pw); err != nil || len(rest) != 0 {
		return nil, errors.New("invalid TSPasswordCreds")
	}
	res := &ServerResult{Version: version, Identity: acc.result.identity, SPNEGO: acc.spnego, ChannelBound: acc.result.channelBound}
	var text [3]string
	for i, raw := range [][]byte{pw.Domain, pw.User, pw.Password} {
		if text[i], err = fromUTF16LE(raw); err != nil {
			return nil, err
		}
	}
	if text[1] != "" || text[2] != "" {
		if !strings.EqualFold(text[1], res.Identity.User) || text[2] != acc.password {
			return nil, errors.New("delegated credentials differ from the authenticated identity")
		}
		res.Credentials = &Credentials{Domain: text[0], User: text[1], Password: text[2]}
	}
	acc.password = ""
	return res, nil
}
