package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"rdp.local/kernel/wire"
)

func testCertificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// mcsServer describes how the fake server behaves after the TLS handshake.
type mcsServer struct {
	echoProtocols    uint32
	omitEchoField    bool
	encryptionMethod uint32
	staticChannels   []uint16
	omitBlock        uint16 // user data block type to leave out
	attachFailure    bool
	wrongJoinChannel bool
	gotConnectInit   []byte

	activation   *activationServer // continue after Channel Join when set
	demandActive []byte
}

type fakeServer struct {
	ln       net.Listener
	cert     tls.Certificate
	reply    []byte // X.224 payload sent as connection confirm
	doTLS    bool
	mcs      *mcsServer
	gotCR    chan []byte
	tlsError chan error
	done     chan error
}

func startFakeServer(t *testing.T, cert tls.Certificate, reply []byte, doTLS bool, mcs *mcsServer) *fakeServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{ln: ln, cert: cert, reply: reply, doTLS: doTLS, mcs: mcs,
		gotCR: make(chan []byte, 1), tlsError: make(chan error, 1), done: make(chan error, 1)}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serveOne()
	return s
}

func (s *fakeServer) serveOne() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	cr, err := wire.ReadTPKT(conn, 1024)
	if err != nil {
		return
	}
	s.gotCR <- cr
	if s.reply == nil {
		return
	}
	if err := wire.WriteTPKT(conn, s.reply); err != nil {
		return
	}
	if !s.doTLS {
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
	err = tlsConn.Handshake()
	s.tlsError <- err
	if err != nil || s.mcs == nil {
		return
	}
	s.done <- s.mcs.serve(tlsConn)
}

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func perLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	return []byte{0x80 | byte(n>>8), byte(n)}
}

func (m *mcsServer) connectResponse() []byte {
	var blocks []byte
	core := []byte{0x04, 0x00, 0x08, 0x00}
	if !m.omitEchoField {
		core = binary.LittleEndian.AppendUint32(core, m.echoProtocols)
	}
	netData := []byte{0xeb, 0x03, 0, 0}
	binary.LittleEndian.PutUint16(netData[2:], uint16(len(m.staticChannels)))
	for _, ch := range m.staticChannels {
		netData = binary.LittleEndian.AppendUint16(netData, ch)
	}
	if len(m.staticChannels)%2 == 1 {
		netData = append(netData, 0, 0)
	}
	sec := binary.LittleEndian.AppendUint32(nil, m.encryptionMethod)
	sec = binary.LittleEndian.AppendUint32(sec, 0)
	if m.encryptionMethod != 0 {
		sec = binary.LittleEndian.AppendUint32(sec, 32)
		sec = binary.LittleEndian.AppendUint32(sec, 4)
		sec = append(sec, make([]byte, 36)...)
	}
	for _, b := range []wire.UserDataBlock{{Type: wire.SCCore, Payload: core}, {Type: wire.SCNet, Payload: netData}, {Type: wire.SCSecurity, Payload: sec}} {
		if b.Type == m.omitBlock {
			continue
		}
		enc, _ := b.Encode()
		blocks = append(blocks, enc...)
	}
	gcc := []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x2a, 0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x00, 'M', 'c', 'D', 'n'}
	gcc = append(gcc, perLen(len(blocks))...)
	gcc = append(gcc, blocks...)
	params := []byte{0x02, 0x01, 0x22, 0x02, 0x01, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff, 0xf8, 0x02, 0x01, 0x02}
	body := []byte{0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, byte(len(params))}
	body = append(body, params...)
	body = append(body, 0x04)
	body = append(body, berLen(len(gcc))...)
	body = append(body, gcc...)
	out := []byte{0x7f, 0x66}
	out = append(out, berLen(len(body))...)
	return append(out, body...)
}

func (m *mcsServer) serve(conn net.Conn) error {
	pdu, err := readMCS(conn)
	if err != nil {
		return err
	}
	if len(pdu) < 2 || pdu[0] != 0x7f || pdu[1] != 0x65 {
		return errors.New("expected Connect-Initial")
	}
	m.gotConnectInit = pdu
	if err := writeMCS(conn, m.connectResponse()); err != nil {
		return err
	}
	if pdu, err = readMCS(conn); err != nil || !bytes.Equal(pdu, wire.EncodeErectDomainRequest()) {
		return errors.New("expected Erect Domain Request")
	}
	if pdu, err = readMCS(conn); err != nil || !bytes.Equal(pdu, wire.EncodeAttachUserRequest()) {
		return errors.New("expected Attach User Request")
	}
	if m.attachFailure {
		return writeMCS(conn, []byte{0x2d, 0xc0})
	}
	if err := writeMCS(conn, []byte{0x2e, 0x00, 0x00, 0x06}); err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		req, err := readMCS(conn)
		if err != nil {
			return err
		}
		if len(req) != 5 || req[0] != 0x38 || binary.BigEndian.Uint16(req[1:]) != 6 {
			return errors.New("bad Channel Join Request")
		}
		channel := req[3:5]
		if m.wrongJoinChannel {
			channel = []byte{0x03, 0xff}
		}
		confirm := []byte{0x3e, 0x00, 0x00, 0x06}
		confirm = append(confirm, req[3], req[4])
		confirm = append(confirm, channel...)
		if err := writeMCS(conn, confirm); err != nil {
			return err
		}
	}
	if m.activation != nil {
		return m.activation.serve(conn, m.demandActive)
	}
	return nil
}

func confirm(selected uint32) []byte {
	p := []byte{0x0e, 0xd0, 0, 0, 0, 0, 0, wire.TypeNegotiationResponse, 0, 0x08, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(p[11:], selected)
	return p
}

func TestProbeSuccessWithTrustedCertificate(t *testing.T) {
	cert, pool := testCertificate(t, "localhost")
	s := startFakeServer(t, cert, confirm(wire.ProtocolSSL), true, nil)
	res, err := Probe(context.Background(), s.ln.Addr().String(), Options{ServerName: "localhost", RootCAs: pool, Cookie: "Cookie: mstshash=probe"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stage != StageTLS || res.SelectedProtocol != wire.ProtocolSSL || res.TLSVersion < tls.VersionTLS12 || res.PeerSubject != "CN=localhost" {
		t.Fatalf("unexpected result %+v", res)
	}
	cr := <-s.gotCR
	want, _ := wire.ConnectionRequest{Cookie: "Cookie: mstshash=probe", RequestedProtocols: wire.ProtocolSSL}.Encode()
	if string(cr) != string(want) {
		t.Fatalf("server received %x, want %x", cr, want)
	}
	if err := <-s.tlsError; err != nil {
		t.Fatalf("server side handshake: %v", err)
	}
}

func TestProbeRejectsUntrustedCertificate(t *testing.T) {
	cert, _ := testCertificate(t, "localhost")
	_, otherPool := testCertificate(t, "localhost")
	s := startFakeServer(t, cert, confirm(wire.ProtocolSSL), true, nil)
	_, err := Probe(context.Background(), s.ln.Addr().String(), Options{ServerName: "localhost", RootCAs: otherPool})
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("want unknown authority error, got %v", err)
	}
}

func TestProbeRejectsHostnameMismatch(t *testing.T) {
	cert, pool := testCertificate(t, "rdp.example.test")
	s := startFakeServer(t, cert, confirm(wire.ProtocolSSL), true, nil)
	_, err := Probe(context.Background(), s.ln.Addr().String(), Options{ServerName: "other.example.test", RootCAs: pool})
	var mismatch x509.HostnameError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want hostname error, got %v", err)
	}
}

func TestProbeRefusesNonTLSSelection(t *testing.T) {
	cert, pool := testCertificate(t, "localhost")
	for name, reply := range map[string][]byte{
		"protocol-rdp":    confirm(wire.ProtocolRDP),
		"protocol-hybrid": confirm(wire.ProtocolHybrid),
		"no-negotiation":  {0x06, 0xd0, 0, 0, 0, 0, 0},
	} {
		s := startFakeServer(t, cert, reply, true, nil)
		res, err := Probe(context.Background(), s.ln.Addr().String(), Options{ServerName: "localhost", RootCAs: pool})
		if !errors.Is(err, ErrProtocolNotSelected) || res.Stage != "" {
			t.Fatalf("%s: %v (%+v)", name, err, res)
		}
		select {
		case err := <-s.tlsError:
			if err == nil {
				t.Fatalf("%s: client completed TLS after non-TLS selection", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: server handshake did not finish", name)
		}
	}
}

func TestProbeReportsNegotiationFailure(t *testing.T) {
	cert, pool := testCertificate(t, "localhost")
	reply := []byte{0x0e, 0xd0, 0, 0, 0, 0, 0, wire.TypeNegotiationFailure, 0, 0x08, 0, 0x05, 0, 0, 0}
	s := startFakeServer(t, cert, reply, false, nil)
	_, err := Probe(context.Background(), s.ln.Addr().String(), Options{ServerName: "localhost", RootCAs: pool})
	var failure *wire.NegotiationFailure
	if !errors.As(err, &failure) || failure.Code != wire.FailureHybridRequiredByServer {
		t.Fatalf("got %v", err)
	}
}

func TestProbeTimesOutOnSilentServer(t *testing.T) {
	cert, pool := testCertificate(t, "localhost")
	s := startFakeServer(t, cert, nil, false, nil)
	start := time.Now()
	_, err := Probe(context.Background(), s.ln.Addr().String(), Options{ServerName: "localhost", RootCAs: pool, Timeout: 300 * time.Millisecond})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

func TestProbeRejectsBadAddress(t *testing.T) {
	if _, err := Probe(context.Background(), "localhost", Options{}); err == nil {
		t.Fatal("missing port accepted")
	}
	if _, err := Probe(context.Background(), "127.0.0.1:1", Options{Timeout: time.Second}); err == nil {
		t.Fatal("closed port accepted")
	}
}

func TestConnectReachesChannelJoin(t *testing.T) {
	cert, pool := testCertificate(t, "localhost")
	m := &mcsServer{echoProtocols: wire.ProtocolSSL}
	s := startFakeServer(t, cert, confirm(wire.ProtocolSSL), true, m)
	res, err := Connect(context.Background(), s.ln.Addr().String(), Options{ServerName: "localhost", RootCAs: pool, ClientName: "unit-test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-s.done; err != nil {
		t.Fatalf("server: %v", err)
	}
	if res.Stage != StageChannelJoin || !res.ProtocolReconfirmed || res.ServerVersion != 0x00080004 ||
		res.IOChannel != 1003 || res.UserChannel != 1007 || len(res.JoinedChannels) != 2 || res.JoinedChannels[1] != 1003 ||
		res.EncryptionMethod != 0 || len(res.StaticChannels) != 0 {
		t.Fatalf("unexpected result %+v", res)
	}
	// The Connect-Initial must carry our core data with the negotiated protocol echoed.
	if !bytes.Contains(m.gotConnectInit, []byte{0x01, 0xc0, 0xd8, 0x00}) {
		t.Fatal("client core data block missing")
	}
	name := []byte{'u', 0, 'n', 0, 'i', 0, 't', 0, '-', 0, 't', 0, 'e', 0, 's', 0, 't', 0, 0, 0}
	if !bytes.Contains(m.gotConnectInit, name) {
		t.Fatal("client name not advertised")
	}
}

func TestConnectAcceptsCoreWithoutEcho(t *testing.T) {
	cert, pool := testCertificate(t, "localhost")
	s := startFakeServer(t, cert, confirm(wire.ProtocolSSL), true, &mcsServer{omitEchoField: true})
	res, err := Connect(context.Background(), s.ln.Addr().String(), Options{ServerName: "localhost", RootCAs: pool})
	if err != nil || res.ProtocolReconfirmed || res.Stage != StageChannelJoin {
		t.Fatalf("%+v, %v", res, err)
	}
}

func TestConnectRejectsBadServerSettings(t *testing.T) {
	cert, pool := testCertificate(t, "localhost")
	for name, tc := range map[string]struct {
		server *mcsServer
		want   error
		stage  string
	}{
		"echo-mismatch":      {&mcsServer{echoProtocols: wire.ProtocolHybrid}, ErrSettingsMismatch, StageTLS},
		"encryption":         {&mcsServer{echoProtocols: wire.ProtocolSSL, encryptionMethod: 2}, ErrEncryptionRequested, StageTLS},
		"unrequested-chan":   {&mcsServer{echoProtocols: wire.ProtocolSSL, staticChannels: []uint16{1004}}, ErrSettingsMismatch, StageTLS},
		"missing-security":   {&mcsServer{echoProtocols: wire.ProtocolSSL, omitBlock: wire.SCSecurity}, ErrMissingServerData, StageTLS},
		"missing-net":        {&mcsServer{echoProtocols: wire.ProtocolSSL, omitBlock: wire.SCNet}, ErrMissingServerData, StageTLS},
		"attach-failure":     {&mcsServer{echoProtocols: wire.ProtocolSSL, attachFailure: true}, &wire.MCSResultError{}, StageMCSConnect},
		"wrong-join-channel": {&mcsServer{echoProtocols: wire.ProtocolSSL, wrongJoinChannel: true}, wire.ErrMCS, StageAttachUser},
	} {
		s := startFakeServer(t, cert, confirm(wire.ProtocolSSL), true, tc.server)
		res, err := Connect(context.Background(), s.ln.Addr().String(), Options{ServerName: "localhost", RootCAs: pool})
		var resultErr *wire.MCSResultError
		switch want := tc.want.(type) {
		case *wire.MCSResultError:
			if !errors.As(err, &resultErr) {
				t.Errorf("%s: %v", name, err)
			}
		default:
			if !errors.Is(err, want) {
				t.Errorf("%s: want %v, got %v", name, want, err)
			}
		}
		if res.Stage != tc.stage {
			t.Errorf("%s: stage %q, want %q", name, res.Stage, tc.stage)
		}
	}
}
