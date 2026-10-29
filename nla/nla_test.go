package nla

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
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
	if got := hex.EncodeToString(ntowfV2("User", "Domain", "Password")); got != "0c868a403bfd7a93a3001ef22ef02e3f" {
		t.Fatal(got)
	}
}

var (
	testKey     = []byte("subject-public-key")
	testBinding = bytes.Repeat([]byte{0x5a}, 16)
)

func lookupAlice(user, domain string) (string, bool) {
	if strings.EqualFold(user, "alice") && domain == "CORP" {
		return "s3cret", true
	}
	return "", false
}

func clientConfig() ClientConfig {
	return ClientConfig{PublicKey: testKey, Binding: testBinding, SPN: "TERMSRV/host", User: "alice", Domain: "CORP", Password: "s3cret"}
}

func serverConfig() ServerConfig {
	return ServerConfig{PublicKey: testKey, Binding: testBinding, Lookup: lookupAlice, DomainName: "CORP", ComputerName: "GW"}
}

type serverOutcome struct {
	res *ServerResult
	err error
}

func runServer(t *testing.T, cfg ServerConfig) (net.Conn, <-chan serverOutcome) {
	t.Helper()
	client, srv := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan serverOutcome, 1)
	go func() {
		res, err := Server(srv, cfg)
		_ = srv.Close()
		done <- serverOutcome{res, err}
	}()
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}

// TestClientServerExchange runs the client against the server with raw NTLM
// tokens: NTLMv2 proof, MIC, channel binding, public-key binding both ways
// and delegated credentials.
func TestClientServerExchange(t *testing.T) {
	client, done := runServer(t, serverConfig())
	cr, err := Client(client, clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	out := <-done
	if out.err != nil {
		t.Fatal(out.err)
	}
	res := out.res
	if cr.Version != 6 || res.Version != 6 || res.SPNEGO || !res.ChannelBound {
		t.Fatalf("client %+v server %+v", cr, res)
	}
	if res.Identity != (Identity{User: "alice", Domain: "CORP"}) || res.Credentials == nil || *res.Credentials != (Credentials{Domain: "CORP", User: "alice", Password: "s3cret"}) {
		t.Fatalf("identity %+v credentials %+v", res.Identity, res.Credentials)
	}
}

func TestServerRejectsWrongPassword(t *testing.T) {
	client, done := runServer(t, serverConfig())
	cfg := clientConfig()
	cfg.Password = "wrong"
	_, err := Client(client, cfg)
	if err == nil || !strings.Contains(err.Error(), "0xc000006d") {
		t.Fatalf("client got %v, want STATUS_LOGON_FAILURE", err)
	}
	if out := <-done; !errors.Is(out.err, ErrLogonFailure) {
		t.Fatalf("server got %v", out.err)
	}
}

func TestServerRejectsUnknownUserAndMismatchedBinding(t *testing.T) {
	client, done := runServer(t, serverConfig())
	cfg := clientConfig()
	cfg.User = "mallory"
	if _, err := Client(client, cfg); err == nil || !strings.Contains(err.Error(), "0xc000006d") {
		t.Fatalf("unknown user: %v", err)
	}
	if out := <-done; !errors.Is(out.err, ErrLogonFailure) {
		t.Fatalf("server got %v", out.err)
	}

	client, done = runServer(t, serverConfig())
	cfg = clientConfig()
	cfg.Binding = bytes.Repeat([]byte{1}, 16)
	if _, err := Client(client, cfg); err == nil {
		t.Fatal("client with a foreign channel binding was accepted")
	}
	if out := <-done; out.err == nil || !strings.Contains(out.err.Error(), "channel binding") {
		t.Fatalf("server got %v", out.err)
	}

	client, done = runServer(t, serverConfig())
	cfg = clientConfig()
	cfg.PublicKey = []byte("other-key")
	if _, err := Client(client, cfg); err == nil {
		t.Fatal("client bound to another public key was accepted")
	}
	if out := <-done; out.err == nil || !strings.Contains(out.err.Error(), "public-key binding") {
		t.Fatalf("server got %v", out.err)
	}
}

// TestClientRejectsWrongServerBinding uses a hand-rolled server that passes
// the client proof but answers with a proof for a different key.
func TestClientRejectsWrongServerBinding(t *testing.T) {
	client, srv := net.Pipe()
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		defer func() { _ = srv.Close() }()
		_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
		first, err := readTSRequest(srv)
		if err != nil {
			return
		}
		st, err := ntlmChallenge(first.Tokens[0].Token, "CORP", "GW", time.Now())
		if err != nil {
			return
		}
		if err := writeTSRequest(srv, tsRequest{Version: 6, Tokens: []negoToken{{Token: st.challenge}}}); err != nil {
			return
		}
		second, err := readTSRequest(srv)
		if err != nil {
			return
		}
		v, err := st.verify(second.Tokens[0].Token, testBinding, lookupAlice)
		if err != nil {
			return
		}
		if _, err := v.security.client.unwrap(second.PubKeyAuth); err != nil {
			return
		}
		_ = writeTSRequest(srv, tsRequest{Version: 6, PubKeyAuth: v.security.server.wrap(bindingHash("Server-To-Client", second.Nonce, []byte("other-key")))})
	}()
	_, err := Client(client, clientConfig())
	if err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("got %v, want public-key binding mismatch", err)
	}
}

func TestServerRejectsOldVersionWithErrorCode(t *testing.T) {
	client, done := runServer(t, serverConfig())
	if err := writeTSRequest(client, tsRequest{Version: 4, Tokens: []negoToken{{Token: ntlmNegotiate()}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := readTSRequest(client); err == nil || !strings.Contains(err.Error(), "0xc000006d") {
		t.Fatalf("got %v", err)
	}
	if out := <-done; out.err == nil || !strings.Contains(out.err.Error(), "version 4") {
		t.Fatalf("server got %v", out.err)
	}
}

func TestServerRejectsForeignDelegatedCredentials(t *testing.T) {
	client, done := runServer(t, serverConfig())
	go func() {
		// A client that authenticates as alice but delegates bob's password.
		negotiate := ntlmNegotiate()
		_ = writeTSRequest(client, tsRequest{Version: 6, Tokens: []negoToken{{Token: negotiate}}})
		challenge, err := readTSRequest(client)
		if err != nil {
			return
		}
		auth, sec, err := ntlmAuthenticate(negotiate, challenge.Tokens[0].Token, testBinding, "alice", "CORP", "s3cret", "TERMSRV/host")
		if err != nil {
			return
		}
		nonce := make([]byte, 32)
		_ = writeTSRequest(client, tsRequest{Version: 6, Tokens: []negoToken{{Token: auth}}, PubKeyAuth: sec.client.wrap(bindingHash("Client-To-Server", nonce, testKey)), Nonce: nonce})
		if _, err := readTSRequest(client); err != nil {
			return
		}
		creds := encodeCreds(t, "CORP", "alice", "bobs-password")
		_ = writeTSRequest(client, tsRequest{Version: 6, AuthInfo: sec.client.wrap(creds)})
	}()
	if out := <-done; out.err == nil || !strings.Contains(out.err.Error(), "differ from the authenticated identity") {
		t.Fatalf("server got %v", out.err)
	}
}

func encodeCreds(t *testing.T, domain, user, password string) []byte {
	t.Helper()
	pw, err := marshalPasswordCreds(domain, user, password)
	if err != nil {
		t.Fatal(err)
	}
	return pw
}

// spnegoInitiator mimics mstsc: SPNEGO-wrapped NTLM with a mechListMIC.
// With ntlmFirst the optimistic token is NTLM; otherwise a Kerberos OID
// leads and the server must ask for NTLM with request-mic.
func spnegoInitiator(conn io.ReadWriter, cfg ClientConfig, ntlmFirst bool) (ServerResult, error) {
	krb := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	var list []byte
	if ntlmFirst {
		list = append(derTLV(tagOID, oidNTLM), derTLV(tagOID, krb)...)
	} else {
		list = append(derTLV(tagOID, krb), derTLV(tagOID, oidNTLM)...)
	}
	mechTypes := derTLV(tagSequence, list)
	negotiate := ntlmNegotiate()
	seq := derTLV(tagContext0, mechTypes)
	if ntlmFirst {
		seq = append(seq, derTLV(tagContext0+2, derTLV(tagOctetString, negotiate))...)
	}
	init := derTLV(tagApplication, append(derTLV(tagOID, oidSPNEGO), derTLV(tagContext0, derTLV(tagSequence, seq))...))
	if err := writeTSRequest(conn, tsRequest{Version: 6, Tokens: []negoToken{{Token: init}}}); err != nil {
		return ServerResult{}, err
	}
	req, err := readTSRequest(conn)
	if err != nil {
		return ServerResult{}, err
	}
	resp, err := parseNegTokenResp(req.Tokens[0].Token)
	if err != nil {
		return ServerResult{}, err
	}
	if !ntlmFirst {
		if resp.negState != negRequestMIC || !bytes.Equal(resp.supportedMech, oidNTLM) || len(resp.responseToken) != 0 {
			return ServerResult{}, errors.New("expected request-mic for NTLM")
		}
		if err := writeTSRequest(conn, tsRequest{Version: 6, Tokens: []negoToken{{Token: negTokenResp{negState: negStateAbsent, responseToken: negotiate}.encode()}}}); err != nil {
			return ServerResult{}, err
		}
		if req, err = readTSRequest(conn); err != nil {
			return ServerResult{}, err
		}
		if resp, err = parseNegTokenResp(req.Tokens[0].Token); err != nil {
			return ServerResult{}, err
		}
	} else if !bytes.Equal(resp.supportedMech, oidNTLM) {
		return ServerResult{}, errors.New("expected NTLM to be selected")
	}
	if resp.negState != negAcceptIncomplete || len(resp.responseToken) == 0 {
		return ServerResult{}, errors.New("expected an NTLM challenge")
	}
	auth, sec, err := ntlmAuthenticate(negotiate, resp.responseToken, cfg.Binding, cfg.User, cfg.Domain, cfg.Password, cfg.SPN)
	if err != nil {
		return ServerResult{}, err
	}
	out := negTokenResp{negState: negStateAbsent, responseToken: auth, mic: sec.client.signature(mechTypes)}
	if err := sec.resetCiphers(); err != nil {
		return ServerResult{}, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return ServerResult{}, err
	}
	proof := sec.client.wrap(bindingHash("Client-To-Server", nonce, cfg.PublicKey))
	if err := writeTSRequest(conn, tsRequest{Version: 6, Tokens: []negoToken{{Token: out.encode()}}, PubKeyAuth: proof, Nonce: nonce}); err != nil {
		return ServerResult{}, err
	}
	if req, err = readTSRequest(conn); err != nil {
		return ServerResult{}, err
	}
	if len(req.Tokens) != 1 {
		return ServerResult{}, errors.New("expected the final SPNEGO token")
	}
	if resp, err = parseNegTokenResp(req.Tokens[0].Token); err != nil {
		return ServerResult{}, err
	}
	if resp.negState != negAcceptCompleted || len(resp.mic) == 0 {
		return ServerResult{}, errors.New("expected accept-completed with a mechListMIC")
	}
	if err := sec.server.verify(mechTypes, resp.mic); err != nil {
		return ServerResult{}, err
	}
	// Only the receiving key stream restarts here: the sending one was
	// already restarted after our own MIC and must stay continuous.
	if err := sec.server.reset(); err != nil {
		return ServerResult{}, err
	}
	plain, err := sec.server.unwrap(req.PubKeyAuth)
	if err != nil {
		return ServerResult{}, err
	}
	if !hmac.Equal(plain, bindingHash("Server-To-Client", nonce, cfg.PublicKey)) {
		return ServerResult{}, errors.New("server binding mismatch")
	}
	creds, err := marshalPasswordCreds(cfg.Domain, cfg.User, cfg.Password)
	if err != nil {
		return ServerResult{}, err
	}
	return ServerResult{}, writeTSRequest(conn, tsRequest{Version: 6, AuthInfo: sec.client.wrap(creds)})
}

func TestSPNEGO(t *testing.T) {
	for _, ntlmFirst := range []bool{true, false} {
		client, done := runServer(t, serverConfig())
		if _, err := spnegoInitiator(client, clientConfig(), ntlmFirst); err != nil {
			t.Fatalf("ntlmFirst=%v: %v", ntlmFirst, err)
		}
		out := <-done
		if out.err != nil {
			t.Fatalf("ntlmFirst=%v: server: %v", ntlmFirst, out.err)
		}
		if !out.res.SPNEGO || out.res.Identity.User != "alice" || out.res.Credentials == nil || out.res.Credentials.Password != "s3cret" {
			t.Fatalf("ntlmFirst=%v: %+v", ntlmFirst, out.res)
		}
	}
}

func TestSPNEGORejectsMissingRequiredMIC(t *testing.T) {
	client, done := runServer(t, serverConfig())
	go func() {
		krb := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
		mechTypes := derTLV(tagSequence, append(derTLV(tagOID, krb), derTLV(tagOID, oidNTLM)...))
		init := derTLV(tagApplication, append(derTLV(tagOID, oidSPNEGO), derTLV(tagContext0, derTLV(tagSequence, derTLV(tagContext0, mechTypes)))...))
		_ = writeTSRequest(client, tsRequest{Version: 6, Tokens: []negoToken{{Token: init}}})
		if _, err := readTSRequest(client); err != nil {
			return
		}
		negotiate := ntlmNegotiate()
		_ = writeTSRequest(client, tsRequest{Version: 6, Tokens: []negoToken{{Token: negTokenResp{negState: negStateAbsent, responseToken: negotiate}.encode()}}})
		req, err := readTSRequest(client)
		if err != nil {
			return
		}
		resp, err := parseNegTokenResp(req.Tokens[0].Token)
		if err != nil {
			return
		}
		auth, sec, err := ntlmAuthenticate(negotiate, resp.responseToken, testBinding, "alice", "CORP", "s3cret", "TERMSRV/host")
		if err != nil {
			return
		}
		nonce := make([]byte, 32)
		_ = writeTSRequest(client, tsRequest{Version: 6, Tokens: []negoToken{{Token: negTokenResp{negState: negStateAbsent, responseToken: auth}.encode()}},
			PubKeyAuth: sec.client.wrap(bindingHash("Client-To-Server", nonce, testKey)), Nonce: nonce})
		_, _ = readTSRequest(client) // the STATUS_LOGON_FAILURE reply
	}()
	if out := <-done; out.err == nil || !strings.Contains(out.err.Error(), "mechListMIC required") {
		t.Fatalf("server got %v", out.err)
	}
}

func TestNegTokenRespRoundTrip(t *testing.T) {
	in := negTokenResp{negState: negAcceptIncomplete, supportedMech: oidNTLM, responseToken: bytes.Repeat([]byte{7}, 300), mic: []byte("0123456789abcdef")}
	out, err := parseNegTokenResp(in.encode())
	if err != nil {
		t.Fatal(err)
	}
	if out.negState != in.negState || !bytes.Equal(out.supportedMech, in.supportedMech) || !bytes.Equal(out.responseToken, in.responseToken) || !bytes.Equal(out.mic, in.mic) {
		t.Fatalf("%+v", out)
	}
	absent, err := parseNegTokenResp(negTokenResp{negState: negStateAbsent, responseToken: []byte{1}}.encode())
	if err != nil || absent.negState != negStateAbsent {
		t.Fatalf("%+v %v", absent, err)
	}
}
