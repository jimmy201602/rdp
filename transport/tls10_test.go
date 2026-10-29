package transport

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"rdp.local/kernel/wire"
)

// tls10Server answers X.224 negotiation and completes a TLS 1.0 handshake
// offering a CBC suite and an RC4 suite, then closes. It records the suite
// negotiated on each connection.
func tls10Server(t *testing.T, cert tls.Certificate, selected uint32, conns int) (string, <-chan uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	suites := make(chan uint16, conns)
	go func() {
		for i := 0; i < conns; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := wire.ReadTPKT(conn, 1024); err != nil {
				_ = conn.Close()
				return
			}
			if err := wire.WriteTPKT(conn, confirm(selected)); err != nil {
				_ = conn.Close()
				return
			}
			tc := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS10,
				MaxVersion:   tls.VersionTLS10,
				CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
			})
			if err := tc.Handshake(); err == nil {
				suites <- tc.ConnectionState().CipherSuite
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), suites
}

func TestTLS10CredSSPRetriesWithStreamCipher(t *testing.T) {
	cert, pool := testCertificate(t, "legacy")
	addr, suites := tls10Server(t, cert, wire.ProtocolHybrid, 2)
	res, err := Probe(context.Background(), addr, Options{NLA: true, ServerName: "legacy", RootCAs: pool, MinTLSVersion: tls.VersionTLS10})
	if err != nil {
		t.Fatalf("probe: %v (%+v)", err, res)
	}
	if res.TLSVersion != tls.VersionTLS10 || res.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA || !res.TLS10StreamCipher {
		t.Fatalf("result %s %s stream=%v", TLSVersionString(res.TLSVersion), tls.CipherSuiteName(res.CipherSuite), res.TLS10StreamCipher)
	}
	if first, second := <-suites, <-suites; first != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA || second != tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA {
		t.Fatalf("server saw %s then %s", tls.CipherSuiteName(first), tls.CipherSuiteName(second))
	}
}

func TestTLS10WithoutNLAKeepsBlockCipher(t *testing.T) {
	cert, pool := testCertificate(t, "legacy")
	addr, suites := tls10Server(t, cert, wire.ProtocolSSL, 1)
	res, err := Probe(context.Background(), addr, Options{ServerName: "legacy", RootCAs: pool, MinTLSVersion: tls.VersionTLS10})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA || res.TLS10StreamCipher {
		t.Fatalf("result %s stream=%v", tls.CipherSuiteName(res.CipherSuite), res.TLS10StreamCipher)
	}
	if got := <-suites; got != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA {
		t.Fatalf("server saw %s", tls.CipherSuiteName(got))
	}
}

func TestNeedsLegacyStreamCipher(t *testing.T) {
	cases := []struct {
		version, suite uint16
		want           bool
	}{
		{tls.VersionTLS10, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true},
		{tls.VersionTLS10, tls.TLS_RSA_WITH_AES_128_CBC_SHA, true},
		{tls.VersionTLS10, tls.TLS_RSA_WITH_RC4_128_SHA, false},
		{tls.VersionTLS11, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, false},
		{tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, false},
	}
	for _, c := range cases {
		if got := needsLegacyStreamCipher(tls.ConnectionState{Version: c.version, CipherSuite: c.suite}); got != c.want {
			t.Errorf("%s %s: got %v, want %v", TLSVersionString(c.version), tls.CipherSuiteName(c.suite), got, c.want)
		}
	}
}
