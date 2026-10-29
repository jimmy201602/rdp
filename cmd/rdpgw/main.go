// rdpgw runs the G3-3 authorization gateway with a static route: every
// client that the policy admits is relayed to one target, Client Info
// credentials are passed through once and never stored.
//
//	rdpgw -listen 127.0.0.1:33892 -cert gw.crt -key gw.key \
//	      -target 127.0.0.1:33890 -target-ca .testenv/certs/ca.pem -target-name localhost \
//	      -allow-user rdptest
//
// Without -cert/-key an ephemeral self-signed front-end certificate is
// generated (tests only). -target-ca is required unless the target
// certificate chains to a system root.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"rdp.local/kernel/gateway"
	"rdp.local/kernel/server"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:33892", "front-end address to listen on")
	certFile := flag.String("cert", "", "front-end PEM certificate chain (default: ephemeral self-signed)")
	keyFile := flag.String("key", "", "front-end PEM private key")
	target := flag.String("target", "", "target host:port (required)")
	targetNLA := flag.Bool("target-nla", false, "require backend CredSSP 5/6 with NTLMv2 (no TLS-only fallback); front end remains TLS-only")
	targetCA := flag.String("target-ca", "", "PEM root certificates trusted for the target")
	targetName := flag.String("target-name", "", "TLS name to verify on the target (default: target host)")
	targetPin := flag.String("target-pin", "", "hex SHA-256 of the target's leaf certificate; pins it instead of CA/name verification (self-signed Windows hosts; rdpprobe -json reports peer_sha256)")
	targetTimeout := flag.Duration("target-timeout", 20*time.Second, "target handshake budget")
	targetMinTLS := flag.String("target-min-tls", "1.2", "lowest TLS version accepted from the target: 1.0, 1.1, 1.2 or 1.3 (Windows 7 only offers 1.0)")
	allowUser := flag.String("allow-user", "", "comma-separated user names admitted by the route policy (empty: any)")
	allowDomain := flag.String("allow-domain", "", "required domain (empty: any)")
	nlaUsers := flag.String("nla-users", "", "enable front-end CredSSP/NLA: file with one user:password per line; clients offering PROTOCOL_HYBRID then authenticate with NTLMv2 before MCS and their delegated credentials go to the target")
	requireNLA := flag.Bool("require-nla", false, "refuse clients that do not offer PROTOCOL_HYBRID (needs -nla-users)")
	allowChannel := flag.String("allow-channel", "*", "comma-separated static virtual channels relayed to the target (\"*\": all, \"\": none), e.g. cliprdr,rdpdr,rdpsnd,drdynvc")
	handshake := flag.Duration("handshake-timeout", 30*time.Second, "front-end handshake budget")
	maxSessions := flag.Int("max-sessions", 16, "concurrent client connections")
	once := flag.Bool("once", false, "exit after the first client session ends")
	jsonOut := flag.Bool("json", false, "print one JSON line per finished relay / session")
	flag.Parse()
	if *target == "" {
		log.Fatal("-target is required")
	}
	host, _, err := net.SplitHostPort(*target)
	if err != nil {
		log.Fatalf("-target: %v", err)
	}
	if *targetName == "" {
		*targetName = host
	}
	minTLS, ok := map[string]uint16{"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11, "1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}[*targetMinTLS]
	if !ok {
		log.Fatalf("-target-min-tls: unknown version %q", *targetMinTLS)
	}
	var pool *x509.CertPool
	if *targetCA != "" {
		pem, err := os.ReadFile(*targetCA)
		if err != nil {
			log.Fatal(err)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("%s: no certificates", *targetCA)
		}
	}
	var cert tls.Certificate
	if *certFile != "" || *keyFile != "" {
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
	} else {
		cert, err = selfSigned()
		log.Printf("using an ephemeral self-signed front-end certificate")
	}
	if err != nil {
		log.Fatal(err)
	}
	users := map[string]bool{}
	for _, u := range strings.Split(*allowUser, ",") {
		if u = strings.TrimSpace(strings.ToLower(u)); u != "" {
			users[u] = true
		}
	}

	channels := map[string]bool{}
	for _, ch := range strings.Split(*allowChannel, ",") {
		if ch = strings.TrimSpace(strings.ToLower(ch)); ch != "" {
			channels[ch] = true
		}
	}

	var lookup func(user, domain string) (string, bool)
	if *nlaUsers != "" {
		data, err := os.ReadFile(*nlaUsers)
		if err != nil {
			log.Fatal(err)
		}
		accounts := map[string]string{}
		for i, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			user, password, ok := strings.Cut(line, ":")
			if user = strings.TrimSpace(user); !ok || user == "" || password == "" {
				log.Fatalf("%s:%d: expected user:password", *nlaUsers, i+1)
			}
			accounts[strings.ToLower(user)] = password
		}
		lookup = func(user, _ string) (string, bool) {
			password, ok := accounts[strings.ToLower(user)]
			return password, ok
		}
	} else if *requireNLA {
		log.Fatal("-require-nla needs -nla-users")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sessions := make(chan server.Summary, 16)
	emit := func(rec map[string]any) {
		if *jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(rec)
		}
	}
	gw, err := gateway.New(gateway.Config{
		TLS:        &tls.Config{Certificates: []tls.Certificate{cert}},
		NLA:        lookup,
		RequireNLA: *requireNLA,
		Route: func(_ context.Context, p server.Peer) (gateway.Target, error) {
			if len(users) > 0 && !users[strings.ToLower(p.UserName)] {
				return gateway.Target{}, errors.New("user not allowed")
			}
			if *allowDomain != "" && !strings.EqualFold(p.Domain, *allowDomain) {
				return gateway.Target{}, errors.New("domain not allowed")
			}
			return gateway.Target{NLA: *targetNLA, Address: *target, ServerName: *targetName, RootCAs: pool, PinSHA256: *targetPin, MinTLS: minTLS, Timeout: *targetTimeout}, nil
		},
		AllowChannel:     func(name string) bool { return channels["*"] || channels[strings.ToLower(name)] },
		HandshakeTimeout: *handshake,
		MaxSessions:      *maxSessions,
		Logf:             log.Printf,
		OnSession:        func(s server.Summary) { sessions <- s },
		OnRelay: func(r gateway.Summary) {
			rec := map[string]any{
				"event": "relay", "remote": fmt.Sprint(r.RemoteAddr), "user": r.UserName, "nla": r.NLA, "target": r.Target, "end": r.End,
				"client_pdus": r.ClientPDUs, "client_fastpath": r.ClientFastPath, "server_pdus": r.ServerPDUs, "server_fastpath": r.ServerFastPath,
				"client_bytes": r.ClientBytes, "server_bytes": r.ServerBytes, "input": r.InputEvents, "dropped_caps": fmt.Sprint(r.DroppedCapabilities),
				"channels": fmt.Sprint(r.ChannelPDUs), "dropped_channels": fmt.Sprint(r.DroppedChannels), "reactivations": r.Reactivations, "duration_ms": r.Duration.Milliseconds(),
			}
			if r.Err != nil {
				rec["error"] = r.Err.Error()
			}
			emit(rec)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	targetSecurity := "TLS"
	if *targetNLA {
		targetSecurity = "NLA/CredSSP"
	}
	frontSecurity := "TLS only"
	switch {
	case *requireNLA:
		frontSecurity = "NLA required"
	case lookup != nil:
		frontSecurity = "TLS, NLA offered"
	}
	log.Printf("gateway listening on %s (%s, users %q), target %s (%s)", ln.Addr(), frontSecurity, *allowUser, *target, targetSecurity)
	done := make(chan error, 1)
	go func() { done <- gw.Serve(ctx, ln) }()
	for {
		select {
		case s := <-sessions:
			rec := map[string]any{"event": "session", "remote": fmt.Sprint(s.RemoteAddr), "user": s.UserName, "client": s.ClientName,
				"stage": s.Stage, "nla": s.NLA, "authorized": s.Authorized, "duration_ms": s.Duration.Milliseconds()}
			if s.Err != nil {
				rec["error"] = s.Err.Error()
			}
			emit(rec)
			if *once {
				stop()
				<-done
				if s.Err != nil && !errors.Is(s.Err, context.Canceled) {
					os.Exit(1)
				}
				return
			}
		case err := <-done:
			if err != nil {
				log.Fatal(err)
			}
			return
		}
	}
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "rdpgw"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
