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
//
// With -login-form the client is shown a logon form instead: the user types
// the server address, user name, password and domain, the gateway dials
// that server (restricted by -allow-target, verified with -target-ca /
// -target-pin as above) and shows a reason in the form when it fails:
//
//	rdpgw -listen 127.0.0.1:33892 -login-form -allow-target 192.0.2.0/24 \
//	      -target-pin <sha256> -target-min-tls 1.0 -target-nla
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
	target := flag.String("target", "", "target host:port (required without -login-form)")
	loginForm := flag.Bool("login-form", false, "show every client a logon form and dial the server it enters instead of -target")
	allowTarget := flag.String("allow-target", "", "with -login-form: comma-separated hosts, IPs or CIDRs the user may enter (empty: any; -target, if set, is always allowed)")
	formAttempts := flag.Int("form-attempts", 5, "with -login-form: failed attempts before the client is disconnected")
	formIdle := flag.Duration("form-idle", 5*time.Minute, "with -login-form: disconnect a client that leaves the form idle this long")
	targetNLA := flag.Bool("target-nla", false, "require backend CredSSP 5/6 with NTLMv2 (no TLS-only fallback); front end remains TLS-only")
	targetLegacyCredSSP := flag.Bool("target-credssp-legacy", false, "with -target-nla: also accept CredSSP 2-4 from unpatched Windows 7 / 2008 R2 (public key bound without nonce, CVE-2018-0886); use together with -target-pin")
	targetCA := flag.String("target-ca", "", "PEM root certificates trusted for the target")
	targetName := flag.String("target-name", "", "TLS name to verify on the target (default: target host)")
	targetPin := flag.String("target-pin", "", "hex SHA-256 of the target's leaf certificate; pins it instead of CA/name verification (self-signed Windows hosts; rdpprobe -json reports peer_sha256). With -login-form a comma-separated host=sha256 list pins several hosts")
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
	trace := flag.Bool("trace", false, "log the type of every relayed slow-path share PDU (debugging)")
	flag.Parse()
	if *target == "" && !*loginForm {
		log.Fatal("-target is required (or use -login-form)")
	}
	var host string
	if *target != "" {
		var err error
		if host, _, err = net.SplitHostPort(*target); err != nil {
			log.Fatalf("-target: %v", err)
		}
	}
	if *targetName == "" {
		*targetName = host
	}
	targetAllowed, err := targetMatcher(*allowTarget, host)
	if err != nil {
		log.Fatalf("-allow-target: %v", err)
	}
	pinFor, err := pinMatcher(*targetPin)
	if err != nil {
		log.Fatalf("-target-pin: %v", err)
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
	policy := func(p server.Peer) error {
		if len(users) > 0 && !users[strings.ToLower(p.UserName)] {
			return errors.New("user not allowed")
		}
		if *allowDomain != "" && !strings.EqualFold(p.Domain, *allowDomain) {
			return errors.New("domain not allowed")
		}
		return nil
	}
	cfg := gateway.Config{
		TLS:        &tls.Config{Certificates: []tls.Certificate{cert}},
		NLA:        lookup,
		RequireNLA: *requireNLA,
		Route: func(_ context.Context, p server.Peer) (gateway.Target, error) {
			if err := policy(p); err != nil {
				return gateway.Target{}, err
			}
			return gateway.Target{NLA: *targetNLA, LegacyCredSSP: *targetLegacyCredSSP, Address: *target, ServerName: *targetName, RootCAs: pool, PinSHA256: pinFor(host), MinTLS: minTLS, Timeout: *targetTimeout}, nil
		},
		AllowChannel:     func(name string) bool { return channels["*"] || channels[strings.ToLower(name)] },
		HandshakeTimeout: *handshake,
		MaxSessions:      *maxSessions,
		Logf:             log.Printf,
		Trace:            *trace,
		OnSession:        func(s server.Summary) { sessions <- s },
		OnRelay: func(r gateway.Summary) {
			rec := map[string]any{
				"event": "relay", "remote": fmt.Sprint(r.RemoteAddr), "user": r.UserName, "nla": r.NLA, "target": r.Target, "end": r.End,
				"login_form": r.LoginForm, "form_attempts": r.FormAttempts,
				"client_pdus": r.ClientPDUs, "client_fastpath": r.ClientFastPath, "server_pdus": r.ServerPDUs, "server_fastpath": r.ServerFastPath,
				"client_bytes": r.ClientBytes, "server_bytes": r.ServerBytes, "input": r.InputEvents, "dropped_caps": fmt.Sprint(r.DroppedCapabilities),
				"channels": fmt.Sprint(r.ChannelPDUs), "dropped_channels": fmt.Sprint(r.DroppedChannels), "reactivations": r.Reactivations, "duration_ms": r.Duration.Milliseconds(),
			}
			if r.Err != nil {
				rec["error"] = r.Err.Error()
			}
			emit(rec)
		},
	}
	if *loginForm {
		// The form's user name is only known to the target; -allow-user /
		// -allow-domain apply to the identity the client presented up front
		// (NLA or Client Info), when there is one.
		cfg.Route = nil
		cfg.Form = &gateway.FormConfig{
			Attempts: *formAttempts, IdleTimeout: *formIdle, Prefill: true,
			Route: func(_ context.Context, p server.Peer, address string) (gateway.Target, error) {
				if (p.UserName != "" || p.NLA) && (len(users) > 0 || *allowDomain != "") {
					if err := policy(p); err != nil {
						return gateway.Target{}, err
					}
				}
				h, _, err := net.SplitHostPort(address)
				if err != nil {
					return gateway.Target{}, err
				}
				if !targetAllowed(h) {
					return gateway.Target{}, fmt.Errorf("host %q not in -allow-target", h)
				}
				name := h
				if strings.EqualFold(h, host) {
					name = *targetName
				}
				return gateway.Target{NLA: *targetNLA, LegacyCredSSP: *targetLegacyCredSSP, Address: address, ServerName: name, RootCAs: pool, PinSHA256: pinFor(h), MinTLS: minTLS, Timeout: *targetTimeout}, nil
			},
		}
	}
	gw, err := gateway.New(cfg)
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
	if *loginForm {
		log.Printf("gateway listening on %s (%s, users %q), logon form, targets %q (%s)", ln.Addr(), frontSecurity, *allowUser, *allowTarget, targetSecurity)
	} else {
		log.Printf("gateway listening on %s (%s, users %q), target %s (%s)", ln.Addr(), frontSecurity, *allowUser, *target, targetSecurity)
	}
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

// targetMatcher parses a comma-separated list of host names, IPs and CIDRs
// and returns a predicate over the host part of an address. An empty list
// admits every host; fixed (the -target host) is always admitted.
func targetMatcher(list, fixed string) (func(host string) bool, error) {
	var nets []*net.IPNet
	names := map[string]bool{}
	if fixed != "" {
		names[strings.ToLower(fixed)] = true
	}
	any := true
	for _, e := range strings.Split(list, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		any = false
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
		} else if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		} else if strings.ContainsAny(e, " /") {
			return nil, fmt.Errorf("bad entry %q", e)
		} else {
			names[strings.ToLower(e)] = true
		}
	}
	return func(host string) bool {
		if any || names[strings.ToLower(host)] {
			return true
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}, nil
}

// pinMatcher parses -target-pin: a single fingerprint applied to every
// host, or host=fingerprint entries (hosts without an entry get no pin and
// fall back to CA / name verification).
func pinMatcher(spec string) (func(host string) string, error) {
	perHost := map[string]string{}
	global := ""
	for _, e := range strings.Split(spec, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		host, pin, ok := strings.Cut(e, "=")
		if !ok {
			if global != "" || len(perHost) > 0 {
				return nil, fmt.Errorf("mix of plain and host= entries in %q", spec)
			}
			global = e
			continue
		}
		if global != "" {
			return nil, fmt.Errorf("mix of plain and host= entries in %q", spec)
		}
		perHost[strings.ToLower(strings.TrimSpace(host))] = strings.TrimSpace(pin)
	}
	return func(host string) string {
		if global != "" {
			return global
		}
		return perHost[strings.ToLower(host)]
	}, nil
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
