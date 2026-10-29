// rdpserve runs the G3-1 Go RDP server role: TLS-only listener, caller
// policy (a single allowed account from flags / environment), licensing
// skip, capability exchange and a static test-pattern desktop with a colour
// pointer. It is a validation tool for real clients (xfreerdp, mstsc), not
// a product.
//
//	rdpserve -listen 127.0.0.1:33891 -cert server.crt -key server.key \
//	         -user demo -password-env RDP_DEMO_PASSWORD
//
// Without -cert/-key an ephemeral self-signed certificate is generated.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
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

	"rdp.local/kernel/server"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:33891", "address to listen on")
	certFile := flag.String("cert", "", "PEM certificate chain (default: ephemeral self-signed)")
	keyFile := flag.String("key", "", "PEM private key")
	user := flag.String("user", "", "the only user name the policy accepts (empty: accept any user name)")
	domain := flag.String("domain", "", "required domain (empty: any)")
	passwordEnv := flag.String("password-env", "", "environment variable holding the password the policy requires (empty: any password)")
	handshake := flag.Duration("handshake-timeout", 30*time.Second, "time allowed from accept to activation")
	idle := flag.Duration("idle-timeout", 0, "close activated sessions idle for this long (0: never)")
	maxSessions := flag.Int("max-sessions", 16, "concurrent connections")
	once := flag.Bool("once", false, "exit after the first session ends")
	jsonOut := flag.Bool("json", false, "print one JSON line per finished session")
	flag.Parse()

	password := ""
	if *passwordEnv != "" {
		password = os.Getenv(*passwordEnv)
		if password == "" {
			log.Fatalf("environment variable %s is empty", *passwordEnv)
		}
	}

	var cert tls.Certificate
	var err error
	if *certFile != "" || *keyFile != "" {
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
	} else {
		cert, err = selfSigned()
		log.Printf("using an ephemeral self-signed certificate")
	}
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sessions := make(chan server.Summary, 16)
	srv, err := server.New(server.Config{
		TLS: &tls.Config{Certificates: []tls.Certificate{cert}},
		Authorize: func(_ context.Context, p server.Peer) error {
			if *user != "" && !strings.EqualFold(p.UserName, *user) {
				return errors.New("user not allowed")
			}
			if *domain != "" && !strings.EqualFold(p.Domain, *domain) {
				return errors.New("domain not allowed")
			}
			if password != "" && subtle.ConstantTimeCompare([]byte(p.Password), []byte(password)) != 1 {
				return errors.New("bad password")
			}
			return nil
		},
		HandshakeTimeout: *handshake,
		IdleTimeout:      *idle,
		MaxSessions:      *maxSessions,
		Logf:             log.Printf,
		OnSession:        func(s server.Summary) { sessions <- s },
	})
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s (TLS only, user %q)", ln.Addr(), *user)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	for {
		select {
		case s := <-sessions:
			report(s, *jsonOut)
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

func report(s server.Summary, asJSON bool) {
	if !asJSON {
		return
	}
	rec := map[string]any{
		"remote": fmt.Sprint(s.RemoteAddr), "user": s.UserName, "domain": s.Domain, "client": s.ClientName,
		"stage": s.Stage, "authorized": s.Authorized, "duration_ms": s.Duration.Milliseconds(),
	}
	if s.Err != nil {
		rec["error"] = s.Err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(rec)
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "rdpserve"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
