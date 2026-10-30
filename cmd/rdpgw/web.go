package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// loadUserTargets reads "user: entry,entry" lines (entries as for
// -allow-target, "*" for any).
func loadUserTargets(file string) (map[string]func(string) bool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	out := map[string]func(string) bool{}
	for i, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, list, ok := strings.Cut(line, ":")
		user = strings.ToLower(strings.TrimSpace(user))
		list = strings.TrimSpace(list)
		if !ok || user == "" || list == "" {
			return nil, fmt.Errorf("%s:%d: expected user: host,IP,CIDR,...", file, i+1)
		}
		if list == "*" {
			out[user] = func(string) bool { return true }
			continue
		}
		m, err := targetMatcher(list, "")
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %v", file, i+1, err)
		}
		out[user] = m
	}
	return out, nil
}

// autoCert returns the paths of a self-signed monitor certificate in dir,
// creating it when missing or about to expire.
func autoCert(dir, listen, hosts string) (certFile, keyFile string, err error) {
	certFile, keyFile = filepath.Join(dir, "monitor.crt"), filepath.Join(dir, "monitor.key")
	if pair, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && time.Until(leaf.NotAfter) > 30*24*time.Hour {
			return certFile, keyFile, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	names := map[string]bool{"localhost": true}
	if h, _, err := net.SplitHostPort(listen); err == nil && h != "" {
		names[h] = true
	}
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			names[h] = true
		}
	}
	if hosts == "" {
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
					names[n.IP.String()] = true
				}
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "rdpgw monitor"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for n := range names {
		if ip := net.ParseIP(strings.Trim(n, "[]")); ip != nil {
			if !ip.IsUnspecified() {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			}
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}
