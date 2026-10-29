package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"rdp.local/kernel/nla"
)

// ErrCredSSP means NLA failed before the RDP Basic Settings Exchange.
var ErrCredSSP = errors.New("CredSSP authentication failed")

func authenticateNLA(conn *tls.Conn, address string, opts Options, res *Result) error {
	if !opts.NLA {
		return nil
	}
	if err := credsspClient(conn, address, opts, res); err != nil {
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
	key, err := nla.PublicKey(certs[0])
	if err != nil {
		return err
	}
	name := opts.ServerName
	if name == "" {
		if name, _, err = net.SplitHostPort(address); err != nil {
			return err
		}
	}
	user, domain := nla.SplitUser(opts.UserName, opts.Domain)
	r, err := nla.Client(conn, nla.ClientConfig{
		PublicKey: key, Binding: nla.TLSServerEndPoint(certs[0]), SPN: "TERMSRV/" + name,
		User: user, Domain: domain, Password: opts.Password,
	})
	if err != nil {
		return err
	}
	res.NLA = true
	res.CredSSPVersion = r.Version
	return nil
}
