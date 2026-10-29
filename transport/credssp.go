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

// ErrNoCredentials means NLA was requested without a user and password;
// nothing was sent to the server.
var ErrNoCredentials = errors.New("NLA requires a user and password")

func authenticateNLA(conn *tls.Conn, address string, opts Options, res *Result) error {
	if !opts.NLA {
		return nil
	}
	if err := credsspClient(conn, address, opts, res); err != nil {
		return fmt.Errorf("%w: %w", ErrCredSSP, err)
	}
	return nil
}

func (o Options) credSSPMinVersion() int {
	if o.LegacyCredSSP {
		return 2
	}
	return 5
}

func credsspClient(conn *tls.Conn, address string, opts Options, res *Result) error {
	if opts.UserName == "" || opts.Password == "" {
		return ErrNoCredentials
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
		MinVersion: opts.credSSPMinVersion(),
	})
	if err != nil {
		return err
	}
	res.NLA = true
	res.CredSSPVersion = r.Version
	return nil
}
