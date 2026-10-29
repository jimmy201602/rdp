package server

import (
	"fmt"
	"time"

	"rdp.local/kernel/wire"
)

// PDU is one unit read from a Conn: the payload of an I/O channel
// SendDataRequest (FastPath false) or a complete raw fast-path input frame
// (FastPath true).
type PDU struct {
	FastPath bool
	Data     []byte
}

// Credentials are the Client Info secrets handed to a Handler. They are
// only valid until the Handler returns.
type Credentials struct {
	Domain, UserName, Password string
}

// Conn is an accepted client after licensing, handed to Config.Handler.
// The Handler owns the capability exchange and everything after it.
type Conn struct {
	s     *session
	creds Credentials
}

// Peer describes the client (no password).
func (c *Conn) Peer() Peer { return c.s.peer }

// Credentials returns the Client Info credentials for pass-through.
func (c *Conn) Credentials() Credentials { return c.creds }

// UserChannel is the MCS user channel assigned to the client.
func (c *Conn) UserChannel() uint16 { return c.s.userChannel }

// ReadPDU returns the next client PDU on the I/O channel or a raw fast-path
// input frame; data on other joined static channels is dropped.
func (c *Conn) ReadPDU() (PDU, error) {
	first, err := c.s.r.Peek(1)
	if err != nil {
		return PDU{}, err
	}
	if first[0] != 3 {
		frame, err := wire.ReadFastPathFrame(c.s.r, 0)
		if err != nil {
			return PDU{}, fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		return PDU{FastPath: true, Data: frame}, nil
	}
	data, err := c.s.readIO()
	if err != nil {
		return PDU{}, err
	}
	return PDU{Data: data}, nil
}

// WriteIO sends payload to the client on the I/O channel.
func (c *Conn) WriteIO(payload []byte) error { return c.s.writeIO(payload) }

// WriteFastPath sends a complete fast-path output frame unchanged.
func (c *Conn) WriteFastPath(frame []byte) error {
	if len(frame) < 2 || !wire.IsFastPathHeader(frame[0]) {
		return fmt.Errorf("%w: not a fast-path frame", wire.ErrFastPath)
	}
	_, err := c.s.conn.Write(frame)
	return err
}

// Deny sends Set Error Info with code followed by a
// DisconnectProviderUltimatum; the Handler should then return an error
// wrapping ErrDenied.
func (c *Conn) Deny(code uint32) error {
	pdu, err := wire.EncodeErrorInfo(shareID, code)
	if err != nil {
		return err
	}
	if err := c.s.writeIO(pdu); err != nil {
		return err
	}
	return c.s.writeMCS(wire.EncodeDisconnectProviderUltimatum(wire.DisconnectReasonProviderInit))
}

// Disconnect sends a DisconnectProviderUltimatum with reason.
func (c *Conn) Disconnect(reason uint8) error {
	return c.s.writeMCS(wire.EncodeDisconnectProviderUltimatum(reason))
}

// SetDeadline applies to reads and writes; the handshake deadline is
// cleared before the Handler runs.
func (c *Conn) SetDeadline(t time.Time) error { return c.s.conn.SetDeadline(t) }

// Close closes the client connection (unblocking a pending ReadPDU).
func (c *Conn) Close() error { return c.s.raw.Close() }

// MarkAuthorized records that the Handler's policy accepted the client
// (reported in Summary.Authorized).
func (c *Conn) MarkAuthorized() { c.s.authorized = true }
