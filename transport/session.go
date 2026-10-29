package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"rdp.local/kernel/wire"
)

// PDU is one unit read from a Session after licensing: either the payload
// of an I/O channel SendDataIndication (FastPath false) or a complete raw
// fast-path output frame (FastPath true), both ready to be relayed.
type PDU struct {
	FastPath bool
	Data     []byte
}

// Session is a client-side connection held open after the licensing stage
// so that a relay (the G3 gateway) can run the capability exchange and the
// active session itself. Dial performs negotiation, TLS, MCS/GCC, channel
// joins, Client Info (credentials from Options, passed through once) and
// licensing; the caller then owns every PDU in both directions.
type Session struct {
	conn *bufConn
	res  Result
}

// Dial connects and stops after licensing. Options.StopAfter and Observe
// are ignored; Options.Timeout bounds the whole handshake.
func Dial(ctx context.Context, address string, opts Options) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	start := time.Now()
	rawConn, res, err := secureTransport(ctx, address, opts)
	if err != nil {
		return nil, err
	}
	conn := newBufConn(rawConn)
	deadline, _ := ctx.Deadline()
	_ = rawConn.SetDeadline(deadline)
	s := &Session{conn: conn}
	if err := s.handshake(opts, &res); err != nil {
		_ = rawConn.Close()
		res.Duration = time.Since(start)
		return nil, fmt.Errorf("%s: %w", address, err)
	}
	_ = rawConn.SetDeadline(time.Time{})
	res.Duration = time.Since(start)
	s.res = res
	return s, nil
}

func (s *Session) handshake(opts Options, res *Result) error {
	conn := s.conn
	if err := basicSettingsExchange(conn, opts, res); err != nil {
		return err
	}
	res.Stage = StageMCSConnect
	if err := writeMCS(conn, wire.EncodeErectDomainRequest()); err != nil {
		return fmt.Errorf("erect domain: %w", err)
	}
	if err := writeMCS(conn, wire.EncodeAttachUserRequest()); err != nil {
		return fmt.Errorf("attach user: %w", err)
	}
	pdu, err := readMCS(conn)
	if err != nil {
		return fmt.Errorf("attach user confirm: %w", err)
	}
	if res.UserChannel, err = wire.DecodeAttachUserConfirm(pdu); err != nil {
		return fmt.Errorf("attach user confirm: %w", err)
	}
	res.Stage = StageAttachUser
	for _, channel := range []uint16{res.UserChannel, res.IOChannel} {
		if err := joinChannel(conn, res.UserChannel, channel); err != nil {
			return err
		}
		res.JoinedChannels = append(res.JoinedChannels, channel)
	}
	res.Stage = StageChannelJoin
	if err := sendClientInfo(conn, opts, res); err != nil {
		return err
	}
	res.Stage = StageClientInfo
	if err := license(conn, opts, res); err != nil {
		return err
	}
	res.Stage = StageLicense
	return nil
}

// Result reports the handshake outcome (stage license).
func (s *Session) Result() Result { return s.res }

// UserChannel is the MCS user channel the server assigned to this client.
func (s *Session) UserChannel() uint16 { return s.res.UserChannel }

// ReadPDU returns the next server PDU. Data on channels other than the I/O
// channel is skipped (no static channels are requested). A
// DisconnectProviderUltimatum is returned as ErrDisconnected.
func (s *Session) ReadPDU() (PDU, error) {
	for {
		first, err := s.conn.r.Peek(1)
		if err != nil {
			return PDU{}, err
		}
		if wire.IsFastPathHeader(first[0]) {
			frame, err := wire.ReadFastPathFrame(s.conn.r, 0)
			if err != nil {
				return PDU{}, err
			}
			return PDU{FastPath: true, Data: frame}, nil
		}
		mcs, err := readMCS(s.conn)
		if err != nil {
			return PDU{}, err
		}
		if reason, ok := wire.IsDisconnectProviderUltimatum(mcs); ok {
			return PDU{}, fmt.Errorf("%w (reason %d)", ErrDisconnected, reason)
		}
		sd, err := wire.DecodeSendDataIndication(mcs)
		if err != nil {
			return PDU{}, err
		}
		if sd.ChannelID == s.res.IOChannel {
			return PDU{Data: sd.Data}, nil
		}
	}
}

// ErrDisconnected is returned by ReadPDU when the server sends a
// DisconnectProviderUltimatum.
var ErrDisconnected = errors.New("server disconnected")

// WriteIO sends payload on the I/O channel.
func (s *Session) WriteIO(payload []byte) error { return sendIO(s.conn, &s.res, payload) }

// WriteFastPath sends a complete fast-path input frame unchanged.
func (s *Session) WriteFastPath(frame []byte) error {
	if len(frame) < 2 || !wire.IsFastPathHeader(frame[0]) {
		return fmt.Errorf("%w: not a fast-path frame", wire.ErrFastPath)
	}
	_, err := s.conn.Write(frame)
	return err
}

// Disconnect sends a DisconnectProviderUltimatum (user requested) before
// closing.
func (s *Session) Disconnect() error {
	err := writeMCS(s.conn, wire.EncodeDisconnectProviderUltimatum(wire.DisconnectReasonUserRequested))
	if cerr := s.Close(); err == nil {
		err = cerr
	}
	return err
}

// SetDeadline applies to reads and writes.
func (s *Session) SetDeadline(t time.Time) error { return s.conn.SetDeadline(t) }

// Close closes the TLS connection.
func (s *Session) Close() error {
	err := s.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
