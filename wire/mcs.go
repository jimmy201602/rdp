package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// T.125 MCS encodings used by the RDP connection sequence: BER Connect-Initial /
// Connect-Response (MS-RDPBCGR 2.2.1.3 / 2.2.1.4) and PER domain PDUs
// (2.2.1.5 – 2.2.1.9). Only the subset RDP needs is implemented.

var ErrMCS = errors.New("invalid MCS PDU")

// X224DataHeader is the fixed class 0 Data TPDU prefix carried after TPKT for
// every PDU once the connection is confirmed (LI=2, DT, EOT).
var X224DataHeader = []byte{0x02, X224Data, 0x80}

// StripX224Data removes the X.224 Data TPDU header from a TPKT payload.
func StripX224Data(p []byte) ([]byte, error) {
	if len(p) < 3 || p[0] != 0x02 || p[1]&0xF0 != X224Data {
		return nil, fmt.Errorf("%w: missing X.224 data header", ErrX224)
	}
	if p[2]&0x80 == 0 {
		return nil, fmt.Errorf("%w: fragmented X.224 data (EOT not set)", ErrX224)
	}
	return p[3:], nil
}

// WrapX224Data prefixes an MCS PDU with the X.224 Data TPDU header.
func WrapX224Data(mcs []byte) []byte {
	out := make([]byte, 0, 3+len(mcs))
	out = append(out, X224DataHeader...)
	return append(out, mcs...)
}

const (
	mcsTagConnectInitial  = 0x65
	mcsTagConnectResponse = 0x66

	// DomainMCSPDU choice indexes (T.125 section 7, part 10).
	mcsDisconnectProviderUltimatum = 8
	mcsErectDomainRequest          = 1
	mcsAttachUserRequest           = 10
	mcsAttachUserConfirm           = 11
	mcsChannelJoinRequest          = 14
	mcsChannelJoinConfirm          = 15
	mcsSendDataRequest             = 25
	mcsSendDataIndication          = 26

	mcsUserIDBase = 1001
)

// DomainParameters mirrors T.125 DomainParameters.
type DomainParameters struct {
	MaxChannelIDs, MaxUserIDs, MaxTokenIDs, NumPriorities,
	MinThroughput, MaxHeight, MaxMCSPDUSize, ProtocolVersion uint32
}

func (d DomainParameters) encode() []byte {
	var body []byte
	for _, v := range []uint32{d.MaxChannelIDs, d.MaxUserIDs, d.MaxTokenIDs, d.NumPriorities, d.MinThroughput, d.MaxHeight, d.MaxMCSPDUSize, d.ProtocolVersion} {
		body = append(body, berInt(v)...)
	}
	return berElement([]byte{berSequence}, body)
}

func decodeDomainParameters(p []byte) (DomainParameters, error) {
	var d DomainParameters
	fields := []*uint32{&d.MaxChannelIDs, &d.MaxUserIDs, &d.MaxTokenIDs, &d.NumPriorities, &d.MinThroughput, &d.MaxHeight, &d.MaxMCSPDUSize, &d.ProtocolVersion}
	for _, f := range fields {
		v, rest, err := berReadUint(p, berInteger)
		if err != nil {
			return d, err
		}
		*f, p = v, rest
	}
	if len(p) != 0 {
		return d, fmt.Errorf("%w: %d trailing bytes in DomainParameters", ErrBER, len(p))
	}
	return d, nil
}

// Values taken from the MS-RDPBCGR 4.1.3 annotated Connect-Initial.
var (
	TargetDomainParameters  = DomainParameters{34, 2, 0, 1, 0, 1, 65535, 2}
	MinimumDomainParameters = DomainParameters{1, 1, 1, 1, 0, 1, 1056, 2}
	MaximumDomainParameters = DomainParameters{65535, 64535, 65535, 1, 0, 1, 65535, 2}
)

// EncodeConnectInitial builds the BER MCS Connect-Initial carrying GCC user data.
func EncodeConnectInitial(userData []byte) []byte {
	body := []byte{berOctetString, 1, 1, berOctetString, 1, 1, berBoolean, 1, 0xff}
	body = append(body, TargetDomainParameters.encode()...)
	body = append(body, MinimumDomainParameters.encode()...)
	body = append(body, MaximumDomainParameters.encode()...)
	body = append(body, berElement([]byte{berOctetString}, userData)...)
	return berElement([]byte{0x7f, mcsTagConnectInitial}, body)
}

type ConnectResponse struct {
	Result           uint8
	CalledConnectID  uint32
	DomainParameters DomainParameters
	UserData         []byte
}

// MCSResultError reports a non rt-successful result in an MCS response.
type MCSResultError struct {
	PDU    string
	Result uint8
}

func (e *MCSResultError) Error() string {
	return fmt.Sprintf("MCS %s failed with result %d", e.PDU, e.Result)
}

func DecodeConnectResponse(p []byte) (ConnectResponse, error) {
	var cr ConnectResponse
	body, rest, err := berRead(p, []byte{0x7f, mcsTagConnectResponse})
	if err != nil {
		return cr, fmt.Errorf("%w: connect response: %v", ErrMCS, err)
	}
	if len(rest) != 0 {
		return cr, fmt.Errorf("%w: %d trailing bytes after Connect-Response", ErrMCS, len(rest))
	}
	result, body, err := berReadUint(body, berEnumerated)
	if err != nil {
		return cr, fmt.Errorf("%w: result: %v", ErrMCS, err)
	}
	if result > 0xff {
		return cr, fmt.Errorf("%w: result %d out of range", ErrMCS, result)
	}
	cr.Result = uint8(result)
	if cr.CalledConnectID, body, err = berReadUint(body, berInteger); err != nil {
		return cr, fmt.Errorf("%w: calledConnectId: %v", ErrMCS, err)
	}
	params, body, err := berRead(body, []byte{berSequence})
	if err != nil {
		return cr, fmt.Errorf("%w: domainParameters: %v", ErrMCS, err)
	}
	if cr.DomainParameters, err = decodeDomainParameters(params); err != nil {
		return cr, fmt.Errorf("%w: domainParameters: %v", ErrMCS, err)
	}
	userData, body, err := berRead(body, []byte{berOctetString})
	if err != nil {
		return cr, fmt.Errorf("%w: userData: %v", ErrMCS, err)
	}
	if len(body) != 0 {
		return cr, fmt.Errorf("%w: %d trailing bytes in Connect-Response", ErrMCS, len(body))
	}
	cr.UserData = userData
	if cr.Result != 0 {
		return cr, &MCSResultError{PDU: "Connect-Response", Result: cr.Result}
	}
	return cr, nil
}

// EncodeErectDomainRequest returns the PER ErectDomainRequest with
// subHeight = 0 and subInterval = 0.
func EncodeErectDomainRequest() []byte {
	return []byte{mcsErectDomainRequest << 2, 0x01, 0x00, 0x01, 0x00}
}

func EncodeAttachUserRequest() []byte {
	return []byte{mcsAttachUserRequest << 2}
}

// DisconnectError is returned when the server sends DisconnectProviderUltimatum.
type DisconnectError struct{ Reason uint8 }

func (e *DisconnectError) Error() string {
	return fmt.Sprintf("server sent MCS DisconnectProviderUltimatum (reason %d)", e.Reason)
}

func domainPDUChoice(p []byte, want int, name string) error {
	if len(p) == 0 {
		return fmt.Errorf("%w: empty domain PDU", ErrMCS)
	}
	choice := int(p[0] >> 2)
	if choice == mcsDisconnectProviderUltimatum && want != mcsDisconnectProviderUltimatum {
		reason := p[0] & 0x03 << 1
		if len(p) > 1 {
			reason |= p[1] >> 7
		}
		return &DisconnectError{Reason: reason}
	}
	if choice != want {
		return fmt.Errorf("%w: expected %s (choice %d), got choice %d", ErrMCS, name, want, choice)
	}
	return nil
}

// DecodeAttachUserConfirm returns the user channel id (initiator + 1001).
func DecodeAttachUserConfirm(p []byte) (uint16, error) {
	if err := domainPDUChoice(p, mcsAttachUserConfirm, "AttachUserConfirm"); err != nil {
		return 0, err
	}
	if len(p) < 2 {
		return 0, fmt.Errorf("%w: AttachUserConfirm too short", ErrMCS)
	}
	// result is a 4-bit enumerated straddling the first two octets; any
	// non-zero bit there means the request was not rt-successful.
	if p[0]&0x01 != 0 || p[1] != 0 {
		return 0, &MCSResultError{PDU: "AttachUserConfirm", Result: p[0]&0x01<<3 | p[1]>>5}
	}
	if p[0]&0x02 == 0 {
		return 0, fmt.Errorf("%w: AttachUserConfirm without initiator", ErrMCS)
	}
	if len(p) != 4 {
		return 0, fmt.Errorf("%w: AttachUserConfirm has %d bytes, want 4", ErrMCS, len(p))
	}
	return userID(binary.BigEndian.Uint16(p[2:]))
}

func userID(initiator uint16) (uint16, error) {
	if int(initiator)+mcsUserIDBase > 0xffff {
		return 0, fmt.Errorf("%w: initiator %d out of range", ErrMCS, initiator)
	}
	return initiator + mcsUserIDBase, nil
}

func EncodeChannelJoinRequest(userChannel, channelID uint16) ([]byte, error) {
	if userChannel < mcsUserIDBase {
		return nil, fmt.Errorf("%w: user channel %d below %d", ErrMCS, userChannel, mcsUserIDBase)
	}
	out := []byte{mcsChannelJoinRequest << 2, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(out[1:], userChannel-mcsUserIDBase)
	binary.BigEndian.PutUint16(out[3:], channelID)
	return out, nil
}

type ChannelJoinConfirm struct {
	UserChannel uint16
	Requested   uint16
	ChannelID   uint16
}

func DecodeChannelJoinConfirm(p []byte) (ChannelJoinConfirm, error) {
	var c ChannelJoinConfirm
	if err := domainPDUChoice(p, mcsChannelJoinConfirm, "ChannelJoinConfirm"); err != nil {
		return c, err
	}
	if len(p) < 2 {
		return c, fmt.Errorf("%w: ChannelJoinConfirm too short", ErrMCS)
	}
	if p[0]&0x01 != 0 || p[1] != 0 {
		return c, &MCSResultError{PDU: "ChannelJoinConfirm", Result: p[0]&0x01<<3 | p[1]>>5}
	}
	if p[0]&0x02 == 0 {
		return c, fmt.Errorf("%w: ChannelJoinConfirm without channelId", ErrMCS)
	}
	if len(p) != 8 {
		return c, fmt.Errorf("%w: ChannelJoinConfirm has %d bytes, want 8", ErrMCS, len(p))
	}
	user, err := userID(binary.BigEndian.Uint16(p[2:]))
	if err != nil {
		return c, err
	}
	c.UserChannel = user
	c.Requested = binary.BigEndian.Uint16(p[4:])
	c.ChannelID = binary.BigEndian.Uint16(p[6:])
	if c.Requested != c.ChannelID {
		return c, fmt.Errorf("%w: joined channel %d differs from requested %d", ErrMCS, c.ChannelID, c.Requested)
	}
	return c, nil
}
