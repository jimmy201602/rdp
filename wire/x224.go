package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// X.224 class 0 TPDU codes carried inside TPKT (MS-RDPBCGR 2.2.1.1 / 2.2.1.2).
const (
	X224ConnectionRequest = 0xE0
	X224ConnectionConfirm = 0xD0
	X224Data              = 0xF0
)

// RDP negotiation structure types (MS-RDPBCGR 2.2.1.1.1, 2.2.1.2.1, 2.2.1.2.2).
const (
	TypeNegotiationRequest  = 0x01
	TypeNegotiationResponse = 0x02
	TypeNegotiationFailure  = 0x03

	negotiationStructureSize = 8
	x224FixedPartSize        = 7 // LI, CR/CC code, DST-REF, SRC-REF, class option
)

// Security protocols (MS-RDPBCGR 2.2.1.1.1 requestedProtocols).
const (
	ProtocolRDP      uint32 = 0x00000000
	ProtocolSSL      uint32 = 0x00000001
	ProtocolHybrid   uint32 = 0x00000002
	ProtocolRDSTLS   uint32 = 0x00000004
	ProtocolHybridEx uint32 = 0x00000008
	ProtocolRDSAAD   uint32 = 0x00000010
)

// Negotiation failure codes (MS-RDPBCGR 2.2.1.2.2 failureCode).
const (
	FailureSSLRequiredByServer     uint32 = 0x00000001
	FailureSSLNotAllowedByServer   uint32 = 0x00000002
	FailureSSLCertNotOnServer      uint32 = 0x00000003
	FailureInconsistentFlags       uint32 = 0x00000004
	FailureHybridRequiredByServer  uint32 = 0x00000005
	FailureSSLWithUserAuthRequired uint32 = 0x00000006
)

var ErrX224 = errors.New("invalid X.224 PDU")

// NegotiationFailure is returned when the server answers with RDP_NEG_FAILURE.
type NegotiationFailure struct{ Code uint32 }

func (e *NegotiationFailure) Error() string {
	return fmt.Sprintf("server rejected security negotiation: %s", FailureCodeString(e.Code))
}

func FailureCodeString(code uint32) string {
	switch code {
	case FailureSSLRequiredByServer:
		return "SSL_REQUIRED_BY_SERVER"
	case FailureSSLNotAllowedByServer:
		return "SSL_NOT_ALLOWED_BY_SERVER"
	case FailureSSLCertNotOnServer:
		return "SSL_CERT_NOT_ON_SERVER"
	case FailureInconsistentFlags:
		return "INCONSISTENT_FLAGS"
	case FailureHybridRequiredByServer:
		return "HYBRID_REQUIRED_BY_SERVER"
	case FailureSSLWithUserAuthRequired:
		return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
	default:
		return fmt.Sprintf("unknown failure code 0x%08x", code)
	}
}

func ProtocolString(p uint32) string {
	switch p {
	case ProtocolRDP:
		return "PROTOCOL_RDP"
	case ProtocolSSL:
		return "PROTOCOL_SSL"
	case ProtocolHybrid:
		return "PROTOCOL_HYBRID"
	case ProtocolRDSTLS:
		return "PROTOCOL_RDSTLS"
	case ProtocolHybridEx:
		return "PROTOCOL_HYBRID_EX"
	case ProtocolRDSAAD:
		return "PROTOCOL_RDSAAD"
	default:
		return fmt.Sprintf("unknown protocol 0x%08x", p)
	}
}

// ConnectionRequest is a Client X.224 Connection Request PDU with an RDP_NEG_REQ.
type ConnectionRequest struct {
	Cookie             string // optional routing token / cookie, printable ASCII without CR LF
	Flags              uint8
	RequestedProtocols uint32
}

// Encode returns the TPKT payload. The X.224 length indicator covers the cookie
// and the negotiation structure, matching the MS-RDPBCGR 4.1.1 annotated dump.
func (c ConnectionRequest) Encode() ([]byte, error) {
	for i := 0; i < len(c.Cookie); i++ {
		if b := c.Cookie[i]; b < 0x20 || b > 0x7e {
			return nil, fmt.Errorf("%w: cookie contains non-printable byte 0x%02x", ErrX224, b)
		}
	}
	variable := len(c.Cookie)
	if variable > 0 {
		variable += 2 // CR LF terminator
	}
	length := x224FixedPartSize + variable + negotiationStructureSize
	if length-1 > 0xfe {
		return nil, fmt.Errorf("%w: connection request too long", ErrX224)
	}
	out := make([]byte, length)
	out[0] = byte(length - 1)
	out[1] = X224ConnectionRequest
	// DST-REF, SRC-REF are zero; class option 0 (class 0, no extended format).
	n := x224FixedPartSize
	if variable > 0 {
		n += copy(out[n:], c.Cookie)
		out[n], out[n+1] = '\r', '\n'
		n += 2
	}
	out[n] = TypeNegotiationRequest
	out[n+1] = c.Flags
	binary.LittleEndian.PutUint16(out[n+2:], negotiationStructureSize)
	binary.LittleEndian.PutUint32(out[n+4:], c.RequestedProtocols)
	return out, nil
}

// ConnectionConfirm is the decoded Server X.224 Connection Confirm PDU.
type ConnectionConfirm struct {
	Flags            uint8
	SelectedProtocol uint32
	// HasNegotiation is false when the server omitted RDP_NEG_RSP, which per
	// MS-RDPBCGR 3.2.5.3.2 means Standard RDP Security was implicitly selected.
	HasNegotiation bool
}

// DecodeConnectionConfirm parses a TPKT payload. A server RDP_NEG_FAILURE is
// reported as *NegotiationFailure so callers can distinguish it from malformed input.
func DecodeConnectionConfirm(p []byte) (ConnectionConfirm, error) {
	var cc ConnectionConfirm
	if len(p) < x224FixedPartSize {
		return cc, fmt.Errorf("%w: connection confirm shorter than fixed part (%d bytes)", ErrX224, len(p))
	}
	li := int(p[0])
	// Microsoft servers count rdpNegData inside LI; some implementations use LI=6
	// and append rdpNegData as user data. Both shapes are accepted, nothing else.
	if li != len(p)-1 && li != x224FixedPartSize-1 {
		return cc, fmt.Errorf("%w: length indicator %d does not match payload %d", ErrX224, li, len(p))
	}
	if p[1]&0xF0 != X224ConnectionConfirm {
		return cc, fmt.Errorf("%w: expected connection confirm, got TPDU code 0x%02x", ErrX224, p[1])
	}
	if p[6]&0x03 != 0 {
		return cc, fmt.Errorf("%w: unsupported X.224 class option 0x%02x", ErrX224, p[6])
	}
	rest := p[x224FixedPartSize:]
	if len(rest) == 0 {
		return cc, nil
	}
	if len(rest) != negotiationStructureSize {
		return cc, fmt.Errorf("%w: negotiation structure has %d bytes, want %d", ErrX224, len(rest), negotiationStructureSize)
	}
	if size := binary.LittleEndian.Uint16(rest[2:]); size != negotiationStructureSize {
		return cc, fmt.Errorf("%w: negotiation length field %d", ErrX224, size)
	}
	value := binary.LittleEndian.Uint32(rest[4:])
	switch rest[0] {
	case TypeNegotiationResponse:
		cc.HasNegotiation = true
		cc.Flags = rest[1]
		cc.SelectedProtocol = value
		return cc, nil
	case TypeNegotiationFailure:
		return cc, &NegotiationFailure{Code: value}
	default:
		return cc, fmt.Errorf("%w: unexpected negotiation type 0x%02x", ErrX224, rest[0])
	}
}

// --- Server side -----------------------------------------------------------

// DecodeConnectionRequest parses a Client X.224 Connection Request TPKT
// payload. A request without RDP_NEG_REQ (HasNegotiation false) asks for
// Standard RDP Security only, which a TLS-only server must refuse.
func DecodeConnectionRequest(p []byte) (ConnectionRequest, bool, error) {
	var cr ConnectionRequest
	if len(p) < x224FixedPartSize {
		return cr, false, fmt.Errorf("%w: connection request shorter than fixed part (%d bytes)", ErrX224, len(p))
	}
	if li := int(p[0]); li != len(p)-1 {
		return cr, false, fmt.Errorf("%w: length indicator %d does not match payload %d", ErrX224, li, len(p))
	}
	if p[1]&0xF0 != X224ConnectionRequest {
		return cr, false, fmt.Errorf("%w: expected connection request, got TPDU code 0x%02x", ErrX224, p[1])
	}
	if p[6]&0x03 != 0 {
		return cr, false, fmt.Errorf("%w: unsupported X.224 class option 0x%02x", ErrX224, p[6])
	}
	rest := p[x224FixedPartSize:]
	// Optional routingToken / cookie: printable ASCII terminated by CR LF.
	if i := bytes.Index(rest, []byte("\r\n")); i >= 0 {
		for _, b := range rest[:i] {
			if b < 0x20 || b > 0x7e {
				return cr, false, fmt.Errorf("%w: cookie contains non-printable byte 0x%02x", ErrX224, b)
			}
		}
		cr.Cookie = string(rest[:i])
		rest = rest[i+2:]
	}
	if len(rest) == 0 {
		return cr, false, nil
	}
	if len(rest) != negotiationStructureSize {
		return cr, false, fmt.Errorf("%w: negotiation structure has %d bytes, want %d", ErrX224, len(rest), negotiationStructureSize)
	}
	if rest[0] != TypeNegotiationRequest {
		return cr, false, fmt.Errorf("%w: unexpected negotiation type 0x%02x", ErrX224, rest[0])
	}
	if size := binary.LittleEndian.Uint16(rest[2:]); size != negotiationStructureSize {
		return cr, false, fmt.Errorf("%w: negotiation length field %d", ErrX224, size)
	}
	cr.Flags = rest[1]
	cr.RequestedProtocols = binary.LittleEndian.Uint32(rest[4:])
	return cr, true, nil
}

// EncodeConnectionConfirm builds a Server X.224 Connection Confirm with an
// RDP_NEG_RSP selecting the given protocol (MS-RDPBCGR 2.2.1.2 / 4.1.2 shape:
// LI covers rdpNegData).
func EncodeConnectionConfirm(flags uint8, selected uint32) []byte {
	return connectionConfirm(TypeNegotiationResponse, flags, selected)
}

// EncodeNegotiationFailure builds a Server X.224 Connection Confirm carrying
// an RDP_NEG_FAILURE with the given failureCode.
func EncodeNegotiationFailure(code uint32) []byte {
	return connectionConfirm(TypeNegotiationFailure, 0, code)
}

func connectionConfirm(typ, flags uint8, value uint32) []byte {
	out := make([]byte, x224FixedPartSize+negotiationStructureSize)
	out[0] = byte(len(out) - 1)
	out[1] = X224ConnectionConfirm
	n := x224FixedPartSize
	out[n] = typ
	out[n+1] = flags
	binary.LittleEndian.PutUint16(out[n+2:], negotiationStructureSize)
	binary.LittleEndian.PutUint32(out[n+4:], value)
	return out
}
