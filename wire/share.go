package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Share Control / Share Data PDUs (MS-RDPBCGR 2.2.8.1.1.1.1 and 2.2.8.1.1.1.2)
// plus the Capability Exchange and Connection Finalization PDUs that use them:
// Demand Active (2.2.1.13.1), Confirm Active (2.2.1.13.2), Synchronize
// (2.2.1.14 / 2.2.1.19), Control (2.2.1.15 / 2.2.1.16 / 2.2.1.20 / 2.2.1.21),
// Font List (2.2.1.18) and Font Map (2.2.1.22). Under Enhanced RDP Security
// with ENCRYPTION_LEVEL_NONE these PDUs carry no security header.

var ErrShare = errors.New("invalid share PDU")

const (
	PDUTypeDemandActive  uint16 = 0x1
	PDUTypeConfirmActive uint16 = 0x3
	PDUTypeDeactivateAll uint16 = 0x6
	PDUTypeData          uint16 = 0x7
	PDUTypeServerRedir   uint16 = 0xA

	shareProtocolVersion  uint16 = 0x0010
	shareControlHeaderLen int    = 6
	shareDataHeaderLen    int    = 18

	StreamLow uint8 = 0x01
	StreamMed uint8 = 0x02
	StreamHi  uint8 = 0x04

	PDUType2Update                uint8 = 0x02
	PDUType2Control               uint8 = 0x14
	PDUType2Pointer               uint8 = 0x1B
	PDUType2Input                 uint8 = 0x1C
	PDUType2Synchronize           uint8 = 0x1F
	PDUType2RefreshRect           uint8 = 0x21
	PDUType2PlaySound             uint8 = 0x22
	PDUType2SuppressOutput        uint8 = 0x23
	PDUType2ShutdownRequest       uint8 = 0x24
	PDUType2ShutdownDenied        uint8 = 0x25
	PDUType2SaveSessionInfo       uint8 = 0x26
	PDUType2FontList              uint8 = 0x27
	PDUType2FontMap               uint8 = 0x28
	PDUType2SetKeyboardIndicators uint8 = 0x29
	PDUType2BitmapCachePersistent uint8 = 0x2B
	PDUType2BitmapCacheError      uint8 = 0x2C
	PDUType2SetKeyboardIMEStatus  uint8 = 0x2D
	PDUType2OffscreenCacheError   uint8 = 0x2E
	PDUType2SetErrorInfo          uint8 = 0x2F
	PDUType2DrawNineGridError     uint8 = 0x30
	PDUType2DrawGDIPlusError      uint8 = 0x31
	PDUType2ARCStatus             uint8 = 0x32
	PDUType2StatusInfo            uint8 = 0x36
	PDUType2MonitorLayout         uint8 = 0x37

	packetCompressed uint8 = 0x20

	// ServerChannelID is the MCS channel the server uses as pduSource and as
	// originatorID / targetUser / controlId in the finalization PDUs.
	ServerChannelID uint16 = 0x03EA
)

// ShareControlHeader is TS_SHARECONTROLHEADER.
type ShareControlHeader struct {
	TotalLength uint16
	PDUType     uint16 // low nibble only; version bits are validated and stripped
	PDUSource   uint16
}

// EncodeShareControl prefixes body with a Share Control Header.
func EncodeShareControl(pduType, source uint16, body []byte) ([]byte, error) {
	total := shareControlHeaderLen + len(body)
	if total > 0xffff {
		return nil, fmt.Errorf("%w: share PDU of %d bytes too large", ErrShare, total)
	}
	out := make([]byte, shareControlHeaderLen, total)
	binary.LittleEndian.PutUint16(out, uint16(total))
	binary.LittleEndian.PutUint16(out[2:], pduType&0x000f|shareProtocolVersion)
	binary.LittleEndian.PutUint16(out[4:], source)
	return append(out, body...), nil
}

// DecodeShareControl splits a Share Control Header from the PDU body. It
// requires totalLength to match the buffer exactly, so callers must hand it
// one complete PDU (one MCS SendDataIndication payload).
func DecodeShareControl(p []byte) (ShareControlHeader, []byte, error) {
	var h ShareControlHeader
	if len(p) < shareControlHeaderLen {
		return h, nil, fmt.Errorf("%w: %d bytes, need %d for share control header", ErrShare, len(p), shareControlHeaderLen)
	}
	h.TotalLength = binary.LittleEndian.Uint16(p)
	pduType := binary.LittleEndian.Uint16(p[2:])
	h.PDUSource = binary.LittleEndian.Uint16(p[4:])
	if int(h.TotalLength) != len(p) {
		return h, nil, fmt.Errorf("%w: totalLength %d, PDU has %d bytes", ErrShare, h.TotalLength, len(p))
	}
	if pduType&0xfff0 != shareProtocolVersion {
		return h, nil, fmt.Errorf("%w: pduType 0x%04x has unexpected version bits", ErrShare, pduType)
	}
	h.PDUType = pduType & 0x000f
	return h, p[shareControlHeaderLen:], nil
}

// ShareDataHeader is TS_SHAREDATAHEADER (including the control header).
type ShareDataHeader struct {
	Control            ShareControlHeader
	ShareID            uint32
	StreamID           uint8
	UncompressedLength uint16
	PDUType2           uint8
	CompressedType     uint8
	CompressedLength   uint16
}

// EncodeShareData wraps body in a Share Data Header and Share Control Header.
// uncompressedLength follows the client convention of the specification
// samples (body length plus the four trailing header bytes).
func EncodeShareData(shareID uint32, source uint16, pduType2 uint8, body []byte) ([]byte, error) {
	if len(body)+4 > 0xffff {
		return nil, fmt.Errorf("%w: share data body of %d bytes too large", ErrShare, len(body))
	}
	data := make([]byte, shareDataHeaderLen-shareControlHeaderLen, shareDataHeaderLen-shareControlHeaderLen+len(body))
	binary.LittleEndian.PutUint32(data, shareID)
	data[4] = 0 // pad1
	data[5] = StreamLow
	binary.LittleEndian.PutUint16(data[6:], uint16(len(body)+4))
	data[8] = pduType2
	data[9] = 0 // compressedType
	binary.LittleEndian.PutUint16(data[10:], 0)
	return EncodeShareControl(PDUTypeData, source, append(data, body...))
}

// DecodeShareData parses a Data PDU and returns the body after the 18-byte
// header. Compressed PDUs are refused (no bulk compression is negotiated).
func DecodeShareData(p []byte) (ShareDataHeader, []byte, error) {
	var h ShareDataHeader
	ctl, rest, err := DecodeShareControl(p)
	if err != nil {
		return h, nil, err
	}
	h.Control = ctl
	if ctl.PDUType != PDUTypeData {
		return h, nil, fmt.Errorf("%w: pduType %d is not PDUTYPE_DATAPDU", ErrShare, ctl.PDUType)
	}
	if len(rest) < shareDataHeaderLen-shareControlHeaderLen {
		return h, nil, fmt.Errorf("%w: share data header truncated", ErrShare)
	}
	h.ShareID = binary.LittleEndian.Uint32(rest)
	h.StreamID = rest[5]
	h.UncompressedLength = binary.LittleEndian.Uint16(rest[6:])
	h.PDUType2 = rest[8]
	h.CompressedType = rest[9]
	h.CompressedLength = binary.LittleEndian.Uint16(rest[10:])
	if h.CompressedType&packetCompressed != 0 {
		return h, nil, fmt.Errorf("%w: compressed data PDU (type 0x%02x) not supported", ErrShare, h.CompressedType)
	}
	return h, rest[12:], nil
}

// --- Capability Exchange -------------------------------------------------

// CapabilitySet is a raw TS_CAPS_SET (2.2.1.13.1.1.1).
type CapabilitySet struct {
	Type uint16
	Data []byte // capabilityData without the 4-byte header
}

const (
	CapsTypeGeneral                uint16 = 0x0001
	CapsTypeBitmap                 uint16 = 0x0002
	CapsTypeOrder                  uint16 = 0x0003
	CapsTypeBitmapCache            uint16 = 0x0004
	CapsTypeControl                uint16 = 0x0005
	CapsTypeActivation             uint16 = 0x0007
	CapsTypePointer                uint16 = 0x0008
	CapsTypeShare                  uint16 = 0x0009
	CapsTypeColorCache             uint16 = 0x000A
	CapsTypeSound                  uint16 = 0x000C
	CapsTypeInput                  uint16 = 0x000D
	CapsTypeFont                   uint16 = 0x000E
	CapsTypeBrush                  uint16 = 0x000F
	CapsTypeGlyphCache             uint16 = 0x0010
	CapsTypeOffscreenCache         uint16 = 0x0011
	CapsTypeBitmapCacheHostSupport uint16 = 0x0012
	CapsTypeBitmapCacheRev2        uint16 = 0x0013
	CapsTypeVirtualChannel         uint16 = 0x0014
	CapsTypeDrawNineGridCache      uint16 = 0x0015
	CapsTypeDrawGDIPlus            uint16 = 0x0016
	CapsTypeRail                   uint16 = 0x0017
	CapsTypeWindow                 uint16 = 0x0018
	CapsTypeCompDesk               uint16 = 0x0019
	CapsTypeMultifragmentUpdate    uint16 = 0x001A
	CapsTypeLargePointer           uint16 = 0x001B
	CapsTypeSurfaceCommands        uint16 = 0x001C
	CapsTypeBitmapCodecs           uint16 = 0x001D
	CapsTypeFrameAcknowledge       uint16 = 0x001E
	capabilitySetHeaderLen                = 4
	maxCapabilitySets                     = 64
)

func encodeCapabilitySets(sets []CapabilitySet) ([]byte, error) {
	if len(sets) == 0 || len(sets) > maxCapabilitySets {
		return nil, fmt.Errorf("%w: %d capability sets", ErrShare, len(sets))
	}
	out := make([]byte, 0, 512)
	for _, s := range sets {
		n := capabilitySetHeaderLen + len(s.Data)
		if n > 0xffff {
			return nil, fmt.Errorf("%w: capability set 0x%04x too large", ErrShare, s.Type)
		}
		out = binary.LittleEndian.AppendUint16(out, s.Type)
		out = binary.LittleEndian.AppendUint16(out, uint16(n))
		out = append(out, s.Data...)
	}
	return out, nil
}

func decodeCapabilitySets(p []byte, count int) ([]CapabilitySet, error) {
	if count > maxCapabilitySets {
		return nil, fmt.Errorf("%w: %d capability sets exceeds %d", ErrShare, count, maxCapabilitySets)
	}
	sets := make([]CapabilitySet, 0, count)
	for i := 0; i < count; i++ {
		if len(p) < capabilitySetHeaderLen {
			return nil, fmt.Errorf("%w: capability set %d truncated", ErrShare, i)
		}
		typ := binary.LittleEndian.Uint16(p)
		n := int(binary.LittleEndian.Uint16(p[2:]))
		if n < capabilitySetHeaderLen || n > len(p) {
			return nil, fmt.Errorf("%w: capability set 0x%04x length %d (have %d)", ErrShare, typ, n, len(p))
		}
		sets = append(sets, CapabilitySet{Type: typ, Data: p[capabilitySetHeaderLen:n]})
		p = p[n:]
	}
	if len(p) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after capability sets", ErrShare, len(p))
	}
	return sets, nil
}

// Find returns the first capability set of the given type.
func FindCapability(sets []CapabilitySet, typ uint16) (CapabilitySet, bool) {
	for _, s := range sets {
		if s.Type == typ {
			return s, true
		}
	}
	return CapabilitySet{}, false
}

// DemandActive is the decoded TS_DEMAND_ACTIVE_PDU.
type DemandActive struct {
	Control          ShareControlHeader
	ShareID          uint32
	SourceDescriptor []byte
	Capabilities     []CapabilitySet
	SessionID        uint32
}

// DecodeDemandActive parses a complete Demand Active PDU (no security header).
func DecodeDemandActive(p []byte) (DemandActive, error) {
	var d DemandActive
	ctl, rest, err := DecodeShareControl(p)
	if err != nil {
		return d, err
	}
	d.Control = ctl
	if ctl.PDUType != PDUTypeDemandActive {
		return d, fmt.Errorf("%w: pduType %d is not PDUTYPE_DEMANDACTIVEPDU", ErrShare, ctl.PDUType)
	}
	if len(rest) < 8 {
		return d, fmt.Errorf("%w: demand active truncated", ErrShare)
	}
	d.ShareID = binary.LittleEndian.Uint32(rest)
	srcLen := int(binary.LittleEndian.Uint16(rest[4:]))
	combined := int(binary.LittleEndian.Uint16(rest[6:]))
	rest = rest[8:]
	if srcLen > len(rest) {
		return d, fmt.Errorf("%w: sourceDescriptor length %d exceeds %d", ErrShare, srcLen, len(rest))
	}
	d.SourceDescriptor = rest[:srcLen]
	rest = rest[srcLen:]
	// combined covers numberCapabilities + pad2Octets + capabilitySets and is
	// followed by the 4-byte sessionId.
	if combined < 4 || combined+4 > len(rest) {
		return d, fmt.Errorf("%w: lengthCombinedCapabilities %d does not fit %d bytes", ErrShare, combined, len(rest))
	}
	count := int(binary.LittleEndian.Uint16(rest))
	sets, err := decodeCapabilitySets(rest[4:combined], count)
	if err != nil {
		return d, err
	}
	d.Capabilities = sets
	rest = rest[combined:]
	if len(rest) != 4 {
		return d, fmt.Errorf("%w: %d bytes after capability sets, want 4-byte sessionId", ErrShare, len(rest))
	}
	d.SessionID = binary.LittleEndian.Uint32(rest)
	return d, nil
}

// EncodeConfirmActive builds a Confirm Active PDU (TS_CONFIRM_ACTIVE_PDU).
// userChannel becomes pduSource; the originatorID is the server channel.
func EncodeConfirmActive(shareID uint32, userChannel uint16, sourceDescriptor string, sets []CapabilitySet) ([]byte, error) {
	caps, err := encodeCapabilitySets(sets)
	if err != nil {
		return nil, err
	}
	src := append([]byte(sourceDescriptor), 0)
	if len(src) > 0xffff {
		return nil, fmt.Errorf("%w: source descriptor too long", ErrShare)
	}
	combined := 4 + len(caps)
	if combined > 0xffff {
		return nil, fmt.Errorf("%w: capability sets too large", ErrShare)
	}
	body := make([]byte, 0, 10+len(src)+combined)
	body = binary.LittleEndian.AppendUint32(body, shareID)
	body = binary.LittleEndian.AppendUint16(body, ServerChannelID)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(src)))
	body = binary.LittleEndian.AppendUint16(body, uint16(combined))
	body = append(body, src...)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(sets)))
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = append(body, caps...)
	return EncodeShareControl(PDUTypeConfirmActive, userChannel, body)
}

// ConfirmActive is the decoded TS_CONFIRM_ACTIVE_PDU (used by tests and a
// future server role).
type ConfirmActive struct {
	Control          ShareControlHeader
	ShareID          uint32
	OriginatorID     uint16
	SourceDescriptor []byte
	Capabilities     []CapabilitySet
}

// DecodeConfirmActive parses a complete Confirm Active PDU.
func DecodeConfirmActive(p []byte) (ConfirmActive, error) {
	var c ConfirmActive
	ctl, rest, err := DecodeShareControl(p)
	if err != nil {
		return c, err
	}
	c.Control = ctl
	if ctl.PDUType != PDUTypeConfirmActive {
		return c, fmt.Errorf("%w: pduType %d is not PDUTYPE_CONFIRMACTIVEPDU", ErrShare, ctl.PDUType)
	}
	if len(rest) < 10 {
		return c, fmt.Errorf("%w: confirm active truncated", ErrShare)
	}
	c.ShareID = binary.LittleEndian.Uint32(rest)
	c.OriginatorID = binary.LittleEndian.Uint16(rest[4:])
	srcLen := int(binary.LittleEndian.Uint16(rest[6:]))
	combined := int(binary.LittleEndian.Uint16(rest[8:]))
	rest = rest[10:]
	if srcLen > len(rest) {
		return c, fmt.Errorf("%w: sourceDescriptor length %d exceeds %d", ErrShare, srcLen, len(rest))
	}
	c.SourceDescriptor = rest[:srcLen]
	rest = rest[srcLen:]
	if combined < 4 || combined != len(rest) {
		return c, fmt.Errorf("%w: lengthCombinedCapabilities %d, %d bytes remain", ErrShare, combined, len(rest))
	}
	count := int(binary.LittleEndian.Uint16(rest))
	sets, err := decodeCapabilitySets(rest[4:], count)
	if err != nil {
		return c, err
	}
	c.Capabilities = sets
	return c, nil
}

// --- Connection Finalization ----------------------------------------------

const (
	SyncMsgTypeSync uint16 = 0x0001

	CtrlActionRequestControl uint16 = 0x0001
	CtrlActionGrantedControl uint16 = 0x0002
	CtrlActionDetach         uint16 = 0x0003
	CtrlActionCooperate      uint16 = 0x0004

	fontListFlags   uint16 = 0x0003
	fontListEntry   uint16 = 0x0032
	fontMapFlags    uint16 = 0x0003
	fontMapEntrySiz uint16 = 0x0004
)

// EncodeSynchronize builds a client Synchronize PDU targeting the server
// channel reported in the Demand Active pduSource.
func EncodeSynchronize(shareID uint32, userChannel, targetUser uint16) ([]byte, error) {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body, SyncMsgTypeSync)
	binary.LittleEndian.PutUint16(body[2:], targetUser)
	return EncodeShareData(shareID, userChannel, PDUType2Synchronize, body)
}

// EncodeControl builds a Control PDU with the given action (Cooperate or
// Request Control); grantId and controlId are zero for client requests.
func EncodeControl(shareID uint32, userChannel uint16, action uint16) ([]byte, error) {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body, action)
	return EncodeShareData(shareID, userChannel, PDUType2Control, body)
}

// EncodeFontList builds the (empty) Font List PDU that completes activation.
func EncodeFontList(shareID uint32, userChannel uint16) ([]byte, error) {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[4:], fontListFlags)
	binary.LittleEndian.PutUint16(body[6:], fontListEntry)
	return EncodeShareData(shareID, userChannel, PDUType2FontList, body)
}

// Synchronize is TS_SYNCHRONIZE_PDU payload.
type Synchronize struct {
	MessageType uint16
	TargetUser  uint16
}

func decodeSynchronize(body []byte) (Synchronize, error) {
	if len(body) < 4 {
		return Synchronize{}, fmt.Errorf("%w: synchronize body %d bytes", ErrShare, len(body))
	}
	s := Synchronize{MessageType: binary.LittleEndian.Uint16(body), TargetUser: binary.LittleEndian.Uint16(body[2:])}
	if s.MessageType != SyncMsgTypeSync {
		return s, fmt.Errorf("%w: synchronize messageType 0x%04x", ErrShare, s.MessageType)
	}
	return s, nil
}

// Control is TS_CONTROL_PDU payload.
type Control struct {
	Action    uint16
	GrantID   uint16
	ControlID uint32
}

func decodeControl(body []byte) (Control, error) {
	if len(body) < 8 {
		return Control{}, fmt.Errorf("%w: control body %d bytes", ErrShare, len(body))
	}
	return Control{
		Action:    binary.LittleEndian.Uint16(body),
		GrantID:   binary.LittleEndian.Uint16(body[2:]),
		ControlID: binary.LittleEndian.Uint32(body[4:]),
	}, nil
}

// FontMap is TS_FONT_MAP_PDU payload.
type FontMap struct {
	NumberEntries   uint16
	TotalNumEntries uint16
	MapFlags        uint16
	EntrySize       uint16
}

func decodeFontMap(body []byte) (FontMap, error) {
	if len(body) < 8 {
		return FontMap{}, fmt.Errorf("%w: font map body %d bytes", ErrShare, len(body))
	}
	return FontMap{
		NumberEntries:   binary.LittleEndian.Uint16(body),
		TotalNumEntries: binary.LittleEndian.Uint16(body[2:]),
		MapFlags:        binary.LittleEndian.Uint16(body[4:]),
		EntrySize:       binary.LittleEndian.Uint16(body[6:]),
	}, nil
}

// ErrorInfo is the TS_SET_ERROR_INFO_PDU payload (2.2.5.1.1).
type ErrorInfo struct{ Code uint32 }

func (e *ErrorInfo) Error() string {
	return fmt.Sprintf("server sent Set Error Info PDU (errorInfo 0x%08x)", e.Code)
}

// DataPDU is a decoded Share Data PDU with the typed payload for the PDUs the
// connection sequence cares about. Other pduType2 values leave Body raw.
type DataPDU struct {
	Header      ShareDataHeader
	Body        []byte
	Synchronize *Synchronize
	Control     *Control
	FontMap     *FontMap
}

// DecodeDataPDU parses a Data PDU and, for the finalization PDUs, its body.
// A Set Error Info PDU is returned as an *ErrorInfo error.
func DecodeDataPDU(p []byte) (DataPDU, error) {
	var d DataPDU
	h, body, err := DecodeShareData(p)
	if err != nil {
		return d, err
	}
	d.Header = h
	d.Body = body
	switch h.PDUType2 {
	case PDUType2Synchronize:
		s, err := decodeSynchronize(body)
		if err != nil {
			return d, err
		}
		d.Synchronize = &s
	case PDUType2Control:
		c, err := decodeControl(body)
		if err != nil {
			return d, err
		}
		d.Control = &c
	case PDUType2FontMap:
		f, err := decodeFontMap(body)
		if err != nil {
			return d, err
		}
		d.FontMap = &f
	case PDUType2SetErrorInfo:
		if len(body) < 4 {
			return d, fmt.Errorf("%w: error info body %d bytes", ErrShare, len(body))
		}
		return d, &ErrorInfo{Code: binary.LittleEndian.Uint32(body)}
	}
	return d, nil
}
