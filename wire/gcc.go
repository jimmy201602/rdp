package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// T.124 GCC Conference Create Request/Response wrappers and the MS-RDPBCGR
// user data blocks exchanged during Basic Settings Exchange (2.2.1.3, 2.2.1.4).

var ErrGCC = errors.New("invalid GCC data")

// User data block types (MS-RDPBCGR 2.2.1.3.1).
const (
	CSCore       uint16 = 0xC001
	CSSecurity   uint16 = 0xC002
	CSNet        uint16 = 0xC003
	CSCluster    uint16 = 0xC004
	SCCore       uint16 = 0x0C01
	SCSecurity   uint16 = 0x0C02
	SCNet        uint16 = 0x0C03
	SCMsgChannel uint16 = 0x0C04
	SCMultitrans uint16 = 0x0C08
)

// Client core constants (MS-RDPBCGR 2.2.1.3.2).
const (
	RDPVersion5Plus        uint32 = 0x00080004
	ColorDepth8bpp         uint16 = 0xCA01
	SASSequenceDel         uint16 = 0xAA03
	HighColorDepth24       uint16 = 0x0018
	SupportColorDepths24   uint16 = 0x0001
	SupportColorDepths16   uint16 = 0x0002
	SupportColorDepths15   uint16 = 0x0004
	SupportColorDepths32   uint16 = 0x0008
	CapSupportErrInfoPDU   uint16 = 0x0001
	KeyboardTypeIBMEnhance uint32 = 0x00000004
)

var (
	t124ObjectKey      = []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01}
	ccRequestPrefix    = []byte{0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 'D', 'u', 'c', 'a'} // ends with the "Duca" client H.221 key
	h221ServerKey      = []byte("McDn")
	userDataHeaderSize = 4
)

// UserDataBlock is one TS_UD_HEADER-prefixed settings block.
type UserDataBlock struct {
	Type    uint16
	Payload []byte
}

func (b UserDataBlock) Encode() ([]byte, error) {
	size := userDataHeaderSize + len(b.Payload)
	if size > 0xffff {
		return nil, fmt.Errorf("%w: user data block too large", ErrGCC)
	}
	out := make([]byte, size)
	binary.LittleEndian.PutUint16(out, b.Type)
	binary.LittleEndian.PutUint16(out[2:], uint16(size))
	copy(out[4:], b.Payload)
	return out, nil
}

// ParseUserDataBlocks splits concatenated TS_UD_HEADER blocks.
func ParseUserDataBlocks(p []byte) ([]UserDataBlock, error) {
	var blocks []UserDataBlock
	for len(p) > 0 {
		if len(p) < userDataHeaderSize {
			return nil, fmt.Errorf("%w: truncated user data header", ErrGCC)
		}
		size := int(binary.LittleEndian.Uint16(p[2:]))
		if size < userDataHeaderSize || size > len(p) {
			return nil, fmt.Errorf("%w: block length %d outside %d available", ErrGCC, size, len(p))
		}
		blocks = append(blocks, UserDataBlock{Type: binary.LittleEndian.Uint16(p), Payload: p[4:size]})
		p = p[size:]
	}
	return blocks, nil
}

// ClientCoreData is TS_UD_CS_CORE up to and including serverSelectedProtocol.
type ClientCoreData struct {
	Version                uint32
	DesktopWidth           uint16
	DesktopHeight          uint16
	ColorDepth             uint16
	SASSequence            uint16
	KeyboardLayout         uint32
	ClientBuild            uint32
	ClientName             string // at most 15 characters
	KeyboardType           uint32
	KeyboardSubType        uint32
	KeyboardFunctionKey    uint32
	ImeFileName            string // at most 31 characters
	PostBeta2ColorDepth    uint16
	ClientProductID        uint16
	SerialNumber           uint32
	HighColorDepth         uint16
	SupportedColorDepths   uint16
	EarlyCapabilityFlags   uint16
	ClientDigProductID     string // at most 31 characters
	ConnectionType         uint8
	ServerSelectedProtocol uint32
}

func putUTF16Fixed(dst []byte, s string, size int) error {
	units := utf16.Encode([]rune(s))
	if len(units)*2 > size-2 {
		return fmt.Errorf("%w: string %q exceeds %d UTF-16 units", ErrGCC, s, size/2-1)
	}
	for i, u := range units {
		binary.LittleEndian.PutUint16(dst[2*i:], u)
	}
	return nil
}

func (c ClientCoreData) Encode() ([]byte, error) {
	p := make([]byte, 212)
	binary.LittleEndian.PutUint32(p[0:], c.Version)
	binary.LittleEndian.PutUint16(p[4:], c.DesktopWidth)
	binary.LittleEndian.PutUint16(p[6:], c.DesktopHeight)
	binary.LittleEndian.PutUint16(p[8:], c.ColorDepth)
	binary.LittleEndian.PutUint16(p[10:], c.SASSequence)
	binary.LittleEndian.PutUint32(p[12:], c.KeyboardLayout)
	binary.LittleEndian.PutUint32(p[16:], c.ClientBuild)
	if err := putUTF16Fixed(p[20:52], c.ClientName, 32); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(p[52:], c.KeyboardType)
	binary.LittleEndian.PutUint32(p[56:], c.KeyboardSubType)
	binary.LittleEndian.PutUint32(p[60:], c.KeyboardFunctionKey)
	if err := putUTF16Fixed(p[64:128], c.ImeFileName, 64); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint16(p[128:], c.PostBeta2ColorDepth)
	binary.LittleEndian.PutUint16(p[130:], c.ClientProductID)
	binary.LittleEndian.PutUint32(p[132:], c.SerialNumber)
	binary.LittleEndian.PutUint16(p[136:], c.HighColorDepth)
	binary.LittleEndian.PutUint16(p[138:], c.SupportedColorDepths)
	binary.LittleEndian.PutUint16(p[140:], c.EarlyCapabilityFlags)
	if err := putUTF16Fixed(p[142:206], c.ClientDigProductID, 64); err != nil {
		return nil, err
	}
	p[206] = c.ConnectionType
	binary.LittleEndian.PutUint32(p[208:], c.ServerSelectedProtocol)
	return UserDataBlock{Type: CSCore, Payload: p}.Encode()
}

// ClientSecurityData is TS_UD_CS_SEC. The methods only matter for Standard RDP
// Security; with TLS the server must answer ENCRYPTION_METHOD_NONE.
type ClientSecurityData struct {
	EncryptionMethods    uint32
	ExtEncryptionMethods uint32
}

func (c ClientSecurityData) Encode() ([]byte, error) {
	p := make([]byte, 8)
	binary.LittleEndian.PutUint32(p, c.EncryptionMethods)
	binary.LittleEndian.PutUint32(p[4:], c.ExtEncryptionMethods)
	return UserDataBlock{Type: CSSecurity, Payload: p}.Encode()
}

// ChannelDef is one CHANNEL_DEF entry of TS_UD_CS_NET.
type ChannelDef struct {
	Name    string // ASCII, at most 7 characters
	Options uint32
}

type ClientNetworkData struct{ Channels []ChannelDef }

func (c ClientNetworkData) Encode() ([]byte, error) {
	if len(c.Channels) > 31 {
		return nil, fmt.Errorf("%w: %d static channels exceeds 31", ErrGCC, len(c.Channels))
	}
	p := make([]byte, 4+12*len(c.Channels))
	binary.LittleEndian.PutUint32(p, uint32(len(c.Channels)))
	for i, ch := range c.Channels {
		if len(ch.Name) > 7 {
			return nil, fmt.Errorf("%w: channel name %q too long", ErrGCC, ch.Name)
		}
		for j := 0; j < len(ch.Name); j++ {
			if b := ch.Name[j]; b < 0x21 || b > 0x7e {
				return nil, fmt.Errorf("%w: channel name %q contains invalid byte", ErrGCC, ch.Name)
			}
		}
		off := 4 + 12*i
		copy(p[off:off+8], ch.Name)
		binary.LittleEndian.PutUint32(p[off+8:], ch.Options)
	}
	return UserDataBlock{Type: CSNet, Payload: p}.Encode()
}

// EncodeConferenceCreateRequest wraps concatenated client user data blocks in
// the PER GCC ConnectData / ConferenceCreateRequest structure.
func EncodeConferenceCreateRequest(blocks []byte) ([]byte, error) {
	inner, err := perLength(len(blocks))
	if err != nil {
		return nil, err
	}
	pdu := make([]byte, 0, len(ccRequestPrefix)+len(inner)+len(blocks))
	pdu = append(pdu, ccRequestPrefix...)
	pdu = append(pdu, inner...)
	pdu = append(pdu, blocks...)
	outer, err := perLength(len(pdu))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(t124ObjectKey)+len(outer)+len(pdu))
	out = append(out, t124ObjectKey...)
	out = append(out, outer...)
	return append(out, pdu...), nil
}

// ParseConferenceCreateResponse extracts the server user data blocks ("McDn"
// h221NonStandard set) from the GCC ConnectData in an MCS Connect-Response.
func ParseConferenceCreateResponse(p []byte) ([]byte, error) {
	if len(p) < len(t124ObjectKey) || !bytes.Equal(p[:len(t124ObjectKey)], t124ObjectKey) {
		return nil, fmt.Errorf("%w: missing T.124 object identifier", ErrGCC)
	}
	p = p[len(t124ObjectKey):]
	// MS-RDPBCGR 3.2.5.3.4: the connectPDU length is ignored by the client,
	// but it must still be well-formed.
	if _, rest, err := perReadLength(p); err != nil {
		return nil, fmt.Errorf("%w: connectPDU length: %v", ErrGCC, err)
	} else {
		p = rest
	}
	if len(p) < 7 {
		return nil, fmt.Errorf("%w: ConferenceCreateResponse too short", ErrGCC)
	}
	// choice conferenceCreateResponse (1) with userData present: 0b0001_01xx.
	if p[0]&0xfc != 0x14 {
		return nil, fmt.Errorf("%w: not a ConferenceCreateResponse (0x%02x)", ErrGCC, p[0])
	}
	p = p[3:] // choice/preamble + nodeID
	tagLen, p, err := perReadLength(p)
	if err != nil {
		return nil, fmt.Errorf("%w: tag: %v", ErrGCC, err)
	}
	if _, p, err = perReadBytes(p, tagLen); err != nil {
		return nil, fmt.Errorf("%w: tag: %v", ErrGCC, err)
	}
	if len(p) < 2 {
		return nil, fmt.Errorf("%w: missing result", ErrGCC)
	}
	if result := p[0] >> 4 & 0x07; result != 0 {
		return nil, fmt.Errorf("%w: ConferenceCreateResponse result %d", ErrGCC, result)
	}
	setCount := int(p[1])
	p = p[2:]
	for i := 0; i < setCount; i++ {
		if len(p) < 2 {
			return nil, fmt.Errorf("%w: truncated user data set", ErrGCC)
		}
		if p[0]&0xc0 != 0xc0 {
			return nil, fmt.Errorf("%w: user data set without h221NonStandard key/value", ErrGCC)
		}
		keyLen := int(p[1]) + 4
		key, rest, err := perReadBytes(p[2:], keyLen)
		if err != nil {
			return nil, fmt.Errorf("%w: key: %v", ErrGCC, err)
		}
		valueLen, rest, err := perReadLength(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: value length: %v", ErrGCC, err)
		}
		value, rest, err := perReadBytes(rest, valueLen)
		if err != nil {
			return nil, fmt.Errorf("%w: value: %v", ErrGCC, err)
		}
		if bytes.Equal(key, h221ServerKey) {
			return value, nil
		}
		p = rest
	}
	return nil, fmt.Errorf("%w: no %q user data set", ErrGCC, h221ServerKey)
}

// ServerCoreData is TS_UD_SC_CORE (MS-RDPBCGR 2.2.1.4.2).
type ServerCoreData struct {
	Version                  uint32
	ClientRequestedProtocols uint32
	HasRequestedProtocols    bool
	EarlyCapabilityFlags     uint32
	HasEarlyCapabilityFlags  bool
}

func DecodeServerCoreData(p []byte) (ServerCoreData, error) {
	var s ServerCoreData
	if len(p) < 4 {
		return s, fmt.Errorf("%w: SC_CORE has %d bytes", ErrGCC, len(p))
	}
	s.Version = binary.LittleEndian.Uint32(p)
	if len(p) >= 8 {
		s.ClientRequestedProtocols = binary.LittleEndian.Uint32(p[4:])
		s.HasRequestedProtocols = true
	}
	if len(p) >= 12 {
		s.EarlyCapabilityFlags = binary.LittleEndian.Uint32(p[8:])
		s.HasEarlyCapabilityFlags = true
	}
	return s, nil
}

// ServerSecurityData is TS_UD_SC_SEC1 (MS-RDPBCGR 2.2.1.4.3).
type ServerSecurityData struct {
	EncryptionMethod  uint32
	EncryptionLevel   uint32
	ServerRandom      []byte
	ServerCertificate []byte
}

func DecodeServerSecurityData(p []byte) (ServerSecurityData, error) {
	var s ServerSecurityData
	if len(p) < 8 {
		return s, fmt.Errorf("%w: SC_SECURITY has %d bytes", ErrGCC, len(p))
	}
	s.EncryptionMethod = binary.LittleEndian.Uint32(p)
	s.EncryptionLevel = binary.LittleEndian.Uint32(p[4:])
	if s.EncryptionMethod == 0 && s.EncryptionLevel == 0 {
		if len(p) != 8 {
			return s, fmt.Errorf("%w: SC_SECURITY carries %d extra bytes without encryption", ErrGCC, len(p)-8)
		}
		return s, nil
	}
	if len(p) < 16 {
		return s, fmt.Errorf("%w: SC_SECURITY missing random/certificate lengths", ErrGCC)
	}
	randomLen := int(binary.LittleEndian.Uint32(p[8:]))
	certLen := int(binary.LittleEndian.Uint32(p[12:]))
	if randomLen < 0 || certLen < 0 || randomLen > len(p)-16 || certLen > len(p)-16-randomLen || 16+randomLen+certLen != len(p) {
		return s, fmt.Errorf("%w: SC_SECURITY lengths %d/%d do not match %d bytes", ErrGCC, randomLen, certLen, len(p))
	}
	s.ServerRandom = p[16 : 16+randomLen]
	s.ServerCertificate = p[16+randomLen:]
	return s, nil
}

// ServerNetworkData is TS_UD_SC_NET (MS-RDPBCGR 2.2.1.4.4).
type ServerNetworkData struct {
	IOChannel  uint16
	ChannelIDs []uint16
}

func DecodeServerNetworkData(p []byte) (ServerNetworkData, error) {
	var s ServerNetworkData
	if len(p) < 4 {
		return s, fmt.Errorf("%w: SC_NET has %d bytes", ErrGCC, len(p))
	}
	s.IOChannel = binary.LittleEndian.Uint16(p)
	count := int(binary.LittleEndian.Uint16(p[2:]))
	need := 4 + 2*count
	pad := need % 4
	if len(p) != need && len(p) != need+pad {
		return s, fmt.Errorf("%w: SC_NET has %d bytes for %d channels", ErrGCC, len(p), count)
	}
	for i := 0; i < count; i++ {
		s.ChannelIDs = append(s.ChannelIDs, binary.LittleEndian.Uint16(p[4+2*i:]))
	}
	return s, nil
}
