package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Client Info PDU data: TS_INFO_PACKET (MS-RDPBCGR 2.2.1.11.1.1),
// TS_EXTENDED_INFO_PACKET (2.2.1.11.1.1.1) and TS_TIME_ZONE_INFORMATION
// (2.2.1.11.1.1.1.1). Only the Unicode form (INFO_UNICODE) is produced.
//
// The packet carries logon credentials. Callers must only populate Password
// (and set InfoAutoLogon) for an explicitly authorised test account; the
// transport layer never fills it in on its own.

var ErrClientInfo = errors.New("invalid client info")

const (
	InfoMouse                uint32 = 0x00000001
	InfoDisableCtrlAltDel    uint32 = 0x00000002
	InfoAutoLogon            uint32 = 0x00000008
	InfoUnicode              uint32 = 0x00000010
	InfoMaximizeShell        uint32 = 0x00000020
	InfoLogonNotify          uint32 = 0x00000040
	InfoCompression          uint32 = 0x00000080
	InfoEnableWindowsKey     uint32 = 0x00000100
	InfoRemoteConsoleAudio   uint32 = 0x00002000
	InfoForceEncryptedCSPDU  uint32 = 0x00004000
	InfoRail                 uint32 = 0x00008000
	InfoLogonErrors          uint32 = 0x00010000
	InfoMouseHasWheel        uint32 = 0x00020000
	InfoPasswordIsSCPin      uint32 = 0x00040000
	InfoNoAudioPlayback      uint32 = 0x00080000
	InfoUsingSavedCreds      uint32 = 0x00100000
	InfoAudioCapture         uint32 = 0x00200000
	InfoVideoDisable         uint32 = 0x00400000
	InfoCompressionTypeMask  uint32 = 0x00001E00
	InfoReservedCompression1 uint32 = 0x00000200
)

const (
	AddressFamilyINet  uint16 = 0x0002
	AddressFamilyINet6 uint16 = 0x0017

	PerfDisableWallpaper         uint32 = 0x00000001
	PerfDisableFullWindowDrag    uint32 = 0x00000002
	PerfDisableMenuAnimations    uint32 = 0x00000004
	PerfDisableTheming           uint32 = 0x00000008
	PerfDisableCursorShadow      uint32 = 0x00000020
	PerfDisableCursorSettings    uint32 = 0x00000040
	PerfEnableFontSmoothing      uint32 = 0x00000080
	PerfEnableDesktopComposition uint32 = 0x00000100
)

// Maximum byte lengths of the UTF-16 strings (excluding terminators) as
// mandated by 2.2.1.11.1.1 / 2.2.1.11.1.1.1.
const (
	maxInfoDomainBytes     = 512
	maxInfoUserNameBytes   = 512
	maxInfoPasswordBytes   = 512
	maxInfoAltShellBytes   = 512
	maxInfoWorkingDirBytes = 512
	maxInfoClientAddrBytes = 80 - 2
	maxInfoClientDirBytes  = 512 - 2
	timeZoneInfoLen        = 172
	timeZoneNameChars      = 32
)

// SystemTime mirrors the 16-byte SYSTEMTIME used in TS_TIME_ZONE_INFORMATION.
// A zero value means "no transition".
type SystemTime struct {
	Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds uint16
}

func (t SystemTime) encode() []byte {
	out := make([]byte, 16)
	for i, v := range []uint16{t.Year, t.Month, t.DayOfWeek, t.Day, t.Hour, t.Minute, t.Second, t.Milliseconds} {
		binary.LittleEndian.PutUint16(out[2*i:], v)
	}
	return out
}

// TimeZoneInformation is TS_TIME_ZONE_INFORMATION. Bias values are minutes
// such that UTC = local time + Bias.
type TimeZoneInformation struct {
	Bias         int32
	StandardName string
	StandardDate SystemTime
	StandardBias int32
	DaylightName string
	DaylightDate SystemTime
	DaylightBias int32
}

// UTCTimeZone is a neutral zone with no daylight saving transitions.
var UTCTimeZone = TimeZoneInformation{StandardName: "UTC", DaylightName: "UTC"}

func (tz TimeZoneInformation) encode() ([]byte, error) {
	out := make([]byte, 0, timeZoneInfoLen)
	out = binary.LittleEndian.AppendUint32(out, uint32(tz.Bias))
	name, err := fixedUTF16(tz.StandardName, timeZoneNameChars)
	if err != nil {
		return nil, fmt.Errorf("%w: StandardName: %v", ErrClientInfo, err)
	}
	out = append(out, name...)
	out = append(out, tz.StandardDate.encode()...)
	out = binary.LittleEndian.AppendUint32(out, uint32(tz.StandardBias))
	name, err = fixedUTF16(tz.DaylightName, timeZoneNameChars)
	if err != nil {
		return nil, fmt.Errorf("%w: DaylightName: %v", ErrClientInfo, err)
	}
	out = append(out, name...)
	out = append(out, tz.DaylightDate.encode()...)
	out = binary.LittleEndian.AppendUint32(out, uint32(tz.DaylightBias))
	return out, nil
}

// ClientInfo holds the fields of TS_INFO_PACKET and its extended part.
type ClientInfo struct {
	CodePage       uint32 // low word: active input locale when INFO_UNICODE
	Flags          uint32 // INFO_UNICODE is always added
	Domain         string
	UserName       string
	Password       string
	AlternateShell string
	WorkingDir     string

	ClientAddressFamily uint16
	ClientAddress       string
	ClientDir           string
	TimeZone            TimeZoneInformation
	SessionID           uint32
	PerformanceFlags    uint32
}

// Encode produces the TS_INFO_PACKET bytes (without security header).
func (ci ClientInfo) Encode() ([]byte, error) {
	if ci.Flags&InfoAutoLogon != 0 && ci.Password == "" {
		return nil, fmt.Errorf("%w: INFO_AUTOLOGON without password", ErrClientInfo)
	}
	if ci.Password != "" && ci.Flags&InfoAutoLogon == 0 {
		return nil, fmt.Errorf("%w: password set without INFO_AUTOLOGON", ErrClientInfo)
	}
	type field struct {
		name  string
		value string
		max   int
	}
	fields := []field{
		{"Domain", ci.Domain, maxInfoDomainBytes},
		{"UserName", ci.UserName, maxInfoUserNameBytes},
		{"Password", ci.Password, maxInfoPasswordBytes},
		{"AlternateShell", ci.AlternateShell, maxInfoAltShellBytes},
		{"WorkingDir", ci.WorkingDir, maxInfoWorkingDirBytes},
	}
	encoded := make([][]byte, len(fields))
	for i, f := range fields {
		b, err := utf16z(f.value)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrClientInfo, f.name, err)
		}
		if len(b)-2 > f.max {
			return nil, fmt.Errorf("%w: %s is %d bytes, max %d", ErrClientInfo, f.name, len(b)-2, f.max)
		}
		encoded[i] = b
	}

	out := make([]byte, 0, 256)
	out = binary.LittleEndian.AppendUint32(out, ci.CodePage)
	out = binary.LittleEndian.AppendUint32(out, ci.Flags|InfoUnicode)
	for _, b := range encoded {
		out = binary.LittleEndian.AppendUint16(out, uint16(len(b)-2))
	}
	for _, b := range encoded {
		out = append(out, b...)
	}

	family := ci.ClientAddressFamily
	if family == 0 {
		family = AddressFamilyINet
	}
	addr, err := utf16z(ci.ClientAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: ClientAddress: %v", ErrClientInfo, err)
	}
	if len(addr)-2 > maxInfoClientAddrBytes {
		return nil, fmt.Errorf("%w: ClientAddress too long", ErrClientInfo)
	}
	dir, err := utf16z(ci.ClientDir)
	if err != nil {
		return nil, fmt.Errorf("%w: ClientDir: %v", ErrClientInfo, err)
	}
	if len(dir)-2 > maxInfoClientDirBytes {
		return nil, fmt.Errorf("%w: ClientDir too long", ErrClientInfo)
	}
	tz, err := ci.TimeZone.encode()
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint16(out, family)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(addr)))
	out = append(out, addr...)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(dir)))
	out = append(out, dir...)
	out = append(out, tz...)
	out = binary.LittleEndian.AppendUint32(out, ci.SessionID)
	out = binary.LittleEndian.AppendUint32(out, ci.PerformanceFlags)
	out = binary.LittleEndian.AppendUint16(out, 0) // cbAutoReconnectCookie
	out = binary.LittleEndian.AppendUint16(out, 0) // reserved1
	out = binary.LittleEndian.AppendUint16(out, 0) // reserved2
	return out, nil
}

// EncodeClientInfoPDU returns the security-header-prefixed Client Info PDU
// payload ready for an MCS SendDataRequest on the I/O channel.
func EncodeClientInfoPDU(ci ClientInfo) ([]byte, error) {
	body, err := ci.Encode()
	if err != nil {
		return nil, err
	}
	return EncodeBasicSecurityHeader(SecInfoPkt, body), nil
}

// utf16z encodes s as UTF-16LE with a two-byte terminator. Embedded NULs
// and unpaired surrogates are rejected rather than silently altered.
func utf16z(s string) ([]byte, error) {
	if strings.ContainsRune(s, 0) {
		return nil, errors.New("embedded NUL")
	}
	if !utf8.ValidString(s) {
		return nil, errors.New("invalid UTF-8")
	}
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return append(out, 0, 0), nil
}

func fixedUTF16(s string, chars int) ([]byte, error) {
	b, err := utf16z(s)
	if err != nil {
		return nil, err
	}
	if len(b) > 2*chars {
		return nil, fmt.Errorf("%d UTF-16 units exceed %d", len(b)/2-1, chars-1)
	}
	return append(b, make([]byte, 2*chars-len(b))...), nil
}

// DecodeClientInfoPDU strips the Basic Security Header (SEC_INFO_PKT must be
// set) and decodes the TS_INFO_PACKET.
func DecodeClientInfoPDU(p []byte) (ClientInfo, error) {
	hdr, body, err := DecodeBasicSecurityHeader(p)
	if err != nil {
		return ClientInfo{}, err
	}
	if hdr.Flags&SecInfoPkt == 0 {
		return ClientInfo{}, fmt.Errorf("%w: security flags 0x%04x lack SEC_INFO_PKT", ErrClientInfo, hdr.Flags)
	}
	return DecodeClientInfo(body)
}

// DecodeClientInfo parses a TS_INFO_PACKET (without security header). Both
// the Unicode and the ANSI (code page 1252 subset) forms are accepted; the
// extended info packet is optional.
func DecodeClientInfo(p []byte) (ClientInfo, error) {
	var ci ClientInfo
	if len(p) < 18 {
		return ci, fmt.Errorf("%w: info packet %d bytes", ErrClientInfo, len(p))
	}
	ci.CodePage = binary.LittleEndian.Uint32(p)
	ci.Flags = binary.LittleEndian.Uint32(p[4:])
	unicode := ci.Flags&InfoUnicode != 0
	lengths := make([]int, 5)
	for i := range lengths {
		lengths[i] = int(binary.LittleEndian.Uint16(p[8+2*i:]))
	}
	rest := p[18:]
	term := 1
	if unicode {
		term = 2
	}
	fields := []*string{&ci.Domain, &ci.UserName, &ci.Password, &ci.AlternateShell, &ci.WorkingDir}
	maxes := []int{maxInfoDomainBytes, maxInfoUserNameBytes, maxInfoPasswordBytes, maxInfoAltShellBytes, maxInfoWorkingDirBytes}
	for i, n := range lengths {
		if n > maxes[i] || (unicode && n%2 != 0) {
			return ci, fmt.Errorf("%w: field %d length %d", ErrClientInfo, i, n)
		}
		if len(rest) < n+term {
			return ci, fmt.Errorf("%w: field %d truncated", ErrClientInfo, i)
		}
		s, err := infoString(rest[:n], unicode)
		if err != nil {
			return ci, fmt.Errorf("%w: field %d: %v", ErrClientInfo, i, err)
		}
		*fields[i] = s
		rest = rest[n+term:]
	}
	if len(rest) == 0 {
		return ci, nil
	}
	// TS_EXTENDED_INFO_PACKET (optional; RDP 5.0+).
	if len(rest) < 4 {
		return ci, fmt.Errorf("%w: extended info truncated", ErrClientInfo)
	}
	ci.ClientAddressFamily = binary.LittleEndian.Uint16(rest)
	n := int(binary.LittleEndian.Uint16(rest[2:]))
	rest = rest[4:]
	if n > maxInfoClientAddrBytes+2 || len(rest) < n {
		return ci, fmt.Errorf("%w: cbClientAddress %d", ErrClientInfo, n)
	}
	ci.ClientAddress = utf16zString(rest[:n], n)
	rest = rest[n:]
	if len(rest) < 2 {
		return ci, nil
	}
	n = int(binary.LittleEndian.Uint16(rest))
	rest = rest[2:]
	if n > maxInfoClientDirBytes+2 || len(rest) < n {
		return ci, fmt.Errorf("%w: cbClientDir %d", ErrClientInfo, n)
	}
	ci.ClientDir = utf16zString(rest[:n], n)
	rest = rest[n:]
	if len(rest) < timeZoneInfoLen {
		return ci, nil
	}
	ci.TimeZone = decodeTimeZone(rest[:timeZoneInfoLen])
	rest = rest[timeZoneInfoLen:]
	if len(rest) >= 4 {
		ci.SessionID = binary.LittleEndian.Uint32(rest)
		rest = rest[4:]
	}
	if len(rest) >= 4 {
		ci.PerformanceFlags = binary.LittleEndian.Uint32(rest)
	}
	// cbAutoReconnectCookie, the cookie, reserved1/2 and later fields are
	// not needed by the server role and are ignored.
	return ci, nil
}

func infoString(b []byte, unicode bool) (string, error) {
	if unicode {
		return utf16zString(b, len(b)), nil
	}
	for _, c := range b {
		if c >= 0x80 || c == 0 {
			return "", errors.New("non-ASCII byte in ANSI info string")
		}
	}
	return string(b), nil
}

func decodeSystemTime(b []byte) SystemTime {
	var t SystemTime
	for i, f := range []*uint16{&t.Year, &t.Month, &t.DayOfWeek, &t.Day, &t.Hour, &t.Minute, &t.Second, &t.Milliseconds} {
		*f = binary.LittleEndian.Uint16(b[2*i:])
	}
	return t
}

func decodeTimeZone(b []byte) TimeZoneInformation {
	return TimeZoneInformation{
		Bias:         int32(binary.LittleEndian.Uint32(b)),
		StandardName: utf16zString(b[4:68], 64),
		StandardDate: decodeSystemTime(b[68:84]),
		StandardBias: int32(binary.LittleEndian.Uint32(b[84:])),
		DaylightName: utf16zString(b[88:152], 64),
		DaylightDate: decodeSystemTime(b[152:168]),
		DaylightBias: int32(binary.LittleEndian.Uint32(b[168:])),
	}
}
