package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TS_SECURITY_HEADER (MS-RDPBCGR 2.2.8.1.1.2.1, Basic Security Header).
//
// This module only speaks Enhanced RDP Security (the whole stream is
// protected by TLS), where the Encryption Method and Encryption Level are
// both zero. In that mode a security header is present only on the PDUs
// that always carry one: the Client Info PDU (SEC_INFO_PKT) and the
// licensing PDUs (SEC_LICENSE_PKT). Share Control PDUs (Demand Active and
// later) carry no header at all (2.2.1.13.1 "securityHeader" rule for
// ENCRYPTION_LEVEL_NONE). SEC_ENCRYPT and the non-basic header variants
// belong to Standard RDP Security and are rejected.

var ErrSecurity = errors.New("invalid security header")

const (
	SecExchangePkt      uint16 = 0x0001
	SecTransportReq     uint16 = 0x0002
	SecTransportRsp     uint16 = 0x0004
	SecEncrypt          uint16 = 0x0008
	SecResetSeqno       uint16 = 0x0010
	SecIgnoreSeqno      uint16 = 0x0020
	SecInfoPkt          uint16 = 0x0040
	SecLicensePkt       uint16 = 0x0080
	SecLicenseEncryptCS uint16 = 0x0200
	SecLicenseEncryptSC uint16 = 0x0200
	SecRedirectionPkt   uint16 = 0x0400
	SecSecureChecksum   uint16 = 0x0800
	SecAutodetectReq    uint16 = 0x1000
	SecAutodetectRsp    uint16 = 0x2000
	SecHeartbeat        uint16 = 0x4000
	SecFlagsHiValid     uint16 = 0x8000
)

const basicSecurityHeaderLen = 4

// EncodeBasicSecurityHeader prefixes payload with a Basic Security Header.
func EncodeBasicSecurityHeader(flags uint16, payload []byte) []byte {
	out := make([]byte, basicSecurityHeaderLen, basicSecurityHeaderLen+len(payload))
	binary.LittleEndian.PutUint16(out, flags)
	return append(out, payload...)
}

// SecurityHeader is a decoded Basic Security Header.
type SecurityHeader struct {
	Flags   uint16
	FlagsHi uint16
}

// DecodeBasicSecurityHeader splits a Basic Security Header from its payload.
// Encrypted PDUs are refused because Standard RDP Security is not supported.
func DecodeBasicSecurityHeader(p []byte) (SecurityHeader, []byte, error) {
	var h SecurityHeader
	if len(p) < basicSecurityHeaderLen {
		return h, nil, fmt.Errorf("%w: %d bytes, need %d", ErrSecurity, len(p), basicSecurityHeaderLen)
	}
	h.Flags = binary.LittleEndian.Uint16(p)
	h.FlagsHi = binary.LittleEndian.Uint16(p[2:])
	if h.Flags&SecEncrypt != 0 {
		return h, nil, fmt.Errorf("%w: SEC_ENCRYPT set (Standard RDP Security is not supported)", ErrSecurity)
	}
	return h, p[basicSecurityHeaderLen:], nil
}
