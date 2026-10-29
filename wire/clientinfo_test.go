package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// Field values from the MS-RDPBCGR 4.1.10 Client Info PDU sample (decrypted
// TS_INFO_PACKET): code page 0x04090409, flags 0x43b3, domain "NTDEV", user
// "eltons", no password, AF_INET, address "157.59.242.156".
func TestClientInfoEncodeMatchesSamplePrefix(t *testing.T) {
	ci := ClientInfo{
		CodePage:      0x04090409,
		Flags:         0x43b3,
		Domain:        "NTDEV",
		UserName:      "eltons",
		ClientAddress: "157.59.242.156",
		ClientDir:     `C:\WINNT\System32\mstscax.dll`,
		TimeZone:      TimeZoneInformation{Bias: 480, StandardName: "Pacific Standard Time", DaylightName: "Pacific Daylight Time"},
	}
	b, err := ci.Encode()
	if err != nil {
		t.Fatal(err)
	}
	prefix := mustHex(t, "09 04 09 04 b3 43 00 00 0a 00 0c 00 00 00 00 00 00 00"+
		"4e 00 54 00 44 00 45 00 56 00 00 00"+
		"65 00 6c 00 74 00 6f 00 6e 00 73 00 00 00"+
		"00 00 00 00 00 00"+
		"02 00 1e 00 31 00 35 00 37 00 2e 00 35 00 39 00 2e 00 32 00 34 00 32 00 2e 00 31 00 35 00 36 00 00 00")
	if !bytes.HasPrefix(b, prefix) {
		t.Fatalf("encoding differs from sample:\n% x\n% x", b[:len(prefix)], prefix)
	}
	rest := b[len(prefix):]
	cbDir := int(binary.LittleEndian.Uint16(rest))
	if cbDir != 2*(len(ci.ClientDir)+1) {
		t.Fatalf("cbClientDir %d", cbDir)
	}
	rest = rest[2+cbDir:]
	if len(rest) != timeZoneInfoLen+4+4+2+2+2 {
		t.Fatalf("trailer %d bytes", len(rest))
	}
	if int32(binary.LittleEndian.Uint32(rest)) != 480 {
		t.Fatalf("bias % x", rest[:4])
	}
	if name := rest[4 : 4+64]; !bytes.HasPrefix(name, []byte("P\x00a\x00c\x00")) || name[63] != 0 {
		t.Fatalf("standard name % x", name)
	}
	pdu, err := EncodeClientInfoPDU(ci)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pdu[:4], []byte{0x40, 0x00, 0x00, 0x00}) || !bytes.Equal(pdu[4:], b) {
		t.Fatalf("client info PDU header % x", pdu[:4])
	}
}

func TestClientInfoPasswordRules(t *testing.T) {
	if _, err := (ClientInfo{UserName: "u", Password: "p"}).Encode(); !errors.Is(err, ErrClientInfo) {
		t.Fatalf("password without INFO_AUTOLOGON: %v", err)
	}
	if _, err := (ClientInfo{UserName: "u", Flags: InfoAutoLogon}).Encode(); !errors.Is(err, ErrClientInfo) {
		t.Fatalf("INFO_AUTOLOGON without password: %v", err)
	}
	b, err := (ClientInfo{UserName: "u", Password: "pw", Flags: InfoAutoLogon}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(b[4:])&(InfoAutoLogon|InfoUnicode) != InfoAutoLogon|InfoUnicode {
		t.Fatalf("flags %#x", binary.LittleEndian.Uint32(b[4:]))
	}
	if binary.LittleEndian.Uint16(b[12:]) != 4 { // cbPassword excludes the terminator
		t.Fatalf("cbPassword %d", binary.LittleEndian.Uint16(b[12:]))
	}
}

func TestClientInfoRejectsBadStrings(t *testing.T) {
	cases := map[string]ClientInfo{
		"nul in user":      {UserName: "a\x00b"},
		"invalid utf8":     {Domain: "\xff"},
		"user too long":    {UserName: strings.Repeat("u", 257)},
		"domain too long":  {Domain: strings.Repeat("d", 257)},
		"address too long": {ClientAddress: strings.Repeat("1", 40)},
		"tz name too long": {TimeZone: TimeZoneInformation{StandardName: strings.Repeat("z", 32)}},
	}
	for name, ci := range cases {
		if _, err := ci.Encode(); !errors.Is(err, ErrClientInfo) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := (ClientInfo{UserName: strings.Repeat("u", 256), Domain: "d\u00e9"}).Encode(); err != nil {
		t.Fatalf("256-char user name rejected: %v", err)
	}
}

func TestUTCTimeZoneEncodesTo172Bytes(t *testing.T) {
	b, err := UTCTimeZone.encode()
	if err != nil || len(b) != timeZoneInfoLen {
		t.Fatalf("%d bytes, %v", len(b), err)
	}
	for _, x := range b {
		if x != 0 && x != 'U' && x != 'T' && x != 'C' {
			t.Fatalf("unexpected byte % x", b)
		}
	}
}
