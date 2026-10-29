package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// dump converts the hex columns of an MS-RDPBCGR annotated dump into bytes.
func dump(t *testing.T, s string) []byte {
	t.Helper()
	var hexText strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields[0]) == 8 { // offset column
			fields = fields[1:]
		}
		for _, f := range fields {
			if len(f) != 2 {
				break // ASCII column
			}
			hexText.WriteString(f)
		}
	}
	b, err := hex.DecodeString(hexText.String())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MS-RDPBCGR 4.1.3 Client MCS Connect Initial PDU with GCC Conference Create Request.
const msConnectInitialDump = `
00000000 03 00 01 a0 02 f0 80 7f 65 82 01 94 04 01 01 04
00000010 01 01 01 01 ff 30 19 02 01 22 02 01 02 02 01 00
00000020 02 01 01 02 01 00 02 01 01 02 02 ff ff 02 01 02
00000030 30 19 02 01 01 02 01 01 02 01 01 02 01 01 02 01
00000040 00 02 01 01 02 02 04 20 02 01 02 30 1c 02 02 ff
00000050 ff 02 02 fc 17 02 02 ff ff 02 01 01 02 01 00 02
00000060 01 01 02 02 ff ff 02 01 02 04 82 01 33 00 05 00
00000070 14 7c 00 01 81 2a 00 08 00 10 00 01 c0 00 44 75
00000080 63 61 81 1c 01 c0 d8 00 04 00 08 00 00 05 00 04
00000090 01 ca 03 aa 09 04 00 00 ce 0e 00 00 45 00 4c 00
000000a0 54 00 4f 00 4e 00 53 00 2d 00 44 00 45 00 56 00
000000b0 32 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00
000000c0 00 00 00 00 0c 00 00 00 00 00 00 00 00 00 00 00
000000d0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000000e0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000000f0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000100 00 00 00 00 00 00 00 00 01 ca 01 00 00 00 00 00
00000110 18 00 07 00 01 00 36 00 39 00 37 00 31 00 32 00
00000120 2d 00 37 00 38 00 33 00 2d 00 30 00 33 00 35 00
00000130 37 00 39 00 37 00 34 00 2d 00 34 00 32 00 37 00
00000140 31 00 34 00 00 00 00 00 00 00 00 00 00 00 00 00
00000150 00 00 00 00 00 00 00 00 00 00 00 00 04 c0 0c 00
00000160 0d 00 00 00 00 00 00 00 02 c0 0c 00 1b 00 00 00
00000170 00 00 00 00 03 c0 2c 00 03 00 00 00 72 64 70 64
00000180 72 00 00 00 00 00 80 80 63 6c 69 70 72 64 72 00
00000190 00 00 a0 c0 72 64 70 73 6e 64 00 00 00 00 00 c0
`

// MS-RDPBCGR 4.1.4 Server MCS Connect Response PDU with GCC Conference Create Response.
const msConnectResponseDump = `
00000000 03 00 01 51 02 f0 80 7f 66 82 01 45 0a 01 00 02
00000010 01 00 30 1a 02 01 22 02 01 03 02 01 00 02 01 01
00000020 02 01 00 02 01 01 02 03 00 ff f8 02 01 02 04 82
00000030 01 1f 00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00
00000040 01 c0 00 4d 63 44 6e 81 08 01 0c 0c 00 04 00 08
00000050 00 00 00 00 00 03 0c 10 00 eb 03 03 00 ec 03 ed
00000060 03 ee 03 00 00 02 0c ec 00 02 00 00 00 02 00 00
00000070 00 20 00 00 00 b8 00 00 00 10 11 77 20 30 61 0a
00000080 12 e4 34 a1 1e f2 c3 9f 31 7d a4 5f 01 89 34 96
00000090 e0 ff 11 08 69 7f 1a c3 d2 01 00 00 00 01 00 00
000000a0 00 01 00 00 00 06 00 5c 00 52 53 41 31 48 00 00
000000b0 00 00 02 00 00 3f 00 00 00 01 00 01 00 cb 81 fe
000000c0 ba 6d 61 c3 55 05 d5 5f 2e 87 f8 71 94 d6 f1 a5
000000d0 cb f1 5f 0c 3d f8 70 02 96 c4 fb 9b c8 3c 2d 55
000000e0 ae e8 ff 32 75 ea 68 79 e5 a2 01 fd 31 a0 b1 1f
000000f0 55 a6 1f c1 f6 d1 83 88 63 26 56 12 bc 00 00 00
00000100 00 00 00 00 00 08 00 48 00 e9 e1 d6 28 46 8b 4e
00000110 f5 0a df fd ee 21 99 ac b4 e1 8f 5f 81 57 82 ef
00000120 9d 96 52 63 27 18 29 db b3 4a fd 9a da 42 ad b5
00000130 69 21 89 0e 1d c0 4c 1a a8 aa 71 3e 0f 54 b9 9a
00000140 e4 99 68 3f 6c d6 76 84 61 00 00 00 00 00 00 00
00000150 00
`

func msClientBlocks(t *testing.T) []byte {
	t.Helper()
	core, err := ClientCoreData{
		Version: RDPVersion5Plus, DesktopWidth: 1280, DesktopHeight: 1024,
		ColorDepth: ColorDepth8bpp, SASSequence: SASSequenceDel, KeyboardLayout: 0x409, ClientBuild: 3790,
		ClientName: "ELTONS-DEV2", KeyboardType: KeyboardTypeIBMEnhance, KeyboardFunctionKey: 12,
		PostBeta2ColorDepth: ColorDepth8bpp, ClientProductID: 1, HighColorDepth: HighColorDepth24,
		SupportedColorDepths: SupportColorDepths24 | SupportColorDepths16 | SupportColorDepths15,
		EarlyCapabilityFlags: CapSupportErrInfoPDU, ClientDigProductID: "69712-783-0357974-42714",
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cluster, _ := UserDataBlock{Type: CSCluster, Payload: []byte{0x0d, 0, 0, 0, 0, 0, 0, 0}}.Encode()
	sec, _ := ClientSecurityData{EncryptionMethods: 0x1b}.Encode()
	network, err := ClientNetworkData{Channels: []ChannelDef{
		{"rdpdr", 0x80800000}, {"cliprdr", 0xc0a00000}, {"rdpsnd", 0xc0000000},
	}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var blocks []byte
	for _, b := range [][]byte{core, cluster, sec, network} {
		blocks = append(blocks, b...)
	}
	return blocks
}

func TestConnectInitialMatchesMicrosoftDump(t *testing.T) {
	want := dump(t, msConnectInitialDump)
	if len(want) != 416 {
		t.Fatalf("dump has %d bytes", len(want))
	}
	gcc, err := EncodeConferenceCreateRequest(msClientBlocks(t))
	if err != nil {
		t.Fatal(err)
	}
	mcs := EncodeConnectInitial(gcc)
	got, err := EncodeTPKT(WrapX224Data(mcs))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("mismatch\n got %x\nwant %x", got, want)
	}
}

func TestConnectResponseMatchesMicrosoftDump(t *testing.T) {
	packet := dump(t, msConnectResponseDump)
	if len(packet) != 337 {
		t.Fatalf("dump has %d bytes", len(packet))
	}
	mcs, err := StripX224Data(packet[TPKTHeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	cr, err := DecodeConnectResponse(mcs)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Result != 0 || cr.CalledConnectID != 0 || cr.DomainParameters != (DomainParameters{34, 3, 0, 1, 0, 1, 65528, 2}) || len(cr.UserData) != 287 {
		t.Fatalf("unexpected connect response %+v", cr)
	}
	serverBlocks, err := ParseConferenceCreateResponse(cr.UserData)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := ParseUserDataBlocks(serverBlocks)
	if err != nil || len(blocks) != 3 {
		t.Fatalf("blocks %v, %v", blocks, err)
	}
	core, err := DecodeServerCoreData(blocks[0].Payload)
	if err != nil || blocks[0].Type != SCCore || core.Version != 0x00080004 || !core.HasRequestedProtocols || core.ClientRequestedProtocols != ProtocolRDP || core.HasEarlyCapabilityFlags {
		t.Fatalf("core %+v, %v", core, err)
	}
	network, err := DecodeServerNetworkData(blocks[1].Payload)
	if err != nil || blocks[1].Type != SCNet || network.IOChannel != 1003 || len(network.ChannelIDs) != 3 || network.ChannelIDs[2] != 1006 {
		t.Fatalf("network %+v, %v", network, err)
	}
	sec, err := DecodeServerSecurityData(blocks[2].Payload)
	if err != nil || blocks[2].Type != SCSecurity || sec.EncryptionMethod != 2 || sec.EncryptionLevel != 2 || len(sec.ServerRandom) != 32 || len(sec.ServerCertificate) != 184 {
		t.Fatalf("security %+v, %v", sec, err)
	}
}

func TestConnectResponseRejectsMalformed(t *testing.T) {
	good, _ := StripX224Data(dump(t, msConnectResponseDump)[TPKTHeaderSize:])
	failed := append([]byte{}, good...)
	failed[7] = 0x01 // Connect-Response::result = rt-domain-merging
	var resultErr *MCSResultError
	if _, err := DecodeConnectResponse(failed); !errors.As(err, &resultErr) || resultErr.Result != 1 {
		t.Fatalf("result: %v", err)
	}
	for name, p := range map[string][]byte{
		"wrong-tag":   append([]byte{0x7f, 0x65}, good[2:]...),
		"truncated":   good[:len(good)-1],
		"trailing":    append(append([]byte{}, good...), 0),
		"empty":       {},
		"bad-length":  {0x7f, 0x66, 0x84, 1, 1, 1, 1},
		"indefinite":  {0x7f, 0x66, 0x80, 0x0a, 0x01, 0x00},
		"no-userdata": {0x7f, 0x66, 0x06, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00},
	} {
		if _, err := DecodeConnectResponse(p); !errors.Is(err, ErrMCS) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDomainPDUs(t *testing.T) {
	if !bytes.Equal(EncodeErectDomainRequest(), []byte{0x04, 0x01, 0x00, 0x01, 0x00}) {
		t.Fatal("erect domain")
	}
	if !bytes.Equal(EncodeAttachUserRequest(), []byte{0x28}) {
		t.Fatal("attach user")
	}
	// MS-RDPBCGR 4.1.7: initiator 6 -> user channel 1007.
	user, err := DecodeAttachUserConfirm([]byte{0x2e, 0x00, 0x00, 0x06})
	if err != nil || user != 1007 {
		t.Fatalf("attach confirm: %d, %v", user, err)
	}
	join, err := EncodeChannelJoinRequest(1007, 1003)
	if err != nil || !bytes.Equal(join, []byte{0x38, 0x00, 0x06, 0x03, 0xeb}) {
		t.Fatalf("join request %x, %v", join, err)
	}
	confirm, err := DecodeChannelJoinConfirm([]byte{0x3e, 0x00, 0x00, 0x06, 0x03, 0xeb, 0x03, 0xeb})
	if err != nil || confirm != (ChannelJoinConfirm{UserChannel: 1007, Requested: 1003, ChannelID: 1003}) {
		t.Fatalf("join confirm %+v, %v", confirm, err)
	}
	if _, err := EncodeChannelJoinRequest(1000, 1003); !errors.Is(err, ErrMCS) {
		t.Fatal("user channel below 1001 accepted")
	}

	var resultErr *MCSResultError
	// rt-unspecified-failure (14) without initiator: result bits straddle both octets.
	if _, err := DecodeAttachUserConfirm([]byte{0x2d, 0xc0}); !errors.As(err, &resultErr) || resultErr.Result != 14 {
		t.Fatalf("attach failure: %v", err)
	}
	if _, err := DecodeChannelJoinConfirm([]byte{0x3d, 0xc0, 0x00, 0x06, 0x03, 0xeb}); !errors.As(err, &resultErr) {
		t.Fatalf("join failure: %v", err)
	}
	var disconnect *DisconnectError
	if _, err := DecodeAttachUserConfirm([]byte{0x21, 0x80}); !errors.As(err, &disconnect) || disconnect.Reason != 3 {
		t.Fatalf("disconnect: %v", err)
	}
	for name, p := range map[string][]byte{
		"empty":            {},
		"wrong-choice":     {0x38, 0x00, 0x00, 0x06},
		"no-initiator":     {0x2c, 0x00},
		"short":            {0x2e, 0x00, 0x00},
		"long":             {0x2e, 0x00, 0x00, 0x06, 0x00},
		"initiator-range":  {0x2e, 0x00, 0xfc, 0x18},
		"join-no-channel":  {0x3c, 0x00, 0x00, 0x06, 0x03, 0xeb},
		"join-short":       {0x3e, 0x00, 0x00, 0x06, 0x03, 0xeb, 0x03},
		"join-id-mismatch": {0x3e, 0x00, 0x00, 0x06, 0x03, 0xeb, 0x03, 0xec},
	} {
		var err error
		if strings.HasPrefix(name, "join") {
			_, err = DecodeChannelJoinConfirm(p)
		} else {
			_, err = DecodeAttachUserConfirm(p)
		}
		if !errors.Is(err, ErrMCS) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestX224DataWrapper(t *testing.T) {
	if _, err := StripX224Data([]byte{0x02, 0xf0, 0x00, 0x28}); !errors.Is(err, ErrX224) {
		t.Fatal("fragmented data accepted")
	}
	if _, err := StripX224Data([]byte{0x02, 0xe0, 0x80}); !errors.Is(err, ErrX224) {
		t.Fatal("wrong TPDU accepted")
	}
	got, err := StripX224Data(WrapX224Data([]byte{0x28}))
	if err != nil || !bytes.Equal(got, []byte{0x28}) {
		t.Fatalf("roundtrip %x, %v", got, err)
	}
}

func TestBERInteger(t *testing.T) {
	for v, want := range map[uint32][]byte{
		0:          {0x02, 0x01, 0x00},
		34:         {0x02, 0x01, 0x22},
		0x80:       {0x02, 0x01, 0x80},
		1056:       {0x02, 0x02, 0x04, 0x20},
		65535:      {0x02, 0x02, 0xff, 0xff},
		0xffffffff: {0x02, 0x04, 0xff, 0xff, 0xff, 0xff},
	} {
		got := berInt(v)
		if !bytes.Equal(got, want) {
			t.Errorf("berInt(%d) = %x, want %x", v, got, want)
		}
		back, rest, err := berReadUint(got, berInteger)
		if err != nil || back != v || len(rest) != 0 {
			t.Errorf("roundtrip %d: %d, %v", v, back, err)
		}
	}
	// Sign-padded form from the MS-RDPBCGR 4.1.4 server dump (65528).
	if v, _, err := berReadUint([]byte{0x02, 0x03, 0x00, 0xff, 0xf8}, berInteger); err != nil || v != 65528 {
		t.Fatalf("sign-padded integer: %d, %v", v, err)
	}
	if _, _, err := berReadUint([]byte{0x02, 0x05, 0x01, 0, 0, 0, 0}, berInteger); !errors.Is(err, ErrBER) {
		t.Fatal("oversized integer accepted")
	}
}

func TestPERLength(t *testing.T) {
	for n, want := range map[int][]byte{0: {0}, 0x7f: {0x7f}, 0x80: {0x80, 0x80}, 298: {0x81, 0x2a}, 0x3fff: {0xbf, 0xff}} {
		got, err := perLength(n)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("perLength(%d) = %x, %v", n, got, err)
		}
		back, rest, err := perReadLength(got)
		if err != nil || back != n || len(rest) != 0 {
			t.Errorf("roundtrip %d: %d, %v", n, back, err)
		}
	}
	if _, err := perLength(0x4000); !errors.Is(err, ErrPER) {
		t.Fatal("fragmented length produced")
	}
	for _, p := range [][]byte{{}, {0x80}, {0xc1}} {
		if _, _, err := perReadLength(p); !errors.Is(err, ErrPER) {
			t.Errorf("%x accepted", p)
		}
	}
}

func FuzzDecodeConnectResponse(f *testing.F) {
	f.Add(func() []byte { b, _ := hex.DecodeString("7f6682014500"); return b }())
	f.Fuzz(func(t *testing.T, data []byte) {
		cr, err := DecodeConnectResponse(data)
		if err != nil {
			return
		}
		if blocks, err := ParseConferenceCreateResponse(cr.UserData); err == nil {
			if parsed, err := ParseUserDataBlocks(blocks); err == nil {
				for _, b := range parsed {
					switch b.Type {
					case SCCore:
						_, _ = DecodeServerCoreData(b.Payload)
					case SCSecurity:
						_, _ = DecodeServerSecurityData(b.Payload)
					case SCNet:
						_, _ = DecodeServerNetworkData(b.Payload)
					}
				}
			}
		}
	})
}

func FuzzDomainPDUs(f *testing.F) {
	f.Add([]byte{0x2e, 0x00, 0x00, 0x06})
	f.Add([]byte{0x3e, 0x00, 0x00, 0x06, 0x03, 0xeb, 0x03, 0xeb})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeAttachUserConfirm(data)
		_, _ = DecodeChannelJoinConfirm(data)
	})
}
