package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestUserDataBlocks(t *testing.T) {
	block, err := UserDataBlock{Type: CSSecurity, Payload: []byte{1, 2, 3, 4}}.Encode()
	if err != nil || !bytes.Equal(block, []byte{0x02, 0xc0, 0x08, 0x00, 1, 2, 3, 4}) {
		t.Fatalf("%x, %v", block, err)
	}
	blocks, err := ParseUserDataBlocks(append(append([]byte{}, block...), block...))
	if err != nil || len(blocks) != 2 || blocks[1].Type != CSSecurity || !bytes.Equal(blocks[1].Payload, []byte{1, 2, 3, 4}) {
		t.Fatalf("%v, %v", blocks, err)
	}
	for name, p := range map[string][]byte{
		"short-header": {0x02, 0xc0, 0x08},
		"tiny-length":  {0x02, 0xc0, 0x03, 0x00},
		"over-length":  {0x02, 0xc0, 0x09, 0x00, 1, 2, 3, 4},
	} {
		if _, err := ParseUserDataBlocks(p); !errors.Is(err, ErrGCC) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (UserDataBlock{Payload: make([]byte, 0xfffd)}).Encode(); !errors.Is(err, ErrGCC) {
		t.Fatal("oversized block accepted")
	}
}

func TestClientBlocksRejectInvalidStrings(t *testing.T) {
	if _, err := (ClientCoreData{ClientName: strings.Repeat("x", 16)}).Encode(); !errors.Is(err, ErrGCC) {
		t.Fatal("16-char client name accepted")
	}
	if _, err := (ClientCoreData{ClientName: strings.Repeat("x", 15), ClientDigProductID: strings.Repeat("y", 31)}).Encode(); err != nil {
		t.Fatal(err)
	}
	if _, err := (ClientCoreData{ClientDigProductID: strings.Repeat("y", 32)}).Encode(); !errors.Is(err, ErrGCC) {
		t.Fatal("32-char product id accepted")
	}
	if _, err := (ClientNetworkData{Channels: []ChannelDef{{Name: "toolong1"}}}).Encode(); !errors.Is(err, ErrGCC) {
		t.Fatal("8-char channel name accepted")
	}
	if _, err := (ClientNetworkData{Channels: []ChannelDef{{Name: "a b"}}}).Encode(); !errors.Is(err, ErrGCC) {
		t.Fatal("channel name with space accepted")
	}
	if _, err := (ClientNetworkData{Channels: make([]ChannelDef, 32)}).Encode(); !errors.Is(err, ErrGCC) {
		t.Fatal("32 channels accepted")
	}
	empty, err := ClientNetworkData{}.Encode()
	if err != nil || !bytes.Equal(empty, []byte{0x03, 0xc0, 0x08, 0x00, 0, 0, 0, 0}) {
		t.Fatalf("empty network data %x, %v", empty, err)
	}
}

func TestConferenceCreateResponseParsing(t *testing.T) {
	good := []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x2a, 0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x00, 'M', 'c', 'D', 'n', 0x02, 0xaa, 0xbb}
	value, err := ParseConferenceCreateResponse(good)
	if err != nil || !bytes.Equal(value, []byte{0xaa, 0xbb}) {
		t.Fatalf("%x, %v", value, err)
	}
	// Two user data sets: an unknown key first, then McDn.
	two := []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x2a, 0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x02,
		0xc0, 0x00, 'X', 'X', 'X', 'X', 0x01, 0x11,
		0xc0, 0x00, 'M', 'c', 'D', 'n', 0x01, 0x22}
	if value, err = ParseConferenceCreateResponse(two); err != nil || !bytes.Equal(value, []byte{0x22}) {
		t.Fatalf("two sets: %x, %v", value, err)
	}
	mutate := func(i int, b byte) []byte {
		p := append([]byte{}, good...)
		p[i] = b
		return p
	}
	for name, p := range map[string][]byte{
		"bad-oid":        mutate(3, 0x15),
		"not-response":   mutate(8, 0x00),
		"result-failure": mutate(13, 0x10),
		"no-sets":        mutate(14, 0x00),
		"key-missing":    mutate(15, 0x00),
		"other-key":      mutate(17, 'X'),
		"value-overrun":  mutate(21, 0x03),
		"truncated":      good[:12],
		"empty":          {},
	} {
		if _, err := ParseConferenceCreateResponse(p); !errors.Is(err, ErrGCC) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestServerBlockDecoders(t *testing.T) {
	core, err := DecodeServerCoreData([]byte{0x04, 0x00, 0x08, 0x00})
	if err != nil || core.Version != 0x00080004 || core.HasRequestedProtocols {
		t.Fatalf("minimal core %+v, %v", core, err)
	}
	core, err = DecodeServerCoreData([]byte{0x04, 0x00, 0x08, 0x00, 0x01, 0, 0, 0, 0x02, 0, 0, 0})
	if err != nil || core.ClientRequestedProtocols != ProtocolSSL || !core.HasEarlyCapabilityFlags || core.EarlyCapabilityFlags != 2 {
		t.Fatalf("full core %+v, %v", core, err)
	}
	if _, err := DecodeServerCoreData([]byte{1, 2, 3}); !errors.Is(err, ErrGCC) {
		t.Fatal("short core accepted")
	}

	sec, err := DecodeServerSecurityData(make([]byte, 8))
	if err != nil || sec.EncryptionMethod != 0 || sec.ServerRandom != nil {
		t.Fatalf("tls security %+v, %v", sec, err)
	}
	for name, p := range map[string][]byte{
		"short":           make([]byte, 7),
		"none-with-extra": make([]byte, 12),
		"enc-no-lengths":  {2, 0, 0, 0, 2, 0, 0, 0, 1, 0},
		"enc-bad-lengths": {2, 0, 0, 0, 2, 0, 0, 0, 0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff},
		"enc-short-data":  append([]byte{2, 0, 0, 0, 2, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 31)...),
	} {
		if _, err := DecodeServerSecurityData(p); !errors.Is(err, ErrGCC) {
			t.Errorf("%s: %v", name, err)
		}
	}
	enc := append([]byte{2, 0, 0, 0, 2, 0, 0, 0, 0x02, 0, 0, 0, 0x01, 0, 0, 0}, 0xaa, 0xbb, 0xcc)
	sec, err = DecodeServerSecurityData(enc)
	if err != nil || !bytes.Equal(sec.ServerRandom, []byte{0xaa, 0xbb}) || !bytes.Equal(sec.ServerCertificate, []byte{0xcc}) {
		t.Fatalf("encrypted security %+v, %v", sec, err)
	}

	network, err := DecodeServerNetworkData([]byte{0xeb, 0x03, 0x00, 0x00})
	if err != nil || network.IOChannel != 1003 || len(network.ChannelIDs) != 0 {
		t.Fatalf("no channels %+v, %v", network, err)
	}
	network, err = DecodeServerNetworkData([]byte{0xeb, 0x03, 0x02, 0x00, 0xec, 0x03, 0xed, 0x03})
	if err != nil || len(network.ChannelIDs) != 2 {
		t.Fatalf("even channels %+v, %v", network, err)
	}
	for name, p := range map[string][]byte{
		"short":       {0xeb, 0x03, 0x00},
		"count-over":  {0xeb, 0x03, 0x05, 0x00, 0xec, 0x03},
		"odd-no-pad":  {0xeb, 0x03, 0x01, 0x00, 0xec, 0x03, 0x00, 0x00, 0x00, 0x00},
		"even-padded": {0xeb, 0x03, 0x02, 0x00, 0xec, 0x03, 0xed, 0x03, 0x00, 0x00},
	} {
		if _, err := DecodeServerNetworkData(p); !errors.Is(err, ErrGCC) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
