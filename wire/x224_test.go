package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Test vectors are the annotated dumps from MS-RDPBCGR section 4.1.1 and 4.1.2,
// with the TPKT header removed.
var (
	msClientCR = []byte{
		0x27, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
		'C', 'o', 'o', 'k', 'i', 'e', ':', ' ', 'm', 's', 't', 's', 'h', 'a', 's', 'h', '=', 'e', 'l', 't', 'o', 'n', 's', 0x0d, 0x0a,
		0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	msServerCC = []byte{0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
)

func TestConnectionRequestMatchesMicrosoftDump(t *testing.T) {
	got, err := ConnectionRequest{Cookie: "Cookie: mstshash=eltons", RequestedProtocols: ProtocolRDP}.Encode()
	if err != nil || !bytes.Equal(got, msClientCR) {
		t.Fatalf("got %x, err %v", got, err)
	}
	got, err = ConnectionRequest{RequestedProtocols: ProtocolSSL}.Encode()
	want := []byte{0x0e, 0xe0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00}
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %x, err %v", got, err)
	}
	packet, _ := EncodeTPKT(got)
	if len(packet) != 19 {
		t.Fatalf("TLS-only request TPKT size %d", len(packet))
	}
}

func TestConnectionRequestRejectsBadCookie(t *testing.T) {
	for _, cookie := range []string{"a\r\nb", "x\x00", "é", strings.Repeat("c", 300)} {
		if _, err := (ConnectionRequest{Cookie: cookie}).Encode(); !errors.Is(err, ErrX224) {
			t.Fatalf("cookie %q: %v", cookie, err)
		}
	}
	if _, err := (ConnectionRequest{Cookie: strings.Repeat("c", 238)}).Encode(); err != nil {
		t.Fatalf("maximum cookie: %v", err)
	}
	if _, err := (ConnectionRequest{Cookie: strings.Repeat("c", 239)}).Encode(); !errors.Is(err, ErrX224) {
		t.Fatalf("over-long cookie accepted: %v", err)
	}
}

func TestDecodeConnectionConfirm(t *testing.T) {
	cc, err := DecodeConnectionConfirm(msServerCC)
	if err != nil || !cc.HasNegotiation || cc.SelectedProtocol != ProtocolRDP || cc.Flags != 0 {
		t.Fatalf("microsoft dump: %+v, %v", cc, err)
	}
	tls := []byte{0x0e, 0xd0, 0, 0, 0, 0, 0, 0x02, 0x03, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00}
	cc, err = DecodeConnectionConfirm(tls)
	if err != nil || cc.SelectedProtocol != ProtocolSSL || cc.Flags != 0x03 {
		t.Fatalf("tls: %+v, %v", cc, err)
	}
	legacyLI := append([]byte{0x06}, tls[1:]...)
	if cc2, err := DecodeConnectionConfirm(legacyLI); err != nil || cc2 != cc {
		t.Fatalf("LI=6 shape: %+v, %v", cc2, err)
	}
	cc, err = DecodeConnectionConfirm([]byte{0x06, 0xd0, 0, 0, 0, 0, 0})
	if err != nil || cc.HasNegotiation {
		t.Fatalf("no negotiation: %+v, %v", cc, err)
	}
	var failure *NegotiationFailure
	_, err = DecodeConnectionConfirm([]byte{0x0e, 0xd0, 0, 0, 0, 0, 0, 0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00})
	if !errors.As(err, &failure) || failure.Code != FailureHybridRequiredByServer || !strings.Contains(err.Error(), "HYBRID_REQUIRED_BY_SERVER") {
		t.Fatalf("failure: %v", err)
	}
	if errors.Is(err, ErrX224) {
		t.Fatal("negotiation failure must not be reported as malformed input")
	}
}

func TestDecodeConnectionConfirmRejectsMalformed(t *testing.T) {
	for name, data := range map[string][]byte{
		"short":            {0x05, 0xd0, 0, 0, 0, 0},
		"li-mismatch":      {0x0d, 0xd0, 0, 0, 0, 0, 0, 0x02, 0, 0x08, 0, 1, 0, 0, 0},
		"li-too-large":     {0x20, 0xd0, 0, 0, 0, 0, 0, 0x02, 0, 0x08, 0, 1, 0, 0, 0},
		"wrong-tpdu":       {0x0e, 0xe0, 0, 0, 0, 0, 0, 0x02, 0, 0x08, 0, 1, 0, 0, 0},
		"class-option":     {0x0e, 0xd0, 0, 0, 0, 0, 0x02, 0x02, 0, 0x08, 0, 1, 0, 0, 0},
		"neg-too-short":    {0x0a, 0xd0, 0, 0, 0, 0, 0, 0x02, 0, 0x08, 0},
		"neg-length-field": {0x0e, 0xd0, 0, 0, 0, 0, 0, 0x02, 0, 0x09, 0, 1, 0, 0, 0},
		"neg-type":         {0x0e, 0xd0, 0, 0, 0, 0, 0, 0x01, 0, 0x08, 0, 1, 0, 0, 0},
		"neg-trailing":     {0x0f, 0xd0, 0, 0, 0, 0, 0, 0x02, 0, 0x08, 0, 1, 0, 0, 0, 0},
	} {
		if _, err := DecodeConnectionConfirm(data); !errors.Is(err, ErrX224) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestStrings(t *testing.T) {
	if ProtocolString(ProtocolSSL) != "PROTOCOL_SSL" || !strings.Contains(ProtocolString(0x80), "unknown") {
		t.Fatal("protocol strings")
	}
	if FailureCodeString(FailureSSLRequiredByServer) != "SSL_REQUIRED_BY_SERVER" || !strings.Contains(FailureCodeString(0x99), "unknown") {
		t.Fatal("failure strings")
	}
}

func FuzzDecodeConnectionConfirm(f *testing.F) {
	f.Add(msServerCC)
	f.Add([]byte{0x06, 0xd0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		cc, err := DecodeConnectionConfirm(data)
		var failure *NegotiationFailure
		switch {
		case err == nil:
			if cc.HasNegotiation && len(data) != x224FixedPartSize+negotiationStructureSize {
				t.Fatalf("negotiation accepted from %d bytes", len(data))
			}
		case errors.As(err, &failure), errors.Is(err, ErrX224):
		default:
			t.Fatalf("unclassified error %v", err)
		}
	})
}
