package wire

import (
	"bytes"
	"errors"
	"testing"
)

// Envelope bytes from MS-RDPBCGR 4.1.10 (client, user 1007 -> I/O channel
// 1003, 412-byte payload) and 4.1.11 (server -> client, 20-byte payload).
func TestSendDataEnvelopes(t *testing.T) {
	payload := make([]byte, 0x19c)
	req, err := EncodeSendDataRequest(1007, 1003, payload)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x81, 0x9c}; !bytes.Equal(req[:8], want) {
		t.Fatalf("request header % x", req[:8])
	}
	if len(req) != 8+len(payload) {
		t.Fatalf("request length %d", len(req))
	}
	got, err := DecodeSendDataRequest(req)
	if err != nil || got.UserChannel != 1007 || got.ChannelID != 1003 || len(got.Data) != len(payload) {
		t.Fatalf("decode request: %+v %v", got, err)
	}

	small := []byte("\xff\x03\x10\x00\x07\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00")
	ind, err := EncodeSendDataIndication(1002, 1003, small)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x68, 0x00, 0x01, 0x03, 0xeb, 0x70, 0x10}; !bytes.Equal(ind[:7], want) {
		t.Fatalf("indication header % x", ind[:7])
	}
	sd, err := DecodeSendDataIndication(ind)
	if err != nil || sd.UserChannel != 1002 || sd.ChannelID != 1003 || !bytes.Equal(sd.Data, small) {
		t.Fatalf("decode indication: %+v %v", sd, err)
	}
	if _, err := DecodeSendDataRequest(ind); !errors.Is(err, ErrMCS) {
		t.Fatalf("indication as request: %v", err)
	}
}

func TestSendDataRejects(t *testing.T) {
	if _, err := EncodeSendDataRequest(1000, 1003, nil); !errors.Is(err, ErrMCS) {
		t.Fatalf("user channel below 1001: %v", err)
	}
	if _, err := EncodeSendDataRequest(1004, 1003, make([]byte, MaxSendDataPayload+1)); !errors.Is(err, ErrMCS) {
		t.Fatalf("oversized payload: %v", err)
	}
	cases := map[string][]byte{
		"short":            {0x68, 0x00, 0x01, 0x03, 0xeb, 0x70},
		"segmented":        {0x68, 0x00, 0x01, 0x03, 0xeb, 0x50, 0x01, 0xaa},
		"length too long":  {0x68, 0x00, 0x01, 0x03, 0xeb, 0x70, 0x05, 0xaa},
		"length too short": {0x68, 0x00, 0x01, 0x03, 0xeb, 0x70, 0x01, 0xaa, 0xbb},
		"fragmented":       {0x68, 0x00, 0x01, 0x03, 0xeb, 0x70, 0xc1},
		"wrong choice":     {0x64, 0x00, 0x01, 0x03, 0xeb, 0x70, 0x00},
	}
	for name, p := range cases {
		if _, err := DecodeSendDataIndication(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var de *DisconnectError
	if _, err := DecodeSendDataIndication([]byte{0x21, 0x80}); !errors.As(err, &de) || de.Reason != 3 {
		t.Fatalf("disconnect ultimatum: %v", err)
	}
}

func TestBasicSecurityHeader(t *testing.T) {
	pdu := EncodeBasicSecurityHeader(SecInfoPkt, []byte{1, 2})
	if !bytes.Equal(pdu, []byte{0x40, 0x00, 0x00, 0x00, 1, 2}) {
		t.Fatalf("% x", pdu)
	}
	h, body, err := DecodeBasicSecurityHeader([]byte{0x80, 0x02, 0x00, 0x00, 0xff})
	if err != nil || h.Flags != SecLicensePkt|SecLicenseEncryptSC || !bytes.Equal(body, []byte{0xff}) {
		t.Fatalf("%+v % x %v", h, body, err)
	}
	if _, _, err := DecodeBasicSecurityHeader([]byte{0x48, 0x00, 0x00, 0x00}); !errors.Is(err, ErrSecurity) {
		t.Fatalf("SEC_ENCRYPT accepted: %v", err)
	}
	if _, _, err := DecodeBasicSecurityHeader([]byte{0x40}); !errors.Is(err, ErrSecurity) {
		t.Fatalf("short header: %v", err)
	}
}

func FuzzDecodeSendDataIndication(f *testing.F) {
	f.Add([]byte{0x68, 0x00, 0x01, 0x03, 0xeb, 0x70, 0x02, 0xaa, 0xbb})
	f.Fuzz(func(t *testing.T, p []byte) {
		sd, err := DecodeSendDataIndication(p)
		if err != nil {
			return
		}
		again, err := EncodeSendDataIndication(sd.UserChannel, sd.ChannelID, sd.Data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeSendDataIndication(again); err != nil {
			t.Fatal(err)
		}
	})
}
