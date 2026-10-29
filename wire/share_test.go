package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadHex reads a whitespace-separated hex dump from testdata. The files hold
// the plaintext PDU bodies of the annotated samples in MS-RDPBCGR section 4
// and MS-RDPELE section 4.
func loadHex(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MS-RDPBCGR 4.1.12 Server Demand Active PDU (decrypted body).
func TestDecodeDemandActiveSample(t *testing.T) {
	pdu := loadHex(t, "bcgr-4.1.12-demand-active-plain.hex")
	d, err := DecodeDemandActive(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if d.Control.PDUSource != ServerChannelID || d.ShareID != 0x000103ea {
		t.Fatalf("source %#x shareID %#x", d.Control.PDUSource, d.ShareID)
	}
	if string(d.SourceDescriptor) != "RDP\x00" {
		t.Fatalf("sourceDescriptor %q", d.SourceDescriptor)
	}
	gen, ok := FindCapability(d.Capabilities, CapsTypeGeneral)
	if !ok {
		t.Fatal("no general capability set")
	}
	g, err := DecodeGeneralCapability(gen)
	if err != nil || g.OSMajorType != OSMajorTypeWindows || g.ProtocolVersion != capsProtocolVersion {
		t.Fatalf("general %+v %v", g, err)
	}
	bmp, ok := FindCapability(d.Capabilities, CapsTypeBitmap)
	if !ok {
		t.Fatal("no bitmap capability set")
	}
	if b, err := DecodeBitmapCapability(bmp); err != nil || b.DesktopWidth == 0 || b.DesktopHeight == 0 {
		t.Fatalf("bitmap %+v %v", b, err)
	}
	share, ok := FindCapability(d.Capabilities, CapsTypeShare)
	if !ok {
		t.Fatal("no share capability set")
	}
	if s, err := DecodeShareCapability(share); err != nil || s.NodeID != ServerChannelID {
		t.Fatalf("share %+v %v", s, err)
	}
	if _, ok := FindCapability(d.Capabilities, CapsTypeOrder); !ok {
		t.Fatal("no order capability set")
	}
}

// MS-RDPBCGR 4.1.13 Client Confirm Active PDU (decrypted body) decodes and
// re-encodes byte for byte.
func TestConfirmActiveSampleRoundTrip(t *testing.T) {
	pdu := loadHex(t, "bcgr-4.1.13-confirm-active-plain.hex")
	c, err := DecodeConfirmActive(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if c.Control.PDUSource != 1007 || c.ShareID != 0x000103ea || c.OriginatorID != ServerChannelID {
		t.Fatalf("header %+v", c)
	}
	if string(c.SourceDescriptor) != "MSTSC\x00" || len(c.Capabilities) != 18 {
		t.Fatalf("source %q, %d capability sets", c.SourceDescriptor, len(c.Capabilities))
	}
	gen, _ := FindCapability(c.Capabilities, CapsTypeGeneral)
	g, err := DecodeGeneralCapability(gen)
	if err != nil || g.OSMajorType != 1 || g.OSMinorType != 3 || g.ExtraFlags != 0x041d {
		t.Fatalf("general %+v %v", g, err)
	}
	bmp, _ := FindCapability(c.Capabilities, CapsTypeBitmap)
	b, err := DecodeBitmapCapability(bmp)
	if err != nil || b.PreferredBitsPerPixel != 24 || b.DesktopWidth != 1280 || b.DesktopHeight != 1024 || b.DesktopResizeFlag != 1 {
		t.Fatalf("bitmap %+v %v", b, err)
	}
	ord, _ := FindCapability(c.Capabilities, CapsTypeOrder)
	o, err := DecodeOrderCapability(ord)
	if err != nil || o.OrderFlags != 0x002a || o.TextFlags != 0x06a1 || o.DesktopSaveSize != 230400 || o.TextANSICodePage != 1252 {
		t.Fatalf("order %+v %v", o, err)
	}
	if o.OrderSupport[0] != 1 || o.OrderSupport[0x1f] != 0 {
		t.Fatalf("orderSupport %v", o.OrderSupport)
	}
	in, _ := FindCapability(c.Capabilities, CapsTypeInput)
	i, err := DecodeInputCapability(in)
	if err != nil || i.InputFlags != 0x0015 || i.KeyboardLayout != 0x409 || i.KeyboardType != 4 || i.KeyboardFunctionKey != 12 {
		t.Fatalf("input %+v %v", i, err)
	}
	if ctl, _ := FindCapability(c.Capabilities, CapsTypeControl); !bytes.Equal(ctl.Data, ControlCapabilitySet().Data) {
		t.Fatalf("control caps % x", ctl.Data)
	}

	again, err := EncodeConfirmActive(c.ShareID, c.Control.PDUSource, "MSTSC", c.Capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, pdu) {
		t.Fatalf("re-encoded confirm active differs:\n% x\n% x", again, pdu)
	}
}

func TestDefaultClientCapabilitiesEncodeAndDecode(t *testing.T) {
	sets := DefaultClientCapabilities(ClientCapabilityOptions{
		DesktopWidth: 1024, DesktopHeight: 768, ColorDepth: 16,
		KeyboardLayout: 0x409, KeyboardType: 4, FunctionKeys: 12,
	})
	pdu, err := EncodeConfirmActive(0x12345678, 1004, "rdpkernel", sets)
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeConfirmActive(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Capabilities) != len(sets) || string(c.SourceDescriptor) != "rdpkernel\x00" {
		t.Fatalf("decoded %+v", c)
	}
	want := map[uint16]int{
		CapsTypeGeneral: 24, CapsTypeBitmap: 28, CapsTypeOrder: 88, CapsTypeBitmapCache: 40,
		CapsTypeColorCache: 8, CapsTypeActivation: 12, CapsTypeControl: 12, CapsTypePointer: 10,
		CapsTypeShare: 8, CapsTypeInput: 88, CapsTypeSound: 8, CapsTypeFont: 8, CapsTypeBrush: 8,
		CapsTypeGlyphCache: 52, CapsTypeOffscreenCache: 12, CapsTypeVirtualChannel: 12,
	}
	for _, s := range c.Capabilities {
		if n, ok := want[s.Type]; !ok || n != len(s.Data)+capabilitySetHeaderLen {
			t.Errorf("capability 0x%04x has length %d", s.Type, len(s.Data)+capabilitySetHeaderLen)
		}
		delete(want, s.Type)
	}
	if len(want) != 0 {
		t.Errorf("missing capability sets %v", want)
	}
	b, _ := DecodeBitmapCapability(sets[1])
	if b.PreferredBitsPerPixel != 16 || b.DesktopWidth != 1024 || b.DesktopHeight != 768 {
		t.Fatalf("bitmap %+v", b)
	}
}

// MS-RDPBCGR 4.1.14 Client Synchronize PDU and 4.1.18 Client Font List PDU.
func TestEncodeFinalizationPDUs(t *testing.T) {
	sync, err := EncodeSynchronize(0x000103ea, 1007, ServerChannelID)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, "16 00 17 00 ef 03 ea 03 01 00 00 01 08 00 1f 00 00 00 01 00 ea 03"); !bytes.Equal(sync, want) {
		t.Fatalf("synchronize\n% x\n% x", sync, want)
	}
	coop, err := EncodeControl(0x000103ea, 1007, CtrlActionCooperate)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, "1a 00 17 00 ef 03 ea 03 01 00 00 01 0c 00 14 00 00 00 04 00 00 00 00 00 00 00"); !bytes.Equal(coop, want) {
		t.Fatalf("control cooperate\n% x\n% x", coop, want)
	}
	fonts, err := EncodeFontList(0x000103ea, 1007)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, "1a 00 17 00 ef 03 ea 03 01 00 00 01 0c 00 27 00 00 00 00 00 00 00 03 00 32 00"); !bytes.Equal(fonts, want) {
		t.Fatalf("font list\n% x\n% x", fonts, want)
	}
}

// MS-RDPBCGR 4.1.21 Server Control PDU - Granted Control and 4.1.22 Server
// Font Map PDU (decrypted bodies; the random pad1 bytes are kept).
func TestDecodeServerFinalizationPDUs(t *testing.T) {
	granted, err := DecodeDataPDU(mustHex(t, "1a 00 17 00 ea 03 ea 03 01 00 b5 02 1a 00 14 00 00 00 02 00 ef 03 ea 03 00 00"))
	if err != nil {
		t.Fatal(err)
	}
	if granted.Control == nil || granted.Control.Action != CtrlActionGrantedControl || granted.Control.GrantID != 1007 || granted.Control.ControlID != uint32(ServerChannelID) {
		t.Fatalf("granted %+v", granted.Control)
	}
	if granted.Header.ShareID != 0x000103ea || granted.Header.StreamID != StreamMed || granted.Header.Control.PDUSource != ServerChannelID {
		t.Fatalf("header %+v", granted.Header)
	}
	fm, err := DecodeDataPDU(mustHex(t, "1a 00 17 00 ea 03 ea 03 01 00 45 02 1a 00 28 00 00 00 00 00 00 00 03 00 04 00"))
	if err != nil {
		t.Fatal(err)
	}
	if fm.FontMap == nil || fm.FontMap.MapFlags != 0x0003 || fm.FontMap.EntrySize != 4 {
		t.Fatalf("font map %+v", fm.FontMap)
	}
	sync, err := DecodeDataPDU(mustHex(t, "16 00 17 00 ea 03 ea 03 01 00 00 02 08 00 1f 00 00 00 01 00 ef 03"))
	if err != nil || sync.Synchronize == nil || sync.Synchronize.TargetUser != 1007 {
		t.Fatalf("synchronize %+v %v", sync.Synchronize, err)
	}
	_, err = DecodeDataPDU(mustHex(t, "16 00 17 00 ea 03 ea 03 01 00 00 02 08 00 2f 00 00 00 05 00 00 00"))
	var ei *ErrorInfo
	if !errors.As(err, &ei) || ei.Code != 5 {
		t.Fatalf("error info: %v", err)
	}
}

func TestShareDecodersRejectMalformed(t *testing.T) {
	good := mustHex(t, "16 00 17 00 ea 03 ea 03 01 00 00 02 08 00 1f 00 00 00 01 00 ef 03")
	cases := map[string][]byte{
		"short":            good[:5],
		"length mismatch":  append([]byte{0x17, 0x00}, good[2:]...),
		"bad version":      append([]byte{0x16, 0x00, 0x07, 0x00}, good[4:]...),
		"compressed":       append(append([]byte{}, good[:15]...), append([]byte{0x20}, good[16:]...)...),
		"truncated header": append([]byte{0x0c, 0x00}, good[2:12]...),
		"not data pdu":     append([]byte{0x16, 0x00, 0x11, 0x00}, good[4:]...),
	}
	for name, pdu := range cases {
		if _, err := DecodeDataPDU(pdu); !errors.Is(err, ErrShare) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	demand := loadHex(t, "bcgr-4.1.12-demand-active-plain.hex")
	bad := append([]byte{}, demand...)
	bad[13] ^= 0x01 // corrupt lengthCombinedCapabilities
	if _, err := DecodeDemandActive(bad); !errors.Is(err, ErrShare) {
		t.Errorf("corrupted demand active: %v", err)
	}
	if _, err := DecodeDemandActive(demand[:len(demand)-1]); !errors.Is(err, ErrShare) {
		t.Errorf("truncated demand active: %v", err)
	}
	if _, err := DecodeConfirmActive(demand); !errors.Is(err, ErrShare) {
		t.Errorf("demand active as confirm active: %v", err)
	}
}

func FuzzDecodeDemandActive(f *testing.F) {
	f.Add(loadHexFuzz(f, "bcgr-4.1.12-demand-active-plain.hex"))
	f.Fuzz(func(t *testing.T, p []byte) {
		d, err := DecodeDemandActive(p)
		if err != nil {
			return
		}
		again, err := EncodeConfirmActive(d.ShareID, 1004, "x", d.Capabilities)
		if err != nil {
			return
		}
		if _, err := DecodeConfirmActive(again); err != nil {
			t.Fatalf("round trip: %v", err)
		}
	})
}

func FuzzDecodeDataPDU(f *testing.F) {
	f.Add([]byte("\x1a\x00\x17\x00\xea\x03\xea\x03\x01\x00\x45\x02\x1a\x00\x28\x00\x00\x00\x00\x00\x00\x00\x03\x00\x04\x00"))
	f.Fuzz(func(t *testing.T, p []byte) {
		_, _ = DecodeDataPDU(p)
	})
}

func loadHexFuzz(f *testing.F, name string) []byte {
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.Fatal(err)
	}
	b, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		f.Fatal(err)
	}
	return b
}
