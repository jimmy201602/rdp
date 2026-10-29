package wire

import (
	"bytes"
	"strings"
	"testing"
)

func TestConnectionRequestRoundTrip(t *testing.T) {
	cr, hasNeg, err := DecodeConnectionRequest(msClientCR)
	if err != nil || !hasNeg || cr.Cookie != "Cookie: mstshash=eltons" || cr.RequestedProtocols != ProtocolRDP {
		t.Fatalf("got %+v %v %v", cr, hasNeg, err)
	}
	enc, _ := ConnectionRequest{RequestedProtocols: ProtocolSSL | ProtocolHybrid}.Encode()
	cr, hasNeg, err = DecodeConnectionRequest(enc)
	if err != nil || !hasNeg || cr.Cookie != "" || cr.RequestedProtocols != ProtocolSSL|ProtocolHybrid {
		t.Fatalf("got %+v %v %v", cr, hasNeg, err)
	}
	// Legacy request without RDP_NEG_REQ.
	legacy := []byte{0x06, 0xe0, 0, 0, 0, 0, 0}
	if _, hasNeg, err = DecodeConnectionRequest(legacy); err != nil || hasNeg {
		t.Fatalf("legacy: %v %v", hasNeg, err)
	}
	for _, bad := range [][]byte{
		{0x05, 0xe0, 0, 0, 0, 0},
		{0x07, 0xe0, 0, 0, 0, 0, 0},
		{0x06, 0xd0, 0, 0, 0, 0, 0},
		{0x0e, 0xe0, 0, 0, 0, 0, 0, 0x02, 0, 8, 0, 1, 0, 0, 0},
		{0x0d, 0xe0, 0, 0, 0, 0, 0, 0x01, 0, 8, 0, 1, 0, 0},
		append([]byte{0x09, 0xe0, 0, 0, 0, 0, 0}, 0x01, 0x0d, 0x0a),
	} {
		if _, _, err := DecodeConnectionRequest(bad); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
}

func TestConnectionConfirmEncoders(t *testing.T) {
	cc, err := DecodeConnectionConfirm(EncodeConnectionConfirm(0, ProtocolSSL))
	if err != nil || !cc.HasNegotiation || cc.SelectedProtocol != ProtocolSSL {
		t.Fatalf("confirm %+v %v", cc, err)
	}
	if _, err := DecodeConnectionConfirm(EncodeNegotiationFailure(FailureSSLRequiredByServer)); err == nil {
		t.Fatal("negotiation failure must decode as an error")
	}
}

func TestConnectInitialDecodeAndResponseEncode(t *testing.T) {
	packet := dump(t, msConnectInitialDump)
	mcs, err := StripX224Data(packet[TPKTHeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	ci, err := DecodeConnectInitial(mcs)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Target.MaxChannelIDs != 34 || ci.Maximum.MaxMCSPDUSize != 65535 {
		t.Fatalf("params %+v", ci)
	}
	blocks, err := ParseConferenceCreateRequest(ci.UserData)
	if err != nil {
		t.Fatal(err)
	}
	uds, err := ParseUserDataBlocks(blocks)
	if err != nil || len(uds) < 3 {
		t.Fatalf("blocks %v %v", uds, err)
	}
	core, err := DecodeClientCoreData(uds[0].Payload)
	if err != nil || core.Version != 0x00080004 || core.DesktopWidth != 1280 || core.ClientName != "ELTONS-DEV2" || core.ClientProductID != 1 {
		t.Fatalf("core %+v %v", core, err)
	}
	byType := map[uint16][]byte{}
	for _, b := range uds {
		byType[b.Type] = b.Payload
	}
	if sec, err := DecodeClientSecurityData(byType[CSSecurity]); err != nil || sec.EncryptionMethods != 0x1b {
		t.Fatalf("security %+v %v", sec, err)
	}
	net, err := DecodeClientNetworkData(byType[CSNet])
	if err != nil || len(net.Channels) != 3 || net.Channels[0].Name != "rdpdr" {
		t.Fatalf("net %+v %v", net, err)
	}
	// Re-encoding the Microsoft Connect-Response must reproduce the dump.
	resp := dump(t, msConnectResponseDump)
	respMCS, _ := StripX224Data(resp[TPKTHeaderSize:])
	cr, err := DecodeConnectResponse(respMCS)
	if err != nil {
		t.Fatal(err)
	}
	if got := EncodeConnectResponse(cr.DomainParameters, cr.UserData); !bytes.Equal(got, respMCS) {
		t.Fatalf("connect response mismatch\n got %x\nwant %x", got, respMCS)
	}
	// Our own encode -> decode of the Enhanced-security response.
	sc, _ := ServerCoreData{Version: 0x00080004, ClientRequestedProtocols: ProtocolSSL, HasRequestedProtocols: true}.Encode()
	sn, _ := ServerNetworkData{IOChannel: 1003, ChannelIDs: []uint16{1004}}.Encode()
	ss, _ := ServerSecurityData{}.Encode()
	ccr, err := EncodeConferenceCreateResponse(append(append(sc, sn...), ss...))
	if err != nil {
		t.Fatal(err)
	}
	cr2, err := DecodeConnectResponse(EncodeConnectResponse(ServerDomainParameters, ccr))
	if err != nil || cr2.DomainParameters != ServerDomainParameters {
		t.Fatalf("%+v %v", cr2, err)
	}
	inner, err := ParseConferenceCreateResponse(cr2.UserData)
	if err != nil {
		t.Fatal(err)
	}
	ub, err := ParseUserDataBlocks(inner)
	if err != nil || len(ub) != 3 {
		t.Fatalf("%v %v", ub, err)
	}
	c2, err := DecodeServerCoreData(ub[0].Payload)
	if err != nil || c2.ClientRequestedProtocols != ProtocolSSL || !c2.HasRequestedProtocols || c2.HasEarlyCapabilityFlags {
		t.Fatalf("%+v %v", c2, err)
	}
	n2, err := DecodeServerNetworkData(ub[1].Payload)
	if err != nil || n2.IOChannel != 1003 || len(n2.ChannelIDs) != 1 || n2.ChannelIDs[0] != 1004 {
		t.Fatalf("%+v %v", n2, err)
	}
	s2, err := DecodeServerSecurityData(ub[2].Payload)
	if err != nil || s2.EncryptionLevel != 0 || s2.EncryptionMethod != 0 {
		t.Fatalf("%+v %v", s2, err)
	}
	if _, err := (ServerSecurityData{EncryptionMethod: 2}).Encode(); err == nil {
		t.Fatal("standard security encode must fail")
	}
	for _, bad := range [][]byte{mcs[:len(mcs)-1], append(append([]byte{}, mcs...), 0), {0x7f, 0x66, 0}} {
		if _, err := DecodeConnectInitial(bad); err == nil {
			t.Errorf("accepted %x", bad[:min(8, len(bad))])
		}
	}
}

func TestServerDomainPDUs(t *testing.T) {
	if err := DecodeErectDomainRequest(EncodeErectDomainRequest()); err != nil {
		t.Fatal(err)
	}
	if err := DecodeAttachUserRequest(EncodeAttachUserRequest()); err != nil {
		t.Fatal(err)
	}
	auc, err := EncodeAttachUserConfirm(1007)
	if err != nil {
		t.Fatal(err)
	}
	if user, err := DecodeAttachUserConfirm(auc); err != nil || user != 1007 {
		t.Fatalf("%d %v", user, err)
	}
	if _, err := DecodeAttachUserConfirm(EncodeAttachUserFailure(1)); err == nil {
		t.Fatal("failure accepted")
	}
	cjr, _ := EncodeChannelJoinRequest(1007, 1003)
	req, err := DecodeChannelJoinRequest(cjr)
	if err != nil || req.UserChannel != 1007 || req.ChannelID != 1003 {
		t.Fatalf("%+v %v", req, err)
	}
	cjc, _ := EncodeChannelJoinConfirm(1007, 1003)
	c, err := DecodeChannelJoinConfirm(cjc)
	if err != nil || c.ChannelID != 1003 || c.Requested != 1003 || c.UserChannel != 1007 {
		t.Fatalf("%+v %v", c, err)
	}
	fail, _ := EncodeChannelJoinFailure(2, 1007, 1003)
	if _, err := DecodeChannelJoinConfirm(fail); err == nil {
		t.Fatal("join failure accepted")
	}
	dpu := EncodeDisconnectProviderUltimatum(DisconnectReasonUserRequested)
	if r, ok := IsDisconnectProviderUltimatum(dpu); !ok || r != DisconnectReasonUserRequested {
		t.Fatalf("%d %v", r, ok)
	}
	if _, ok := IsDisconnectProviderUltimatum(cjc); ok {
		t.Fatal("confirm detected as DPU")
	}
	for _, bad := range [][]byte{{0x28}, {0x28, 0, 0, 6, 0}, {0x38, 0, 0, 3}, {0x04}, {0x38, 0xff, 0xff, 3, 0xea}} {
		if _, err := DecodeChannelJoinRequest(bad); err == nil {
			t.Errorf("join request accepted %x", bad)
		}
	}
	for _, bad := range [][]byte{{0x28, 0}, {0x38}, {0x04}, {}} {
		if err := DecodeAttachUserRequest(bad); err == nil {
			t.Errorf("attach user accepted %x", bad)
		}
	}
}

func TestClientInfoRoundTrip(t *testing.T) {
	in := ClientInfo{
		Domain: "dom", UserName: "alice", Password: "s3cret", AlternateShell: "", WorkingDir: "",
		Flags:               InfoAutoLogon | InfoMouse | InfoDisableCtrlAltDel,
		ClientAddressFamily: AddressFamilyINet, ClientAddress: "10.0.0.2", ClientDir: `C:\x`,
		PerformanceFlags: PerfDisableWallpaper,
	}
	pdu, err := EncodeClientInfoPDU(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeClientInfoPDU(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if out.Domain != "dom" || out.UserName != "alice" || out.Password != "s3cret" || out.Flags&InfoAutoLogon == 0 ||
		out.ClientAddress != "10.0.0.2" || out.ClientDir != `C:\x` || out.PerformanceFlags != PerfDisableWallpaper || out.ClientAddressFamily != AddressFamilyINet {
		t.Fatalf("decoded %+v", out)
	}
	// Minimal packet without extended info, ANSI strings.
	ansi := []byte{0, 0, 0, 0, 0x23, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 'b', 'o', 'b', 0, 0, 0, 0}
	ci, err := DecodeClientInfo(ansi)
	if err != nil || ci.UserName != "bob" || ci.Domain != "" {
		t.Fatalf("%+v %v", ci, err)
	}
	// Non-info security header must be refused.
	if _, err := DecodeClientInfoPDU(EncodeBasicSecurityHeader(SecLicensePkt, pdu[4:])); err == nil {
		t.Fatal("license header accepted as info")
	}
	for _, bad := range [][]byte{pdu[4:20], pdu[4:30], ansi[:len(ansi)-1],
		{0, 0, 0, 0, 0x33, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0}} {
		if _, err := DecodeClientInfo(bad); err == nil {
			t.Errorf("accepted %d-byte packet", len(bad))
		}
	}
}

func TestDemandActiveRoundTrip(t *testing.T) {
	sets := DefaultClientCapabilities(ClientCapabilityOptions{})
	pdu, err := EncodeDemandActive(0x000103ea, "RDP", sets)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeDemandActive(pdu)
	if err != nil || d.ShareID != 0x000103ea || string(d.SourceDescriptor) != "RDP\x00" || len(d.Capabilities) != len(sets) || d.Control.PDUSource != ServerChannelID {
		t.Fatalf("%+v %v", d, err)
	}
	sample := loadHex(t, "bcgr-4.1.12-demand-active-plain.hex")
	sd, err := DecodeDemandActive(sample)
	if err != nil {
		t.Fatal(err)
	}
	re, err := EncodeDemandActive(sd.ShareID, strings.TrimRight(string(sd.SourceDescriptor), "\x00"), sd.Capabilities)
	if err != nil || !bytes.Equal(re, sample) {
		t.Fatalf("re-encoded demand active differs (%v)\n got %x\nwant %x", err, re, sample)
	}
	da, err := EncodeDeactivateAll(7, "RDP")
	if err != nil {
		t.Fatal(err)
	}
	if hdr, _, err := DecodeShareControl(da); err != nil || hdr.PDUType != PDUTypeDeactivateAll {
		t.Fatalf("%+v %v", hdr, err)
	}
	fm, _ := EncodeFontMap(7)
	dp, err := DecodeDataPDU(fm)
	if err != nil || dp.FontMap == nil || dp.Header.PDUType2 != PDUType2FontMap {
		t.Fatalf("%+v %v", dp, err)
	}
	ei, _ := EncodeErrorInfo(7, ErrInfoServerDeniedConnection)
	if _, err = DecodeDataPDU(ei); err == nil || !strings.Contains(err.Error(), "0x00000007") {
		t.Fatalf("error info: %v", err)
	}
	fl, _ := EncodeFontList(7, 1007)
	_, list, ok, err := DecodeClientDataPDU(fl)
	if err != nil || !ok || list.EntrySize != 0x32 {
		t.Fatalf("%+v %v %v", list, ok, err)
	}
}

func TestBitmapAndPointerEncoders(t *testing.T) {
	px := make([]byte, 4*2*3)
	for i := range px {
		px[i] = byte(i)
	}
	bd, err := NewBitmapData(10, 20, 4, 2, 24, false, px)
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeBitmapUpdate([]BitmapData{bd})
	if err != nil {
		t.Fatal(err)
	}
	u, err := DecodeUpdate(body)
	if err != nil || u.Type != UpdateTypeBitmap || len(u.Bitmaps) != 1 {
		t.Fatalf("%+v %v", u, err)
	}
	got := u.Bitmaps[0]
	if got.DestLeft != 10 || got.DestTop != 20 || got.DestRight != 13 || got.DestBottom != 21 || got.Width != 4 || got.Height != 2 || got.BitsPerPixel != 24 || got.Compressed || !bytes.Equal(got.Data(), px) {
		t.Fatalf("%+v", got)
	}
	if _, err := NewBitmapData(0, 0, 4, 2, 24, false, px[:5]); err == nil {
		t.Fatal("short data accepted")
	}
	if _, err := NewBitmapData(0, 0, 4, 2, 12, false, px); err == nil {
		t.Fatal("bad bpp accepted")
	}
	pdu, _ := EncodeUpdatePDU(7, body)
	if dp, err := DecodeDataPDU(pdu); err != nil || dp.Header.PDUType2 != PDUType2Update {
		t.Fatalf("%v %v", dp, err)
	}

	xor := make([]byte, 32*32*3)
	and := make([]byte, 32*32/8)
	for _, in := range []Pointer{
		{Type: PointerTypeSystem, SystemType: 0},
		{Type: PointerTypePosition, X: 5, Y: 6},
		{Type: PointerTypeCached, CacheIndex: 3},
		{Type: PointerTypeColor, XorBpp: 24, CacheIndex: 1, HotSpotX: 2, HotSpotY: 3, Width: 32, Height: 32, XorMask: xor, AndMask: and},
		{Type: PointerTypeNew, XorBpp: 32, CacheIndex: 1, HotSpotX: 2, HotSpotY: 3, Width: 32, Height: 32, XorMask: make([]byte, 32*32*4), AndMask: and},
	} {
		enc, err := EncodePointer(in)
		if err != nil {
			t.Fatalf("%+v: %v", in, err)
		}
		out, err := DecodePointer(enc)
		if err != nil {
			t.Fatalf("%+v: %v", in, err)
		}
		if out.Type != in.Type || out.SystemType != in.SystemType || out.X != in.X || out.Y != in.Y || out.CacheIndex != in.CacheIndex ||
			out.Width != in.Width || out.Height != in.Height || out.HotSpotX != in.HotSpotX || out.HotSpotY != in.HotSpotY ||
			!bytes.Equal(out.XorMask, in.XorMask) || !bytes.Equal(out.AndMask, in.AndMask) {
			t.Fatalf("round trip %+v -> %+v", in, out)
		}
	}
	if _, err := EncodePointer(Pointer{Type: PointerTypeColor, XorBpp: 16, Width: 32, Height: 32}); err == nil {
		t.Fatal("16bpp color pointer accepted")
	}
	if _, err := EncodePointer(Pointer{Type: 0xffff}); err == nil {
		t.Fatal("unknown pointer type accepted")
	}
	pp, _ := EncodePointerPDU(7, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	if dp, err := DecodeDataPDU(pp); err != nil || dp.Header.PDUType2 != PDUType2Pointer {
		t.Fatalf("%v %v", dp, err)
	}
}

func FuzzDecodeConnectInitial(f *testing.F) {
	packet, _ := StripX224Data(dump(&testing.T{}, msConnectInitialDump)[TPKTHeaderSize:])
	f.Add(packet)
	f.Add([]byte{0x7f, 0x65, 0x00})
	f.Fuzz(func(t *testing.T, p []byte) {
		ci, err := DecodeConnectInitial(p)
		if err != nil {
			return
		}
		if blocks, err := ParseConferenceCreateRequest(ci.UserData); err == nil {
			if uds, err := ParseUserDataBlocks(blocks); err == nil {
				for _, b := range uds {
					switch b.Type {
					case CSCore:
						_, _ = DecodeClientCoreData(b.Payload)
					case CSSecurity:
						_, _ = DecodeClientSecurityData(b.Payload)
					case CSNet:
						_, _ = DecodeClientNetworkData(b.Payload)
					}
				}
			}
		}
	})
}

func FuzzDecodeClientInfo(f *testing.F) {
	pdu, _ := EncodeClientInfoPDU(ClientInfo{UserName: "u", Password: "p", Flags: InfoAutoLogon | InfoUnicode, ClientAddress: "1.2.3.4", ClientDir: "C:"})
	f.Add(pdu)
	f.Add([]byte{0, 0, 0, 0, 0x23, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 'b', 'o', 'b', 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, p []byte) {
		if ci, err := DecodeClientInfoPDU(p); err == nil {
			if len(ci.UserName) > maxInfoUserNameBytes || len(ci.Password) > maxInfoPasswordBytes {
				t.Fatalf("oversized field accepted")
			}
		}
	})
}

func FuzzDecodeChannelJoinRequest(f *testing.F) {
	f.Add([]byte{0x38, 0, 3, 3, 0xeb})
	f.Fuzz(func(t *testing.T, p []byte) {
		_, _ = DecodeChannelJoinRequest(p)
		_ = DecodeAttachUserRequest(p)
		_ = DecodeErectDomainRequest(p)
		_, _, _ = DecodeConnectionRequest(p)
		_, _ = IsDisconnectProviderUltimatum(p)
	})
}
