package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"image/color"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rdp.local/kernel/licensing"
	"rdp.local/kernel/wire"
)

// activationServer continues the fake MCS server after Channel Join: it
// consumes the Client Info PDU, answers licensing with STATUS_VALID_CLIENT,
// sends the MS-RDPBCGR 4.1.12 Demand Active sample, consumes Confirm Active
// and the client finalization PDUs and replies with Synchronize, Control
// Cooperate, Control Granted and Font Map.
type activationServer struct {
	licenseError bool // answer licensing with ERR_INVALID_CLIENT instead
	errorInfo    bool // send Set Error Info instead of Font Map
	deactivate   bool // send Deactivate All instead of Font Map

	reactivate bool          // after Font Map: Deactivate All + a second activation
	post       [][]byte      // payloads written after activation
	raw        [][]byte      // bytes written verbatim after post (fast-path PDUs)
	hold       time.Duration // keep the connection open this long before closing

	gotClientInfo    []byte
	gotConfirmActive wire.ConfirmActive
	gotFinalization  []uint8
}

const (
	testUserChannel  uint16 = 1007
	testIOChannel    uint16 = 1003
	sampleShareID    uint32 = 0x000103ea
	validClientAlert        = "ff 03 10 00 07 00 00 00 02 00 00 00 04 00 00 00"
	invalidClient           = "ff 03 10 00 08 00 00 00 01 00 00 00 04 00 00 00"
)

func sampleDemandActive(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "wire", "testdata", "bcgr-4.1.12-demand-active-plain.hex"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (a *activationServer) readIO(conn net.Conn) ([]byte, error) {
	pdu, err := readMCS(conn)
	if err != nil {
		return nil, err
	}
	sd, err := wire.DecodeSendDataRequest(pdu)
	if err != nil {
		return nil, err
	}
	if sd.UserChannel != testUserChannel || sd.ChannelID != testIOChannel {
		return nil, errors.New("send data request on wrong channel")
	}
	return sd.Data, nil
}

func (a *activationServer) writeIO(conn net.Conn, payload []byte) error {
	pdu, err := wire.EncodeSendDataIndication(wire.ServerChannelID, testIOChannel, payload)
	if err != nil {
		return err
	}
	return writeMCS(conn, pdu)
}

func (a *activationServer) serve(conn net.Conn, demandActive []byte) error {
	data, err := a.readIO(conn)
	if err != nil {
		return err
	}
	hdr, body, err := wire.DecodeBasicSecurityHeader(data)
	if err != nil || hdr.Flags&wire.SecInfoPkt == 0 {
		return errors.New("expected Client Info PDU")
	}
	a.gotClientInfo = body

	alert := validClientAlert
	if a.licenseError {
		alert = invalidClient
	}
	raw, _ := hex.DecodeString(strings.ReplaceAll(alert, " ", ""))
	if err := a.writeIO(conn, wire.EncodeBasicSecurityHeader(wire.SecLicensePkt, raw)); err != nil {
		return err
	}
	if a.licenseError {
		return nil
	}

	if err := a.writeIO(conn, demandActive); err != nil {
		return err
	}
	if data, err = a.readIO(conn); err != nil {
		return err
	}
	if a.gotConfirmActive, err = wire.DecodeConfirmActive(data); err != nil {
		return err
	}
	for i := 0; i < 4; i++ {
		if data, err = a.readIO(conn); err != nil {
			return err
		}
		d, err := wire.DecodeDataPDU(data)
		if err != nil {
			return err
		}
		if d.Header.ShareID != sampleShareID || d.Header.Control.PDUSource != testUserChannel {
			return errors.New("client data PDU with wrong shareId/pduSource")
		}
		a.gotFinalization = append(a.gotFinalization, d.Header.PDUType2)
	}

	sync, _ := wire.EncodeSynchronize(sampleShareID, wire.ServerChannelID, testUserChannel)
	coop, _ := wire.EncodeControl(sampleShareID, wire.ServerChannelID, wire.CtrlActionCooperate)
	granted, _ := wire.EncodeControl(sampleShareID, wire.ServerChannelID, wire.CtrlActionGrantedControl)
	fontMapBody := []byte{0, 0, 0, 0, 3, 0, 4, 0}
	last, _ := wire.EncodeShareData(sampleShareID, wire.ServerChannelID, wire.PDUType2FontMap, fontMapBody)
	if a.errorInfo {
		errBody := binary.LittleEndian.AppendUint32(nil, 0x00000005) // ERRINFO_LICENSE_INTERNAL
		last, _ = wire.EncodeShareData(sampleShareID, wire.ServerChannelID, wire.PDUType2SetErrorInfo, errBody)
	}
	if a.deactivate {
		last, _ = wire.EncodeShareControl(wire.PDUTypeDeactivateAll, wire.ServerChannelID, append(binary.LittleEndian.AppendUint32(nil, sampleShareID), 0, 0))
	}
	for _, p := range [][]byte{sync, coop, granted, last} {
		if err := a.writeIO(conn, p); err != nil {
			return err
		}
	}
	if a.reactivate {
		deact, _ := wire.EncodeShareControl(wire.PDUTypeDeactivateAll, wire.ServerChannelID, append(binary.LittleEndian.AppendUint32(nil, sampleShareID), 0, 0))
		for _, p := range [][]byte{deact, demandActive} {
			if err := a.writeIO(conn, p); err != nil {
				return err
			}
		}
		for i := 0; i < 5; i++ { // Confirm Active + 4 finalization PDUs
			if _, err := a.readIO(conn); err != nil {
				return err
			}
		}
		for _, p := range [][]byte{sync, coop, granted, last} {
			if err := a.writeIO(conn, p); err != nil {
				return err
			}
		}
	}
	for _, p := range a.post {
		if err := a.writeIO(conn, p); err != nil {
			return err
		}
	}
	for _, p := range a.raw {
		if _, err := conn.Write(p); err != nil {
			return err
		}
	}
	time.Sleep(a.hold)
	return nil
}

func serverData(pduType2 uint8, body []byte) []byte {
	p, err := wire.EncodeShareData(sampleShareID, wire.ServerChannelID, pduType2, body)
	if err != nil {
		panic(err)
	}
	return p
}

func TestActivateObserve(t *testing.T) {
	bitmap := []byte{1, 0, 1, 0, 0, 0, 0, 0, 3, 0, 1, 0, 4, 0, 2, 0, 16, 0, 0, 0, 16, 0}
	bitmap = append(bitmap, make([]byte, 16)...)
	plain := append([]byte{2, 0, 0, 0}, make([]byte, 576)...)
	a := &activationServer{reactivate: true, post: [][]byte{
		serverData(wire.PDUType2Update, bitmap),
		serverData(wire.PDUType2Pointer, []byte{3, 0, 0, 0, 7, 0, 9, 0}),
		serverData(wire.PDUType2SaveSessionInfo, plain),
		serverData(wire.PDUType2SetKeyboardIndicators, []byte{0, 0, 0, 0}),
		serverData(wire.PDUType2SetErrorInfo, []byte{0, 0, 0, 0}),
	}}
	s, opts := startActivationServer(t, a)
	opts.Observe = 5 * time.Second
	opts.Render = true
	res, err := Activate(context.Background(), s.ln.Addr().String(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-s.done; err != nil {
		t.Fatalf("server: %v", err)
	}
	o := res.Observation
	if o == nil || o.End != "closed" || o.PDUs != 6 || o.Reactivations != 1 || len(res.Finalization) != 8 ||
		o.Updates["bitmap"] != 1 || o.BitmapRects != 1 || o.BitmapBytes != 16 || o.Compressed != 0 ||
		o.Pointers["position"] != 1 || o.Other["0x29"] != 1 || len(o.Logon) != 1 || o.Logon[0].InfoType != wire.InfoTypeLogonPlain ||
		o.ErrorInfo == nil || *o.ErrorInfo != 0 || res.Duration <= 0 {
		t.Fatalf("observation %+v (finalization %v, duration %s)", o, res.Finalization, res.Duration)
	}
	if res.Framebuffer == nil || o.Frame == nil || o.Frame.Width != 1024 || o.Frame.Rects != 1 || o.Frame.Errors != 0 || o.Frame.Pixels == 0 || o.Frame.Hash == "" {
		t.Fatalf("frame %+v", o.Frame)
	}

	// Observation window elapses while the server stays silent.
	a = &activationServer{hold: 2 * time.Second}
	s, opts = startActivationServer(t, a)
	opts.Observe = 200 * time.Millisecond
	res, err = Activate(context.Background(), s.ln.Addr().String(), opts)
	if err != nil || res.Observation == nil || res.Observation.End != "timeout" || res.Observation.PDUs != 0 {
		t.Fatalf("%+v %v", res.Observation, err)
	}
	<-s.done
}

// fastPathPDU frames (code, fragmentation, data) triples in a TS_FP_UPDATE_PDU.
func fastPathPDU(updates ...[]byte) []byte {
	var body []byte
	for _, u := range updates {
		body = append(body, u...)
	}
	size := 2 + len(body)
	if size+1 > 0x7F {
		size++
	}
	pdu := []byte{0}
	if size > 0x7F {
		pdu = append(pdu, byte(size>>8)|0x80, byte(size))
	} else {
		pdu = append(pdu, byte(size))
	}
	return append(pdu, body...)
}

func fastPathUpdate(code, frag uint8, data []byte) []byte {
	return append(binary.LittleEndian.AppendUint16([]byte{code | frag<<4}, uint16(len(data))), data...)
}

func TestActivateObserveFastPath(t *testing.T) {
	bitmap := []byte{1, 0, 1, 0, 0, 0, 0, 0, 3, 0, 1, 0, 4, 0, 2, 0, 16, 0, 0, 0, 16, 0}
	bitmap = append(bitmap, make([]byte, 16)...)
	// 2x1 24bpp colour pointer at cache 0, hotspot (1,0): red + white, AND mask all visible.
	cursor := []byte{0, 0, 1, 0, 0, 0, 2, 0, 1, 0, 2, 0, 6, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0}
	a := &activationServer{
		post: [][]byte{serverData(wire.PDUType2Update, bitmap)},
		raw: [][]byte{
			fastPathPDU(
				fastPathUpdate(wire.FastPathUpdateBitmap, wire.FastPathFragmentSingle, bitmap),
				fastPathUpdate(wire.FastPathUpdateSynchronize, wire.FastPathFragmentSingle, nil),
				fastPathUpdate(wire.FastPathUpdatePtrPosition, wire.FastPathFragmentSingle, []byte{7, 0, 9, 0})),
			fastPathPDU(fastPathUpdate(wire.FastPathUpdateColor, wire.FastPathFragmentFirst, cursor[:10])),
			fastPathPDU(fastPathUpdate(wire.FastPathUpdateColor, wire.FastPathFragmentNext, cursor[10:15])),
			fastPathPDU(fastPathUpdate(wire.FastPathUpdateColor, wire.FastPathFragmentLast, cursor[15:]),
				fastPathUpdate(wire.FastPathUpdateOrders, wire.FastPathFragmentSingle, []byte{2, 0, 0}),
				fastPathUpdate(wire.FastPathUpdateCached, wire.FastPathFragmentSingle, []byte{0, 0})),
			fastPathPDU(fastPathUpdate(wire.FastPathUpdateSurfCmds, wire.FastPathFragmentSingle, []byte{1, 2, 3})),
		},
	}
	s, opts := startActivationServer(t, a)
	opts.Observe = 5 * time.Second
	opts.Render = true
	res, err := Activate(context.Background(), s.ln.Addr().String(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-s.done; err != nil {
		t.Fatalf("server: %v", err)
	}
	if a.gotConfirmActive.Capabilities == nil {
		t.Fatal("no confirm active")
	}
	var general *wire.GeneralCapability
	for _, c := range a.gotConfirmActive.Capabilities {
		if c.Type == wire.CapsTypeGeneral {
			g, err := wire.DecodeGeneralCapability(c)
			if err != nil {
				t.Fatal(err)
			}
			general = &g
		}
	}
	if general == nil || general.ExtraFlags&wire.GeneralFastPathOutputSupported == 0 {
		t.Fatalf("fast-path output not advertised: %+v", general)
	}
	o := res.Observation
	if o == nil || o.End != "closed" || o.PDUs != 6 || o.FastPathPDUs != 5 || o.Fragments != 1 ||
		o.Updates["bitmap"] != 2 || o.Updates["synchronize"] != 1 || o.Updates["orders"] != 1 || o.Orders != 2 || o.BitmapRects != 2 ||
		o.Pointers["position"] != 1 || o.Pointers["color"] != 1 || o.Pointers["cached"] != 1 ||
		o.FastPathUpdates["bitmap"] != 1 || o.FastPathUpdates["ptr-color"] != 1 || o.FastPathUpdates["ptr-cached"] != 1 || o.Other["fp-surfcmds"] != 1 {
		t.Fatalf("observation %+v", o)
	}
	if o.Frame == nil || o.Frame.Rects != 2 || o.Frame.Errors != 0 {
		t.Fatalf("frame %+v", o.Frame)
	}
	p := o.Pointer
	if p == nil || p.Decoded != 1 || p.CacheHits != 1 || p.Errors != 0 || p.X == nil || *p.X != 7 || *p.Y != 9 || p.Current == nil || p.Current.Width != 2 || p.Current.HotX != 1 {
		t.Fatalf("pointer %+v", p)
	}
	x, y, ok := res.Pointer.Position()
	c := res.Pointer.Current()
	if !ok || c == nil {
		t.Fatal("no cursor/position")
	}
	if img := res.Framebuffer.Composite(c, x, y); img.RGBAAt(6, 9) != (color.RGBA{0xFF, 0, 0, 0xFF}) || img.RGBAAt(7, 9) != (color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Fatalf("composite %v %v", img.RGBAAt(6, 9), img.RGBAAt(7, 9))
	}
}

func startActivationServer(t *testing.T, a *activationServer) (*fakeServer, Options) {
	cert, pool := testCertificate(t, "localhost")
	m := &mcsServer{echoProtocols: wire.ProtocolSSL, activation: a, demandActive: sampleDemandActive(t)}
	s := startFakeServer(t, cert, confirm(wire.ProtocolSSL), true, m)
	return s, Options{ServerName: "localhost", RootCAs: pool, ClientName: "unit-test"}
}

func TestActivateReachesFontMap(t *testing.T) {
	a := &activationServer{}
	s, opts := startActivationServer(t, a)
	res, err := Activate(context.Background(), s.ln.Addr().String(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-s.done; err != nil {
		t.Fatalf("server: %v", err)
	}
	if res.Stage != StageActivated || !res.ClientInfoSent || res.AutoLogon ||
		res.LicenseOutcome != "valid-client" || res.ShareID != sampleShareID ||
		res.ServerChannel != wire.ServerChannelID || res.ServerSourceDescriptor != "RDP" ||
		len(res.ServerCapabilities) != 13 {
		t.Fatalf("unexpected result %+v", res)
	}
	want := []string{FinalSynchronize, FinalControlCooperate, FinalControlGranted, FinalFontMap}
	if strings.Join(res.Finalization, ",") != strings.Join(want, ",") {
		t.Fatalf("finalization %v", res.Finalization)
	}

	// Client Info: INFO_UNICODE without INFO_AUTOLOGON, no password bytes.
	flags := binary.LittleEndian.Uint32(a.gotClientInfo[4:])
	if flags&wire.InfoUnicode == 0 || flags&wire.InfoAutoLogon != 0 {
		t.Fatalf("client info flags 0x%08x", flags)
	}
	if binary.LittleEndian.Uint16(a.gotClientInfo[12:]) != 0 { // cbPassword
		t.Fatal("password sent without credentials")
	}
	if a.gotConfirmActive.ShareID != sampleShareID || a.gotConfirmActive.OriginatorID != wire.ServerChannelID ||
		!bytes.Equal(a.gotConfirmActive.SourceDescriptor, []byte("unit-test\x00")) {
		t.Fatalf("confirm active %+v", a.gotConfirmActive)
	}
	if _, ok := wire.FindCapability(a.gotConfirmActive.Capabilities, wire.CapsTypeGeneral); !ok {
		t.Fatal("confirm active lacks general capability set")
	}
	wantSeq := []uint8{wire.PDUType2Synchronize, wire.PDUType2Control, wire.PDUType2Control, wire.PDUType2FontList}
	if !bytes.Equal(a.gotFinalization, wantSeq) {
		t.Fatalf("client finalization sequence %v", a.gotFinalization)
	}
}

func TestActivateSendsCredentialsOnlyWhenGiven(t *testing.T) {
	a := &activationServer{}
	s, opts := startActivationServer(t, a)
	opts.UserName, opts.Password, opts.Domain = "tester", "pw-unit", "d"
	opts.StopAfter = StageClientInfo
	res, err := Activate(context.Background(), s.ln.Addr().String(), opts)
	if err != nil || res.Stage != StageClientInfo || !res.AutoLogon {
		t.Fatalf("%+v, %v", res, err)
	}
	// The server may fail after the client closed; only the Client Info matters.
	<-s.done
	if a.gotClientInfo == nil {
		t.Fatal("client info not received")
	}
	flags := binary.LittleEndian.Uint32(a.gotClientInfo[4:])
	if flags&wire.InfoAutoLogon == 0 {
		t.Fatalf("client info flags 0x%08x lack INFO_AUTOLOGON", flags)
	}
	user := []byte{'t', 0, 'e', 0, 's', 0, 't', 0, 'e', 0, 'r', 0, 0, 0}
	pw := []byte{'p', 0, 'w', 0, '-', 0, 'u', 0, 'n', 0, 'i', 0, 't', 0, 0, 0}
	if !bytes.Contains(a.gotClientInfo, user) || !bytes.Contains(a.gotClientInfo, pw) {
		t.Fatal("credentials not encoded in client info")
	}
}

func TestActivateFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		server *activationServer
		stage  string
		check  func(error) bool
	}{
		"license-error": {&activationServer{licenseError: true}, StageClientInfo, func(err error) bool {
			var alert *licensing.ErrorAlert
			return errors.As(err, &alert) && alert.Code == licensing.ErrInvalidClient
		}},
		"error-info": {&activationServer{errorInfo: true}, StageCapabilities, func(err error) bool {
			var info *wire.ErrorInfo
			return errors.As(err, &info) && info.Code == 5
		}},
		"deactivate": {&activationServer{deactivate: true}, StageCapabilities, func(err error) bool {
			return errors.Is(err, ErrDeactivated)
		}},
	} {
		s, opts := startActivationServer(t, tc.server)
		res, err := Activate(context.Background(), s.ln.Addr().String(), opts)
		if err == nil || !tc.check(err) {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if res.Stage != tc.stage {
			t.Errorf("%s: stage %q, want %q", name, res.Stage, tc.stage)
		}
	}
}

func TestActivateRejectsEarlyStopStage(t *testing.T) {
	_, err := Activate(context.Background(), "127.0.0.1:1", Options{StopAfter: StageChannelJoin})
	if !errors.Is(err, ErrStopStage) {
		t.Fatal(err)
	}
}
