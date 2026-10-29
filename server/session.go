package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"rdp.local/kernel/licensing"
	"rdp.local/kernel/wire"
)

const (
	ioChannel           uint16 = 1003
	firstStaticChannel  uint16 = 1004
	userChannelBase     uint16 = 1004 // first user id handed out (initiator 3)
	shareID             uint32 = 0x000103EA
	sourceDescriptor           = "RDP"
	maxJoinPDUs                = 64
	maxFinalizationPDUs        = 16
	maxBitmapPayload           = 16 << 10
	bufferSize                 = 16 << 10
)

type session struct {
	cfg  Config
	raw  net.Conn
	conn net.Conn // raw, then TLS
	r    *bufio.Reader

	stage       string
	peer        Peer
	authorized  bool
	userChannel uint16
	channelIDs  []uint16
	joined      map[uint16]bool
	clientCore  wire.ClientCoreData
	clientCaps  []wire.CapabilitySet
	bpp         uint16
	frame       *Frame
	pending     []byte       // MCS PDU read ahead during channel joins
	creds       *Credentials // kept only until Config.Handler returns
}

func newSession(cfg Config, c net.Conn) *session {
	return &session{cfg: cfg, raw: c, conn: c, stage: "accept", joined: map[uint16]bool{}, peer: Peer{RemoteAddr: c.RemoteAddr()}}
}

func (s *session) summary(err error, d time.Duration) Summary {
	return Summary{RemoteAddr: s.peer.RemoteAddr, UserName: s.peer.UserName, Domain: s.peer.Domain, ClientName: s.peer.ClientName,
		Stage: s.stage, Authorized: s.authorized, Err: err, Duration: d}
}

func (s *session) logf(format string, args ...any) {
	s.cfg.Logf("%s: "+format, append([]any{s.raw.RemoteAddr()}, args...)...)
}

func (s *session) run(ctx context.Context) error {
	deadline := time.Now().Add(s.cfg.HandshakeTimeout)
	_ = s.raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = s.raw.Close() })
	defer stop()
	steps := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"x224", s.negotiate},
		{"tls", s.startTLS},
		{"mcs-connect", s.mcsConnect},
		{"mcs-join", s.mcsJoin},
		{"client-info", s.clientInfo},
		{"license", s.license},
	}
	if s.cfg.Handler != nil {
		steps = append(steps, struct {
			name string
			fn   func(context.Context) error
		}{"handler", s.runHandler})
		return s.runSteps(ctx, steps)
	}
	steps = append(steps, []struct {
		name string
		fn   func(context.Context) error
	}{
		{"capabilities", s.capabilities},
		{"finalize", s.finalize},
		{"output", s.output},
	}...)
	if err := s.runSteps(ctx, steps); err != nil {
		return err
	}
	_ = s.conn.SetDeadline(time.Time{})
	return s.serveActive(ctx)
}

func (s *session) runSteps(ctx context.Context, steps []struct {
	name string
	fn   func(context.Context) error
}) error {
	for _, st := range steps {
		if err := st.fn(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return fmt.Errorf("%w during %s", ErrTimeout, st.name)
			}
			return err
		}
		s.stage = st.name
		s.logf("%s ok", st.name)
	}
	return nil
}

// runHandler hands the licensed connection to Config.Handler and wipes the
// pass-through credentials when it returns.
func (s *session) runHandler(ctx context.Context) error {
	_ = s.conn.SetDeadline(time.Time{})
	c := &Conn{s: s}
	if s.creds != nil {
		c.creds = *s.creds
		s.creds = nil
	}
	err := s.cfg.Handler(ctx, c)
	c.creds = Credentials{}
	return err
}

// --- X.224 --------------------------------------------------------------------

func (s *session) negotiate(context.Context) error {
	s.r = bufio.NewReaderSize(s.raw, bufferSize)
	p, err := wire.ReadTPKT(s.r, 0)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	cr, hasNeg, err := wire.DecodeConnectionRequest(p)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if !hasNeg || cr.RequestedProtocols&wire.ProtocolSSL == 0 {
		_ = wire.WriteTPKT(s.raw, wire.EncodeNegotiationFailure(wire.FailureSSLRequiredByServer))
		return fmt.Errorf("%w: client offered protocols 0x%08x without PROTOCOL_SSL", ErrNegotiation, cr.RequestedProtocols)
	}
	return wire.WriteTPKT(s.raw, wire.EncodeConnectionConfirm(0, wire.ProtocolSSL))
}

func (s *session) startTLS(ctx context.Context) error {
	if s.r.Buffered() != 0 {
		return fmt.Errorf("%w: %d bytes sent before TLS handshake", ErrProtocol, s.r.Buffered())
	}
	tc := tls.Server(s.raw, s.cfg.TLS)
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("%w: TLS handshake: %v", ErrNegotiation, err)
	}
	s.conn = tc
	s.r = bufio.NewReaderSize(tc, bufferSize)
	return nil
}

// --- MCS ----------------------------------------------------------------------

func (s *session) readMCS() ([]byte, error) {
	p, err := wire.ReadTPKT(s.r, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	mcs, err := wire.StripX224Data(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	return mcs, nil
}

func (s *session) writeMCS(mcs []byte) error {
	return wire.WriteTPKT(s.conn, wire.WrapX224Data(mcs))
}

func (s *session) mcsConnect(context.Context) error {
	mcs, err := s.readMCS()
	if err != nil {
		return err
	}
	ci, err := wire.DecodeConnectInitial(mcs)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	userData, err := wire.ParseConferenceCreateRequest(ci.UserData)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	blocks, err := wire.ParseUserDataBlocks(userData)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	var haveCore bool
	var channels []wire.ChannelDef
	for _, b := range blocks {
		switch b.Type {
		case wire.CSCore:
			if s.clientCore, err = wire.DecodeClientCoreData(b.Payload); err != nil {
				return fmt.Errorf("%w: %v", ErrProtocol, err)
			}
			haveCore = true
		case wire.CSSecurity:
			if _, err = wire.DecodeClientSecurityData(b.Payload); err != nil {
				return fmt.Errorf("%w: %v", ErrProtocol, err)
			}
		case wire.CSNet:
			n, err := wire.DecodeClientNetworkData(b.Payload)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrProtocol, err)
			}
			channels = n.Channels
		}
	}
	if !haveCore {
		return fmt.Errorf("%w: Connect-Initial without CS_CORE", ErrProtocol)
	}
	c := s.clientCore
	s.peer.ClientName, s.peer.ClientBuild = c.ClientName, c.ClientBuild
	s.peer.DesktopWidth, s.peer.DesktopHeight = c.DesktopWidth, c.DesktopHeight
	s.peer.ColorDepth = c.HighColorDepth
	if s.peer.ColorDepth == 0 {
		s.peer.ColorDepth = 8
	}
	for i, ch := range channels {
		s.peer.Channels = append(s.peer.Channels, ch.Name)
		s.channelIDs = append(s.channelIDs, firstStaticChannel+uint16(i))
	}
	s.userChannel = firstStaticChannel + uint16(len(channels))

	core, err := wire.ServerCoreData{Version: 0x00080004, ClientRequestedProtocols: wire.ProtocolSSL, HasRequestedProtocols: true}.Encode()
	if err != nil {
		return err
	}
	netData, err := wire.ServerNetworkData{IOChannel: ioChannel, ChannelIDs: s.channelIDs}.Encode()
	if err != nil {
		return err
	}
	sec, err := wire.ServerSecurityData{}.Encode()
	if err != nil {
		return err
	}
	ccr, err := wire.EncodeConferenceCreateResponse(append(append(core, netData...), sec...))
	if err != nil {
		return err
	}
	return s.writeMCS(wire.EncodeConnectResponse(wire.ServerDomainParameters, ccr))
}

func (s *session) mcsJoin(context.Context) error {
	mcs, err := s.readMCS()
	if err != nil {
		return err
	}
	if err := wire.DecodeErectDomainRequest(mcs); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if mcs, err = s.readMCS(); err != nil {
		return err
	}
	if err := wire.DecodeAttachUserRequest(mcs); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	auc, err := wire.EncodeAttachUserConfirm(s.userChannel)
	if err != nil {
		return err
	}
	if err := s.writeMCS(auc); err != nil {
		return err
	}
	// Channel joins arrive until the client is satisfied; the next PDU
	// (Client Info) is a SendDataRequest, which we leave in s.pending.
	for i := 0; i < maxJoinPDUs; i++ {
		mcs, err := s.readMCS()
		if err != nil {
			return err
		}
		if _, err := wire.DecodeChannelJoinRequest(mcs); err != nil {
			if s.joined[s.userChannel] && s.joined[ioChannel] {
				s.pending = mcs
				return nil
			}
			return fmt.Errorf("%w: Client Info before user/IO channel joins: %v", ErrProtocol, err)
		}
		req, _ := wire.DecodeChannelJoinRequest(mcs)
		if req.UserChannel != s.userChannel || !s.allowedChannel(req.ChannelID) {
			fail, err := wire.EncodeChannelJoinFailure(1, s.userChannel, req.ChannelID)
			if err != nil {
				return err
			}
			_ = s.writeMCS(fail)
			return fmt.Errorf("%w: join of channel %d by user %d refused", ErrProtocol, req.ChannelID, req.UserChannel)
		}
		s.joined[req.ChannelID] = true
		cjc, err := wire.EncodeChannelJoinConfirm(s.userChannel, req.ChannelID)
		if err != nil {
			return err
		}
		if err := s.writeMCS(cjc); err != nil {
			return err
		}
	}
	return fmt.Errorf("%w: more than %d channel joins", ErrProtocol, maxJoinPDUs)
}

func (s *session) allowedChannel(id uint16) bool {
	if id == s.userChannel || id == ioChannel {
		return true
	}
	for _, c := range s.channelIDs {
		if c == id {
			return true
		}
	}
	return false
}

// readIO returns the next payload the client sent on the I/O channel,
// skipping data on other static channels.
func (s *session) readIO() ([]byte, error) {
	for {
		var mcs []byte
		if s.pending != nil {
			mcs, s.pending = s.pending, nil
		} else {
			var err error
			if mcs, err = s.readMCS(); err != nil {
				return nil, err
			}
		}
		if reason, ok := wire.IsDisconnectProviderUltimatum(mcs); ok {
			return nil, fmt.Errorf("%w: client disconnected (reason %d)", io.EOF, reason)
		}
		sd, err := wire.DecodeSendDataRequest(mcs)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		if sd.UserChannel != s.userChannel {
			return nil, fmt.Errorf("%w: data from user channel %d, expected %d", ErrProtocol, sd.UserChannel, s.userChannel)
		}
		if sd.ChannelID == ioChannel {
			return sd.Data, nil
		}
		if !s.joined[sd.ChannelID] {
			return nil, fmt.Errorf("%w: data on unjoined channel %d", ErrProtocol, sd.ChannelID)
		}
	}
}

func (s *session) writeIO(payload []byte) error {
	mcs, err := wire.EncodeSendDataIndication(s.userChannel, ioChannel, payload)
	if err != nil {
		return err
	}
	return s.writeMCS(mcs)
}

// --- Client Info / policy -----------------------------------------------------

func (s *session) clientInfo(ctx context.Context) error {
	p, err := s.readIO()
	if err != nil {
		return err
	}
	ci, err := wire.DecodeClientInfoPDU(p)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	s.peer.Domain, s.peer.UserName = ci.Domain, ci.UserName
	s.peer.AutoLogon = ci.Flags&wire.InfoAutoLogon != 0
	peer := s.peer
	peer.Password = ci.Password
	if s.cfg.Handler != nil {
		s.creds = &Credentials{Domain: ci.Domain, UserName: ci.UserName, Password: ci.Password}
	}
	ci.Password = ""
	if s.cfg.Authorize != nil {
		err = s.cfg.Authorize(ctx, peer)
	}
	peer.Password = ""
	if err != nil {
		s.creds = nil
		s.logf("policy denied user %q domain %q client %q: %v", s.peer.UserName, s.peer.Domain, s.peer.ClientName, err)
		// Finish licensing first so clients expecting SEC_LICENSE_PKT
		// (FreeRDP, our transport) then see the Set Error Info PDU as an
		// out-of-sequence Share Data PDU and report ERRINFO 0x7.
		_ = s.license(ctx)
		if pdu, encErr := wire.EncodeErrorInfo(shareID, wire.ErrInfoServerDeniedConnection); encErr == nil {
			_ = s.writeIO(pdu)
		}
		_ = s.writeMCS(wire.EncodeDisconnectProviderUltimatum(wire.DisconnectReasonProviderInit))
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	s.authorized = s.cfg.Authorize != nil
	return nil
}

func (s *session) license(context.Context) error {
	return s.writeIO(wire.EncodeBasicSecurityHeader(wire.SecLicensePkt, licensing.EncodeValidClientAlert()))
}

// --- Capabilities -------------------------------------------------------------

func (s *session) serverCapabilities() []wire.CapabilitySet {
	w, h := s.peer.DesktopWidth, s.peer.DesktopHeight
	var orders wire.OrderCapability
	orders.OrderFlags = wire.OrderNegotiateOrderSupport | wire.OrderZeroBoundsDeltasSupport
	orders.TextANSICodePage = 1252
	return []wire.CapabilitySet{
		wire.GeneralCapability{
			OSMajorType: wire.OSMajorTypeUnix, OSMinorType: wire.OSMinorTypeUnspecified,
			ExtraFlags: wire.GeneralLongCredentialsSupported | wire.GeneralNoBitmapCompressionHdr,
		}.Set(),
		wire.BitmapCapability{PreferredBitsPerPixel: 24, DesktopWidth: w, DesktopHeight: h, DesktopResizeFlag: 1, MultipleRectangleSupport: 1}.Set(),
		orders.Set(),
		wire.PointerCapability{ColorPointerFlag: 1, ColorPointerCacheSize: wire.DefaultPointerCacheSize, PointerCacheSize: wire.DefaultPointerCacheSize}.Set(),
		wire.InputCapability{InputFlags: wire.InputFlagScancodes | wire.InputFlagMouseX | wire.InputFlagUnicode}.Set(),
		wire.ShareCapability{NodeID: wire.ServerChannelID}.Set(),
		wire.FontCapabilitySet(),
		wire.ColorCacheCapabilitySet(),
		wire.VirtualChannelCapabilitySet(),
	}
}

func (s *session) capabilities(context.Context) error {
	da, err := wire.EncodeDemandActive(shareID, sourceDescriptor, s.serverCapabilities())
	if err != nil {
		return err
	}
	if err := s.writeIO(da); err != nil {
		return err
	}
	p, err := s.readIO()
	if err != nil {
		return err
	}
	ca, err := wire.DecodeConfirmActive(p)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if ca.ShareID != shareID {
		return fmt.Errorf("%w: Confirm Active shareId 0x%08x, want 0x%08x", ErrProtocol, ca.ShareID, shareID)
	}
	s.clientCaps = ca.Capabilities
	s.bpp = 24
	if set, ok := wire.FindCapability(ca.Capabilities, wire.CapsTypeBitmap); ok {
		bc, err := wire.DecodeBitmapCapability(set)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		switch bc.PreferredBitsPerPixel {
		case 16, 24, 32:
			s.bpp = bc.PreferredBitsPerPixel
		}
		if bc.DesktopWidth != 0 && bc.DesktopHeight != 0 {
			s.peer.DesktopWidth, s.peer.DesktopHeight = bc.DesktopWidth, bc.DesktopHeight
		}
	} else {
		return fmt.Errorf("%w: Confirm Active without Bitmap Capability Set", ErrProtocol)
	}
	if _, ok := wire.FindCapability(ca.Capabilities, wire.CapsTypeGeneral); !ok {
		return fmt.Errorf("%w: Confirm Active without General Capability Set", ErrProtocol)
	}
	return nil
}

// --- Finalization ---------------------------------------------------------------

func (s *session) finalize(context.Context) error {
	var sync, coop, req, fonts bool
	for i := 0; i < maxFinalizationPDUs && (!sync || !coop || !req || !fonts); i++ {
		p, err := s.readIO()
		if err != nil {
			return err
		}
		d, _, isFontList, err := wire.DecodeClientDataPDU(p)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		switch {
		case d.Synchronize != nil:
			sync = true
		case d.Control != nil && d.Control.Action == wire.CtrlActionCooperate:
			coop = true
		case d.Control != nil && d.Control.Action == wire.CtrlActionRequestControl:
			req = true
		case isFontList:
			fonts = true
		default:
			s.logf("ignoring pduType2 0x%02x during finalization", d.Header.PDUType2)
		}
	}
	if !sync || !coop || !req || !fonts {
		return fmt.Errorf("%w: finalization incomplete (sync %v cooperate %v request %v fontlist %v)", ErrProtocol, sync, coop, req, fonts)
	}
	for _, enc := range []func() ([]byte, error){
		func() ([]byte, error) { return wire.EncodeServerSynchronize(shareID, s.userChannel) },
		func() ([]byte, error) { return wire.EncodeServerControl(shareID, wire.CtrlActionCooperate, 0, 0) },
		func() ([]byte, error) {
			return wire.EncodeServerControl(shareID, wire.CtrlActionGrantedControl, s.userChannel, uint32(wire.ServerChannelID))
		},
		func() ([]byte, error) { return wire.EncodeFontMap(shareID) },
	} {
		pdu, err := enc()
		if err != nil {
			return err
		}
		if err := s.writeIO(pdu); err != nil {
			return err
		}
	}
	return nil
}

// --- Output -----------------------------------------------------------------------

func (s *session) output(context.Context) error {
	if s.cfg.Desktop != nil {
		s.frame = s.cfg.Desktop(s.peer)
	}
	if s.frame == nil {
		s.frame = TestPattern(s.peer.DesktopWidth, s.peer.DesktopHeight)
	}
	if err := s.frame.validate(); err != nil {
		return err
	}
	if err := s.sendFrame(); err != nil {
		return err
	}
	ptr := DefaultPointer()
	if s.cfg.Pointer != nil {
		if p := s.cfg.Pointer(s.peer); p != nil {
			ptr = p
		}
	}
	if err := ptr.validate(); err != nil {
		return err
	}
	xor, and := ptr.wireMasks()
	body, err := wire.EncodePointer(wire.Pointer{Type: wire.PointerTypeColor, XorBpp: 24, CacheIndex: 0,
		HotSpotX: ptr.HotSpotX, HotSpotY: ptr.HotSpotY, Width: ptr.Width, Height: ptr.Height, XorMask: xor, AndMask: and})
	if err != nil {
		return err
	}
	pdu, err := wire.EncodePointerPDU(shareID, body)
	if err != nil {
		return err
	}
	return s.writeIO(pdu)
}

// sendFrame pushes the frame as uncompressed bitmap rectangles, each at
// most maxBitmapPayload bytes.
func (s *session) sendFrame() error {
	f := s.frame
	w, h := int(f.Width), int(f.Height)
	stride := w * int(s.bpp) / 8
	rowsPer := maxBitmapPayload / stride
	if rowsPer < 1 {
		rowsPer = 1
	}
	for y := 0; y < h; y += rowsPer {
		y1 := min(y+rowsPer, h)
		bd, err := wire.NewBitmapData(0, uint16(y), f.Width, uint16(y1-y), s.bpp, false, f.rows(y, y1, s.bpp))
		if err != nil {
			return err
		}
		body, err := wire.EncodeBitmapUpdate([]wire.BitmapData{bd})
		if err != nil {
			return err
		}
		pdu, err := wire.EncodeUpdatePDU(shareID, body)
		if err != nil {
			return err
		}
		if err := s.writeIO(pdu); err != nil {
			return err
		}
	}
	return nil
}

// --- Active session ---------------------------------------------------------------

// serveActive reads client PDUs after activation: slow-path input and
// fast-path input are discarded (G3-2 will route them), Refresh Rect
// re-sends the frame, Shutdown Request is answered by closing.
func (s *session) serveActive(ctx context.Context) error {
	for {
		if s.cfg.IdleTimeout > 0 {
			_ = s.conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		}
		hdr, err := s.r.Peek(1)
		if err != nil {
			return s.closeErr(ctx, err)
		}
		if hdr[0] != 3 {
			if err := s.discardFastPath(); err != nil {
				return s.closeErr(ctx, err)
			}
			continue
		}
		p, err := s.readIO()
		if err != nil {
			return s.closeErr(ctx, err)
		}
		ctl, _, err := wire.DecodeShareControl(p)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		if ctl.PDUType != wire.PDUTypeData {
			s.logf("ignoring share control pduType %d", ctl.PDUType)
			continue
		}
		d, err := wire.DecodeDataPDU(p)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		switch d.Header.PDUType2 {
		case wire.PDUType2RefreshRect:
			if err := s.sendFrame(); err != nil {
				return err
			}
		case wire.PDUType2ShutdownRequest:
			s.logf("client requested shutdown")
			_ = s.writeMCS(wire.EncodeDisconnectProviderUltimatum(wire.DisconnectReasonUserRequested))
			return nil
		case wire.PDUType2Input, wire.PDUType2SuppressOutput, wire.PDUType2FontList, wire.PDUType2Synchronize, wire.PDUType2Control:
		default:
			s.logf("ignoring pduType2 0x%02x", d.Header.PDUType2)
		}
	}
}

func (s *session) closeErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("%w: idle", ErrTimeout)
	}
	return err
}

// discardFastPath consumes one TS_FP_INPUT_PDU.
func (s *session) discardFastPath() error {
	hdr, err := s.r.Peek(2)
	if err != nil {
		return err
	}
	if hdr[0]&0x80 != 0 {
		return fmt.Errorf("%w: encrypted fast-path input", ErrProtocol)
	}
	n := int(hdr[1])
	consumed := 2
	if hdr[1]&0x80 != 0 {
		hdr, err = s.r.Peek(3)
		if err != nil {
			return err
		}
		n = int(binary.BigEndian.Uint16(hdr[1:]) & 0x7fff)
		consumed = 3
	}
	if n < consumed {
		return fmt.Errorf("%w: fast-path length %d", ErrProtocol, n)
	}
	_, err = s.r.Discard(n)
	return err
}
