package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"rdp.local/kernel/wire"
)

const maxMCSPDUSize = 16384

var (
	// ErrSettingsMismatch means the server's Basic Settings Exchange data
	// contradicts the security negotiation (MS-RDPBCGR 3.2.5.3.4 / 5.4.2.1).
	ErrSettingsMismatch = errors.New("server settings contradict negotiation")
	// ErrEncryptionRequested means the server selected Standard RDP Security
	// encryption, which this implementation does not provide.
	ErrEncryptionRequested = errors.New("server requested Standard RDP Security encryption")
	// ErrMissingServerData means a mandatory server data block was absent.
	ErrMissingServerData = errors.New("server settings incomplete")
)

// Connect runs Connection Initiation, the TLS upgrade, Basic Settings Exchange
// and Channel Connection (user channel + I/O channel), then closes the
// connection. No Client Info PDU is sent; with Options.NLA, credentials
// are delegated via CredSSP before MCS. Use Activate for the later stages.
func Connect(ctx context.Context, address string, opts Options) (Result, error) {
	return run(ctx, address, opts, StageChannelJoin)
}

// run executes the connection sequence up to and including stopAfter.
func run(ctx context.Context, address string, opts Options, stopAfter string) (Result, error) {
	start := time.Now()
	res, err := runSequence(ctx, address, opts, stopAfter)
	res.Duration = time.Since(start)
	return res, err
}

func runSequence(ctx context.Context, address string, opts Options, stopAfter string) (Result, error) {
	budget := opts.timeout()
	if stopAfter == StageActivated && opts.Observe > 0 {
		budget += opts.Observe
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	rawConn, res, err := secureTransport(ctx, address, opts)
	if err != nil {
		return res, err
	}
	defer func() { _ = rawConn.Close() }()
	if err := authenticateNLA(rawConn, address, opts, &res); err != nil {
		return res, err
	}
	conn := newBufConn(rawConn)

	if err := basicSettingsExchange(conn, opts, &res); err != nil {
		return res, err
	}
	res.Stage = StageMCSConnect

	if err := writeMCS(conn, wire.EncodeErectDomainRequest()); err != nil {
		return res, fmt.Errorf("erect domain: %w", err)
	}
	if err := writeMCS(conn, wire.EncodeAttachUserRequest()); err != nil {
		return res, fmt.Errorf("attach user: %w", err)
	}
	pdu, err := readMCS(conn)
	if err != nil {
		return res, fmt.Errorf("attach user confirm: %w", err)
	}
	if res.UserChannel, err = wire.DecodeAttachUserConfirm(pdu); err != nil {
		return res, fmt.Errorf("attach user confirm: %w", err)
	}
	res.Stage = StageAttachUser

	if err := joinChannels(conn, &res); err != nil {
		return res, err
	}
	res.Stage = StageChannelJoin
	if stopAfter == StageChannelJoin {
		return res, nil
	}

	if err := sendClientInfo(conn, opts, &res); err != nil {
		return res, err
	}
	res.Stage = StageClientInfo
	if stopAfter == StageClientInfo {
		return res, nil
	}

	if err := license(conn, opts, &res); err != nil {
		return res, err
	}
	res.Stage = StageLicense
	if stopAfter == StageLicense {
		return res, nil
	}

	demand, err := capabilityExchange(conn, opts, &res)
	if err != nil {
		return res, err
	}
	res.Stage = StageCapabilities
	if stopAfter == StageCapabilities {
		return res, nil
	}

	if err := finalize(conn, demand, &res); err != nil {
		return res, err
	}
	res.Stage = StageActivated
	if opts.Observe > 0 {
		if err := observe(conn, opts, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

func clientName(opts Options) string {
	if opts.ClientName == "" {
		return "rdpkernel"
	}
	return opts.ClientName
}

func desktopSize(opts Options) (uint16, uint16) {
	if opts.DesktopWidth == 0 || opts.DesktopHeight == 0 {
		return 1024, 768
	}
	return opts.DesktopWidth, opts.DesktopHeight
}

const (
	keyboardLayoutUS    = 0x0409
	keyboardFunctionKey = 12
)

func basicSettingsExchange(conn net.Conn, opts Options, res *Result) error {
	width, height := desktopSize(opts)
	core, err := wire.ClientCoreData{
		Version:                wire.RDPVersion5Plus,
		DesktopWidth:           width,
		DesktopHeight:          height,
		ColorDepth:             wire.ColorDepth8bpp,
		SASSequence:            wire.SASSequenceDel,
		KeyboardLayout:         keyboardLayoutUS,
		ClientName:             clientName(opts),
		KeyboardType:           wire.KeyboardTypeIBMEnhance,
		KeyboardFunctionKey:    keyboardFunctionKey,
		PostBeta2ColorDepth:    wire.ColorDepth8bpp,
		ClientProductID:        1,
		HighColorDepth:         opts.colorDepth(),
		SupportedColorDepths:   wire.SupportColorDepths24 | wire.SupportColorDepths16 | wire.SupportColorDepths15 | wire.SupportColorDepths32,
		EarlyCapabilityFlags:   wire.CapSupportErrInfoPDU,
		ServerSelectedProtocol: res.SelectedProtocol,
	}.Encode()
	if err != nil {
		return err
	}
	// Advertised methods only matter for Standard RDP Security; with TLS the
	// server must answer ENCRYPTION_METHOD_NONE, which is enforced below.
	security, err := wire.ClientSecurityData{EncryptionMethods: 0x1b}.Encode()
	if err != nil {
		return err
	}
	network, err := wire.ClientNetworkData{Channels: opts.Channels}.Encode()
	if err != nil {
		return err
	}
	blocks := append(append(core, security...), network...)
	gcc, err := wire.EncodeConferenceCreateRequest(blocks)
	if err != nil {
		return err
	}
	if err := writeMCS(conn, wire.EncodeConnectInitial(gcc)); err != nil {
		return fmt.Errorf("connect initial: %w", err)
	}
	pdu, err := readMCS(conn)
	if err != nil {
		return fmt.Errorf("connect response: %w", err)
	}
	response, err := wire.DecodeConnectResponse(pdu)
	if err != nil {
		return fmt.Errorf("connect response: %w", err)
	}
	serverData, err := wire.ParseConferenceCreateResponse(response.UserData)
	if err != nil {
		return fmt.Errorf("connect response: %w", err)
	}
	serverBlocks, err := wire.ParseUserDataBlocks(serverData)
	if err != nil {
		return fmt.Errorf("connect response: %w", err)
	}

	var haveCore, haveSecurity, haveNet bool
	for _, b := range serverBlocks {
		switch b.Type {
		case wire.SCCore:
			sc, err := wire.DecodeServerCoreData(b.Payload)
			if err != nil {
				return err
			}
			haveCore = true
			res.ServerVersion = sc.Version
			res.ServerEarlyCapabilities = sc.EarlyCapabilityFlags
			if sc.HasRequestedProtocols {
				if sc.ClientRequestedProtocols != opts.requestedProtocol() {
					return fmt.Errorf("%w: SC_CORE echoed requested protocols %s, client sent %s",
						ErrSettingsMismatch, wire.ProtocolString(sc.ClientRequestedProtocols), wire.ProtocolString(opts.requestedProtocol()))
				}
				res.ProtocolReconfirmed = true
			}
		case wire.SCSecurity:
			sec, err := wire.DecodeServerSecurityData(b.Payload)
			if err != nil {
				return err
			}
			haveSecurity = true
			res.EncryptionMethod = sec.EncryptionMethod
			res.EncryptionLevel = sec.EncryptionLevel
			if sec.EncryptionMethod != 0 || sec.EncryptionLevel != 0 {
				return fmt.Errorf("%w: method 0x%08x level 0x%08x", ErrEncryptionRequested, sec.EncryptionMethod, sec.EncryptionLevel)
			}
		case wire.SCNet:
			sn, err := wire.DecodeServerNetworkData(b.Payload)
			if err != nil {
				return err
			}
			haveNet = true
			res.IOChannel = sn.IOChannel
			res.StaticChannels = sn.ChannelIDs
			if len(sn.ChannelIDs) != len(opts.Channels) {
				return fmt.Errorf("%w: server allocated %d static channels, client requested %d", ErrSettingsMismatch, len(sn.ChannelIDs), len(opts.Channels))
			}
		}
	}
	var missing []string
	for name, ok := range map[string]bool{"SC_CORE": haveCore, "SC_SECURITY": haveSecurity, "SC_NET": haveNet} {
		if !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("%w: missing %v", ErrMissingServerData, missing)
	}
	return nil
}

// joinChannels joins the user channel, the I/O channel and every static
// channel the server allocated, in that order.
func joinChannels(conn net.Conn, res *Result) error {
	channels := append([]uint16{res.UserChannel, res.IOChannel}, res.StaticChannels...)
	for _, channel := range channels {
		if err := joinChannel(conn, res.UserChannel, channel); err != nil {
			return err
		}
		res.JoinedChannels = append(res.JoinedChannels, channel)
	}
	return nil
}

func joinChannel(conn net.Conn, userChannel, channel uint16) error {
	req, err := wire.EncodeChannelJoinRequest(userChannel, channel)
	if err != nil {
		return err
	}
	if err := writeMCS(conn, req); err != nil {
		return fmt.Errorf("channel join %d: %w", channel, err)
	}
	pdu, err := readMCS(conn)
	if err != nil {
		return fmt.Errorf("channel join confirm %d: %w", channel, err)
	}
	confirm, err := wire.DecodeChannelJoinConfirm(pdu)
	if err != nil {
		return fmt.Errorf("channel join confirm %d: %w", channel, err)
	}
	if confirm.ChannelID != channel || confirm.UserChannel != userChannel {
		return fmt.Errorf("%w: join confirm for channel %d/user %d, expected %d/%d",
			wire.ErrMCS, confirm.ChannelID, confirm.UserChannel, channel, userChannel)
	}
	return nil
}

func writeMCS(conn net.Conn, mcs []byte) error {
	return wire.WriteTPKT(conn, wire.WrapX224Data(mcs))
}

// bufConn adds a buffered reader so that the first byte of a server PDU can
// be peeked to tell TPKT (0x03) from fast-path output. All reads after the
// TLS upgrade go through it.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufConn(c net.Conn) *bufConn {
	return &bufConn{Conn: c, r: bufio.NewReaderSize(c, 16<<10)}
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func readMCS(conn net.Conn) ([]byte, error) {
	payload, err := wire.ReadTPKT(conn, maxMCSPDUSize)
	if err != nil {
		return nil, err
	}
	return wire.StripX224Data(payload)
}
