package transport

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"

	"rdp.local/kernel/licensing"
	"rdp.local/kernel/wire"
)

// Secure Settings Exchange, Licensing, Capabilities Exchange and Connection
// Finalization (MS-RDPBCGR 1.3.1.1 steps 5-8) over the I/O channel. Under
// Enhanced RDP Security with ENCRYPTION_LEVEL_NONE only the Client Info PDU
// and the licensing PDUs carry a Basic Security Header.

var (
	// ErrUnexpectedPDU means the server sent a PDU that the connection
	// sequence does not allow at this point.
	ErrUnexpectedPDU = errors.New("unexpected PDU")
	// ErrStopStage means Options.StopAfter names a stage Activate cannot
	// stop at.
	ErrStopStage = errors.New("invalid stop stage")
	// ErrDeactivated means the server sent Deactivate All before activation
	// completed.
	ErrDeactivated = errors.New("server deactivated the share")
)

// maxFinalizationPDUs bounds the PDUs read while waiting for Font Map.
const maxFinalizationPDUs = 64

// Finalization PDU names recorded in Result.Finalization.
const (
	FinalSynchronize      = "synchronize"
	FinalControlCooperate = "control-cooperate"
	FinalControlGranted   = "control-granted"
	FinalFontMap          = "font-map"
)

// Activate runs the whole connection sequence through Connection
// Finalization (Font Map received) or up to Options.StopAfter, then closes
// the connection. It sends a Client Info PDU: with an empty Password the PDU
// carries no INFO_AUTOLOGON and no credentials; with a Password set the
// server will attempt a logon with it, so only use authorised test accounts.
//
// Reaching StageActivated proves that the server accepted the Client Info
// PDU, completed licensing, exchanged capabilities and finished activation.
// It says nothing about user authentication, graphics or input.
func Activate(ctx context.Context, address string, opts Options) (Result, error) {
	stop := opts.StopAfter
	if stop == "" {
		stop = StageActivated
	}
	if StageIndex(stop) < StageIndex(StageClientInfo) {
		return Result{}, fmt.Errorf("%w: %q (use Connect or Probe for earlier stages)", ErrStopStage, stop)
	}
	return run(ctx, address, opts, stop)
}

func sendIO(conn net.Conn, res *Result, payload []byte) error {
	pdu, err := wire.EncodeSendDataRequest(res.UserChannel, res.IOChannel, payload)
	if err != nil {
		return err
	}
	return writeMCS(conn, pdu)
}

func readIO(conn net.Conn, res *Result) ([]byte, error) {
	pdu, err := readMCS(conn)
	if err != nil {
		return nil, err
	}
	sd, err := wire.DecodeSendDataIndication(pdu)
	if err != nil {
		return nil, err
	}
	if sd.ChannelID != res.IOChannel {
		return nil, fmt.Errorf("%w: data on channel %d, expected I/O channel %d", ErrUnexpectedPDU, sd.ChannelID, res.IOChannel)
	}
	return sd.Data, nil
}

func sendClientInfo(conn net.Conn, opts Options, res *Result) error {
	ci := wire.ClientInfo{
		Flags: wire.InfoMouse | wire.InfoDisableCtrlAltDel | wire.InfoMaximizeShell |
			wire.InfoLogonNotify | wire.InfoEnableWindowsKey | wire.InfoLogonErrors,
		Domain:           opts.Domain,
		UserName:         opts.UserName,
		Password:         opts.Password,
		ClientDir:        clientName(opts),
		TimeZone:         wire.UTCTimeZone,
		PerformanceFlags: opts.performanceFlags(),
		AutoReconnect:    opts.AutoReconnect,
	}
	if opts.Password != "" {
		ci.Flags |= wire.InfoAutoLogon
		res.AutoLogon = true
	}
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok && addr.IP != nil {
		ci.ClientAddress = addr.IP.String()
		if addr.IP.To4() == nil {
			ci.ClientAddressFamily = wire.AddressFamilyINet6
		}
	}
	payload, err := wire.EncodeClientInfoPDU(ci)
	if err != nil {
		return fmt.Errorf("client info: %w", err)
	}
	if err := sendIO(conn, res, payload); err != nil {
		return fmt.Errorf("client info: %w", err)
	}
	res.ClientInfoSent = true
	return nil
}

func license(conn net.Conn, opts Options, res *Result) error {
	lc := &licensing.Client{UserName: opts.UserName, MachineName: clientName(opts), Rand: rand.Reader}
	if lc.UserName == "" {
		lc.UserName = lc.MachineName
	}
	for !lc.Done() {
		data, err := readIO(conn, res)
		if err != nil {
			return fmt.Errorf("licensing: %w", err)
		}
		hdr, payload, err := wire.DecodeBasicSecurityHeader(data)
		if err != nil {
			return fmt.Errorf("licensing: %w", err)
		}
		if hdr.Flags&wire.SecLicensePkt == 0 {
			return fmt.Errorf("%w: expected licensing PDU (SEC_LICENSE_PKT), security flags 0x%04x", ErrUnexpectedPDU, hdr.Flags)
		}
		reply, _, err := lc.Handle(payload)
		if err != nil {
			return fmt.Errorf("licensing: %w", err)
		}
		if reply != nil {
			if err := sendIO(conn, res, wire.EncodeBasicSecurityHeader(wire.SecLicensePkt, reply)); err != nil {
				return fmt.Errorf("licensing: %w", err)
			}
		}
	}
	res.LicenseOutcome = lc.Outcome
	res.LicenseProductID = lc.ProductID
	return nil
}

func capabilityExchange(conn net.Conn, opts Options, res *Result) (wire.DemandActive, error) {
	data, err := readIO(conn, res)
	if err != nil {
		return wire.DemandActive{}, fmt.Errorf("demand active: %w", err)
	}
	demand, err := wire.DecodeDemandActive(data)
	if err != nil {
		// A server that denies the connection after licensing sends a Set
		// Error Info PDU (Share Data) instead of Demand Active; surface
		// the ERRINFO code rather than a share-PDU type mismatch.
		if hdr, _, hErr := wire.DecodeShareControl(data); hErr == nil && hdr.PDUType == wire.PDUTypeData {
			if _, dErr := wire.DecodeDataPDU(data); dErr != nil {
				return demand, fmt.Errorf("demand active: %w", dErr)
			}
		}
		return demand, fmt.Errorf("demand active: %w", err)
	}
	res.ShareID = demand.ShareID
	res.ServerChannel = demand.Control.PDUSource
	res.ServerSourceDescriptor = strings.TrimRight(string(demand.SourceDescriptor), "\x00")
	for _, s := range demand.Capabilities {
		res.ServerCapabilities = append(res.ServerCapabilities, s.Type)
	}

	width, height := desktopSize(opts)
	sets := wire.DefaultClientCapabilities(wire.ClientCapabilityOptions{
		DesktopWidth:   width,
		DesktopHeight:  height,
		ColorDepth:     opts.colorDepth(),
		KeyboardLayout: opts.keyboardLayout(),
		KeyboardType:   wire.KeyboardTypeIBMEnhance,
		FunctionKeys:   keyboardFunctionKey,
	})
	pdu, err := wire.EncodeConfirmActive(demand.ShareID, res.UserChannel, clientName(opts), sets)
	if err != nil {
		return demand, fmt.Errorf("confirm active: %w", err)
	}
	if err := sendIO(conn, res, pdu); err != nil {
		return demand, fmt.Errorf("confirm active: %w", err)
	}
	return demand, nil
}

func finalize(conn net.Conn, demand wire.DemandActive, res *Result) error {
	shareID, user, server := demand.ShareID, res.UserChannel, demand.Control.PDUSource
	type step struct {
		name   string
		encode func() ([]byte, error)
	}
	for _, s := range []step{
		{"synchronize", func() ([]byte, error) { return wire.EncodeSynchronize(shareID, user, server) }},
		{"control cooperate", func() ([]byte, error) { return wire.EncodeControl(shareID, user, wire.CtrlActionCooperate) }},
		{"control request", func() ([]byte, error) { return wire.EncodeControl(shareID, user, wire.CtrlActionRequestControl) }},
		{"font list", func() ([]byte, error) { return wire.EncodeFontList(shareID, user) }},
	} {
		pdu, err := s.encode()
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		if err := sendIO(conn, res, pdu); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	for i := 0; i < maxFinalizationPDUs; i++ {
		data, err := readIO(conn, res)
		if err != nil {
			return fmt.Errorf("finalization: %w", err)
		}
		ctl, _, err := wire.DecodeShareControl(data)
		if err != nil {
			return fmt.Errorf("finalization: %w", err)
		}
		switch ctl.PDUType {
		case wire.PDUTypeData:
		case wire.PDUTypeDeactivateAll:
			return ErrDeactivated
		default:
			return fmt.Errorf("%w: share control pduType %d before Font Map", ErrUnexpectedPDU, ctl.PDUType)
		}
		d, err := wire.DecodeDataPDU(data)
		if err != nil {
			return fmt.Errorf("finalization: %w", err)
		}
		if d.Header.ShareID != shareID {
			return fmt.Errorf("%w: data PDU for share 0x%08x, expected 0x%08x", ErrUnexpectedPDU, d.Header.ShareID, shareID)
		}
		switch {
		case d.Synchronize != nil:
			res.Finalization = append(res.Finalization, FinalSynchronize)
		case d.Control != nil:
			switch d.Control.Action {
			case wire.CtrlActionCooperate:
				res.Finalization = append(res.Finalization, FinalControlCooperate)
			case wire.CtrlActionGrantedControl:
				res.Finalization = append(res.Finalization, FinalControlGranted)
			default:
				return fmt.Errorf("%w: control action 0x%04x during finalization", ErrUnexpectedPDU, d.Control.Action)
			}
		case d.FontMap != nil:
			res.Finalization = append(res.Finalization, FinalFontMap)
			return nil
		default:
			res.Finalization = append(res.Finalization, fmt.Sprintf("pduType2-0x%02x", d.Header.PDUType2))
		}
	}
	return fmt.Errorf("%w: no Font Map within %d PDUs", ErrUnexpectedPDU, maxFinalizationPDUs)
}
