// rdpprobe exercises the RDP connection sequence against a server, stage by
// stage: X.224 negotiation for PROTOCOL_SSL, a verified TLS handshake, MCS
// Connect / GCC Basic Settings Exchange, Erect Domain, Attach User, Channel
// Join, Client Info, licensing, Demand/Confirm Active and Connection
// Finalization (Font Map); with -observe it then reads server output for a
// while, decoding bitmap updates into a framebuffer (-png) and pointer
// updates into a cursor (-cursor-png). It never falls back to Standard RDP
// Security.
//
// Stages up to channel-join send no Client Info PDU. Later stages send one;
// it carries a password only when -user is given and -password-env names an
// environment variable holding it, so credentials never appear on the
// command line.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/png"
	"os"
	"strings"
	"time"

	"rdp.local/kernel/transport"
	"rdp.local/kernel/wire"
)

type report struct {
	Address             string                 `json:"address"`
	ServerName          string                 `json:"server_name"`
	TargetStage         string                 `json:"target_stage"`
	ReachedStage        string                 `json:"reached_stage"`
	Negotiation         string                 `json:"negotiation"`
	SelectedProtocol    string                 `json:"selected_protocol,omitempty"`
	NegotiationFlags    uint8                  `json:"negotiation_flags"`
	NLA                 bool                   `json:"nla"`
	CredSSPVersion      int                    `json:"credssp_version,omitempty"`
	TLS                 string                 `json:"tls"`
	TLSVersion          string                 `json:"tls_version,omitempty"`
	CipherSuite         string                 `json:"cipher_suite,omitempty"`
	PeerSubject         string                 `json:"peer_subject,omitempty"`
	PeerSHA256          string                 `json:"peer_sha256,omitempty"`
	PeerNotAfter        string                 `json:"peer_not_after,omitempty"`
	MCSConnect          string                 `json:"mcs_connect"`
	ServerVersion       string                 `json:"server_version,omitempty"`
	ProtocolReconfirmed bool                   `json:"protocol_reconfirmed"`
	EncryptionMethod    uint32                 `json:"encryption_method"`
	EncryptionLevel     uint32                 `json:"encryption_level"`
	IOChannel           uint16                 `json:"io_channel,omitempty"`
	ChannelConnection   string                 `json:"channel_connection"`
	UserChannel         uint16                 `json:"user_channel,omitempty"`
	JoinedChannels      []uint16               `json:"joined_channels,omitempty"`
	ClientInfo          string                 `json:"client_info"`
	AutoLogon           bool                   `json:"auto_logon"`
	License             string                 `json:"license"`
	LicenseOutcome      string                 `json:"license_outcome,omitempty"`
	LicenseProductID    string                 `json:"license_product_id,omitempty"`
	Capabilities        string                 `json:"capabilities"`
	ShareID             string                 `json:"share_id,omitempty"`
	ServerChannel       uint16                 `json:"server_channel,omitempty"`
	ServerSource        string                 `json:"server_source_descriptor,omitempty"`
	ServerCapabilities  int                    `json:"server_capability_sets,omitempty"`
	Activation          string                 `json:"activation"`
	Finalization        []string               `json:"finalization,omitempty"`
	Observation         *transport.Observation `json:"observation,omitempty"`
	DurationMS          int64                  `json:"duration_ms"`
	Error               string                 `json:"error,omitempty"`
	NotVerified         string                 `json:"not_verified"`
}

func main() {
	nla := flag.Bool("nla", false, "require CredSSP 5/6 with NTLMv2; all stages after tls delegate credentials")
	addr := flag.String("addr", "", "server address host:port (required)")
	serverName := flag.String("server-name", "", "name used for SNI and certificate verification (default: host from -addr)")
	caFile := flag.String("ca", "", "PEM file with trusted root certificate(s); default uses system roots")
	minTLS := flag.String("min-tls", "1.2", "lowest TLS version accepted: 1.0, 1.1, 1.2 or 1.3")
	pin := flag.String("pin", "", "hex SHA-256 of the server's leaf certificate; pins it instead of CA/name verification (a mismatch reports the observed value)")
	cookie := flag.String("cookie", "", "optional X.224 cookie, e.g. 'Cookie: mstshash=user'")
	clientName := flag.String("client-name", "rdpkernel", "client name advertised in Client Core Data")
	stage := flag.String("stage", transport.StageChannelJoin,
		"stop after this stage: tls, channel-join, client-info, license, capabilities or activated")
	user := flag.String("user", "", "user name for the Client Info PDU (stages after channel-join)")
	domain := flag.String("domain", "", "domain for the Client Info PDU")
	passwordEnv := flag.String("password-env", "",
		"environment variable holding the password; sets INFO_AUTOLOGON (requires -user)")
	observe := flag.Duration("observe", 0,
		"with -stage activated: keep reading server output (updates, pointers, logon notifications) for this long before closing")
	pngPath := flag.String("png", "", "write the decoded Bitmap Updates (framebuffer, with the cursor composited when its position is known) as PNG to this file (requires -observe)")
	cursorPath := flag.String("cursor-png", "", "write the current decoded cursor shape as PNG to this file (requires -observe)")
	timeout := flag.Duration("timeout", 10*time.Second, "overall timeout (extended by -observe)")
	asJSON := flag.Bool("json", false, "print a JSON report")
	flag.Parse()
	if *addr == "" {
		flag.Usage()
		os.Exit(2)
	}
	target := transport.StageIndex(*stage)
	if target < 0 || *stage == transport.StageNegotiation || *stage == transport.StageMCSConnect || *stage == transport.StageAttachUser {
		fatal(fmt.Errorf("unknown or unsupported stage %q", *stage))
	}
	if *observe != 0 && *stage != transport.StageActivated {
		fatal(errors.New("-observe requires -stage activated"))
	}
	if (*pngPath != "" || *cursorPath != "") && *observe == 0 {
		fatal(errors.New("-png/-cursor-png require -observe"))
	}

	minVersion, ok := map[string]uint16{"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11, "1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}[*minTLS]
	if !ok {
		fatal(fmt.Errorf("-min-tls: unknown version %q", *minTLS))
	}
	opts := transport.Options{NLA: *nla, ServerName: *serverName, PinSHA256: *pin, MinTLSVersion: minVersion, Cookie: *cookie, Timeout: *timeout, ClientName: *clientName,
		UserName: *user, Domain: *domain, StopAfter: *stage, Observe: *observe, Render: *observe != 0}
	if *passwordEnv != "" {
		if *user == "" {
			fatal(errors.New("-password-env requires -user"))
		}
		pw, ok := os.LookupEnv(*passwordEnv)
		if !ok || pw == "" {
			fatal(fmt.Errorf("environment variable %s is not set", *passwordEnv))
		}
		opts.Password = pw
	}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			fatal(fmt.Errorf("no certificates found in %s", *caFile))
		}
		opts.RootCAs = pool
	}

	var res transport.Result
	var err error
	switch *stage {
	case transport.StageTLS:
		res, err = transport.Probe(context.Background(), *addr, opts)
	case transport.StageChannelJoin:
		res, err = transport.Connect(context.Background(), *addr, opts)
	default:
		res, err = transport.Activate(context.Background(), *addr, opts)
	}

	if *pngPath != "" && res.Framebuffer != nil {
		var img image.Image = res.Framebuffer.Image()
		if res.Pointer != nil {
			if x, y, ok := res.Pointer.Position(); ok {
				if c := res.Pointer.Current(); c != nil {
					img = res.Framebuffer.Composite(c, x, y)
				}
			}
		}
		if werr := writePNG(*pngPath, img); werr != nil {
			fatal(werr)
		}
	}
	if *cursorPath != "" && res.Pointer != nil {
		if c := res.Pointer.Current(); c != nil {
			if werr := writePNG(*cursorPath, c.Image); werr != nil {
				fatal(werr)
			}
		}
	}

	rep := report{
		NLA: res.NLA, CredSSPVersion: res.CredSSPVersion,
		Address:             *addr,
		ServerName:          opts.ServerName,
		TargetStage:         *stage,
		ReachedStage:        res.Stage,
		NegotiationFlags:    res.NegotiationFlags,
		ProtocolReconfirmed: res.ProtocolReconfirmed,
		EncryptionMethod:    res.EncryptionMethod,
		EncryptionLevel:     res.EncryptionLevel,
		IOChannel:           res.IOChannel,
		UserChannel:         res.UserChannel,
		JoinedChannels:      res.JoinedChannels,
		AutoLogon:           res.AutoLogon,
		LicenseOutcome:      res.LicenseOutcome,
		LicenseProductID:    res.LicenseProductID,
		ServerChannel:       res.ServerChannel,
		ServerSource:        res.ServerSourceDescriptor,
		ServerCapabilities:  len(res.ServerCapabilities),
		Finalization:        res.Finalization,
		Observation:         res.Observation,
		DurationMS:          res.Duration.Milliseconds(),
		NotVerified:         notVerified(res.Stage, res.AutoLogon, res.NLA, res.Observation != nil),
	}
	reached := transport.StageIndex(res.Stage)
	rep.Negotiation = stageStatus(reached, target, err, transport.StageNegotiation, transport.StageNegotiation)
	rep.TLS = stageStatus(reached, target, err, transport.StageTLS, transport.StageTLS)
	rep.MCSConnect = stageStatus(reached, target, err, transport.StageMCSConnect, transport.StageMCSConnect)
	rep.ChannelConnection = stageStatus(reached, target, err, transport.StageAttachUser, transport.StageChannelJoin)
	rep.ClientInfo = stageStatus(reached, target, err, transport.StageClientInfo, transport.StageClientInfo)
	rep.License = stageStatus(reached, target, err, transport.StageLicense, transport.StageLicense)
	rep.Capabilities = stageStatus(reached, target, err, transport.StageCapabilities, transport.StageCapabilities)
	rep.Activation = stageStatus(reached, target, err, transport.StageActivated, transport.StageActivated)
	if res.SelectedProtocol == wire.ProtocolSSL || reached >= 0 {
		rep.SelectedProtocol = wire.ProtocolString(res.SelectedProtocol)
	}
	if reached >= transport.StageIndex(transport.StageTLS) {
		rep.TLSVersion = transport.TLSVersionString(res.TLSVersion)
		rep.CipherSuite = tls.CipherSuiteName(res.CipherSuite)
		rep.PeerSubject = res.PeerSubject
		rep.PeerSHA256 = res.PeerSHA256
		rep.PeerNotAfter = res.PeerNotAfter.UTC().Format(time.RFC3339)
	}
	if res.ServerVersion != 0 {
		rep.ServerVersion = fmt.Sprintf("0x%08x", res.ServerVersion)
	}
	if reached >= transport.StageIndex(transport.StageCapabilities) {
		rep.ShareID = fmt.Sprintf("0x%08x", res.ShareID)
	}
	if err != nil {
		rep.Error = err.Error()
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printText(rep)
	}
	if err != nil {
		os.Exit(1)
	}
}

// stageStatus describes a report row covering the stages first..last.
func stageStatus(reached, target int, err error, first, last string) string {
	firstIdx, lastIdx := transport.StageIndex(first), transport.StageIndex(last)
	switch {
	case firstIdx > target:
		return "skipped"
	case reached >= lastIdx:
		return "ok"
	case err == nil:
		return "ok"
	case reached >= firstIdx-1:
		var failure *wire.NegotiationFailure
		if first == transport.StageNegotiation && errors.As(err, &failure) {
			return "rejected"
		}
		if first == transport.StageTLS && errors.Is(err, transport.ErrProtocolNotSelected) {
			return "refused: server did not select PROTOCOL_SSL"
		}
		return "failed"
	default:
		return "not attempted"
	}
}

func notVerified(stage string, autoLogon, nla, observed bool) string {
	items := []string{}
	reached := transport.StageIndex(stage)
	if reached < transport.StageIndex(transport.StageClientInfo) {
		items = append(items, "Client Info")
	}
	if reached < transport.StageIndex(transport.StageLicense) {
		items = append(items, "licensing")
	}
	if reached < transport.StageIndex(transport.StageCapabilities) {
		items = append(items, "capability exchange")
	}
	if reached < transport.StageIndex(transport.StageActivated) {
		items = append(items, "session activation")
	}
	switch {
	case nla:
		items = append(items, "logon outcome after CredSSP (credentials accepted by NLA; session logon result not observed by this tool)")
	case !autoLogon:
		items = append(items, "user authentication (no credentials sent)")
	default:
		items = append(items, "logon outcome (credentials sent; server-side result not observed by this tool)")
	}
	if observed {
		items = append(items, "graphics beyond bitmap/pointer updates (orders, surface commands, codecs)")
	} else {
		items = append(items, "graphics")
	}
	items = append(items, "input", "static/dynamic channels")
	return strings.Join(items, ", ")
}

func printText(rep report) {
	fmt.Printf("address:            %s\n", rep.Address)
	fmt.Printf("negotiation:        %s", rep.Negotiation)
	if rep.SelectedProtocol != "" {
		fmt.Printf(" (%s, flags=0x%02x)", rep.SelectedProtocol, rep.NegotiationFlags)
	}
	fmt.Println()
	fmt.Printf("tls:                %s", rep.TLS)
	if rep.TLSVersion != "" {
		fmt.Printf(" (%s, %s, peer=%s, sha256=%s, expires=%s)", rep.TLSVersion, rep.CipherSuite, rep.PeerSubject, rep.PeerSHA256, rep.PeerNotAfter)
	}
	fmt.Println()
	fmt.Printf("mcs connect:        %s", rep.MCSConnect)
	if rep.ServerVersion != "" {
		fmt.Printf(" (server version %s, protocol reconfirmed=%t, encryption method/level=%d/%d, io channel=%d)",
			rep.ServerVersion, rep.ProtocolReconfirmed, rep.EncryptionMethod, rep.EncryptionLevel, rep.IOChannel)
	}
	fmt.Println()
	fmt.Printf("channel connection: %s", rep.ChannelConnection)
	if rep.UserChannel != 0 {
		joined := make([]string, len(rep.JoinedChannels))
		for i, ch := range rep.JoinedChannels {
			joined[i] = fmt.Sprint(ch)
		}
		fmt.Printf(" (user channel %d, joined [%s])", rep.UserChannel, strings.Join(joined, " "))
	}
	fmt.Println()
	fmt.Printf("client info:        %s", rep.ClientInfo)
	if rep.ClientInfo == "ok" {
		fmt.Printf(" (autologon=%t)", rep.AutoLogon)
	}
	fmt.Println()
	fmt.Printf("license:            %s", rep.License)
	if rep.LicenseOutcome != "" {
		fmt.Printf(" (%s", rep.LicenseOutcome)
		if rep.LicenseProductID != "" {
			fmt.Printf(", product %q", rep.LicenseProductID)
		}
		fmt.Print(")")
	}
	fmt.Println()
	fmt.Printf("capabilities:       %s", rep.Capabilities)
	if rep.ShareID != "" {
		fmt.Printf(" (share %s, server channel %d, source %q, %d server capability sets)",
			rep.ShareID, rep.ServerChannel, rep.ServerSource, rep.ServerCapabilities)
	}
	fmt.Println()
	fmt.Printf("activation:         %s", rep.Activation)
	if len(rep.Finalization) != 0 {
		fmt.Printf(" (received %s)", strings.Join(rep.Finalization, " "))
	}
	fmt.Println()
	if o := rep.Observation; o != nil {
		fmt.Printf("observed:           %d PDUs in %s, end=%s, updates=%v (bitmap rects %d, %d compressed, %d bytes; %d orders), pointers=%v, other=%v, reactivations=%d\n",
			o.PDUs, o.Duration.Round(time.Millisecond), o.End, o.Updates, o.BitmapRects, o.Compressed, o.BitmapBytes, o.Orders, o.Pointers, o.Other, o.Reactivations)
		fmt.Printf("fast-path:          %d of %d PDUs, updates=%v, %d reassembled from fragments\n", o.FastPathPDUs, o.PDUs, o.FastPathUpdates, o.Fragments)
		if p := o.Pointer; p != nil {
			fmt.Printf("pointer:            %d cursors decoded, cache hits %d, misses %d, visible=%t", p.Decoded, p.CacheHits, p.CacheMisses, p.Visible)
			if p.System != "" {
				fmt.Printf(", system=%s", p.System)
			}
			if p.X != nil {
				fmt.Printf(", position (%d,%d)", *p.X, *p.Y)
			} else {
				fmt.Print(", position unknown")
			}
			if c := p.Current; c != nil {
				fmt.Printf(", current %dx%d hotspot (%d,%d) xorBpp %d cache %d sha256 %s", c.Width, c.Height, c.HotX, c.HotY, c.XorBpp, c.CacheIndex, c.Hash)
			}
			fmt.Printf(", %d errors", p.Errors)
			if p.FirstError != "" {
				fmt.Printf(" (first: %s)", p.FirstError)
			}
			fmt.Println()
		}
		if f := o.Frame; f != nil {
			fmt.Printf("framebuffer:        %dx%d, %d rects (%d rle, %d clipped), %d pixels written, %d/%d covered (%.1f%%), depths=%v",
				f.Width, f.Height, f.Rects, f.Decompressed, f.Clipped, f.Pixels, f.Covered, f.Width*f.Height,
				100*float64(f.Covered)/float64(max(f.Width*f.Height, 1)), f.Depths)
			if f.Dirty != nil {
				fmt.Printf(", dirty (%d,%d)-(%d,%d)", f.Dirty[0], f.Dirty[1], f.Dirty[2], f.Dirty[3])
			}
			if f.Unpaletted != 0 {
				fmt.Printf(", %d 8bpp rects before palette", f.Unpaletted)
			}
			fmt.Printf(", %d decode errors", f.Errors)
			if f.FirstError != "" {
				fmt.Printf(" (first: %s)", f.FirstError)
			}
			fmt.Printf(", sha256 %s\n", f.Hash)
		}
		for _, l := range o.Logon {
			fmt.Printf("logon notification: infoType=%d session=%d user=%q domain=%q logonErrors=%t", l.InfoType, l.SessionID, l.UserName, l.Domain, l.HasLogonErrors)
			if l.HasLogonErrors {
				fmt.Printf(" (type 0x%08x data 0x%08x)", l.ErrorNotificationType, l.ErrorNotificationData)
			}
			fmt.Println()
		}
		if o.ErrorInfo != nil {
			fmt.Printf("server error info:  0x%08x\n", *o.ErrorInfo)
		}
		if o.Disconnect != "" {
			fmt.Printf("disconnect:         %s\n", o.Disconnect)
		}
	}
	fmt.Printf("reached stage:      %s\n", rep.ReachedStage)
	if rep.Error != "" {
		fmt.Printf("error:              %s\n", rep.Error)
	}
	fmt.Printf("not verified:       %s\n", rep.NotVerified)
}

func writePNG(path string, img image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "rdpprobe:", err)
	os.Exit(2)
}
