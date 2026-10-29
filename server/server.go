// Package server implements the server role of the Go RDP kernel for the
// G3-1 milestone: it accepts a TLS-only (PROTOCOL_SSL) RDP client, runs the
// MCS / GCC basic settings exchange, hands the Client Info credentials to a
// caller-supplied authorization policy, skips licensing with
// STATUS_VALID_CLIENT, negotiates capabilities and pushes a static 24bpp
// desktop plus a colour pointer. Input is read and discarded (G3-2) and no
// upstream target is contacted (G3-3).
//
// Security boundaries: Standard RDP Security and CredSSP/NLA are refused at
// X.224 negotiation, passwords are never logged or kept after the
// Authorize callback returns, and every connection has handshake, idle and
// per-PDU size limits.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Errors returned by the server role.
var (
	ErrConfig      = errors.New("rdp server: invalid configuration")
	ErrDenied      = errors.New("rdp server: connection denied by policy")
	ErrNegotiation = errors.New("rdp server: negotiation failed")
	ErrProtocol    = errors.New("rdp server: protocol error")
	ErrTimeout     = errors.New("rdp server: timeout")
)

// Peer describes a connecting client at authorization time. Password is
// only valid for the duration of the Authorize callback.
type Peer struct {
	RemoteAddr    net.Addr
	ClientName    string
	ClientBuild   uint32
	DesktopWidth  uint16
	DesktopHeight uint16
	ColorDepth    uint16 // client's highColorDepth (or colorDepth) in bpp
	Domain        string
	UserName      string
	Password      string
	AutoLogon     bool
	Channels      []string // static virtual channels the client asked for
}

// Config configures a Server.
type Config struct {
	// TLS must carry the server certificate; MinVersion defaults to 1.2.
	TLS *tls.Config
	// Authorize decides whether the peer may proceed. Returning an error
	// (wrap ErrDenied or any other) sends ERRINFO_SERVER_DENIED_CONNECTION
	// and closes the connection. Required unless Handler is set.
	Authorize func(ctx context.Context, p Peer) error
	// Handler, when set, takes over the connection after licensing (the
	// gateway relay): it receives the pass-through credentials and owns
	// the capability exchange and the active session. Desktop, Pointer and
	// IdleTimeout are then unused.
	Handler func(ctx context.Context, c *Conn) error
	// Desktop returns the frame to push after activation. Defaults to a
	// test pattern at the client's requested size.
	Desktop func(p Peer) *Frame
	// Pointer returned after the frame; nil uses DefaultPointer.
	Pointer func(p Peer) *Pointer
	// HandshakeTimeout bounds the time from accept to Font Map (default 30s).
	HandshakeTimeout time.Duration
	// IdleTimeout closes an activated session that sends nothing for this
	// long (default 0: no limit, the context governs).
	IdleTimeout time.Duration
	// MaxSessions limits concurrent connections (default 64).
	MaxSessions int
	// Logf receives one line per state transition; passwords never appear.
	Logf func(format string, args ...any)
	// OnSession is called when a connection ends with its summary.
	OnSession func(s Summary)
}

// Summary is reported for every finished connection.
type Summary struct {
	RemoteAddr net.Addr
	UserName   string
	Domain     string
	ClientName string
	Stage      string // last completed stage
	Authorized bool
	Err        error
	Duration   time.Duration
}

// Server accepts RDP clients.
type Server struct {
	cfg   Config
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
	sem   chan struct{}
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.TLS == nil || len(cfg.TLS.Certificates) == 0 && cfg.TLS.GetCertificate == nil {
		return nil, fmt.Errorf("%w: TLS certificate required", ErrConfig)
	}
	if cfg.Authorize == nil && cfg.Handler == nil {
		return nil, fmt.Errorf("%w: Authorize policy or Handler required", ErrConfig)
	}
	tc := cfg.TLS.Clone()
	if tc.MinVersion == 0 {
		tc.MinVersion = tls.VersionTLS12
	}
	cfg.TLS = tc
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 30 * time.Second
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Server{cfg: cfg, conns: map[net.Conn]struct{}{}, sem: make(chan struct{}, cfg.MaxSessions)}, nil
}

// Serve accepts connections on ln until ctx is done or ln fails. It closes
// ln and all sessions before returning.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		s.closeAll()
	}()
	var err error
	for {
		c, aerr := ln.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else {
				err = aerr
			}
			break
		}
		select {
		case s.sem <- struct{}{}:
		default:
			s.cfg.Logf("%s: rejected, %d sessions active", c.RemoteAddr(), s.cfg.MaxSessions)
			_ = c.Close()
			continue
		}
		s.track(c)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer s.untrack(c)
			s.handle(ctx, c)
		}()
	}
	cancel()
	s.wg.Wait()
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	_ = c.Close()
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	start := time.Now()
	sess := newSession(s.cfg, c)
	err := sess.run(ctx)
	sum := sess.summary(err, time.Since(start))
	if err != nil {
		s.cfg.Logf("%s: closed after %s: %v", c.RemoteAddr(), sum.Stage, err)
	} else {
		s.cfg.Logf("%s: closed after %s", c.RemoteAddr(), sum.Stage)
	}
	if s.cfg.OnSession != nil {
		s.cfg.OnSession(sum)
	}
}
