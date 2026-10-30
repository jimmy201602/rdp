package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"rdp.local/kernel/wire"
)

// ChannelObserver receives complete, uncompressed messages. Implementations
// must not block forwarding or retain slices without copying them.
type ChannelObserver interface {
	ClientChannel(name string, data []byte)
	ServerChannel(name string, data []byte)
}

func tappedChannel(name string) bool { return name == "rdpdr" || name == "cliprdr" }

func (r *relay) writeClient(write func() error) error {
	r.cwmu.Lock()
	defer r.cwmu.Unlock()
	return write()
}

func sendChannel(msg []byte, write func([]byte) error) error {
	for _, chunk := range wire.SplitChannelPDU(msg, wire.ChannelChunkLength) {
		if err := write(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (r *relay) initChannels() {
	r.cliReasm = map[string]*wire.ChannelReassembler{}
	r.srvReasm = map[string]*wire.ChannelReassembler{}
	if !r.g.cfg.DriveControl {
		return
	}
	for front, name := range r.channels.frontNames {
		back, ok := r.channels.frontToBack[front]
		if !ok || !strings.EqualFold(name, "rdpdr") {
			continue
		}
		r.drive = newDriveMux(
			func(msg []byte) error {
				return r.writeClient(func() error { return sendChannel(msg, func(p []byte) error { return r.client.WriteChannel(front, p) }) })
			},
			func(msg []byte) error {
				return r.writeTarget(func() error { return sendChannel(msg, func(p []byte) error { return r.backend.WriteChannel(back, p) }) })
			},
		)
	}
}

// relayChannel returns handled=true if a drive message was buffered or sent.
// Passive clipboard observation never changes forwarding, even on decode errors.
func (r *relay) relayChannel(client bool, name string, chunk []byte) (bool, error) {
	name = strings.ToLower(name)
	if !tappedChannel(name) {
		return false, nil
	}
	observer, watching := r.obs.(ChannelObserver)
	active := name == "rdpdr" && r.drive != nil
	if !watching && !active {
		return false, nil
	}
	assemblies := r.srvReasm
	if client {
		assemblies = r.cliReasm
	}
	ra := assemblies[name]
	if ra == nil {
		ra = &wire.ChannelReassembler{}
		assemblies[name] = ra
	}
	msg, done, compressed, err := ra.Add(chunk)
	if err != nil || compressed {
		if active {
			return true, fmt.Errorf("%w: unsupported or malformed rdpdr channel data", ErrRelay)
		}
		return false, nil
	}
	if !done {
		return active, nil
	}
	if active && client {
		return true, r.drive.client(msg, func(p []byte) {
			if watching {
				observer.ClientChannel(name, p)
			}
		})
	}
	if watching {
		if client {
			observer.ClientChannel(name, msg)
		} else {
			observer.ServerChannel(name, msg)
		}
	}
	if active {
		return true, r.drive.server(msg)
	}
	return false, nil
}

var errDriveClosed = errors.New("redirected drive connection closed")

type driveResult struct {
	completion wire.IOCompletion
	err        error
}
type drivePending struct {
	original, device, major uint32
	result                  chan driveResult // nil for target requests
	abandoned               bool
}

// All target and administrator requests share one ID allocator. Choosing a
// high-bit range alone is unsafe: a target is allowed to use any uint32 ID.
type driveMux struct {
	mu                 sync.Mutex
	next               uint32
	pending            map[uint32]*drivePending
	closed             bool
	toClient, toTarget func([]byte) error
}

func newDriveMux(client, target func([]byte) error) *driveMux {
	return &driveMux{pending: map[uint32]*drivePending{}, toClient: client, toTarget: target}
}

func (m *driveMux) reserve(req wire.IORequest, result chan driveResult) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, errDriveClosed
	}
	if len(m.pending) >= 4096 {
		return 0, errors.New("too many pending redirected drive requests")
	}
	for {
		m.next++
		if _, exists := m.pending[m.next]; !exists {
			break
		}
	}
	m.pending[m.next] = &drivePending{original: req.CompletionID, device: req.DeviceID, major: req.Major, result: result}
	return m.next, nil
}

func (m *driveMux) server(msg []byte) error {
	h, body, err := wire.DecodeRDPDRHeader(msg)
	if err != nil {
		return err
	}
	if h.Component != wire.RDPDRCtypCore || h.PacketID != wire.PakidCoreDeviceIORequest {
		return m.toClient(msg)
	}
	req, err := wire.DecodeIORequest(body)
	if err != nil {
		return err
	}
	id, err := m.reserve(req, nil)
	if err != nil {
		return err
	}
	out := append([]byte(nil), msg...)
	binary.LittleEndian.PutUint32(out[12:], id)
	if err = m.toClient(out); err != nil {
		m.close()
	}
	return err
}

func (m *driveMux) client(msg []byte, observe func([]byte)) error {
	h, body, err := wire.DecodeRDPDRHeader(msg)
	if err != nil {
		return err
	}
	if h.Component != wire.RDPDRCtypCore || h.PacketID != wire.PakidCoreDeviceIOCompletion {
		observe(msg)
		return m.toTarget(msg)
	}
	c, err := wire.DecodeIOCompletion(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	p := m.pending[c.CompletionID]
	if p == nil || p.device != c.DeviceID {
		m.mu.Unlock()
		return errors.New("unmatched redirected drive completion")
	}
	delete(m.pending, c.CompletionID)
	if p.result != nil && !p.abandoned {
		p.result <- driveResult{completion: c}
	}
	abandoned := p.abandoned
	m.mu.Unlock()
	if p.result != nil {
		// A canceled CREATE can still succeed remotely. Close that late handle.
		if abandoned && p.major == wire.IRPMJCreate && c.IoStatus == 0 {
			if file, _, err := wire.ParseCreateResponse(c.Tail); err == nil {
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, _ = m.request(ctx, wire.EncodeClose(c.DeviceID, file, 0))
				}()
			}
		}
		return nil
	}
	out := append([]byte(nil), msg...)
	binary.LittleEndian.PutUint32(out[8:], p.original)
	observe(out)
	return m.toTarget(out)
}

func (m *driveMux) request(ctx context.Context, msg []byte) (wire.IOCompletion, error) {
	if err := ctx.Err(); err != nil {
		return wire.IOCompletion{}, err
	}
	h, body, err := wire.DecodeRDPDRHeader(msg)
	if err != nil || h.Component != wire.RDPDRCtypCore || h.PacketID != wire.PakidCoreDeviceIORequest {
		return wire.IOCompletion{}, wire.ErrRDPDR
	}
	req, err := wire.DecodeIORequest(body)
	if err != nil {
		return wire.IOCompletion{}, err
	}
	result := make(chan driveResult, 1)
	id, err := m.reserve(req, result)
	if err != nil {
		return wire.IOCompletion{}, err
	}
	out := append([]byte(nil), msg...)
	binary.LittleEndian.PutUint32(out[12:], id)
	if err := m.toClient(out); err != nil {
		m.close()
		return wire.IOCompletion{}, err
	}
	select {
	case got := <-result:
		return got.completion, got.err
	case <-ctx.Done():
		m.mu.Lock()
		if p := m.pending[id]; p != nil {
			p.abandoned = true
			m.mu.Unlock()
			return wire.IOCompletion{}, ctx.Err()
		}
		m.mu.Unlock()
		// A racing completion has already been delivered; don't leak its handle.
		got := <-result
		return got.completion, got.err
	}
}

func (m *driveMux) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	for _, p := range m.pending {
		if p.result != nil && !p.abandoned {
			p.result <- driveResult{err: errDriveClosed}
		}
	}
	m.pending = map[uint32]*drivePending{}
}
