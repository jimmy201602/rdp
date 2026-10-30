package gateway

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// drdynvc commands (MS-RDPEDYC 2.2): the first byte of every PDU is
// Cmd (high nibble) | Sp (2 bits) | cbId (2 bits).
const (
	dvcCreate    = 0x01
	dvcDataFirst = 0x02
	dvcData      = 0x03
	dvcClose     = 0x04
	dvcCaps      = 0x05

	dvcMaxPDU      = 1600 // a DVC PDU must fit one static channel chunk
	dvcMaxMessage  = 8 << 20
	dvcNoListener  = 0xC0000001
	dvcVersionUsed = 2
)

// dvcHandler serves one dynamic channel. open gets a writer for it.
type dvcHandler interface {
	open(write func([]byte) error)
	data(msg []byte) error
	close()
}

// webDVC is the client side of drdynvc for a web session. Channels with a
// registered handler are accepted, all others are refused, which makes
// Windows fall back to the static equivalents (e.g. rdpsnd) or go without.
type webDVC struct {
	send     func([]byte) error
	logf     func(string, ...any)
	handlers map[string]func() dvcHandler

	mu    sync.Mutex
	open  map[uint32]*dvcChannel
	ready bool
}

type dvcChannel struct {
	name  string
	h     dvcHandler
	buf   []byte
	total int
}

func dvcIDLen(cb byte) int { return [4]int{1, 2, 4, 4}[cb&3] }

func readVar(b []byte, cb byte) (uint32, []byte, error) {
	n := dvcIDLen(cb)
	if len(b) < n {
		return 0, nil, errors.New("drdynvc: short PDU")
	}
	switch n {
	case 1:
		return uint32(b[0]), b[1:], nil
	case 2:
		return uint32(binary.LittleEndian.Uint16(b)), b[2:], nil
	}
	return binary.LittleEndian.Uint32(b), b[4:], nil
}

func varLen(v uint32) byte {
	switch {
	case v <= 0xff:
		return 0
	case v <= 0xffff:
		return 1
	}
	return 2
}

func appendVar(b []byte, v uint32, cb byte) []byte {
	switch dvcIDLen(cb) {
	case 1:
		return append(b, byte(v))
	case 2:
		return binary.LittleEndian.AppendUint16(b, uint16(v))
	}
	return binary.LittleEndian.AppendUint32(b, v)
}

func (d *webDVC) handle(msg []byte) error {
	if len(msg) < 1 {
		return nil
	}
	cmd, sp, cb := msg[0]>>4, (msg[0]>>2)&3, msg[0]&3
	body := msg[1:]
	switch cmd {
	case dvcCaps:
		if len(body) < 3 {
			return nil
		}
		version := binary.LittleEndian.Uint16(body[1:])
		if version > dvcVersionUsed {
			version = dvcVersionUsed
		}
		d.mu.Lock()
		d.ready = true
		d.mu.Unlock()
		return d.send(binary.LittleEndian.AppendUint16([]byte{dvcCaps << 4, 0}, version))
	case dvcCreate:
		id, rest, err := readVar(body, cb)
		if err != nil {
			return err
		}
		name := string(rest)
		if i := strings.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		mk := d.handlers[name]
		status := uint32(0)
		if mk == nil {
			status = dvcNoListener
		}
		reply := appendVar([]byte{dvcCreate<<4 | cb}, id, cb)
		reply = binary.LittleEndian.AppendUint32(reply, status)
		if err := d.send(reply); err != nil {
			return err
		}
		if d.logf != nil {
			d.logf("web session dynamic channel %q (id %d) %s", name, id, map[bool]string{true: "opened", false: "refused"}[mk != nil])
		}
		if mk == nil {
			return nil
		}
		ch := &dvcChannel{name: name, h: mk()}
		d.mu.Lock()
		if old := d.open[id]; old != nil {
			old.h.close()
		}
		if d.open == nil {
			d.open = map[uint32]*dvcChannel{}
		}
		d.open[id] = ch
		d.mu.Unlock()
		ch.h.open(func(p []byte) error { return d.write(id, p) })
	case dvcDataFirst, dvcData:
		id, rest, err := readVar(body, cb)
		if err != nil {
			return err
		}
		var total uint32
		if cmd == dvcDataFirst {
			if total, rest, err = readVar(rest, sp); err != nil {
				return err
			}
		}
		d.mu.Lock()
		ch := d.open[id]
		d.mu.Unlock()
		if ch == nil {
			return nil
		}
		switch {
		case cmd == dvcDataFirst && int(total) > len(rest):
			if total > dvcMaxMessage {
				return fmt.Errorf("drdynvc: %d byte message on %q", total, ch.name)
			}
			ch.buf, ch.total = append(make([]byte, 0, total), rest...), int(total)
			return nil
		case cmd == dvcData && ch.total > 0:
			ch.buf = append(ch.buf, rest...)
			if len(ch.buf) < ch.total {
				return nil
			}
			full := ch.buf[:ch.total]
			ch.buf, ch.total = nil, 0
			return ch.h.data(full)
		}
		return ch.h.data(rest)
	case dvcClose:
		id, _, err := readVar(body, cb)
		if err != nil {
			return err
		}
		d.mu.Lock()
		ch := d.open[id]
		delete(d.open, id)
		d.mu.Unlock()
		if ch != nil {
			ch.h.close()
			return d.send(appendVar([]byte{dvcClose<<4 | cb}, id, cb))
		}
	}
	return nil
}

// write sends msg on dynamic channel id, split into Data First / Data PDUs.
func (d *webDVC) write(id uint32, msg []byte) error {
	cb := varLen(id)
	if hdr := 1 + dvcIDLen(cb); hdr+len(msg) <= dvcMaxPDU {
		return d.send(append(appendVar([]byte{dvcData<<4 | cb}, id, cb), msg...))
	}
	sp := varLen(uint32(len(msg)))
	first := appendVar(appendVar([]byte{dvcDataFirst<<4 | sp<<2 | cb}, id, cb), uint32(len(msg)), sp)
	n := dvcMaxPDU - len(first)
	if err := d.send(append(first, msg[:n]...)); err != nil {
		return err
	}
	for msg = msg[n:]; len(msg) > 0; {
		hdr := appendVar([]byte{dvcData<<4 | cb}, id, cb)
		n := min(len(msg), dvcMaxPDU-len(hdr))
		if err := d.send(append(hdr, msg[:n]...)); err != nil {
			return err
		}
		msg = msg[n:]
	}
	return nil
}

func (d *webDVC) closeAll() {
	d.mu.Lock()
	open := d.open
	d.open = nil
	d.mu.Unlock()
	for _, ch := range open {
		ch.h.close()
	}
}

// displayControl is the client side of Microsoft::Windows::RDS::DisplayControl
// (MS-RDPEDISP): it sends a single-monitor layout whenever the browser
// asks for a new desktop size.
type displayControl struct {
	mu      sync.Mutex
	write   func([]byte) error
	ready   bool   // server's DISPLAYCONTROL_CAPS_PDU seen
	pending [2]int // size asked for before the channel was ready
	onReady func(bool)
}

const (
	dispTypeCaps   = 0x00000005
	dispTypeLayout = 0x00000002
)

func (c *displayControl) open(write func([]byte) error) {
	c.mu.Lock()
	c.write = write
	c.mu.Unlock()
}

func (c *displayControl) data(msg []byte) error {
	if len(msg) < 8 || binary.LittleEndian.Uint32(msg) != dispTypeCaps {
		return nil
	}
	c.mu.Lock()
	c.ready = true
	p := c.pending
	on := c.onReady
	c.mu.Unlock()
	if on != nil {
		on(true)
	}
	if p[0] > 0 {
		return c.resize(p[0], p[1])
	}
	return nil
}

func (c *displayControl) close() {
	c.mu.Lock()
	c.ready, c.write = false, nil
	on := c.onReady
	c.mu.Unlock()
	if on != nil {
		on(false)
	}
}

// clampLayout applies MS-RDPEDISP's limits: 200..8192 and an even width.
func clampLayout(w, h int) (int, int) {
	w, h = max(200, min(8192, w)), max(200, min(8192, h))
	return w &^ 1, h
}

// resize asks the server for a w x h desktop. It reports false when the
// target has no display control channel (Windows 7, 2008 R2).
func (c *displayControl) resize(w, h int) error {
	w, h = clampLayout(w, h)
	c.mu.Lock()
	write, ready := c.write, c.ready
	if !ready {
		c.pending = [2]int{w, h}
	}
	c.mu.Unlock()
	if !ready || write == nil {
		return ErrNoDisplayControl
	}
	b := binary.LittleEndian.AppendUint32(nil, dispTypeLayout)
	b = binary.LittleEndian.AppendUint32(b, 8+8+40)
	b = binary.LittleEndian.AppendUint32(b, 40) // MonitorLayoutSize
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint32(b, 1) // DISPLAYCONTROL_MONITOR_PRIMARY
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, uint32(w))
	b = binary.LittleEndian.AppendUint32(b, uint32(h))
	b = binary.LittleEndian.AppendUint32(b, 0) // physical size unknown
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0)   // landscape
	b = binary.LittleEndian.AppendUint32(b, 100) // desktop scale %
	b = binary.LittleEndian.AppendUint32(b, 100) // device scale %
	return write(b)
}

// ErrNoDisplayControl: the target cannot change the desktop size of a
// running session.
var ErrNoDisplayControl = errors.New("gateway: target does not support resizing a running session")

// soundDVC carries rdpsnd over AUDIO_PLAYBACK_DVC; the PDUs are the same.
type soundDVC struct {
	mk func(write func([]byte) error) *webSound
	s  *webSound
}

func (a *soundDVC) open(write func([]byte) error) { a.s = a.mk(write) }

func (a *soundDVC) data(msg []byte) error {
	if a.s == nil {
		return nil
	}
	return a.s.handle(msg)
}

func (a *soundDVC) close() {}
