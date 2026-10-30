package gateway

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type recDVC struct {
	opened bool
	got    [][]byte
	write  func([]byte) error
}

func (r *recDVC) open(w func([]byte) error) { r.opened, r.write = true, w }
func (r *recDVC) data(m []byte) error       { r.got = append(r.got, append([]byte(nil), m...)); return nil }
func (r *recDVC) close()                    {}

func TestWebDVC(t *testing.T) {
	var sent [][]byte
	h := &recDVC{}
	d := &webDVC{send: func(b []byte) error { sent = append(sent, append([]byte(nil), b...)); return nil },
		handlers: map[string]func() dvcHandler{"echo": func() dvcHandler { return h }}}
	if err := d.handle([]byte{dvcCaps << 4, 0, 3, 0}); err != nil || !bytes.Equal(sent[0], []byte{0x50, 0, 2, 0}) {
		t.Fatalf("caps reply %x %v", sent, err)
	}
	sent = nil
	_ = d.handle(append([]byte{dvcCreate << 4, 7}, "nope\x00"...))
	_ = d.handle(append([]byte{dvcCreate<<4 | 1, 0x34, 0x12}, "echo\x00"...))
	if binary.LittleEndian.Uint32(sent[0][2:]) != dvcNoListener || binary.LittleEndian.Uint32(sent[1][3:]) != 0 || !h.opened {
		t.Fatalf("create replies %x", sent)
	}
	// Data First + Data reassemble.
	_ = d.handle([]byte{dvcDataFirst<<4 | 1, 0x34, 0x12, 5, 'h', 'e'})
	_ = d.handle([]byte{dvcData<<4 | 1, 0x34, 0x12, 'l', 'l', 'o'})
	if len(h.got) != 1 || string(h.got[0]) != "hello" {
		t.Fatalf("got %q", h.got)
	}
	// Long writes are split into PDUs that fit one channel chunk.
	sent = nil
	big := bytes.Repeat([]byte{9}, 4000)
	if err := h.write(big); err != nil {
		t.Fatal(err)
	}
	var total int
	for i, p := range sent {
		if len(p) > dvcMaxPDU {
			t.Fatalf("pdu %d is %d bytes", i, len(p))
		}
		hdr := 3
		if i == 0 {
			if p[0]>>4 != dvcDataFirst {
				t.Fatalf("first pdu %x", p[:4])
			}
			hdr = 5
		}
		total += len(p) - hdr
	}
	if total != len(big) {
		t.Fatalf("sent %d bytes", total)
	}
}

func TestDisplayControlLayout(t *testing.T) {
	var out []byte
	c := &displayControl{}
	c.open(func(b []byte) error { out = b; return nil })
	if err := c.resize(1601, 900); err != ErrNoDisplayControl {
		t.Fatalf("before caps: %v", err)
	}
	caps := binary.LittleEndian.AppendUint32(nil, dispTypeCaps)
	caps = binary.LittleEndian.AppendUint32(caps, 20)
	caps = append(caps, make([]byte, 12)...)
	if err := c.data(caps); err != nil {
		t.Fatal(err)
	}
	// The pending request is sent once the caps arrive; width made even.
	if len(out) != 56 || binary.LittleEndian.Uint32(out) != dispTypeLayout || binary.LittleEndian.Uint32(out[28:]) != 1600 || binary.LittleEndian.Uint32(out[32:]) != 900 {
		t.Fatalf("layout %x", out)
	}
}
