package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"rdp.local/kernel/transport"
	"rdp.local/kernel/wire"
)

// activateClient completes one Demand Active / Confirm Active /
// finalization round from the client side and returns the Demand Active.
func activateClient(t *testing.T, s *transport.Session, first []byte) wire.DemandActive {
	t.Helper()
	data := first
	if data == nil {
		p, err := s.ReadPDU()
		if err != nil {
			t.Fatalf("demand active: %v", err)
		}
		data = p.Data
	}
	demand, err := wire.DecodeDemandActive(data)
	if err != nil {
		t.Fatalf("demand active: %v", err)
	}
	sets := wire.DefaultClientCapabilities(wire.ClientCapabilityOptions{DesktopWidth: 320, DesktopHeight: 200, ColorDepth: 16, KeyboardType: wire.KeyboardTypeIBMEnhance})
	user := s.UserChannel()
	pdu, err := wire.EncodeConfirmActive(demand.ShareID, user, "GOTEST", sets)
	if err != nil {
		t.Fatal(err)
	}
	for _, enc := range [][]byte{pdu} {
		if err := s.WriteIO(enc); err != nil {
			t.Fatal(err)
		}
	}
	for _, enc := range []func() ([]byte, error){
		func() ([]byte, error) { return wire.EncodeSynchronize(demand.ShareID, user, demand.Control.PDUSource) },
		func() ([]byte, error) { return wire.EncodeControl(demand.ShareID, user, wire.CtrlActionCooperate) },
		func() ([]byte, error) { return wire.EncodeControl(demand.ShareID, user, wire.CtrlActionRequestControl) },
		func() ([]byte, error) { return wire.EncodeFontList(demand.ShareID, user) },
	} {
		p, err := enc()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.WriteIO(p); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		p, err := s.ReadPDU()
		if err != nil {
			t.Fatalf("finalization: %v", err)
		}
		d, err := wire.DecodeDataPDU(p.Data)
		if err != nil {
			t.Fatalf("finalization: %v", err)
		}
		if d.Header.PDUType2 == wire.PDUType2FontMap {
			return demand
		}
	}
	t.Fatal("no Font Map")
	return demand
}

func TestHandlerActivateInputAndReactivate(t *testing.T) {
	type seen struct {
		act1, act2 Activation
		inputs     []Input
		err        error
	}
	got := make(chan seen, 1)
	h := start(t, nil, func(c *Config) {
		c.Handler = func(ctx context.Context, c *Conn) error {
			var s seen
			defer func() { got <- s }()
			if s.act1, s.err = c.Activate(); s.err != nil {
				return s.err
			}
			f := NewFrame(s.act1.Width, s.act1.Height)
			f.Fill(0, 0, 320, 200, 10, 20, 30)
			if s.err = c.SendFrame(f); s.err != nil {
				return s.err
			}
			if s.err = c.SendPointer(nil); s.err != nil {
				return s.err
			}
			if s.err = c.SendBitmap(f, 13, 7, 50, 20); s.err != nil { // unaligned, clipped
				return s.err
			}
			if s.err = c.SendBitmap(f, 400, 7, 50, 20); s.err != nil { // fully outside: no-op
				return s.err
			}
			for len(s.inputs) < 3 {
				p, err := c.ReadPDU()
				if err != nil {
					s.err = err
					return err
				}
				in, err := c.DecodeInput(p)
				if err != nil {
					s.err = err
					return err
				}
				if len(in.Events) > 0 || in.Refresh {
					s.inputs = append(s.inputs, in)
				}
			}
			if s.err = c.DeactivateAll(); s.err != nil {
				return s.err
			}
			if s.act2, s.err = c.Activate(); s.err != nil {
				return s.err
			}
			if s.err = c.SendFrame(f); s.err != nil {
				return s.err
			}
			for {
				p, err := c.ReadPDU()
				if err != nil {
					return nil
				}
				if in, _ := c.DecodeInput(p); in.Shutdown {
					return nil
				}
			}
		}
	})
	sess, err := transport.Dial(context.Background(), h.addr, clientOpts(h))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = sess.Close() }()
	demand := activateClient(t, sess, nil)
	if demand.ShareID != shareID {
		t.Fatalf("shareID 0x%08x", demand.ShareID)
	}
	// Collect the initial frame, pointer and partial update.
	rects, pointers := 0, 0
	deadline := time.Now().Add(5 * time.Second)
	for rects < 100 || pointers < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("rects=%d pointers=%d", rects, pointers)
		}
		p, err := sess.ReadPDU()
		if err != nil {
			t.Fatal(err)
		}
		d, err := wire.DecodeDataPDU(p.Data)
		if err != nil {
			t.Fatal(err)
		}
		switch d.Header.PDUType2 {
		case wire.PDUType2Update:
			u, err := wire.DecodeUpdate(d.Body)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range u.Bitmaps {
				if b.BitsPerPixel != 16 {
					t.Fatalf("bitmap at %d bpp, confirmed 16", b.BitsPerPixel)
				}
				if b.DestLeft == 12 && b.DestTop == 7 && b.Width == 52 && b.Height == 20 {
					rects += 100 // the aligned partial update
				}
				rects++
			}
		case wire.PDUType2Pointer:
			pointers++
		}
	}
	if rects < 100 {
		t.Fatal("partial SendBitmap rectangle (12,7 52x20) not seen")
	}
	// Slow-path input, fast-path input, refresh rect.
	body, _ := wire.EncodeInputPDU([]wire.InputEvent{{Kind: wire.InputKindScancode, Code: 0x1E}, {Kind: wire.InputKindScancode, Code: 0x1E, Flags: 0x8000}})
	slow, _ := wire.EncodeShareData(shareID, sess.UserChannel(), wire.PDUType2Input, body)
	if err := sess.WriteIO(slow); err != nil {
		t.Fatal(err)
	}
	fast, _ := wire.EncodeFastPathInput([]wire.InputEvent{{Kind: wire.InputKindMouse, Flags: 0x9000, X: 5, Y: 6}})
	if err := sess.WriteFastPath(fast); err != nil {
		t.Fatal(err)
	}
	refresh, _ := wire.EncodeShareData(shareID, sess.UserChannel(), wire.PDUType2RefreshRect, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err := sess.WriteIO(refresh); err != nil {
		t.Fatal(err)
	}
	// Expect Deactivate All, then a fresh Demand Active.
	var deact bool
	var second []byte
	for second == nil {
		p, err := sess.ReadPDU()
		if err != nil {
			t.Fatal(err)
		}
		ctl, _, err := wire.DecodeShareControl(p.Data)
		if err != nil {
			t.Fatal(err)
		}
		switch ctl.PDUType {
		case wire.PDUTypeDeactivateAll:
			deact = true
		case wire.PDUTypeDemandActive:
			if !deact {
				t.Fatal("Demand Active before Deactivate All")
			}
			second = p.Data
		}
	}
	activateClient(t, sess, second)
	p, err := sess.ReadPDU()
	if err != nil {
		t.Fatal(err)
	}
	if d, err := wire.DecodeDataPDU(p.Data); err != nil || d.Header.PDUType2 != wire.PDUType2Update {
		t.Fatalf("after reactivation: %+v %v", d.Header, err)
	}
	shutdown, _ := wire.EncodeShareData(shareID, sess.UserChannel(), wire.PDUType2ShutdownRequest, nil)
	if err := sess.WriteIO(shutdown); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s.err != nil {
			t.Fatalf("handler: %v", s.err)
		}
		if s.act1.Width != 320 || s.act1.BPP != 16 || s.act2.BPP != 16 || len(s.act2.ClientCaps) == 0 {
			t.Fatalf("activations %+v %+v", s.act1, s.act2)
		}
		if len(s.inputs) != 3 || len(s.inputs[0].Events) != 2 || s.inputs[0].FastPath ||
			!s.inputs[1].FastPath || s.inputs[1].Events[0].Kind != wire.InputKindMouse || s.inputs[1].Events[0].X != 5 ||
			!s.inputs[2].Refresh {
			t.Fatalf("inputs %+v", s.inputs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	sum := h.waitSummary(t)
	if sum.Err != nil && !errors.Is(sum.Err, context.Canceled) {
		t.Fatalf("summary %+v", sum)
	}
}

func TestDecodeInputRejectsGarbage(t *testing.T) {
	c := &Conn{s: &session{}}
	if _, err := c.DecodeInput(PDU{FastPath: true, Data: []byte{0x04, 0x01}}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("fast-path garbage: %v", err)
	}
	if in, err := c.DecodeInput(PDU{Channel: 1004, Data: []byte{1, 2, 3}}); err != nil || len(in.Events) != 0 {
		t.Fatalf("channel data: %+v %v", in, err)
	}
	if err := c.SendFrame(NewFrame(4, 4)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("SendFrame before Activate: %v", err)
	}
}
