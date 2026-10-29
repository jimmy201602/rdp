package server

import (
	"context"
	"fmt"

	"rdp.local/kernel/wire"
)

// Activation describes the client after Activate: the desktop size and
// colour depth it confirmed and its full capability sets.
type Activation struct {
	Width, Height uint16
	BPP           uint16
	ClientCaps    []wire.CapabilitySet
}

// Activate runs the server-side Capability Exchange (Demand Active with the
// server's default capability sets, Confirm Active) and Connection
// Finalization on the I/O channel; afterwards the client is in the active
// state and accepts graphics and sends input. A Handler calls it when it
// wants to drive the client itself, and may call it again after
// DeactivateAll (Deactivation-Reactivation Sequence, MS-RDPBCGR 1.3.1.3).
func (c *Conn) Activate() (Activation, error) {
	ctx := context.Background()
	if err := c.s.capabilities(ctx); err != nil {
		return Activation{}, err
	}
	if err := c.s.finalize(ctx); err != nil {
		return Activation{}, err
	}
	return Activation{Width: c.s.peer.DesktopWidth, Height: c.s.peer.DesktopHeight, BPP: c.s.bpp, ClientCaps: c.s.clientCaps}, nil
}

// DeactivateAll sends a Deactivate All PDU: the client drops the active
// state and waits for a new Demand Active, which may come from Activate or
// from a relayed server. Buffered client input sent before the client saw
// the PDU may still arrive and should be discarded.
func (c *Conn) DeactivateAll() error {
	pdu, err := wire.EncodeDeactivateAll(shareID, sourceDescriptor)
	if err != nil {
		return err
	}
	return c.s.writeIO(pdu)
}

// SendBitmap sends the region (x, y, w, h) of f (top-down 24bpp BGR) as
// uncompressed Bitmap Updates at the activated colour depth, split into
// rectangles of at most 16 KiB. The region is clipped to f and widened to a
// 4-pixel boundary so uncompressed rows stay 4-byte aligned at 24 bpp.
func (c *Conn) SendBitmap(f *Frame, x, y, w, h int) error {
	if c.s.bpp == 0 {
		return fmt.Errorf("%w: SendBitmap before Activate", ErrProtocol)
	}
	if err := f.validate(); err != nil {
		return err
	}
	return c.s.sendRegion(f, x, y, w, h)
}

// SendFrame sends all of f.
func (c *Conn) SendFrame(f *Frame) error {
	return c.SendBitmap(f, 0, 0, int(f.Width), int(f.Height))
}

// SendPointer sends p (DefaultPointer when nil) as a colour pointer update.
func (c *Conn) SendPointer(p *Pointer) error {
	if p == nil {
		p = DefaultPointer()
	}
	return c.s.sendPointer(p)
}

// Input is the decoded content of a client PDU read with ReadPDU.
type Input struct {
	Events   []wire.InputEvent // keyboard / mouse / sync events, if any
	FastPath bool              // Events came from a fast-path frame (flag encoding differs)
	Refresh  bool              // Refresh Rect PDU: resend the desktop
	Shutdown bool              // Shutdown Request PDU: the user closed the client
}

// DecodeInput interprets a PDU from ReadPDU while the client is active.
// Static channel data and share PDUs that are not input, Refresh Rect or
// Shutdown Request yield an empty Input. Malformed input is an error.
func (c *Conn) DecodeInput(p PDU) (Input, error) {
	if p.Channel != 0 {
		return Input{}, nil
	}
	if p.FastPath {
		evs, err := wire.DecodeFastPathInput(p.Data)
		if err != nil {
			return Input{}, fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		return Input{Events: evs, FastPath: true}, nil
	}
	ctl, _, err := wire.DecodeShareControl(p.Data)
	if err != nil {
		return Input{}, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if ctl.PDUType != wire.PDUTypeData {
		return Input{}, nil
	}
	d, err := wire.DecodeDataPDU(p.Data)
	if err != nil {
		return Input{}, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	switch d.Header.PDUType2 {
	case wire.PDUType2Input:
		evs, err := wire.DecodeInputPDU(d.Body)
		if err != nil {
			return Input{}, fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		return Input{Events: evs}, nil
	case wire.PDUType2RefreshRect:
		return Input{Refresh: true}, nil
	case wire.PDUType2ShutdownRequest:
		return Input{Shutdown: true}, nil
	}
	return Input{}, nil
}
