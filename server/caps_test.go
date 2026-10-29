package server

import (
	"testing"

	"rdp.local/kernel/wire"
)

// The first Demand Active must not be narrower than anything a relayed
// target may later advertise: clients merge Demand Actives by AND-ing the
// optional flags and never re-enable a feature once it was dropped.
func TestServerCapabilitiesKeepRelayFeaturesNegotiable(t *testing.T) {
	s := &session{peer: Peer{DesktopWidth: 1024, DesktopHeight: 768}}
	sets := s.serverCapabilities()

	gen, ok := wire.FindCapability(sets, wire.CapsTypeGeneral)
	if !ok {
		t.Fatal("no general capability set")
	}
	g, err := wire.DecodeGeneralCapability(gen)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []uint16{wire.GeneralFastPathOutputSupported, wire.GeneralLongCredentialsSupported, wire.GeneralNoBitmapCompressionHdr, wire.GeneralEncSaltedChecksum} {
		if g.ExtraFlags&f == 0 {
			t.Errorf("general extraFlags 0x%04x lacks 0x%04x", g.ExtraFlags, f)
		}
	}
	if g.RefreshRectSupport != 1 || g.SuppressOutputSupport != 1 {
		t.Errorf("refreshRect %d suppressOutput %d", g.RefreshRectSupport, g.SuppressOutputSupport)
	}

	bmp, _ := wire.FindCapability(sets, wire.CapsTypeBitmap)
	b, err := wire.DecodeBitmapCapability(bmp)
	if err != nil {
		t.Fatal(err)
	}
	if b.DesktopWidth != 1024 || b.DesktopHeight != 768 || b.DesktopResizeFlag != 1 {
		t.Errorf("bitmap %+v", b)
	}
	if want := wire.DrawAllowDynamicColorFidelity | wire.DrawAllowColorSubsampling | wire.DrawAllowSkipAlpha; b.DrawingFlags&want != want {
		t.Errorf("drawingFlags 0x%02x", b.DrawingFlags)
	}

	ord, _ := wire.FindCapability(sets, wire.CapsTypeOrder)
	o, err := wire.DecodeOrderCapability(ord)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range o.OrderSupport {
		if v != 1 {
			t.Errorf("orderSupport[%d] = %d", i, v)
		}
	}
	if o.OrderFlags&wire.OrderFlagsExtraFlags == 0 ||
		o.OrderSupportExFlags&(wire.OrderSupportExCacheBitmapV3|wire.OrderSupportExAltSecFrameMarker) !=
			wire.OrderSupportExCacheBitmapV3|wire.OrderSupportExAltSecFrameMarker {
		t.Errorf("orderFlags 0x%04x orderSupportExFlags 0x%04x", o.OrderFlags, o.OrderSupportExFlags)
	}

	in, _ := wire.FindCapability(sets, wire.CapsTypeInput)
	i, err := wire.DecodeInputCapability(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []uint16{wire.InputFlagScancodes, wire.InputFlagMouseX, wire.InputFlagFastPathInput, wire.InputFlagUnicode, wire.InputFlagFastPathInput2, wire.InputFlagMouseHWheel} {
		if i.InputFlags&f == 0 {
			t.Errorf("inputFlags 0x%04x lacks 0x%04x", i.InputFlags, f)
		}
	}

	ptr, _ := wire.FindCapability(sets, wire.CapsTypePointer)
	p, err := wire.DecodePointerCapability(ptr)
	if err != nil {
		t.Fatal(err)
	}
	if p.ColorPointerCacheSize < wire.DefaultPointerCacheSize || p.PointerCacheSize < wire.DefaultPointerCacheSize {
		t.Errorf("pointer cache %+v smaller than client default %d", p, wire.DefaultPointerCacheSize)
	}
}
