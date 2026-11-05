package gateway

import (
	"testing"

	"rdp.local/kernel/wire"
)

func TestFilterCapsRemoteApp(t *testing.T) {
	sets := []wire.CapabilitySet{
		{Type: wire.CapsTypeGeneral}, {Type: wire.CapsTypeRail}, {Type: wire.CapsTypeWindow}, {Type: wire.CapsTypeBitmapCodecs},
	}
	desktop := &relay{g: &Gateway{cfg: Config{AllowCapability: DefaultAllowCapability}}, sum: Summary{DroppedCapabilities: map[uint16]int{}}}
	if kept := desktop.filterCaps(sets); len(kept) != 1 || kept[0].Type != wire.CapsTypeGeneral {
		t.Fatalf("desktop session kept %+v", kept)
	}
	if desktop.sum.DroppedCapabilities[wire.CapsTypeRail] != 1 || desktop.sum.DroppedCapabilities[wire.CapsTypeWindow] != 1 {
		t.Fatalf("drops %v", desktop.sum.DroppedCapabilities)
	}
	rail := &relay{g: &Gateway{cfg: Config{AllowCapability: DefaultAllowCapability}}, sum: Summary{RemoteApp: true, DroppedCapabilities: map[uint16]int{}}}
	kept := rail.filterCaps(sets)
	if len(kept) != 3 || kept[1].Type != wire.CapsTypeRail || kept[2].Type != wire.CapsTypeWindow {
		t.Fatalf("rail session kept %+v", kept)
	}
	if rail.sum.DroppedCapabilities[wire.CapsTypeBitmapCodecs] != 1 || len(rail.sum.DroppedCapabilities) != 1 {
		t.Fatalf("drops %v", rail.sum.DroppedCapabilities)
	}
}

func TestSplitUserTarget(t *testing.T) {
	cases := []struct {
		in, user, host string
		ok             bool
	}{
		{"administrator@192.0.2.20", "administrator", "192.0.2.20:3389", true},
		{"admin@host.example:3390", "admin", "host.example:3390", true},
		{"admin@[fe80::1]", "admin", "[fe80::1]:3389", true},
		{"administrator", "administrator", "", false},
		{"@host", "@host", "", false},
		{"admin@", "admin@", "", false},
	}
	for _, c := range cases {
		user, host, ok := splitUserTarget(c.in)
		if user != c.user || host != c.host || ok != c.ok {
			t.Errorf("%q: got (%q, %q, %v), want (%q, %q, %v)", c.in, user, host, ok, c.user, c.host, c.ok)
		}
	}
}
