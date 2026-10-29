package wire

import (
	"bufio"
	"bytes"
	"testing"
)

func TestInputPDURoundTrip(t *testing.T) {
	events := []InputEvent{
		{Kind: InputKindSync, Flags: 0x0002},
		{Kind: InputKindScancode, Flags: 0x8000, Code: 0x1e},
		{Kind: InputKindUnicode, Code: 0x4e2d},
		{Kind: InputKindMouse, Flags: 0x0800, X: 100, Y: 200},
		{Kind: InputKindMouseX, Flags: 0x8001, X: 1, Y: 2},
	}
	body, err := EncodeInputPDU(events)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 4+5*12 {
		t.Fatalf("body %d bytes", len(body))
	}
	got, err := DecodeInputPDU(body)
	if err != nil {
		t.Fatal(err)
	}
	for i := range events {
		if got[i] != events[i] {
			t.Fatalf("event %d: %+v != %+v", i, got[i], events[i])
		}
	}
	for _, bad := range [][]byte{body[:3], body[:len(body)-1], append(append([]byte{}, body...), 0),
		{1, 0, 0, 0, 0, 0, 0, 0, 0x99, 0x99, 0, 0, 0, 0, 0, 0}} {
		if _, err := DecodeInputPDU(bad); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
	if _, err := EncodeInputPDU(nil); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestFastPathInputRoundTrip(t *testing.T) {
	events := []InputEvent{
		{Kind: InputKindScancode, Flags: 0x01, Code: 0x1e},
		{Kind: InputKindUnicode, Code: 0x4e2d},
		{Kind: InputKindSync, Flags: 0x02},
		{Kind: InputKindMouse, Flags: 0x0800, X: 100, Y: 200},
		{Kind: InputKindMouseX, Flags: 0x8001, X: 1, Y: 2},
	}
	frame, err := EncodeFastPathInput(events)
	if err != nil {
		t.Fatal(err)
	}
	if frame[0] != 5<<2 || int(frame[1]) != len(frame) {
		t.Fatalf("header %x", frame[:2])
	}
	got, err := DecodeFastPathInput(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) {
		t.Fatalf("%d events", len(got))
	}
	for i := range events {
		if got[i] != events[i] {
			t.Fatalf("event %d: %+v != %+v", i, got[i], events[i])
		}
	}
	// 20 events: numEvents byte form; also exercises ReadFastPathFrame.
	many := make([]InputEvent, 20)
	for i := range many {
		many[i] = InputEvent{Kind: InputKindMouse, Flags: 0x0800, X: uint16(i), Y: 1}
	}
	frame, err = EncodeFastPathInput(many)
	if err != nil {
		t.Fatal(err)
	}
	if frame[0]>>2&0x0f != 0 || frame[1]&0x80 != 0x80 {
		t.Fatalf("header %x for 20 events (%d bytes)", frame[:3], len(frame))
	}
	if got, err = DecodeFastPathInput(frame); err != nil || len(got) != 20 || got[19].X != 19 {
		t.Fatalf("%d events, %v", len(got), err)
	}
	r := bufio.NewReader(bytes.NewReader(append(append([]byte{}, frame...), 3, 0, 0, 7)))
	raw, err := ReadFastPathFrame(r, 0)
	if err != nil || !bytes.Equal(raw, frame) {
		t.Fatalf("frame %x err %v", raw, err)
	}
	if rest, _ := r.Peek(4); !bytes.Equal(rest, []byte{3, 0, 0, 7}) {
		t.Fatalf("over-read: %x", rest)
	}
	for _, bad := range [][]byte{{0x04}, {0x04, 0x03, 0x20}, {0x04, 0x02}, {0x84, 0x04, 0x20, 0x1e}, {0x08, 0x04, 0x20, 0x1e}, {0x04, 0x05, 0x20, 0x1e, 0}, {0x04, 0x03, 0xe0}} {
		if _, err := DecodeFastPathInput(bad); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
	if _, err := ReadFastPathFrame(bufio.NewReader(bytes.NewReader([]byte{3, 0, 0, 7})), 0); err == nil {
		t.Fatal("TPKT accepted as fast-path")
	}
	if _, err := ReadFastPathFrame(bufio.NewReader(bytes.NewReader([]byte{0x80, 0x04, 0, 0})), 0); err == nil {
		t.Fatal("encrypted frame accepted")
	}
}

func FuzzDecodeFastPathInput(f *testing.F) {
	frame, _ := EncodeFastPathInput([]InputEvent{{Kind: InputKindMouse, X: 1, Y: 2}, {Kind: InputKindScancode, Code: 0x1c}})
	f.Add(frame)
	f.Fuzz(func(t *testing.T, p []byte) {
		if ev, err := DecodeFastPathInput(p); err == nil && len(ev) > 255 {
			t.Fatal("too many events")
		}
		_, _ = DecodeInputPDU(p)
	})
}
