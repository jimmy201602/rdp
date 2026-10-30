package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"rdp.local/kernel/wire"
)

func completionFor(req []byte, status uint32, tail []byte) []byte {
	out := make([]byte, 16, len(tail)+16)
	binary.LittleEndian.PutUint16(out, wire.RDPDRCtypCore)
	binary.LittleEndian.PutUint16(out[2:], wire.PakidCoreDeviceIOCompletion)
	copy(out[4:8], req[4:8])
	copy(out[8:12], req[12:16])
	binary.LittleEndian.PutUint32(out[12:], status)
	return append(out, tail...)
}
func receive(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(time.Second):
		t.Fatal("missing channel message")
		return nil
	}
}
func TestDriveMuxIsolation(t *testing.T) {
	client, target := make(chan []byte, 10), make(chan []byte, 10)
	m := newDriveMux(func(p []byte) error { client <- p; return nil }, func(p []byte) error { target <- p; return nil })
	defer m.close()
	// Deliberately overlap the target's original IDs with the allocator.
	if err := m.server(wire.EncodeRead(7, 8, 2, 8, 0)); err != nil {
		t.Fatal(err)
	}
	first := receive(t, client)
	got := make(chan driveResult, 1)
	go func() {
		c, e := m.request(context.Background(), wire.EncodeRead(7, 9, 2, 8, 0))
		got <- driveResult{c, e}
	}()
	own := receive(t, client)
	if err := m.server(wire.EncodeRead(7, 10, binary.LittleEndian.Uint32(own[12:]), 8, 0)); err != nil {
		t.Fatal(err)
	}
	second := receive(t, client)
	ids := map[uint32]bool{}
	for _, p := range [][]byte{first, own, second} {
		id := binary.LittleEndian.Uint32(p[12:])
		if ids[id] {
			t.Fatal("completion id collision")
		}
		ids[id] = true
	}
	observed := 0
	observer := func(p []byte) {
		observed++
		if binary.LittleEndian.Uint32(p[8:]) != 2 {
			t.Fatal("observer received remapped id")
		}
	}
	if err := m.client(completionFor(own, 0, []byte{0, 0, 0, 0}), observer); err != nil {
		t.Fatal(err)
	}
	if res := <-got; res.err != nil {
		t.Fatal(res.err)
	}
	if observed != 0 || len(target) != 0 {
		t.Fatal("admin completion leaked to target/observer")
	}
	for _, p := range [][]byte{second, first} {
		if err := m.client(completionFor(p, 0, []byte{0, 0, 0, 0}), observer); err != nil {
			t.Fatal(err)
		}
		if binary.LittleEndian.Uint32(receive(t, target)[8:]) != 2 {
			t.Fatal("wrong restored id")
		}
	}
	if observed != 2 {
		t.Fatalf("observed %d", observed)
	}
}
func TestDriveMuxLateCreateClosesHandle(t *testing.T) {
	client := make(chan []byte, 10)
	m := newDriveMux(func(p []byte) error { client <- p; return nil }, func([]byte) error { t.Error("leaked completion"); return nil })
	defer m.close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := m.request(ctx, wire.EncodeCreate(1, 0, "\\a", wire.AccessReadFile, wire.FileOpen, wire.OptionsFile))
		done <- err
	}()
	req := receive(t, client)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if err := m.client(completionFor(req, 0, []byte{77, 0, 0, 0, 1}), func([]byte) {}); err != nil {
		t.Fatal(err)
	}
	closeReq := receive(t, client)
	if binary.LittleEndian.Uint32(closeReq[16:]) != wire.IRPMJClose || binary.LittleEndian.Uint32(closeReq[8:]) != 77 || binary.LittleEndian.Uint32(closeReq[4:]) != 1 {
		t.Fatal("late handle not closed")
	}
	if err := m.client(completionFor(closeReq, 0, nil), func([]byte) {}); err != nil {
		t.Fatal(err)
	}
}
func TestDriveMuxDisconnectAndWrongDevice(t *testing.T) {
	client := make(chan []byte, 10)
	m := newDriveMux(func(p []byte) error { client <- p; return nil }, func([]byte) error { return nil })
	done := make(chan error, 1)
	go func() { _, err := m.request(context.Background(), wire.EncodeRead(1, 2, 0, 1, 0)); done <- err }()
	req := receive(t, client)
	bad := completionFor(req, 0, nil)
	binary.LittleEndian.PutUint32(bad[4:], 2)
	if err := m.client(bad, func([]byte) {}); err == nil {
		t.Fatal("wrong device accepted")
	}
	m.close()
	if err := <-done; err == nil {
		t.Fatal("disconnect reported success")
	}
	if _, err := m.request(context.Background(), req); err == nil {
		t.Fatal("closed mux accepted request")
	}
}
func TestDriveMuxBoundedPending(t *testing.T) {
	m := newDriveMux(func([]byte) error { return nil }, func([]byte) error { return nil })
	defer m.close()
	for i := 0; i < 4096; i++ {
		if err := m.server(wire.EncodeRead(1, 2, uint32(i), 1, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.server(wire.EncodeRead(1, 2, 5000, 1, 0)); err == nil {
		t.Fatal("pending map is unbounded")
	}
}
