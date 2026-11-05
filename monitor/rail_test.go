package monitor

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
	"unicode/utf16"

	"rdp.local/kernel/wire"
)

func drainRailEvents(t *testing.T, s *Session) []Event {
	t.Helper()
	var out []Event
	for {
		select {
		case e := <-s.audit.queue:
			out = append(out, e)
		default:
			return out
		}
	}
}

func TestRailExecEvents(t *testing.T) {
	s := &Session{audit: newAudit(), start: time.Now(), meta: Meta{RemoteApp: true}}
	s.ClientChannel("rail", wire.EncodeRailExec(wire.RailExec{Flags: wire.RailExecExpandArguments, ExeOrFile: "||Notepad", Arguments: `C:\notes.txt`}))
	s.ServerChannel("rail", wire.EncodeRailExecResult(wire.RailExecResult{ExecResult: wire.RailExecNotInAllowList, RawResult: 0x80070005, ExeOrFile: "||Notepad"}))
	s.ServerChannel("rail", []byte{1, 2}) // malformed: ignored
	evs := drainRailEvents(t, s)
	if len(evs) != 2 {
		t.Fatalf("%d events: %+v", len(evs), evs)
	}
	if evs[0].Kind != "rail" || evs[0].Source != "client" || evs[0].Action != "exec" || evs[0].Path != "||Notepad" || evs[0].Detail != `C:\notes.txt` {
		t.Fatalf("exec event: %+v", evs[0])
	}
	if evs[1].Action != "exec_result" || evs[1].Source != "target" || evs[1].Status != "not in allow list (0x80070005)" {
		t.Fatalf("result event: %+v", evs[1])
	}
	if s.Info().App != "||Notepad" || s.audit.appName() != "||Notepad" {
		t.Fatalf("app %q", s.Info().App)
	}
	js, _ := json.Marshal(evs[0])
	if string(js) == "" || !json.Valid(js) {
		t.Fatal("event json")
	}
}

func altsecWindow(fields uint32, body []byte) []byte {
	b := []byte{0x0B<<2 | 0x02}
	b = binary.LittleEndian.AppendUint16(b, uint16(7+len(body)))
	b = binary.LittleEndian.AppendUint32(b, fields)
	return append(b, body...)
}

func TestWindowOrderEvents(t *testing.T) {
	s := &Session{audit: newAudit(), start: time.Now(), meta: Meta{RemoteApp: true}}
	title := func(str string) []byte {
		var u []byte
		for _, c := range utf16.Encode([]rune(str)) {
			u = binary.LittleEndian.AppendUint16(u, c)
		}
		return append(binary.LittleEndian.AppendUint16(nil, uint16(len(u))), u...)
	}
	newBody := binary.LittleEndian.AppendUint32(nil, 7)
	newBody = append(newBody, 5) // shown
	newBody = append(newBody, title("Untitled - Notepad")...)
	newBody = binary.LittleEndian.AppendUint32(newBody, 100)
	newBody = binary.LittleEndian.AppendUint32(newBody, 50)
	newBody = binary.LittleEndian.AppendUint32(newBody, 800)
	newBody = binary.LittleEndian.AppendUint32(newBody, 600)
	stream := altsecWindow(wire.WindowOrderTypeWindow|wire.WindowOrderStateNew|wire.WindowFieldShow|wire.WindowFieldTitle|wire.WindowFieldWndOffset|wire.WindowFieldWndSize, newBody)
	// Two moves within a second: only the first is logged.
	move := func(x uint32) []byte {
		b := binary.LittleEndian.AppendUint32(nil, 7)
		b = binary.LittleEndian.AppendUint32(b, x)
		return binary.LittleEndian.AppendUint32(b, 50)
	}
	stream = append(stream, altsecWindow(wire.WindowOrderTypeWindow|wire.WindowFieldWndOffset, move(110))...)
	stream = append(stream, altsecWindow(wire.WindowOrderTypeWindow|wire.WindowFieldWndOffset, move(120))...)
	// Title change, activation, then deletion.
	stream = append(stream, altsecWindow(wire.WindowOrderTypeWindow|wire.WindowFieldTitle, append(binary.LittleEndian.AppendUint32(nil, 7), title("*notes.txt - Notepad")...))...)
	stream = append(stream, altsecWindow(wire.WindowOrderTypeDesktop|wire.WindowFieldDesktopActiveWnd, binary.LittleEndian.AppendUint32(nil, 7))...)
	stream = append(stream, altsecWindow(wire.WindowOrderTypeWindow|wire.WindowOrderStateDeleted, binary.LittleEndian.AppendUint32(nil, 7))...)
	// Fast-path orders update: numberOrders then the orders.
	s.windowOrders(stream)
	evs := drainRailEvents(t, s)
	want := []string{"new", "move", "title", "activate", "closed"}
	if len(evs) != len(want) {
		t.Fatalf("%d events: %+v", len(evs), evs)
	}
	for i, a := range want {
		if evs[i].Kind != "window" || evs[i].Action != a || evs[i].Device != 7 {
			t.Fatalf("event %d: %+v", i, evs[i])
		}
	}
	if evs[0].Detail != "Untitled - Notepad" || evs[0].Status != "shown" || evs[0].X != 100 || evs[0].W != 800 || evs[0].H != 600 {
		t.Fatalf("new: %+v", evs[0])
	}
	if evs[1].X != 110 || evs[2].Detail != "*notes.txt - Notepad" || evs[4].Detail != "*notes.txt - Notepad" {
		t.Fatalf("move/title/closed: %+v %+v %+v", evs[1], evs[2], evs[4])
	}
	if len(s.audit.windows) != 0 {
		t.Fatal("window not forgotten after delete")
	}
}
