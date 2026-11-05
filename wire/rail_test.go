package wire

import (
	"encoding/binary"
	"testing"
)

func TestRailExecRoundTrip(t *testing.T) {
	in := RailExec{Flags: RailExecExpandArguments | RailExecExpandWorkingDir, ExeOrFile: "||Notepad", WorkingDir: `C:\Users\admin`, Arguments: "a.txt"}
	pdu := EncodeRailExec(in)
	typ, body, err := DecodeRailHeader(pdu)
	if err != nil || typ != RailOrderExec {
		t.Fatalf("header: type %#x err %v", typ, err)
	}
	out, err := DecodeRailExec(body)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %+v want %+v", out, in)
	}
	if _, err := DecodeRailExec(body[:len(body)-1]); err == nil {
		t.Fatal("truncated exec accepted")
	}
}

func TestRailExecResultRoundTrip(t *testing.T) {
	in := RailExecResult{Flags: 0x0008, ExecResult: RailExecFileNotFound, RawResult: 2, ExeOrFile: "||Missing"}
	pdu := EncodeRailExecResult(in)
	typ, body, err := DecodeRailHeader(pdu)
	if err != nil || typ != RailOrderExecResult {
		t.Fatalf("header: type %#x err %v", typ, err)
	}
	out, err := DecodeRailExecResult(body)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %+v want %+v", out, in)
	}
	if RailExecResultString(RailExecFileNotFound) != "file not found" || RailExecResultString(0x99) != "0x0099" {
		t.Fatal("result names")
	}
	if _, _, err := DecodeRailHeader([]byte{1, 0, 0x50, 0}); err == nil {
		t.Fatal("oversized order length accepted")
	}
}

// windowOrder builds a TS_ALTSEC_WINDOW order with the given fields.
func windowOrder(fields uint32, body []byte) []byte {
	b := make([]byte, 0, 7+len(body))
	b = append(b, altSecWindow<<2|0x02)
	b = binary.LittleEndian.AppendUint16(b, uint16(7+len(body)))
	b = binary.LittleEndian.AppendUint32(b, fields)
	return append(b, body...)
}

func TestDecodeWindowOrders(t *testing.T) {
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, 0x40042) // window id
	body = binary.LittleEndian.AppendUint32(body, 0)       // owner
	body = binary.LittleEndian.AppendUint32(body, 0x14cf0000)
	body = binary.LittleEndian.AppendUint32(body, 0x00000100)
	body = append(body, 1) // show: minimized
	title := encodeUTF16("无标题 - 记事本")
	body = binary.LittleEndian.AppendUint16(body, uint16(len(title)))
	body = append(body, title...)
	body = binary.LittleEndian.AppendUint32(body, uint32(0xFFFFFFF6)) // x = -10
	body = binary.LittleEndian.AppendUint32(body, 20)
	body = binary.LittleEndian.AppendUint32(body, 640)
	body = binary.LittleEndian.AppendUint32(body, 480)
	body = binary.LittleEndian.AppendUint16(body, 1)
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint16(body, 640)
	body = binary.LittleEndian.AppendUint16(body, 480)
	fields := WindowOrderTypeWindow | WindowOrderStateNew | WindowFieldOwner | WindowFieldStyle | WindowFieldShow | WindowFieldTitle | WindowFieldWndOffset | WindowFieldWndSize | WindowFieldWndRects
	stream := windowOrder(fields, body)
	// A deleted-window order and a desktop order follow.
	stream = append(stream, windowOrder(WindowOrderTypeWindow|WindowOrderStateDeleted, binary.LittleEndian.AppendUint32(nil, 0x40042))...)
	desk := binary.LittleEndian.AppendUint32(nil, 0x40042)
	desk = append(desk, 1)
	desk = binary.LittleEndian.AppendUint32(desk, 0x40042)
	stream = append(stream, windowOrder(WindowOrderTypeDesktop|WindowFieldDesktopActiveWnd|WindowFieldDesktopZOrder, desk)...)
	// A primary order terminates decoding without error.
	stream = append(stream, 0x01, 0xAA, 0xBB)

	ws, err := DecodeWindowOrders(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 3 {
		t.Fatalf("%d orders", len(ws))
	}
	w := ws[0]
	if !w.New() || w.WindowID != 0x40042 || w.Title != "无标题 - 记事本" || w.X != -10 || w.Y != 20 || w.Width != 640 || w.Height != 480 || w.Show != 1 || len(w.Rects) != 1 || w.Rects[0].Right != 640 {
		t.Fatalf("window: %+v", w)
	}
	if !ws[1].Deleted() || ws[1].WindowID != 0x40042 {
		t.Fatalf("deleted: %+v", ws[1])
	}
	if ws[2].Type() != WindowOrderTypeDesktop || ws[2].ActiveWindow != 0x40042 || len(ws[2].ZOrder) != 1 {
		t.Fatalf("desktop: %+v", ws[2])
	}
	if _, err := DecodeWindowOrders(stream[:len(stream)-12]); err == nil {
		t.Fatal("truncated stream accepted")
	}
}
