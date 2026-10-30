package monitor

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

func maskedFrame(b0 byte, p []byte) []byte {
	f := []byte{b0, 0x80 | byte(len(p)), 1, 2, 3, 4}
	for i, c := range p {
		f = append(f, c^[]byte{1, 2, 3, 4}[i%4])
	}
	return f
}

func TestWSReadFragmented(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &wsConn{conn: a, br: bufio.NewReader(a)}
	var in []byte
	in = append(in, maskedFrame(wsText, []byte(`{"t":`))...)
	in = append(in, maskedFrame(0x80|wsPing, []byte("hi"))...)
	in = append(in, maskedFrame(0x00, []byte(`"fs",`))...)
	in = append(in, maskedFrame(0x80, []byte(`"id":1}`))...)
	in = append(in, maskedFrame(0x80|wsBinary, []byte{7})...)
	go func() { _, _ = b.Write(in) }()
	go func() { // drain the pong
		buf := make([]byte, 64)
		_, _ = b.Read(buf)
	}()
	op, p, err := c.read()
	if err != nil || op != wsText || string(p) != `{"t":"fs","id":1}` {
		t.Fatalf("got %d %q %v", op, p, err)
	}
	op, p, err = c.read()
	if err != nil || op != wsBinary || !bytes.Equal(p, []byte{7}) {
		t.Fatalf("got %d %q %v", op, p, err)
	}
}
