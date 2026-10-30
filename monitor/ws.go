package monitor

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// A minimal RFC 6455 server: text/binary messages (fragmented or not),
// ping/pong, close. Enough for the monitor UI without a third-party dependency.

const (
	wsText   = 0x1
	wsBinary = 0x2
	wsClose  = 0x8
	wsPing   = 0x9
	wsPong   = 0xa

	wsMaxMessage = 4 << 20
	wsGUID       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

var errWSProtocol = errors.New("websocket: protocol error")

type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

func wsUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if r.Method != http.MethodGet || !headerHas(r.Header, "Connection", "upgrade") || !headerHas(r.Header, "Upgrade", "websocket") || key == "" || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errWSProtocol
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return nil, errWSProtocol
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"
	_ = conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte(resp)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn, br: brw.Reader}, nil
}

func (c *wsConn) write(op byte, payload []byte) error {
	hdr := make([]byte, 2, 10+len(payload))
	hdr[0] = 0x80 | op
	switch n := len(payload); {
	case n < 126:
		hdr[1] = byte(n)
	case n <= 0xffff:
		hdr[1] = 126
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr[1] = 127
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := c.conn.Write(append(hdr, payload...))
	return err
}

// read returns the next text or binary message, answering pings; io.EOF
// once the peer closed.
func (c *wsConn) read() (byte, []byte, error) {
	// Browsers split large messages (Chromium: ~64 KiB and up) into a first
	// frame plus continuation frames; control frames may come in between.
	var msgOp byte
	var msg []byte
	for {
		var h [2]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return 0, nil, err
		}
		fin, op, masked := h[0]&0x80 != 0, h[0]&0x0f, h[1]&0x80 != 0
		if !masked || h[0]&0x70 != 0 {
			return 0, nil, fmt.Errorf("%w: unmasked or extension frame", errWSProtocol)
		}
		if op >= 0x8 && !fin {
			return 0, nil, fmt.Errorf("%w: fragmented control frame", errWSProtocol)
		}
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return 0, nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return 0, nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > wsMaxMessage || uint64(len(msg))+n > wsMaxMessage {
			return 0, nil, fmt.Errorf("%w: %d byte message", errWSProtocol, n)
		}
		var mask [4]byte
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return 0, nil, err
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(c.br, p); err != nil {
			return 0, nil, err
		}
		for i := range p {
			p[i] ^= mask[i%4]
		}
		switch op {
		case 0x0: // continuation
			if msg == nil {
				return 0, nil, fmt.Errorf("%w: unexpected continuation frame", errWSProtocol)
			}
			msg = append(msg, p...)
			if fin {
				return msgOp, msg, nil
			}
		case wsText, wsBinary:
			if msg != nil {
				return 0, nil, fmt.Errorf("%w: new message inside a fragmented one", errWSProtocol)
			}
			if fin {
				return op, p, nil
			}
			msgOp, msg = op, append(make([]byte, 0, len(p)*2), p...)
		case wsPing:
			if err := c.write(wsPong, p); err != nil {
				return 0, nil, err
			}
		case wsPong:
		case wsClose:
			_ = c.write(wsClose, nil)
			return 0, nil, io.EOF
		default:
			return 0, nil, fmt.Errorf("%w: opcode %d", errWSProtocol, op)
		}
	}
}

func (c *wsConn) close(code uint16, reason string) {
	p := binary.BigEndian.AppendUint16(nil, code)
	_ = c.write(wsClose, append(p, reason...))
	_ = c.conn.Close()
}
