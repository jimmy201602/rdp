package wire

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"testing"
)

func TestARCCookie(t *testing.T) {
	sc := binary.LittleEndian.AppendUint32(nil, 28)
	sc = binary.LittleEndian.AppendUint32(sc, 1)
	sc = binary.LittleEndian.AppendUint32(sc, 7)
	for i := 0; i < 16; i++ {
		sc = append(sc, byte(i))
	}
	c, err := decodeARCCookie(sc)
	if err != nil || c.LogonID != 7 || c.Random[15] != 15 {
		t.Fatalf("decode: %+v %v", c, err)
	}
	cs := c.ClientPacket()
	m := hmac.New(md5.New, sc[12:28])
	m.Write(make([]byte, 32))
	if len(cs) != 28 || binary.LittleEndian.Uint32(cs[8:]) != 7 || !hmac.Equal(cs[12:], m.Sum(nil)) {
		t.Fatalf("client packet % x", cs)
	}
	if _, err := decodeARCCookie(sc[:20]); err == nil {
		t.Fatal("short cookie accepted")
	}
	ci := ClientInfo{AutoReconnect: cs}
	b, err := ci.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if n := binary.LittleEndian.Uint16(b[len(b)-4-28-2:]); n != 28 {
		t.Fatalf("cbAutoReconnectCookie %d", n)
	}
}
