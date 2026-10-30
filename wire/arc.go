package wire

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
)

// ARCCookie is the server's auto-reconnect cookie (ARC_SC_PRIVATE_PACKET,
// MS-RDPBCGR 2.2.4.2). It lets a client that lost its connection rejoin the
// same session without a new logon.
type ARCCookie struct {
	LogonID uint32
	Random  [16]byte
}

const arcPacketLen = 28

func decodeARCCookie(b []byte) (*ARCCookie, error) {
	if len(b) < arcPacketLen || binary.LittleEndian.Uint32(b) != arcPacketLen || binary.LittleEndian.Uint32(b[4:]) != 1 {
		return nil, fmt.Errorf("%w: auto-reconnect cookie %d bytes", ErrShare, len(b))
	}
	c := &ARCCookie{LogonID: binary.LittleEndian.Uint32(b[8:])}
	copy(c.Random[:], b[12:28])
	return c, nil
}

// ClientPacket returns ARC_CS_PRIVATE_PACKET for the Client Info PDU. The
// verifier is HMAC-MD5 keyed with the cookie's random bits over the client
// random; under TLS/CredSSP no client random is exchanged and the value is
// 32 zero bytes (MS-RDPBCGR 5.5).
func (c ARCCookie) ClientPacket() []byte {
	m := hmac.New(md5.New, c.Random[:])
	m.Write(make([]byte, 32))
	out := make([]byte, 0, arcPacketLen)
	out = binary.LittleEndian.AppendUint32(out, arcPacketLen)
	out = binary.LittleEndian.AppendUint32(out, 1)
	out = binary.LittleEndian.AppendUint32(out, c.LogonID)
	return m.Sum(out)
}
