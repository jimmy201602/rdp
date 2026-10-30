package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrChannel is returned for malformed static virtual channel data.
var ErrChannel = errors.New("invalid channel pdu")

// CHANNEL_PDU_HEADER flags (MS-RDPBCGR 2.2.6.1.1).
const (
	ChannelFlagFirst        = 0x00000001
	ChannelFlagLast         = 0x00000002
	ChannelFlagShowProtocol = 0x00000010
	ChannelPacketCompressed = 0x00200000
)

// ChannelChunkLength is the conservative virtual channel chunk size: the
// minimum a server advertises, so splitting at it is always safe.
const ChannelChunkLength = 1600

// SplitChannelPDU frames msg into one or more chunks (each a
// CHANNEL_PDU_HEADER followed by up to chunkSize bytes) ready for
// WriteChannel. The header length is the whole message size; the first and
// last chunks carry CHANNEL_FLAG_FIRST / CHANNEL_FLAG_LAST.
func SplitChannelPDU(msg []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		chunkSize = ChannelChunkLength
	}
	total := uint32(len(msg))
	var out [][]byte
	for off := 0; ; {
		end := off + chunkSize
		if end > len(msg) {
			end = len(msg)
		}
		var flags uint32
		if off == 0 {
			flags |= ChannelFlagFirst
		}
		if end == len(msg) {
			flags |= ChannelFlagLast
		}
		hdr := make([]byte, 8, 8+end-off)
		binary.LittleEndian.PutUint32(hdr, total)
		binary.LittleEndian.PutUint32(hdr[4:], flags)
		out = append(out, append(hdr, msg[off:end]...))
		off = end
		if off >= len(msg) {
			break
		}
	}
	return out
}

// ChannelReassembler joins CHANNEL_PDU_HEADER chunks into whole messages. Use
// one per channel and direction.
type ChannelReassembler struct {
	buf    []byte
	total  uint32
	active bool
}

const MaxChannelMessage = 8 << 20

// Add consumes one chunk (CHANNEL_PDU_HEADER + data). It returns the complete
// message once the CHANNEL_FLAG_LAST chunk arrives (done true). A compressed
// chunk resets the reassembler and reports compressed so the caller can pass
// it through untouched instead of trying to decode it.
func (r *ChannelReassembler) Add(chunk []byte) (msg []byte, done, compressed bool, err error) {
	defer func() {
		if err != nil || compressed {
			*r = ChannelReassembler{}
		}
	}()
	if len(chunk) < 8 {
		return nil, false, false, ErrChannel
	}
	n, flags := binary.LittleEndian.Uint32(chunk), binary.LittleEndian.Uint32(chunk[4:])
	if flags&ChannelPacketCompressed != 0 {
		return nil, false, true, nil
	}
	if n > MaxChannelMessage {
		return nil, false, false, ErrChannel
	}
	if flags&ChannelFlagFirst != 0 {
		if r.active {
			return nil, false, false, ErrChannel
		}
		r.total, r.active, r.buf = n, true, nil
	}
	if !r.active || n != r.total || len(chunk)-8 > int(n)-len(r.buf) {
		return nil, false, false, ErrChannel
	}
	r.buf = append(r.buf, chunk[8:]...)
	if flags&ChannelFlagLast != 0 {
		if len(r.buf) != int(n) {
			return nil, false, false, ErrChannel
		}
		m := r.buf
		*r = ChannelReassembler{}
		return m, true, false, nil
	}
	return nil, false, false, nil
}

// ChannelMessageHead reports the flags and data of a chunk without
// reassembling, for deciding on the first chunk whether to forward it.
func ChannelMessageHead(chunk []byte) (flags uint32, data []byte, err error) {
	if len(chunk) < 8 {
		return 0, nil, fmt.Errorf("%w: chunk of %d bytes", ErrChannel, len(chunk))
	}
	return binary.LittleEndian.Uint32(chunk[4:]), chunk[8:], nil
}
