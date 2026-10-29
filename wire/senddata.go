package wire

import (
	"encoding/binary"
	"fmt"
)

// MCS SendDataRequest / SendDataIndication (T.125 section 7 part 7, ALIGNED
// BASIC-PER). RDP uses them to carry every PDU after Channel Connection:
// initiator = user channel (encoded as UserId - 1001), channelId = the
// target channel (I/O channel 1003 or a static virtual channel), dataPriority
// high and a single unsegmented fragment (segmentation = begin | end).
// See MS-RDPBCGR 2.2.1.11 (Client Info PDU) for the client-to-server envelope
// and 2.2.1.12 (Server License Error PDU) for the server-to-client envelope.

const (
	// dataPriority high (01) + segmentation begin|end (11), left aligned in
	// one octet; the remaining four bits are PER padding.
	mcsSendDataFlags = 0x70

	mcsSegmentationBegin = 0x20
	mcsSegmentationEnd   = 0x10
)

// MaxSendDataPayload is the largest user-data length encodable with an
// unfragmented PER length determinant.
const MaxSendDataPayload = 0x3fff

// EncodeSendDataRequest wraps payload in an MCS SendDataRequest from
// userChannel to channelID.
func EncodeSendDataRequest(userChannel, channelID uint16, payload []byte) ([]byte, error) {
	return encodeSendData(mcsSendDataRequest, userChannel, channelID, payload)
}

// EncodeSendDataIndication builds the server-side envelope; it exists for the
// fake servers used in tests and for a future server role.
func EncodeSendDataIndication(userChannel, channelID uint16, payload []byte) ([]byte, error) {
	return encodeSendData(mcsSendDataIndication, userChannel, channelID, payload)
}

func encodeSendData(choice int, userChannel, channelID uint16, payload []byte) ([]byte, error) {
	if userChannel < mcsUserIDBase {
		return nil, fmt.Errorf("%w: user channel %d below %d", ErrMCS, userChannel, mcsUserIDBase)
	}
	if len(payload) > MaxSendDataPayload {
		return nil, fmt.Errorf("%w: send data payload %d bytes exceeds %d", ErrMCS, len(payload), MaxSendDataPayload)
	}
	length, err := perLength(len(payload))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 6+len(length)+len(payload))
	out = append(out, byte(choice<<2), 0, 0, 0, 0, mcsSendDataFlags)
	binary.BigEndian.PutUint16(out[1:], userChannel-mcsUserIDBase)
	binary.BigEndian.PutUint16(out[3:], channelID)
	out = append(out, length...)
	return append(out, payload...), nil
}

// SendData is a decoded SendDataRequest or SendDataIndication.
type SendData struct {
	UserChannel uint16 // initiator + 1001
	ChannelID   uint16
	Data        []byte
}

// DecodeSendDataIndication parses a server-to-client SendDataIndication.
func DecodeSendDataIndication(p []byte) (SendData, error) {
	return decodeSendData(p, mcsSendDataIndication, "SendDataIndication")
}

// DecodeSendDataRequest parses a client-to-server SendDataRequest.
func DecodeSendDataRequest(p []byte) (SendData, error) {
	return decodeSendData(p, mcsSendDataRequest, "SendDataRequest")
}

func decodeSendData(p []byte, choice int, name string) (SendData, error) {
	var sd SendData
	if err := domainPDUChoice(p, choice, name); err != nil {
		return sd, err
	}
	if len(p) < 7 {
		return sd, fmt.Errorf("%w: %s too short (%d bytes)", ErrMCS, name, len(p))
	}
	user, err := userID(binary.BigEndian.Uint16(p[1:]))
	if err != nil {
		return sd, err
	}
	sd.UserChannel = user
	sd.ChannelID = binary.BigEndian.Uint16(p[3:])
	if p[5]&(mcsSegmentationBegin|mcsSegmentationEnd) != mcsSegmentationBegin|mcsSegmentationEnd {
		return sd, fmt.Errorf("%w: segmented %s not supported (flags 0x%02x)", ErrMCS, name, p[5])
	}
	n, rest, err := perReadLength(p[6:])
	if err != nil {
		return sd, err
	}
	if n != len(rest) {
		return sd, fmt.Errorf("%w: %s declares %d data bytes, %d present", ErrMCS, name, n, len(rest))
	}
	sd.Data = rest
	return sd, nil
}
