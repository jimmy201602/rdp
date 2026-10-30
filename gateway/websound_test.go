package gateway

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func audioFormatBytes(tag, ch uint16, rate uint32, bits uint16, extra []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, tag)
	b = binary.LittleEndian.AppendUint16(b, ch)
	b = binary.LittleEndian.AppendUint32(b, rate)
	b = binary.LittleEndian.AppendUint32(b, rate*uint32(ch)*uint32(bits/8))
	b = binary.LittleEndian.AppendUint16(b, ch*bits/8)
	b = binary.LittleEndian.AppendUint16(b, bits)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(extra)))
	return append(b, extra...)
}

func TestWebSoundNegotiatesAndPlays(t *testing.T) {
	var sent [][]byte
	var got []byte
	var gotFmt AudioFormat
	s := &webSound{send: func(b []byte) error { sent = append(sent, b); return nil }}
	s.onAudio = func(f AudioFormat, pcm []byte) { gotFmt, got = f, append(got, pcm...) }

	body := make([]byte, 20)
	binary.LittleEndian.PutUint16(body[14:], 3)
	binary.LittleEndian.PutUint16(body[17:], 8)
	body = append(body, audioFormatBytes(0x55, 2, 44100, 0, []byte{1, 2, 3, 4})...) // MP3: skipped
	body = append(body, audioFormatBytes(1, 2, 44100, 16, nil)...)
	body = append(body, audioFormatBytes(1, 1, 22050, 8, nil)...) // 8-bit: skipped
	if err := s.handle(sndPDU(sndFormats, body)); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[0][0] != sndFormats || sent[1][0] != sndQualityMode {
		t.Fatalf("replies %x", sent)
	}
	reply := sent[0][4:]
	if n := binary.LittleEndian.Uint16(reply[14:]); n != 1 || binary.LittleEndian.Uint16(reply[17:]) != 6 {
		t.Fatalf("client formats %x", reply)
	}

	// Wave Info + Wave: the first 4 data bytes ride in Wave Info.
	sent = nil
	info := binary.LittleEndian.AppendUint16(nil, 1000)
	info = binary.LittleEndian.AppendUint16(info, 0)
	info = append(info, 7, 0, 0, 0, 1, 2, 3, 4)
	if err := s.handle(sndPDU(sndWave, info)); err != nil {
		t.Fatal(err)
	}
	wave := append([]byte{0, 0, 0, 0}, make([]byte, 4*44100/10-4)...) // 100 ms
	if err := s.handle(wave); err != nil {
		t.Fatal(err)
	}
	if gotFmt.SampleRate != 44100 || gotFmt.Channels != 2 || len(got) != 4*44100/10 || !bytes.Equal(got[:4], []byte{1, 2, 3, 4}) {
		t.Fatalf("audio %+v %d bytes", gotFmt, len(got))
	}
	if len(sent) != 1 || sent[0][0] != sndWaveConfirm || binary.LittleEndian.Uint16(sent[0][4:]) != 1100 || sent[0][6] != 7 {
		t.Fatalf("confirm %x", sent)
	}

	// Wave2 carries everything in one PDU.
	sent = nil
	w2 := binary.LittleEndian.AppendUint16(nil, 5)
	w2 = binary.LittleEndian.AppendUint16(w2, 0)
	w2 = append(w2, 9, 0, 0, 0, 0, 0, 0, 0)
	w2 = append(w2, make([]byte, 400)...)
	if err := s.handle(sndPDU(sndWave2, w2)); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0][6] != 9 {
		t.Fatalf("wave2 confirm %x", sent)
	}

	// Training is echoed.
	sent = nil
	if err := s.handle(sndPDU(sndTraining, []byte{0x34, 0x12, 0, 1})); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || !bytes.Equal(sent[0], sndPDU(sndTraining, []byte{0x34, 0x12, 0, 1})) {
		t.Fatalf("training %x", sent)
	}
}
