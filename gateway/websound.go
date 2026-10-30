package gateway

import (
	"encoding/binary"
	"sync"
)

// AudioFormat is the PCM layout of the samples handed to an AudioObserver:
// signed little-endian, interleaved.
type AudioFormat struct {
	SampleRate uint32
	Channels   uint16
	Bits       uint16
}

// AudioObserver receives the audio a web session's target plays (rdpsnd).
type AudioObserver interface {
	RemoteAudio(f AudioFormat, pcm []byte)
}

// rdpsnd PDU types (MS-RDPEA 2.2.1).
const (
	sndClose       = 0x01
	sndWave        = 0x02
	sndWaveConfirm = 0x05
	sndTraining    = 0x06
	sndFormats     = 0x07
	sndQualityMode = 0x0C
	sndWave2       = 0x0D

	waveFormatPCM  = 0x0001
	sndHighQuality = 0x0002
)

// webSound is the client side of rdpsnd for a web session: it accepts the
// uncompressed PCM formats the server offers, confirms every block and
// passes the samples on.
type webSound struct {
	send    func([]byte) error
	onAudio func(AudioFormat, []byte)
	logf    func(string, ...any)

	mu      sync.Mutex
	formats []AudioFormat // the list sent to the server; waves index it
	pending *pendingWave  // Wave Info seen, its Wave PDU not yet
}

type pendingWave struct {
	ts     uint16
	format uint16
	block  uint8
	head   [4]byte
}

func sndPDU(msgType uint8, body []byte) []byte {
	b := make([]byte, 4, 4+len(body))
	b[0] = msgType
	binary.LittleEndian.PutUint16(b[2:], uint16(len(body)))
	return append(b, body...)
}

func (s *webSound) handle(msg []byte) error {
	s.mu.Lock()
	if p := s.pending; p != nil {
		// The Wave PDU that follows a Wave Info has no header: its first
		// four bytes are padding standing in for Wave Info's Data field.
		s.pending = nil
		s.mu.Unlock()
		if len(msg) < 4 {
			return nil
		}
		pcm := append(p.head[:], msg[4:]...)
		s.play(p.format, pcm)
		return s.confirm(p.ts, p.block, len(pcm), p.format)
	}
	s.mu.Unlock()
	if len(msg) < 4 {
		return nil
	}
	body := msg[4:]
	switch msg[0] {
	case sndFormats:
		return s.formatsPDU(body)
	case sndTraining:
		if len(body) < 4 {
			return nil
		}
		return s.send(sndPDU(sndTraining, append([]byte(nil), body[:4]...)))
	case sndWave:
		if len(body) < 12 {
			return nil
		}
		p := &pendingWave{ts: binary.LittleEndian.Uint16(body), format: binary.LittleEndian.Uint16(body[2:]), block: body[4]}
		copy(p.head[:], body[8:12])
		s.mu.Lock()
		s.pending = p
		s.mu.Unlock()
	case sndWave2:
		if len(body) < 12 {
			return nil
		}
		ts, format, block := binary.LittleEndian.Uint16(body), binary.LittleEndian.Uint16(body[2:]), body[4]
		pcm := body[12:]
		s.play(format, pcm)
		return s.confirm(ts, block, len(pcm), format)
	case sndClose:
		s.mu.Lock()
		s.pending = nil
		s.mu.Unlock()
	}
	return nil
}

func (s *webSound) formatsPDU(body []byte) error {
	if len(body) < 20 {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(body[14:]))
	version := binary.LittleEndian.Uint16(body[17:])
	var accepted []AudioFormat
	var raw [][]byte
	off := 20
	for i := 0; i < n && off+18 <= len(body); i++ {
		f := body[off:]
		tag, ch := binary.LittleEndian.Uint16(f), binary.LittleEndian.Uint16(f[2:])
		rate, bits := binary.LittleEndian.Uint32(f[4:]), binary.LittleEndian.Uint16(f[14:])
		extra := int(binary.LittleEndian.Uint16(f[16:]))
		if off+18+extra > len(body) {
			break
		}
		if tag == waveFormatPCM && bits == 16 && (ch == 1 || ch == 2) && rate >= 8000 && rate <= 48000 {
			accepted = append(accepted, AudioFormat{SampleRate: rate, Channels: ch, Bits: bits})
			raw = append(raw, append([]byte(nil), f[:18]...))
			raw[len(raw)-1][16], raw[len(raw)-1][17] = 0, 0
		}
		off += 18 + extra
	}
	s.mu.Lock()
	s.formats = accepted
	s.mu.Unlock()
	if s.logf != nil {
		s.logf("web session audio: server offers %d formats (rdpsnd version %d), %d PCM accepted", n, version, len(accepted))
	}
	if version > 6 {
		version = 6
	}
	reply := binary.LittleEndian.AppendUint32(nil, 0x1|0x2) // TSSNDCAPS_ALIVE | TSSNDCAPS_VOLUME
	reply = binary.LittleEndian.AppendUint32(reply, 0xFFFFFFFF)
	reply = binary.LittleEndian.AppendUint32(reply, 0)
	reply = binary.LittleEndian.AppendUint16(reply, 0) // no UDP
	reply = binary.LittleEndian.AppendUint16(reply, uint16(len(accepted)))
	reply = append(reply, 0)
	reply = binary.LittleEndian.AppendUint16(reply, version)
	reply = append(reply, 0)
	for _, f := range raw {
		reply = append(reply, f...)
	}
	if err := s.send(sndPDU(sndFormats, reply)); err != nil {
		return err
	}
	if version >= 6 {
		q := binary.LittleEndian.AppendUint16(nil, sndHighQuality)
		return s.send(sndPDU(sndQualityMode, append(q, 0, 0)))
	}
	return nil
}

func (s *webSound) format(i uint16) (AudioFormat, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if int(i) >= len(s.formats) {
		return AudioFormat{}, false
	}
	return s.formats[i], true
}

func (s *webSound) play(format uint16, pcm []byte) {
	f, ok := s.format(format)
	s.mu.Lock()
	on := s.onAudio
	s.mu.Unlock()
	if !ok || on == nil || len(pcm) == 0 {
		return
	}
	on(f, pcm)
}

// confirm acknowledges a block. The timestamp is the server's plus the
// block's play time, which is when a real client would have finished it.
func (s *webSound) confirm(ts uint16, block uint8, n int, format uint16) error {
	if f, ok := s.format(format); ok && f.SampleRate > 0 {
		ts += uint16(n * 1000 / int(f.SampleRate*uint32(f.Channels)*uint32(f.Bits/8)))
	}
	b := binary.LittleEndian.AppendUint16(nil, ts)
	return s.send(sndPDU(sndWaveConfirm, append(b, block, 0)))
}
