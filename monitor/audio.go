package monitor

import (
	"encoding/binary"

	"rdp.local/kernel/gateway"
)

// RecAudio carries sound the remote desktop played (web sessions): sample
// rate u32 | channels u8 | bits u8 | reserved u16, then
//   - bits 16: signed little-endian interleaved PCM (live viewers);
//   - bits 4: IMA ADPCM (recordings, a quarter of the size): frames u32,
//     per channel predictor i16 | step index u8 | pad u8, then one nibble
//     per sample in frame order, channels interleaved, low nibble first.
//     Every record carries its own decoder state, so playback can start at
//     any record.
const RecAudio uint8 = 7

// RemoteAudio is the gateway.AudioObserver hook. Live viewers get PCM and
// it is dropped, not queued for resync, when a viewer is behind: late
// sound is worse than a gap. The recording gets every block as ADPCM.
func (s *Session) RemoteAudio(f gateway.AudioFormat, pcm []byte) {
	if f.Bits != 16 || f.Channels == 0 || f.Channels > 8 {
		return
	}
	p := make([]byte, 8, 8+len(pcm))
	binary.LittleEndian.PutUint32(p, f.SampleRate)
	p[4], p[5] = byte(f.Channels), byte(f.Bits)
	rec := encodeRecord(RecAudio, s.ms(), append(p, pcm...))
	s.vmu.Lock()
	for v := range s.viewers {
		if v.resync || len(v.out) > cap(v.out)/2 {
			continue
		}
		select {
		case v.out <- rec:
		default:
		}
	}
	s.vmu.Unlock()
	if s.audioQ == nil {
		return
	}
	s.adpcmMu.Lock()
	payload := s.adpcm.encode(f.SampleRate, int(f.Channels), pcm)
	s.adpcmMu.Unlock()
	select {
	case s.audioQ <- payload:
	default:
		s.m.cfg.Logf("monitor %s: recording audio queue full, block dropped", s.ID())
	}
}

// flushAudio writes queued audio to the recording; only the loop calls it,
// so records stay in time order with the frames.
func (s *Session) flushAudio() {
	for {
		select {
		case p := <-s.audioQ:
			s.record(encodeRecord(RecAudio, s.ms(), p))
		default:
			return
		}
	}
}

var imaSteps = [89]int32{
	7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
	50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230,
	253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963,
	1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327,
	3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487,
	12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
}

var imaIndex = [16]int32{-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8}

type imaChannel struct {
	pred  int32
	index int32
}

func (c *imaChannel) nibble(sample int32) byte {
	step := imaSteps[c.index]
	diff := sample - c.pred
	var code byte
	if diff < 0 {
		code = 8
		diff = -diff
	}
	delta := step >> 3
	if diff >= step {
		code |= 4
		diff -= step
		delta += step
	}
	if diff >= step>>1 {
		code |= 2
		diff -= step >> 1
		delta += step >> 1
	}
	if diff >= step>>2 {
		code |= 1
		delta += step >> 2
	}
	if code&8 != 0 {
		c.pred -= delta
	} else {
		c.pred += delta
	}
	c.pred = max(-32768, min(32767, c.pred))
	c.index = max(0, min(88, c.index+imaIndex[code]))
	return code
}

// adpcmEncoder keeps per-channel state across blocks so consecutive
// records join without a click.
type adpcmEncoder struct {
	ch []imaChannel
}

func (e *adpcmEncoder) encode(rate uint32, channels int, pcm []byte) []byte {
	if len(e.ch) != channels {
		e.ch = make([]imaChannel, channels)
	}
	frames := len(pcm) / (2 * channels)
	out := make([]byte, 12, 12+4*channels+(frames*channels+1)/2)
	binary.LittleEndian.PutUint32(out, rate)
	out[4], out[5] = byte(channels), 4
	binary.LittleEndian.PutUint32(out[8:], uint32(frames))
	for i := range e.ch {
		out = binary.LittleEndian.AppendUint16(out, uint16(int16(e.ch[i].pred)))
		out = append(out, byte(e.ch[i].index), 0)
	}
	var cur byte
	half := false
	for i := 0; i < frames*channels; i++ {
		n := e.ch[i%channels].nibble(int32(int16(binary.LittleEndian.Uint16(pcm[2*i:]))))
		if half {
			out = append(out, cur|n<<4)
		} else {
			cur = n
		}
		half = !half
	}
	if half {
		out = append(out, cur)
	}
	return out
}
