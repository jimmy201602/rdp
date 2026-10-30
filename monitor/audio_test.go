package monitor

import (
	"encoding/binary"
	"math"
	"testing"
)

// decodeADPCM mirrors web/monitor/src/audio.ts.
func decodeADPCM(p []byte) []int16 {
	ch := int(p[4])
	frames := int(binary.LittleEndian.Uint32(p[8:]))
	st := make([]imaChannel, ch)
	for i := range st {
		st[i].pred = int32(int16(binary.LittleEndian.Uint16(p[12+4*i:])))
		st[i].index = int32(p[14+4*i])
	}
	data := p[12+4*ch:]
	out := make([]int16, frames*ch)
	for i := range out {
		n := data[i/2] >> (4 * (i % 2)) & 15
		c := &st[i%ch]
		step := imaSteps[c.index]
		d := step >> 3
		if n&4 != 0 {
			d += step
		}
		if n&2 != 0 {
			d += step >> 1
		}
		if n&1 != 0 {
			d += step >> 2
		}
		if n&8 != 0 {
			c.pred -= d
		} else {
			c.pred += d
		}
		c.pred = max(-32768, min(32767, c.pred))
		c.index = max(0, min(88, c.index+imaIndex[n]))
		out[i] = int16(c.pred)
	}
	return out
}

func TestADPCMRoundTrip(t *testing.T) {
	var e adpcmEncoder
	var sig, noise float64
	for block := 0; block < 3; block++ {
		pcm := make([]byte, 0, 4*1000)
		var want []int16
		for i := 0; i < 1000; i++ {
			n := block*1000 + i
			l := int16(12000 * math.Sin(float64(n)*2*math.Pi*440/44100))
			r := int16(8000 * math.Sin(float64(n)*2*math.Pi*660/44100))
			pcm = binary.LittleEndian.AppendUint16(pcm, uint16(l))
			pcm = binary.LittleEndian.AppendUint16(pcm, uint16(r))
			want = append(want, l, r)
		}
		p := e.encode(44100, 2, pcm)
		if len(p) != 12+8+1000 {
			t.Fatalf("payload %d bytes", len(p))
		}
		got := decodeADPCM(p)
		for i := range want {
			if block == 0 && i < 200 {
				continue // encoder converging from silence
			}
			d := float64(want[i]) - float64(got[i])
			sig += float64(want[i]) * float64(want[i])
			noise += d * d
		}
	}
	if snr := 10 * math.Log10(sig/noise); snr < 25 {
		t.Fatalf("SNR %.1f dB", snr)
	}
}
