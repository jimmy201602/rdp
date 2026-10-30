// AudioPlayer plays the audio records (REC_AUDIO, monitor/audio.go: PCM
// live, IMA ADPCM in recordings) through Web Audio. Blocks are scheduled back to back; when
// playback falls too far behind real time the backlog is dropped so sound
// stays in step with the picture.
export const REC_AUDIO = 7;

const MAX_LAG = 0.4; // seconds of queued audio before dropping
const LEAD = 0.06; // first block starts this far ahead to absorb jitter

export class AudioPlayer {
  private ctx: AudioContext | null = null;
  private gain: GainNode | null = null;
  private next = 0;
  private muted = false;
  private playing = new Set<AudioBufferSourceNode>();

  // unlock must run from a user gesture: browsers keep an AudioContext
  // suspended until the page has been interacted with.
  unlock() {
    if (!this.ctx) {
      this.ctx = new AudioContext();
      this.gain = this.ctx.createGain();
      this.gain.connect(this.ctx.destination);
      this.gain.gain.value = this.muted ? 0 : 1;
    }
    if (this.ctx.state === 'suspended') void this.ctx.resume();
  }

  get ready() {
    return this.ctx?.state === 'running';
  }

  setMuted(m: boolean) {
    this.muted = m;
    if (this.gain) this.gain.gain.value = m ? 0 : 1;
  }

  push(payload: Uint8Array) {
    const ctx = this.ctx;
    if (!ctx || ctx.state !== 'running' || payload.length < 8) return;
    const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const rate = dv.getUint32(0, true);
    const channels = payload[4];
    if (!channels || rate < 8000) return;
    let buf: AudioBuffer;
    if (payload[5] === 16) {
      const frames = Math.floor((payload.length - 8) / (2 * channels));
      if (!frames) return;
      buf = ctx.createBuffer(channels, frames, rate);
      for (let c = 0; c < channels; c++) {
        const out = buf.getChannelData(c);
        for (let i = 0; i < frames; i++) out[i] = dv.getInt16(8 + (i * channels + c) * 2, true) / 32768;
      }
    } else if (payload[5] === 4) {
      const decoded = decodeADPCM(dv, channels);
      if (!decoded) return;
      buf = ctx.createBuffer(channels, decoded[0].length, rate);
      decoded.forEach((d, c) => buf.copyToChannel(d, c));
    } else {
      return;
    }
    const now = ctx.currentTime;
    if (this.next < now || this.next - now > MAX_LAG) this.next = now + LEAD;
    const src = ctx.createBufferSource();
    src.buffer = buf;
    src.connect(this.gain!);
    src.onended = () => this.playing.delete(src);
    this.playing.add(src);
    src.start(this.next);
    this.next += buf.duration;
  }

  // reset stops scheduled sound (seeking in a recording).
  reset() {
    this.playing.forEach((s) => s.stop());
    this.playing.clear();
    this.next = 0;
  }

  close() {
    void this.ctx?.close();
    this.ctx = null;
    this.gain = null;
  }
}

const STEPS = [
  7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
  130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060,
  1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484,
  7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];
const INDEX = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

// decodeADPCM decodes an IMA ADPCM audio record (layout in monitor/audio.go).
function decodeADPCM(dv: DataView, channels: number): Float32Array<ArrayBuffer>[] | null {
  if (dv.byteLength < 12 + 4 * channels) return null;
  const frames = dv.getUint32(8, true);
  const data = 12 + 4 * channels;
  if (!frames || data + Math.ceil((frames * channels) / 2) > dv.byteLength) return null;
  const pred: number[] = [];
  const index: number[] = [];
  for (let c = 0; c < channels; c++) {
    pred.push(dv.getInt16(12 + 4 * c, true));
    index.push(Math.min(88, dv.getUint8(14 + 4 * c)));
  }
  const out = Array.from({ length: channels }, () => new Float32Array(frames));
  for (let i = 0; i < frames * channels; i++) {
    const n = (dv.getUint8(data + (i >> 1)) >> ((i & 1) * 4)) & 15;
    const c = i % channels;
    const step = STEPS[index[c]];
    let d = step >> 3;
    if (n & 4) d += step;
    if (n & 2) d += step >> 1;
    if (n & 1) d += step >> 2;
    pred[c] = Math.max(-32768, Math.min(32767, n & 8 ? pred[c] - d : pred[c] + d));
    index[c] = Math.max(0, Math.min(88, index[c] + INDEX[n]));
    out[c][(i / channels) | 0] = pred[c] / 32768;
  }
  return out;
}
