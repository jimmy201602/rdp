// Decoder and renderer for the monitor's record stream (monitor/record.go):
// record = kind u8 | time u32 | len u32 | payload, little-endian.
import type { RecordingMeta } from './api';
import i18n from './i18n';

export const REC_FRAME = 1;
export const REC_KEY = 2;
export const REC_RESIZE = 3;
export const REC_POINTER = 4;
export const REC_END = 5;

export interface Rec {
  kind: number;
  time: number;
  payload: Uint8Array;
}

const HEADER = 9;

export function parseRecord(buf: ArrayBuffer, offset = 0): { rec: Rec; next: number } | null {
  if (buf.byteLength - offset < HEADER) return null;
  const dv = new DataView(buf, offset);
  const len = dv.getUint32(5, true);
  if (buf.byteLength - offset - HEADER < len) return null;
  return {
    rec: { kind: dv.getUint8(0), time: dv.getUint32(1, true), payload: new Uint8Array(buf, offset + HEADER, len) },
    next: offset + HEADER + len,
  };
}

export interface Recording {
  meta: RecordingMeta;
  records: Rec[];
  duration: number;
  truncated: boolean;
}

export function parseRecording(buf: ArrayBuffer): Recording {
  const dv = new DataView(buf);
  const magic = new TextDecoder().decode(new Uint8Array(buf, 0, Math.min(4, buf.byteLength)));
  if (buf.byteLength < 10 || magic !== 'RDPV' || dv.getUint16(4, true) !== 1) throw new Error(i18n.t('api:notRdpv'));
  const metaLen = dv.getUint32(6, true);
  const meta = JSON.parse(new TextDecoder().decode(new Uint8Array(buf, 10, metaLen))) as RecordingMeta;
  const records: Rec[] = [];
  let off = 10 + metaLen;
  for (;;) {
    const r = parseRecord(buf, off);
    if (!r) break;
    records.push(r.rec);
    off = r.next;
  }
  const duration = records.length ? records[records.length - 1].time : 0;
  return { meta, records, duration, truncated: off !== buf.byteLength };
}

const u16 = (p: Uint8Array, i: number) => p[i] | (p[i + 1] << 8);

// Renderer draws records onto a screen canvas and the mouse position onto
// an overlay canvas. Records are applied strictly in order.
export class Renderer {
  private chain: Promise<void> = Promise.resolve();
  private epoch = 0;
  private pointer: { x: number; y: number } | null = null;
  private pointerHidden = false;

  // hidePointer stops drawing the relayed pointer (the viewer's own cursor
  // is shown instead).
  hidePointer(hidden: boolean) {
    this.pointerHidden = hidden;
    this.drawPointer();
  }

  constructor(
    private screen: HTMLCanvasElement,
    private overlay: HTMLCanvasElement | null,
    private onResize?: (w: number, h: number) => void,
  ) {}

  push(rec: Rec): Promise<void> {
    const epoch = this.epoch;
    this.chain = this.chain.then(() => (epoch === this.epoch ? this.apply(rec) : undefined)).catch(() => undefined);
    return this.chain;
  }

  // reset drops records still queued (used when seeking).
  reset() {
    this.epoch++;
    this.chain = Promise.resolve();
  }

  idle(): Promise<void> {
    return this.chain;
  }

  private async apply(rec: Rec) {
    const p = rec.payload;
    switch (rec.kind) {
      case REC_RESIZE: {
        const w = u16(p, 0);
        const h = u16(p, 2);
        for (const c of [this.screen, this.overlay]) {
          if (!c) continue;
          c.width = w;
          c.height = h;
        }
        const ctx = this.screen.getContext('2d')!;
        ctx.fillStyle = '#000';
        ctx.fillRect(0, 0, w, h);
        this.onResize?.(w, h);
        this.drawPointer();
        break;
      }
      case REC_FRAME:
      case REC_KEY: {
        const x = u16(p, 0);
        const y = u16(p, 2);
        const type = p[8] === 0xff && p[9] === 0xd8 ? 'image/jpeg' : 'image/png';
        const bmp = await createImageBitmap(new Blob([p.slice(8)], { type }));
        this.screen.getContext('2d')!.drawImage(bmp, x, y);
        bmp.close();
        break;
      }
      case REC_POINTER:
        this.pointer = { x: u16(p, 0), y: u16(p, 2) };
        this.drawPointer();
        break;
    }
  }

  private drawPointer() {
    const c = this.overlay;
    if (!c) return;
    const ctx = c.getContext('2d')!;
    ctx.clearRect(0, 0, c.width, c.height);
    if (!this.pointer || this.pointerHidden) return;
    const { x, y } = this.pointer;
    ctx.save();
    ctx.translate(x, y);
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(0, 17);
    ctx.lineTo(4.5, 13);
    ctx.lineTo(8, 20);
    ctx.lineTo(10.5, 19);
    ctx.lineTo(7, 12);
    ctx.lineTo(12.5, 12);
    ctx.closePath();
    ctx.fillStyle = '#fff';
    ctx.strokeStyle = '#000';
    ctx.lineWidth = 1.2;
    ctx.fill();
    ctx.stroke();
    ctx.restore();
  }
}
