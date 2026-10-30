// Rich clipboard exchange with the remote desktop: plain text, an HTML
// fragment and a PNG image (base64 on the wire, as Go encodes []byte).

export interface ClipPayload {
  text?: string;
  html?: string;
  data?: string; // base64 PNG
}

// The gateway accepts browser messages up to 4 MiB; base64 adds a third.
const MAX_PNG = 2_900_000;

export function clipKey(c: ClipPayload): string {
  return `${c.text ?? ''}\u0000${c.html?.length ?? 0}\u0000${c.data?.length ?? 0}:${c.data?.slice(-64) ?? ''}`;
}

function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// readLocal reads the browser clipboard. It falls back to text only where
// the async Clipboard API's read() is missing or refused.
export async function readLocal(): Promise<{ clip: ClipPayload; skippedImage: boolean }> {
  const clip: ClipPayload = {};
  let skippedImage = false;
  if (navigator.clipboard?.read) {
    try {
      for (const item of await navigator.clipboard.read()) {
        if (item.types.includes('text/plain') && clip.text === undefined) clip.text = await (await item.getType('text/plain')).text();
        if (item.types.includes('text/html') && clip.html === undefined) clip.html = await (await item.getType('text/html')).text();
        if (item.types.includes('image/png') && clip.data === undefined) {
          const blob = await item.getType('image/png');
          if (blob.size > MAX_PNG) skippedImage = true;
          else clip.data = toBase64(await blob.arrayBuffer());
        }
      }
      return { clip, skippedImage };
    } catch {
      // fall through to readText
    }
  }
  if (navigator.clipboard?.readText) clip.text = await navigator.clipboard.readText();
  return { clip, skippedImage };
}

export async function writeLocal(c: ClipPayload): Promise<void> {
  if ((c.html || c.data) && typeof ClipboardItem !== 'undefined' && navigator.clipboard?.write) {
    const parts: Record<string, Blob> = {};
    if (c.text) parts['text/plain'] = new Blob([c.text], { type: 'text/plain' });
    if (c.html) parts['text/html'] = new Blob([c.html], { type: 'text/html' });
    if (c.data) parts['image/png'] = new Blob([fromBase64(c.data)], { type: 'image/png' });
    try {
      await navigator.clipboard.write([new ClipboardItem(parts)]);
      return;
    } catch {
      // Some browsers refuse text/html or images; keep at least the text.
    }
  }
  if (c.text) await navigator.clipboard?.writeText(c.text);
}

export function pngURL(c: ClipPayload): string {
  return c.data ? `data:image/png;base64,${c.data}` : '';
}
