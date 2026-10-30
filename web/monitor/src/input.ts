import i18n from './i18n';
// Viewer input encoding for the live WebSocket (monitor/http.go): 9-byte
// events kind u8 | flags u16 | code u16 | x u16 | y u16 with slow-path flags.

const KIND_SCANCODE = 2;
const KIND_UNICODE = 3;
const KIND_MOUSE = 4;
const KIND_MOUSEX = 5;

export const KBD_EXTENDED = 0x0100;
export const KBD_DOWN = 0x4000;
export const KBD_RELEASE = 0x8000;

export const PTR_WHEEL = 0x0200;
export const PTR_HWHEEL = 0x0400;
const PTRX_BUTTONS: Record<number, number> = { 3: 0x0001, 4: 0x0002 }; // back, forward
export const PTR_MOVE = 0x0800;
export const PTR_DOWN = 0x8000;
const PTR_BUTTONS = [0x1000, 0x4000, 0x2000]; // MouseEvent.button 0 left, 1 middle, 2 right

export interface InputEvent {
  kind: number;
  flags: number;
  code?: number;
  x?: number;
  y?: number;
}

export function encodeEvents(events: InputEvent[]): ArrayBuffer {
  const buf = new ArrayBuffer(events.length * 9);
  const dv = new DataView(buf);
  events.forEach((e, i) => {
    const o = i * 9;
    dv.setUint8(o, e.kind);
    dv.setUint16(o + 1, e.flags, true);
    dv.setUint16(o + 3, e.code ?? 0, true);
    dv.setUint16(o + 5, Math.max(0, Math.round(e.x ?? 0)), true);
    dv.setUint16(o + 7, Math.max(0, Math.round(e.y ?? 0)), true);
  });
  return buf;
}

export const mouseMove = (x: number, y: number): InputEvent => ({ kind: KIND_MOUSE, flags: PTR_MOVE, x, y });

export function mouseButton(button: number, down: boolean, x: number, y: number): InputEvent | null {
  const xb = PTRX_BUTTONS[button];
  if (xb) return { kind: KIND_MOUSEX, flags: xb | (down ? PTR_DOWN : 0), x, y };
  const b = PTR_BUTTONS[button];
  if (!b) return null;
  return { kind: KIND_MOUSE, flags: b | (down ? PTR_DOWN : 0), x, y };
}

// Wheel accumulates browser deltas and emits Windows wheel units (120 per
// notch), so trackpads scroll smoothly instead of one notch per event.
const PIXELS_PER_NOTCH = 100; // Chromium and Firefox: one mouse notch
const LINES_PER_NOTCH = 3;
const MIN_UNITS = 24;

export class Wheel {
  private acc = { x: 0, y: 0 };

  events(e: { deltaX: number; deltaY: number; deltaMode: number; shiftKey?: boolean }, x: number, y: number): InputEvent[] {
    const scale = e.deltaMode === 1 ? 120 / LINES_PER_NOTCH : e.deltaMode === 2 ? 120 * 3 : 120 / PIXELS_PER_NOTCH;
    let dx = e.deltaX;
    let dy = e.deltaY;
    if (e.shiftKey && !dx) [dx, dy] = [dy, 0];
    this.acc.x += dx * scale;
    this.acc.y += dy * scale;
    const out: InputEvent[] = [];
    for (const axis of ['y', 'x'] as const) {
      let units = this.acc[axis];
      if (Math.abs(units) < MIN_UNITS) continue;
      units = Math.max(-255, Math.min(255, Math.round(units)));
      this.acc[axis] -= units;
      // Windows: positive rotation scrolls up (vertical) or right (horizontal).
      const rot = axis === 'y' ? -units : units;
      out.push({ kind: KIND_MOUSE, flags: (axis === 'y' ? PTR_WHEEL : PTR_HWHEEL) | (rot & 0x1ff), x, y });
    }
    return out;
  }
}

// KeyboardEvent.code -> [scancode, extended] (set 1).
const SCANCODES: Record<string, [number, boolean?]> = {
  Escape: [0x01], Digit1: [0x02], Digit2: [0x03], Digit3: [0x04], Digit4: [0x05], Digit5: [0x06],
  Digit6: [0x07], Digit7: [0x08], Digit8: [0x09], Digit9: [0x0a], Digit0: [0x0b], Minus: [0x0c],
  Equal: [0x0d], Backspace: [0x0e], Tab: [0x0f], KeyQ: [0x10], KeyW: [0x11], KeyE: [0x12],
  KeyR: [0x13], KeyT: [0x14], KeyY: [0x15], KeyU: [0x16], KeyI: [0x17], KeyO: [0x18], KeyP: [0x19],
  BracketLeft: [0x1a], BracketRight: [0x1b], Enter: [0x1c], ControlLeft: [0x1d], KeyA: [0x1e],
  KeyS: [0x1f], KeyD: [0x20], KeyF: [0x21], KeyG: [0x22], KeyH: [0x23], KeyJ: [0x24], KeyK: [0x25],
  KeyL: [0x26], Semicolon: [0x27], Quote: [0x28], Backquote: [0x29], ShiftLeft: [0x2a],
  Backslash: [0x2b], KeyZ: [0x2c], KeyX: [0x2d], KeyC: [0x2e], KeyV: [0x2f], KeyB: [0x30],
  KeyN: [0x31], KeyM: [0x32], Comma: [0x33], Period: [0x34], Slash: [0x35], ShiftRight: [0x36],
  NumpadMultiply: [0x37], AltLeft: [0x38], Space: [0x39], CapsLock: [0x3a], F1: [0x3b], F2: [0x3c],
  F3: [0x3d], F4: [0x3e], F5: [0x3f], F6: [0x40], F7: [0x41], F8: [0x42], F9: [0x43], F10: [0x44],
  NumLock: [0x45], ScrollLock: [0x46], Numpad7: [0x47], Numpad8: [0x48], Numpad9: [0x49],
  NumpadSubtract: [0x4a], Numpad4: [0x4b], Numpad5: [0x4c], Numpad6: [0x4d], NumpadAdd: [0x4e],
  Numpad1: [0x4f], Numpad2: [0x50], Numpad3: [0x51], Numpad0: [0x52], NumpadDecimal: [0x53],
  IntlBackslash: [0x56], F11: [0x57], F12: [0x58],
  NumpadEnter: [0x1c, true], ControlRight: [0x1d, true], NumpadDivide: [0x35, true],
  PrintScreen: [0x37, true], AltRight: [0x38, true], Home: [0x47, true], ArrowUp: [0x48, true],
  PageUp: [0x49, true], ArrowLeft: [0x4b, true], ArrowRight: [0x4d, true], End: [0x4f, true],
  ArrowDown: [0x50, true], PageDown: [0x51, true], Insert: [0x52, true], Delete: [0x53, true],
  MetaLeft: [0x5b, true], MetaRight: [0x5c, true], ContextMenu: [0x5d, true],
  F13: [0x64], F14: [0x65], F15: [0x66], IntlRo: [0x73], IntlYen: [0x7d], KanaMode: [0x70],
  Convert: [0x79], NonConvert: [0x7b], Lang1: [0x72], Lang2: [0x71], NumpadEqual: [0x59],
  AudioVolumeMute: [0x20, true], AudioVolumeDown: [0x2e, true], AudioVolumeUp: [0x30, true],
  MediaTrackNext: [0x19, true], MediaTrackPrevious: [0x10, true], MediaStop: [0x24, true],
  MediaPlayPause: [0x22, true], BrowserBack: [0x6a, true], BrowserForward: [0x69, true],
  BrowserRefresh: [0x67, true], BrowserHome: [0x32, true], BrowserSearch: [0x65, true],
};

// Pause has no make/break of its own: it is Ctrl+NumLock with the E1 prefix,
// which slow-path input expresses as KBDFLAGS_EXTENDED1 on 0x1d then 0x45.
const KBD_EXTENDED1 = 0x0200;
const pause = (): InputEvent[] => [
  { kind: KIND_SCANCODE, flags: KBD_EXTENDED1, code: 0x1d },
  { kind: KIND_SCANCODE, flags: 0, code: 0x45 },
  { kind: KIND_SCANCODE, flags: KBD_EXTENDED1 | KBD_RELEASE, code: 0x1d },
  { kind: KIND_SCANCODE, flags: KBD_RELEASE, code: 0x45 },
];

export function keyEvents(e: KeyboardEvent, down: boolean): InputEvent[] {
  if (e.code === 'Pause') return down ? pause() : [];
  const sc = SCANCODES[e.code];
  if (sc) {
    let flags = down ? (e.repeat ? KBD_DOWN : 0) : KBD_RELEASE;
    if (sc[1]) flags |= KBD_EXTENDED;
    return [{ kind: KIND_SCANCODE, flags, code: sc[0] }];
  }
  // Unmapped keys that produce text go as Unicode, one event per UTF-16
  // unit so characters beyond the BMP (emoji) arrive as surrogate pairs.
  if ([...e.key].length === 1) return unicodeText(e.key, down);
  return [];
}

export function unicodeText(text: string, down: boolean | 'both' = 'both'): InputEvent[] {
  const out: InputEvent[] = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (down === true || down === 'both') out.push({ kind: KIND_UNICODE, flags: 0, code });
    if (down === false || down === 'both') out.push({ kind: KIND_UNICODE, flags: KBD_RELEASE, code });
  }
  return out;
}

type Key = [number, boolean?];

// combo presses keys in order and releases them in reverse.
export function combo(...keys: Key[]): InputEvent[] {
  const ev = (k: Key, up: boolean): InputEvent => ({ kind: KIND_SCANCODE, flags: (k[1] ? KBD_EXTENDED : 0) | (up ? KBD_RELEASE : 0), code: k[0] });
  return [...keys.map((k) => ev(k, false)), ...[...keys].reverse().map((k) => ev(k, true))];
}

const K = {
  win: [0x5b, true] as Key,
  ctrl: [0x1d] as Key,
  alt: [0x38] as Key,
  shift: [0x2a] as Key,
  tab: [0x0f] as Key,
  esc: [0x01] as Key,
  f4: [0x3e] as Key,
  r: [0x13] as Key,
  e: [0x12] as Key,
  d: [0x20] as Key,
  l: [0x26] as Key,
  prtsc: [0x37, true] as Key,
};

// Shortcuts the browser or the local OS would keep for itself.
export const SHORTCUTS: { key: string; label: string; events: () => InputEvent[] }[] = [
  { key: 'win', get label() { return i18n.t('live:shortcuts.win'); }, events: () => combo(K.win) },
  { key: 'alttab', get label() { return i18n.t('live:shortcuts.alttab'); }, events: () => combo(K.alt, K.tab) },
  { key: 'winr', get label() { return i18n.t('live:shortcuts.winr'); }, events: () => combo(K.win, K.r) },
  { key: 'wine', get label() { return i18n.t('live:shortcuts.wine'); }, events: () => combo(K.win, K.e) },
  { key: 'wind', get label() { return i18n.t('live:shortcuts.wind'); }, events: () => combo(K.win, K.d) },
  { key: 'winl', get label() { return i18n.t('live:shortcuts.winl'); }, events: () => combo(K.win, K.l) },
  { key: 'ctrlesc', label: 'Ctrl+Esc', events: () => combo(K.ctrl, K.esc) },
  { key: 'ctrlshiftesc', get label() { return i18n.t('live:shortcuts.ctrlshiftesc'); }, events: () => combo(K.ctrl, K.shift, K.esc) },
  { key: 'altf4', get label() { return i18n.t('live:shortcuts.altf4'); }, events: () => combo(K.alt, K.f4) },
  { key: 'prtsc', get label() { return i18n.t('live:shortcuts.prtsc'); }, events: () => combo(K.prtsc) },
];

export const ctrlAltDel = (): InputEvent[] => [
  { kind: KIND_SCANCODE, flags: 0, code: 0x1d },
  { kind: KIND_SCANCODE, flags: 0, code: 0x38 },
  { kind: KIND_SCANCODE, flags: KBD_EXTENDED, code: 0x53 },
  { kind: KIND_SCANCODE, flags: KBD_EXTENDED | KBD_RELEASE, code: 0x53 },
  { kind: KIND_SCANCODE, flags: KBD_RELEASE, code: 0x38 },
  { kind: KIND_SCANCODE, flags: KBD_RELEASE, code: 0x1d },
];

const MODIFIERS = [0x1d, 0x2a, 0x36, 0x38];

// releaseModifiers is sent when control ends or the view loses focus so no
// key stays pressed on the target.
export const releaseModifiers = (): InputEvent[] => [
  ...MODIFIERS.map((code) => ({ kind: KIND_SCANCODE, flags: KBD_RELEASE, code })),
  { kind: KIND_SCANCODE, flags: KBD_RELEASE | KBD_EXTENDED, code: 0x1d },
  { kind: KIND_SCANCODE, flags: KBD_RELEASE | KBD_EXTENDED, code: 0x38 },
  { kind: KIND_SCANCODE, flags: KBD_RELEASE | KBD_EXTENDED, code: 0x5b },
  { kind: KIND_SCANCODE, flags: KBD_RELEASE | KBD_EXTENDED, code: 0x5c },
];
