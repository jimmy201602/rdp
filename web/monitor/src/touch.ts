import { mouseButton, mouseMove, Wheel, type InputEvent } from './input';

type Pos = { x: number; y: number };
type Map = (p: { clientX: number; clientY: number }) => Pos;

const LONG_PRESS_MS = 550;
const TAP_SLOP_PX = 10;

// TouchGestures turns touch input into mouse input for the remote desktop:
// tap = left click, long press or two-finger tap = right click, one-finger
// drag = left-button drag, two-finger drag = scroll.
export class TouchGestures {
  private start: { x: number; y: number; t: number } | null = null;
  private dragging = false;
  private longTimer = 0;
  private longFired = false;
  private two: { y: number; x: number; moved: boolean } | null = null;
  private wheel = new Wheel();

  constructor(
    private map: Map,
    private send: (evs: InputEvent[]) => void,
  ) {}

  handle(e: TouchEvent) {
    e.preventDefault();
    const t = e.touches;
    if (e.type === 'touchstart') {
      if (t.length === 1) {
        const p = this.map(t[0]);
        this.start = { x: t[0].clientX, y: t[0].clientY, t: Date.now() };
        this.dragging = false;
        this.longFired = false;
        this.send([mouseMove(p.x, p.y)]);
        window.clearTimeout(this.longTimer);
        this.longTimer = window.setTimeout(() => {
          if (!this.start || this.dragging) return;
          this.longFired = true;
          this.click(2, p);
        }, LONG_PRESS_MS);
      } else if (t.length === 2) {
        this.cancelOne();
        this.two = { x: (t[0].clientX + t[1].clientX) / 2, y: (t[0].clientY + t[1].clientY) / 2, moved: false };
      }
      return;
    }
    if (e.type === 'touchmove') {
      if (this.two && t.length >= 2) {
        const x = (t[0].clientX + t[1].clientX) / 2;
        const y = (t[0].clientY + t[1].clientY) / 2;
        const dx = this.two.x - x;
        const dy = this.two.y - y;
        if (Math.abs(dx) + Math.abs(dy) > 2) {
          this.two = { x, y, moved: true };
          const p = this.map({ clientX: x, clientY: y });
          this.send(this.wheel.events({ deltaX: dx, deltaY: dy, deltaMode: 0 }, p.x, p.y));
        }
        return;
      }
      if (!this.start || t.length !== 1 || this.longFired) return;
      const p = this.map(t[0]);
      if (!this.dragging && Math.hypot(t[0].clientX - this.start.x, t[0].clientY - this.start.y) > TAP_SLOP_PX) {
        this.dragging = true;
        window.clearTimeout(this.longTimer);
        const s = this.map({ clientX: this.start.x, clientY: this.start.y });
        const down = mouseButton(0, true, s.x, s.y);
        if (down) this.send([down]);
      }
      if (this.dragging) this.send([mouseMove(p.x, p.y)]);
      return;
    }
    // touchend / touchcancel
    if (this.two) {
      if (t.length === 0) {
        if (!this.two.moved && e.type === 'touchend') {
          const c = e.changedTouches[0];
          this.click(2, this.map(c));
        }
        this.two = null;
      }
      return;
    }
    if (!this.start) return;
    window.clearTimeout(this.longTimer);
    const c = e.changedTouches[0];
    const p = this.map(c);
    if (this.dragging) {
      const up = mouseButton(0, false, p.x, p.y);
      if (up) this.send([up]);
    } else if (!this.longFired && e.type === 'touchend') {
      this.click(0, p);
    }
    this.start = null;
    this.dragging = false;
  }

  private cancelOne() {
    window.clearTimeout(this.longTimer);
    if (this.dragging && this.start) {
      const s = this.map({ clientX: this.start.x, clientY: this.start.y });
      const up = mouseButton(0, false, s.x, s.y);
      if (up) this.send([up]);
    }
    this.start = null;
    this.dragging = false;
  }

  private click(button: number, p: Pos) {
    const evs = [mouseButton(button, true, p.x, p.y), mouseButton(button, false, p.x, p.y)].filter((v): v is InputEvent => !!v);
    this.send(evs);
  }
}
