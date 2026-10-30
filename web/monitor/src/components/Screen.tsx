import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react';

export interface ScreenHandle {
  screen: HTMLCanvasElement;
  overlay: HTMLCanvasElement;
  // position maps a mouse event to desktop coordinates.
  position: (e: { clientX: number; clientY: number }) => { x: number; y: number };
}

export type ScreenFit = 'contain' | 'actual';

interface Props {
  interactive?: boolean;
  // localCursor shows the browser's own cursor instead of the relayed
  // remote position, which lags by a frame interval plus a round trip.
  localCursor?: boolean;
  size?: [number, number];
  fit?: ScreenFit;
  onPointerEvent?: (kind: 'move' | 'down' | 'up' | 'wheel', e: React.MouseEvent | React.WheelEvent) => void;
  // onTouch gets raw touch events; it is attached non-passively so the
  // handler can stop the browser's scrolling and synthetic mouse events.
  onTouch?: (e: TouchEvent) => void;
}

// Screen stacks the desktop canvas and the pointer overlay. In contain mode the
// desktop keeps its aspect ratio and fits both the width and --screen-max-h.
const Screen = forwardRef<ScreenHandle, Props>(function Screen({ interactive, localCursor, size, fit = 'contain', onPointerEvent, onTouch }, ref) {
  const screen = useRef<HTMLCanvasElement>(null);
  const overlay = useRef<HTMLCanvasElement>(null);
  const stageRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = stageRef.current;
    if (!el || !interactive || !onTouch) return;
    const types = ['touchstart', 'touchmove', 'touchend', 'touchcancel'] as const;
    types.forEach((t) => el.addEventListener(t, onTouch, { passive: false }));
    return () => types.forEach((t) => el.removeEventListener(t, onTouch));
  }, [interactive, onTouch]);

  useImperativeHandle(ref, () => ({
    get screen() {
      return screen.current!;
    },
    get overlay() {
      return overlay.current!;
    },
    position: (e) => {
      const c = screen.current!;
      const r = c.getBoundingClientRect();
      return {
        x: Math.min(c.width - 1, Math.max(0, ((e.clientX - r.left) / r.width) * c.width)),
        y: Math.min(c.height - 1, Math.max(0, ((e.clientY - r.top) / r.height) * c.height)),
      };
    },
  }));

  const [w, h] = size && size[0] > 0 && size[1] > 0 ? size : [1024, 640];
  const stage: React.CSSProperties = {
    aspectRatio: `${w} / ${h}`,
    width: fit === 'actual' ? `${w}px` : `min(100%, calc(var(--screen-max-h) * ${w} / ${h}))`,
    cursor: interactive && !localCursor ? 'none' : 'default',
    touchAction: interactive && onTouch ? 'none' : undefined,
  };
  const style: React.CSSProperties = { position: 'absolute', inset: 0, width: '100%', height: '100%', imageRendering: fit === 'actual' ? 'pixelated' : 'auto' };
  return (
    <div className={`screen-frame is-${fit}`}>
      <div
        ref={stageRef}
        className="screen-stage"
        style={stage}
        onMouseMove={(e) => onPointerEvent?.('move', e)}
        onMouseDown={(e) => onPointerEvent?.('down', e)}
        onMouseUp={(e) => onPointerEvent?.('up', e)}
        onWheel={(e) => onPointerEvent?.('wheel', e)}
        onContextMenu={(e) => interactive && e.preventDefault()}
      >
        <canvas ref={screen} width={1024} height={640} style={style} />
        <canvas ref={overlay} width={1024} height={640} style={{ ...style, pointerEvents: 'none' }} />
      </div>
    </div>
  );
});

export default Screen;
