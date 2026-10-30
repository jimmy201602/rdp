import { useCallback, useEffect, useRef, useState } from 'react';
import { App, Alert, Button, Card, Descriptions, Dropdown, Input, Popover, Space, Switch, Tag, Tooltip, Typography } from 'antd';
import {
  ArrowLeftOutlined,
  CopyOutlined,
  DisconnectOutlined,
  FolderOpenOutlined,
  FullscreenExitOutlined,
  FullscreenOutlined,
  HolderOutlined,
  LoadingOutlined,
  LockOutlined,
  MacCommandOutlined,
  MutedOutlined,
  SendOutlined,
  SoundOutlined,
} from '@ant-design/icons';
import { useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { account, api, clearOwnerKey, fmtBytes, getOwnerKey, liveURL, type SessionInfo } from '../api';
import { parseRecord, Renderer, REC_END } from '../rdpv';
import { ctrlAltDel, encodeEvents, keyEvents, mouseButton, mouseMove, releaseModifiers, SHORTCUTS, unicodeText, Wheel, type InputEvent } from '../input';
import Screen, { type ScreenHandle } from '../components/Screen';
import Events, { readEvent, type AuditEvent } from '../components/Events';
import DriveBrowser from '../components/DriveBrowser';
import { BrowserFolder, folderSupported, pickFolder, type FSRequest } from '../webfs';
import { AudioPlayer, REC_AUDIO } from '../audio';
import { TouchGestures } from '../touch';
import { clipKey, pngURL, readLocal, writeLocal, type ClipPayload } from '../clipboard';

type State = 'connecting' | 'live' | 'reconnecting' | 'ended' | 'error';

interface Hello {
  type: 'hello';
  session: SessionInfo;
  control: boolean;
  owner: boolean;
  clipboard?: boolean;
  drives?: boolean;
  drive?: string;
  resize?: boolean;
}

// How long the page keeps trying to get back to a session after the
// WebSocket dropped; the gateway keeps it for -web-reconnect (2 min).
const RECONNECT_FOR = 150_000;

export default function Live() {
  const { id = '' } = useParams();
  const nav = useNavigate();
  const { message } = App.useApp();
  const { t } = useTranslation(['live', 'common']);
  const view = useRef<ScreenHandle>(null);
  const box = useRef<HTMLDivElement>(null);
  const ws = useRef<WebSocket | null>(null);
  const [state, setState] = useState<State>('connecting');
  const [error, setError] = useState('');
  const [info, setInfo] = useState<SessionInfo | null>(null);
  const [control, setControl] = useState(false);
  const [granted, setGranted] = useState(false);
  const [size, setSize] = useState<[number, number]>([0, 0]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  // own is set when this browser opened the session itself (web client):
  // it is the RDP client, so it always has keyboard and mouse.
  const own = getOwnerKey(id);
  const [owned, setOwned] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const droppedAt = useRef(0);
  const [features, setFeatures] = useState({ clipboard: false, drives: false });
  const [clipText, setClipText] = useState('');
  const [clipImage, setClipImage] = useState('');
  const lastClip = useRef('');
  const folder = useRef<BrowserFolder | null>(null);
  const [drive, setDrive] = useState('');
  const [canResize, setCanResize] = useState(false);
  const player = useRef<AudioPlayer>(new AudioPlayer());
  const [muted, setMuted] = useState(false);
  const [audioReady, setAudioReady] = useState(false);
  const [heardAudio, setHeardAudio] = useState(false);

  // Browsers only start audio after a user gesture on the page.
  useEffect(() => {
    const p = player.current;
    const unlock = () => {
      p.unlock();
      setTimeout(() => setAudioReady(p.ready), 100);
    };
    window.addEventListener('pointerdown', unlock);
    window.addEventListener('keydown', unlock);
    return () => {
      window.removeEventListener('pointerdown', unlock);
      window.removeEventListener('keydown', unlock);
      p.close();
    };
  }, []);

  const sendCtl = useCallback((msg: object) => {
    if (ws.current?.readyState === WebSocket.OPEN) ws.current.send(JSON.stringify(msg));
  }, []);

  useEffect(() => {
    const socket = new WebSocket(liveURL(id, control, own));
    socket.binaryType = 'arraybuffer';
    if (attempt === 0) setEvents([]);
    ws.current = socket;
    let ended = false;
    const renderer = new Renderer(view.current!.screen, view.current!.overlay, (w, h) => setSize([w, h]));
    socket.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'hello') {
          const hello = msg as Hello;
          setInfo(hello.session);
          setGranted(hello.control);
          setOwned(hello.owner);
          renderer.hidePointer(hello.owner);
          setFeatures({ clipboard: !!hello.clipboard, drives: !!hello.drives });
          setCanResize(!!hello.resize);
          setState('live');
          setError('');
          droppedAt.current = 0;
          if (hello.owner) {
            // After a page reload the folder handle is gone; withdraw the
            // stale drive. After a plain reconnect it is still here.
            if (hello.drive && !folder.current) socket.send(JSON.stringify({ t: 'unmap' }));
            else if (!hello.drive && folder.current) socket.send(JSON.stringify({ t: 'map', name: folder.current.name }));
            setDrive(hello.drive && folder.current ? hello.drive : '');
          }
          if (control && !hello.control) message.warning(t('msg.controlDisabled'));
          return;
        }
        if (msg.t === 'clip') {
          const c = msg as ClipPayload;
          lastClip.current = clipKey(c);
          setClipText(c.text ?? '');
          setClipImage(pngURL(c));
          void writeLocal(c).catch(() => undefined);
        } else if (msg.t === 'display') {
          setCanResize(!!msg.resize);
        } else if (msg.t === 'reconnect') {
          if (msg.attempt > 0) {
            message.loading({ key: 'target-reconnect', content: t('msg.targetReconnecting', { n: msg.attempt }), duration: 0 });
          } else {
            message.success({ key: 'target-reconnect', content: t('msg.targetReconnected'), duration: 3 });
          }
        } else if (msg.t === 'drive') {
          if (msg.error) message.error(t('msg.mapFailed', { error: msg.error }));
          setDrive(msg.name ?? '');
        } else if (msg.t === 'fs') {
          const f = folder.current;
          if (!f) socket.send(JSON.stringify({ t: 'fs', id: msg.id, err: 'offline' }));
          else void f.handle(msg as FSRequest).then((r) => socket.readyState === WebSocket.OPEN && socket.send(JSON.stringify(r)));
        }
        return;
      }
      const r = parseRecord(ev.data as ArrayBuffer);
      if (!r) return;
      if (r.rec.kind === REC_END) {
        ended = true;
        setState('ended');
        return;
      }
      if (r.rec.kind === REC_AUDIO) {
        player.current.push(r.rec.payload);
        setHeardAudio(true);
        return;
      }
      const event = readEvent(r.rec);
      if (event) {
        setEvents((list) => [...list.slice(-499), event]);
        return;
      }
      void renderer.push(r.rec);
    };
    let retry = 0;
    socket.onclose = () => {
      if (ended || ws.current !== socket) return;
      if (!droppedAt.current) droppedAt.current = Date.now();
      if (Date.now() - droppedAt.current > RECONNECT_FOR) {
        setState('error');
        setError(t('msg.gatewayReconnectFailed'));
        return;
      }
      setState('reconnecting');
      const delay = Math.min(1000 * 2 ** Math.min(attempt, 3), 8000);
      retry = window.setTimeout(() => setAttempt((a) => a + 1), delay);
    };
    return () => {
      clearTimeout(retry);
      renderer.reset();
      ws.current = null;
      socket.close();
    };
  }, [id, control, own, attempt]);

  useEffect(() => {
    if (state !== 'ended') return;
    if (own) clearOwnerKey(id);
    void folder.current?.close();
  }, [id, own, state]);

  useEffect(() => {
    if (state !== 'live') return;
    const t = setInterval(async () => {
      const found = (await api.sessions()).find((s) => s.id === id);
      if (found) setInfo(found);
    }, 3000);
    return () => clearInterval(t);
  }, [id, state]);

  // Local clipboard -> remote: whenever the page regains focus (the user
  // copied something elsewhere) offer its text to the remote desktop.
  const pushClipboard = useCallback(async () => {
    if (!owned || !features.clipboard || !navigator.clipboard) return;
    try {
      const { clip, skippedImage } = await readLocal();
      const key = clipKey(clip);
      if ((clip.text || clip.html || clip.data) && key !== lastClip.current) {
        lastClip.current = key;
        setClipText(clip.text ?? '');
        setClipImage(pngURL(clip));
        sendCtl({ t: 'clip', ...clip });
        if (skippedImage) message.warning(t('msg.clipImageTooLarge'));
      }
    } catch {
      // Permission denied or document not focused: the panel still works.
    }
  }, [owned, features.clipboard, sendCtl]);

  useEffect(() => {
    if (!owned || state !== 'live') return;
    const onFocus = () => void pushClipboard();
    window.addEventListener('focus', onFocus);
    void pushClipboard();
    return () => window.removeEventListener('focus', onFocus);
  }, [owned, state, pushClipboard]);

  const send = useCallback(
    (events: InputEvent[]) => {
      if (!granted || !events.length || ws.current?.readyState !== WebSocket.OPEN) return;
      ws.current.send(encodeEvents(events));
    },
    [granted],
  );

  const wheel = useRef(new Wheel());
  const ime = useRef<HTMLTextAreaElement>(null);
  const onPointerEvent = useCallback(
    (kind: 'move' | 'down' | 'up' | 'wheel', e: React.MouseEvent | React.WheelEvent) => {
      if (!granted) return;
      const { x, y } = view.current!.position(e);
      if (kind === 'wheel') {
        send(wheel.current.events(e as React.WheelEvent, x, y));
        return;
      }
      if (kind === 'move') {
        send([mouseMove(x, y)]);
        return;
      }
      e.preventDefault();
      // The hidden text box takes the focus so a local IME can compose.
      if (kind === 'down') ime.current?.focus({ preventScroll: true });
      const ev = mouseButton((e as React.MouseEvent).button, kind === 'down', x, y);
      if (ev) send([ev]);
    },
    [granted, send],
  );

  const touch = useRef<TouchGestures | null>(null);
  const onTouch = useCallback(
    (e: TouchEvent) => {
      if (!granted || !view.current) return;
      touch.current ??= new TouchGestures((p) => view.current!.position(p), (evs) => send(evs));
      touch.current.handle(e);
    },
    [granted, send],
  );

  useEffect(() => {
    if (!granted) return;
    const key = (down: boolean) => (e: KeyboardEvent) => {
      if (!box.current?.contains(document.activeElement) && document.activeElement !== document.body) return;
      // Keys that feed a local IME composition are not sent; the
      // composed text arrives as Unicode on compositionend.
      if (e.isComposing || e.keyCode === 229) return;
      const evs = keyEvents(e, down);
      if (!evs.length) return;
      e.preventDefault();
      send(evs);
    };
    const [down, up] = [key(true), key(false)];
    const blur = () => send(releaseModifiers());
    window.addEventListener('keydown', down);
    window.addEventListener('keyup', up);
    window.addEventListener('blur', blur);
    return () => {
      window.removeEventListener('keydown', down);
      window.removeEventListener('keyup', up);
      window.removeEventListener('blur', blur);
      blur();
    };
  }, [granted, send]);

  const mapFolder = async () => {
    try {
      const f = new BrowserFolder(await pickFolder());
      if (!(await f.permitted())) {
        message.error(t('msg.folderPermissionDenied'));
        return;
      }
      await folder.current?.close();
      folder.current = f;
      sendCtl({ t: 'map', name: f.name });
    } catch (e) {
      if ((e as DOMException).name !== 'AbortError') message.error(t('msg.pickFolderFailed', { error: (e as Error).message }));
    }
  };

  const unmapFolder = async () => {
    sendCtl({ t: 'unmap' });
    await folder.current?.close();
    folder.current = null;
    setDrive('');
  };

  const live = state === 'live';

  const disconnect = async () => {
    await api.disconnect(id);
    message.success(t('msg.disconnected'));
  };

  // With display control (Windows 8.1 / 2012 R2 and later) the remote
  // desktop follows the browser window; older targets keep their size.
  useEffect(() => {
    if (!owned || !canResize || state !== 'live') return;
    let timer = 0;
    const want = () => [Math.max(200, Math.floor(window.innerWidth)) & ~1, Math.max(200, Math.floor(window.innerHeight))];
    const fit = () => {
      clearTimeout(timer);
      timer = window.setTimeout(() => {
        const [w, h] = want();
        if (w !== size[0] || h !== size[1]) sendCtl({ t: 'resize', w, h });
      }, 400);
    };
    fit();
    window.addEventListener('resize', fit);
    return () => {
      clearTimeout(timer);
      window.removeEventListener('resize', fit);
    };
  }, [owned, canResize, state, size, sendCtl]);

  const [fullscreen, setFullscreen] = useState(false);
  useEffect(() => {
    // In fullscreen, Chromium's Keyboard Lock lets Win, Alt+Tab, Ctrl+W
    // and Esc reach the remote desktop (hold Esc to leave fullscreen).
    const kb = (navigator as unknown as { keyboard?: { lock?: () => Promise<void>; unlock?: () => void } }).keyboard;
    const on = () => {
      const fs = !!document.fullscreenElement;
      setFullscreen(fs);
      if (fs) void kb?.lock?.().catch(() => undefined);
      else kb?.unlock?.();
    };
    document.addEventListener('fullscreenchange', on);
    return () => document.removeEventListener('fullscreenchange', on);
  }, []);

  // The floating toolbar can be dragged up and down along the right edge.
  const [barTop, setBarTop] = useState(96);
  const dragFrom = useRef<number | null>(null);
  const startDrag = (e: React.PointerEvent) => {
    dragFrom.current = e.clientY - barTop;
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const drag = (e: React.PointerEvent) => {
    if (dragFrom.current === null) return;
    setBarTop(Math.max(8, Math.min(window.innerHeight - 280, e.clientY - dragFrom.current)));
  };
  const endDrag = () => {
    dragFrom.current = null;
  };
  const title = (
    <Space>
      <Button icon={<ArrowLeftOutlined />} onClick={() => nav('/')}>
        {t('common:action.back')}
      </Button>
      <span>{info ? `${account(info)} → ${info.target}` : id}</span>
      {live && <Tag color="green">{t('tag.live')}</Tag>}
      {state === 'reconnecting' && <Tag color="orange">{t('tag.reconnecting')}</Tag>}
      {state === 'ended' && <Tag>{t('tag.ended')}</Tag>}
      {granted && <Tag color="gold">{t('tag.controlling')}</Tag>}
    </Space>
  );

  const extra = (
    <Space wrap>
      <Tooltip title={t('control.tooltip')}>
        <Switch checkedChildren={t('control.on')} unCheckedChildren={t('control.off')} checked={control} onChange={setControl} disabled={state === 'ended'} />
      </Tooltip>
      <Button disabled={!granted || !live} onClick={() => send(ctrlAltDel())}>
        Ctrl+Alt+Del
      </Button>
      <Button icon={<FullscreenOutlined />} onClick={() => void box.current?.requestFullscreen()}>
        {t('toolbar.fullscreen')}
      </Button>
      <Button danger icon={<DisconnectOutlined />} disabled={state === 'ended'} onClick={() => void disconnect()}>
        {t('toolbar.disconnect')}
      </Button>
    </Space>
  );

  // The owner view is a bare desktop: the Card stays (so the Screen canvases
  // are never remounted under the renderer) but covers the whole viewport.
  return (
    <Card className={owned ? 'rdp-own' : undefined} title={owned ? undefined : title} extra={owned ? undefined : extra}>
      {error && !owned && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
      {state === 'reconnecting' && !owned && <Alert type="warning" showIcon message={t('alert.gatewayReconnecting')} style={{ marginBottom: 12 }} />}
      {granted && !owned && <Alert type="warning" showIcon message={t('alert.controlActive')} style={{ marginBottom: 12 }} />}
      <div className={`monitor-workspace live-workspace${owned ? ' no-aside' : ''}`}>
        <div className="monitor-stage">
          <div ref={box} tabIndex={-1} className="screen-box" style={{ outline: 'none' }} onPointerEnter={() => void pushClipboard()}>
            {granted && (
              <textarea
                ref={ime}
                className="rdp-ime"
                aria-hidden
                tabIndex={-1}
                autoComplete="off"
                autoCorrect="off"
                spellCheck={false}
                onCompositionEnd={(e) => {
                  send(unicodeText(e.data));
                  e.currentTarget.value = '';
                }}
                onInput={(e) => {
                  if (!(e.nativeEvent as unknown as { isComposing?: boolean }).isComposing) e.currentTarget.value = '';
                }}
              />
            )}
            <Screen ref={view} size={size} interactive={granted} localCursor={owned} fit={owned ? 'actual' : 'contain'} onPointerEvent={onPointerEvent} onTouch={onTouch} />
          </div>
          {info && !owned && (
            <Descriptions size="small" column={{ xs: 1, sm: 2, md: 2, lg: 2, xl: 2, xxl: 3 }} style={{ marginTop: 16 }}>
              <Descriptions.Item label={t('info.client')}>{info.remote_addr}</Descriptions.Item>
              <Descriptions.Item label={t('info.resolution')}>{size[0] ? `${size[0]}×${size[1]}` : '-'}</Descriptions.Item>
              <Descriptions.Item label={t('info.traffic')}>{fmtBytes(info.server_bytes)}</Descriptions.Item>
              <Descriptions.Item label={t('info.viewers')}>
                {t('info.viewerCount', { n: info.viewers })}{info.controllers ? t('info.controllerCount', { n: info.controllers }) : ''}
              </Descriptions.Item>
              <Descriptions.Item label={t('info.frames')}>{info.frames}</Descriptions.Item>
              <Descriptions.Item label={t('info.injected')}>{info.injected}</Descriptions.Item>
              <Descriptions.Item label={t('info.decodeErrors')}>{info.decode_errors}</Descriptions.Item>
              <Descriptions.Item label={t('info.recording')}>{info.recording ? t('info.recordingOn') : t('info.recordingOff')}</Descriptions.Item>
            </Descriptions>
          )}
          {!owned && <Events events={events} live />}
        </div>
        {!owned && (
          <aside className="monitor-aside" aria-label={t('aside.userDrive')}>
            <DriveBrowser key={id} id={id} ended={state === 'ended'} web={!!info?.web} />
          </aside>
        )}
      </div>
      {owned && (
        <div className="rdp-toolbar" style={{ top: barTop }}>
          <Tooltip title={t('aside.dragHint')} placement="left">
            <div className="rdp-toolbar-handle" onPointerDown={startDrag} onPointerMove={drag} onPointerUp={endDrag}>
              <HolderOutlined />
            </div>
          </Tooltip>
          {state === 'reconnecting' && (
            <Tooltip title={t('aside.gatewayReconnecting')} placement="left">
              <div className="rdp-toolbar-status">
                <LoadingOutlined />
              </div>
            </Tooltip>
          )}
          {features.clipboard && (
            <Popover
              trigger="click"
              placement="left"
              title={t('clipboard.title')}
              content={
                <div style={{ width: 320 }}>
                  <Input.TextArea
                    rows={5}
                    value={clipText}
                    onChange={(e) => setClipText(e.target.value)}
                    placeholder={t('clipboard.placeholder')}
                  />
                  {clipImage && (
                    <img src={clipImage} alt={t('clipboard.imageAlt')} style={{ display: 'block', maxWidth: '100%', maxHeight: 160, marginTop: 8, objectFit: 'contain' }} />
                  )}
                  <Button
                    type="primary"
                    icon={<SendOutlined />}
                    style={{ marginTop: 8 }}
                    disabled={!live}
                    onClick={() => {
                      lastClip.current = clipKey({ text: clipText });
                      setClipImage('');
                      sendCtl({ t: 'clip', text: clipText });
                      message.success(t('clipboard.sent'));
                    }}
                  >
                    {t('clipboard.send')}
                  </Button>
                  <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0, fontSize: 12 }}>
                    {t('clipboard.hint')}
                  </Typography.Paragraph>
                </div>
              }
            >
              <Tooltip title={t('clipboard.title')} placement="left">
                <Button type="text" icon={<CopyOutlined />} />
              </Tooltip>
            </Popover>
          )}
          {features.drives &&
            (drive ? (
              <Dropdown
                placement="bottomRight"
                menu={{
                  items: [
                    { key: 'name', label: t('drive.mapped', { drive }), disabled: true },
                    { key: 'change', label: t('drive.change'), icon: <FolderOpenOutlined /> },
                    { key: 'unmap', label: t('drive.unmap'), danger: true },
                  ],
                  onClick: ({ key }) => void (key === 'unmap' ? unmapFolder() : mapFolder()),
                }}
                disabled={!live}
              >
                <Button type="text" className="is-on" icon={<FolderOpenOutlined />} />
              </Dropdown>
            ) : (
              <Tooltip
                placement="left"
                title={folderSupported() ? t('drive.mapTooltip') : t('drive.unsupported')}
              >
                <Button type="text" icon={<FolderOpenOutlined />} disabled={!live || !folderSupported()} onClick={() => void mapFolder()} />
              </Tooltip>
            ))}
          <Tooltip
            placement="left"
            title={muted ? t('audio.unmute') : heardAudio && !audioReady ? t('audio.clickToPlay') : t('audio.mute')}
          >
            <Button
              type="text"
              className={heardAudio && !audioReady && !muted ? 'is-warn' : undefined}
              icon={muted ? <MutedOutlined /> : <SoundOutlined />}
              onClick={() => {
                player.current.setMuted(!muted);
                setMuted(!muted);
              }}
            />
          </Tooltip>
          <Dropdown
            placement="bottomRight"
            trigger={['click']}
            disabled={!live}
            menu={{
              items: SHORTCUTS.map((s) => ({ key: s.key, label: s.label })),
              onClick: ({ key }) => {
                const s = SHORTCUTS.find((x) => x.key === key);
                if (s) send(s.events());
              },
            }}
          >
            <Tooltip title={t('toolbar.shortcutsTooltip')} placement="left">
              <Button type="text" icon={<MacCommandOutlined />} />
            </Tooltip>
          </Dropdown>
          <Tooltip title={t('toolbar.ctrlAltDel')} placement="left">
            <Button type="text" icon={<LockOutlined />} disabled={!live} onClick={() => send(ctrlAltDel())} />
          </Tooltip>
          <Tooltip title={fullscreen ? t('toolbar.exitFullscreen') : t('toolbar.fullscreen')} placement="left">
            <Button
              type="text"
              icon={fullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
              onClick={() => void (document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen())}
            />
          </Tooltip>
          <Tooltip title={t('toolbar.disconnect')} placement="left">
            <Button type="text" danger icon={<DisconnectOutlined />} disabled={state === 'ended'} onClick={() => void disconnect()} />
          </Tooltip>
        </div>
      )}
      {owned && (state === 'ended' || state === 'error') && (
        <div className="rdp-ended">
          <Card>
            <Typography.Title level={5} style={{ marginTop: 0 }}>
              {state === 'ended' ? t('tag.ended') : error || t('ended.connectionLost')}
            </Typography.Title>
            <Button type="primary" onClick={() => nav('/connect')}>
              {t('ended.backToConnect')}
            </Button>
          </Card>
        </div>
      )}
    </Card>
  );
}
