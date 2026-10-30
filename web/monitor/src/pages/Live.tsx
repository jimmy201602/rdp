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
          if (control && !hello.control) message.warning('网关未开启 -monitor-control，仅能观看');
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
            message.loading({ key: 'target-reconnect', content: `与远程主机的连接中断，正在重连（第 ${msg.attempt} 次）…`, duration: 0 });
          } else {
            message.success({ key: 'target-reconnect', content: '已重新连接远程主机', duration: 3 });
          }
        } else if (msg.t === 'drive') {
          if (msg.error) message.error(`映射失败：${msg.error}`);
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
        setError('与网关的连接已中断，重连失败');
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
        if (skippedImage) message.warning('剪贴板图片超过 2.9 MB，只同步了文字');
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
        message.error('浏览器未授予该文件夹的读写权限');
        return;
      }
      await folder.current?.close();
      folder.current = f;
      sendCtl({ t: 'map', name: f.name });
    } catch (e) {
      if ((e as DOMException).name !== 'AbortError') message.error(`选择文件夹失败：${(e as Error).message}`);
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
    message.success('已断开');
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
        返回
      </Button>
      <span>{info ? `${account(info)} → ${info.target}` : id}</span>
      {live && <Tag color="green">实时</Tag>}
      {state === 'reconnecting' && <Tag color="orange">重连中…</Tag>}
      {state === 'ended' && <Tag>会话已结束</Tag>}
      {granted && <Tag color="gold">协同控制中</Tag>}
    </Space>
  );

  const extra = (
    <Space wrap>
      <Tooltip title="开启后你的键盘和鼠标会与原用户一起操作该会话">
        <Switch checkedChildren="协同" unCheckedChildren="旁观" checked={control} onChange={setControl} disabled={state === 'ended'} />
      </Tooltip>
      <Button disabled={!granted || !live} onClick={() => send(ctrlAltDel())}>
        Ctrl+Alt+Del
      </Button>
      <Button icon={<FullscreenOutlined />} onClick={() => void box.current?.requestFullscreen()}>
        全屏
      </Button>
      <Button danger icon={<DisconnectOutlined />} disabled={state === 'ended'} onClick={() => void disconnect()}>
        断开
      </Button>
    </Space>
  );

  // The owner view is a bare desktop: the Card stays (so the Screen canvases
  // are never remounted under the renderer) but covers the whole viewport.
  return (
    <Card className={owned ? 'rdp-own' : undefined} title={owned ? undefined : title} extra={owned ? undefined : extra}>
      {error && !owned && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
      {state === 'reconnecting' && !owned && <Alert type="warning" showIcon message="与网关的连接中断，正在重连。" style={{ marginBottom: 12 }} />}
      {granted && !owned && <Alert type="warning" showIcon message="协同控制已开启：你的操作会直接作用于用户的桌面。" style={{ marginBottom: 12 }} />}
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
              <Descriptions.Item label="客户端">{info.remote_addr}</Descriptions.Item>
              <Descriptions.Item label="分辨率">{size[0] ? `${size[0]}×${size[1]}` : '-'}</Descriptions.Item>
              <Descriptions.Item label="流量">{fmtBytes(info.server_bytes)}</Descriptions.Item>
              <Descriptions.Item label="观看">
                {info.viewers} 人{info.controllers ? `（${info.controllers} 人协同）` : ''}
              </Descriptions.Item>
              <Descriptions.Item label="画面帧">{info.frames}</Descriptions.Item>
              <Descriptions.Item label="注入事件">{info.injected}</Descriptions.Item>
              <Descriptions.Item label="解码异常">{info.decode_errors}</Descriptions.Item>
              <Descriptions.Item label="录像">{info.recording ? '录制中' : '未开启'}</Descriptions.Item>
            </Descriptions>
          )}
          {!owned && <Events events={events} live />}
        </div>
        {!owned && (
          <aside className="monitor-aside" aria-label="用户映射磁盘">
            <DriveBrowser key={id} id={id} ended={state === 'ended'} web={!!info?.web} />
          </aside>
        )}
      </div>
      {owned && (
        <div className="rdp-toolbar" style={{ top: barTop }}>
          <Tooltip title="拖动可上下移动" placement="left">
            <div className="rdp-toolbar-handle" onPointerDown={startDrag} onPointerMove={drag} onPointerUp={endDrag}>
              <HolderOutlined />
            </div>
          </Tooltip>
          {state === 'reconnecting' && (
            <Tooltip title="与网关的连接中断，正在重连" placement="left">
              <div className="rdp-toolbar-status">
                <LoadingOutlined />
              </div>
            </Tooltip>
          )}
          {features.clipboard && (
            <Popover
              trigger="click"
              placement="left"
              title="剪贴板"
              content={
                <div style={{ width: 320 }}>
                  <Input.TextArea
                    rows={5}
                    value={clipText}
                    onChange={(e) => setClipText(e.target.value)}
                    placeholder="远程复制的文字会出现在这里；输入或粘贴后点“发送”即可在远程粘贴"
                  />
                  {clipImage && (
                    <img src={clipImage} alt="剪贴板图片" style={{ display: 'block', maxWidth: '100%', maxHeight: 160, marginTop: 8, objectFit: 'contain' }} />
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
                      message.success('已发送到远程剪贴板');
                    }}
                  >
                    发送到远程
                  </Button>
                  <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0, fontSize: 12 }}>
                    切回本页时自动同步本机剪贴板（文字、HTML 格式、图片），远程复制的内容自动写入本机。
                  </Typography.Paragraph>
                </div>
              }
            >
              <Tooltip title="剪贴板" placement="left">
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
                    { key: 'name', label: `已映射：${drive}`, disabled: true },
                    { key: 'change', label: '更换文件夹', icon: <FolderOpenOutlined /> },
                    { key: 'unmap', label: '取消映射', danger: true },
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
                title={folderSupported() ? '映射本地文件夹到远程（刷新页面后需重新选择）' : '映射文件夹需要 Chrome / Edge，并通过 HTTPS 或 localhost 访问'}
              >
                <Button type="text" icon={<FolderOpenOutlined />} disabled={!live || !folderSupported()} onClick={() => void mapFolder()} />
              </Tooltip>
            ))}
          <Tooltip
            placement="left"
            title={muted ? '取消静音' : heardAudio && !audioReady ? '点击页面任意处即可播放远程声音' : '静音'}
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
            <Tooltip title="发送快捷键（全屏时可直接按 Win、Alt+Tab 等）" placement="left">
              <Button type="text" icon={<MacCommandOutlined />} />
            </Tooltip>
          </Dropdown>
          <Tooltip title="发送 Ctrl+Alt+Del" placement="left">
            <Button type="text" icon={<LockOutlined />} disabled={!live} onClick={() => send(ctrlAltDel())} />
          </Tooltip>
          <Tooltip title={fullscreen ? '退出全屏' : '全屏'} placement="left">
            <Button
              type="text"
              icon={fullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
              onClick={() => void (document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen())}
            />
          </Tooltip>
          <Tooltip title="断开" placement="left">
            <Button type="text" danger icon={<DisconnectOutlined />} disabled={state === 'ended'} onClick={() => void disconnect()} />
          </Tooltip>
        </div>
      )}
      {owned && (state === 'ended' || state === 'error') && (
        <div className="rdp-ended">
          <Card>
            <Typography.Title level={5} style={{ marginTop: 0 }}>
              {state === 'ended' ? '会话已结束' : error || '连接中断'}
            </Typography.Title>
            <Button type="primary" onClick={() => nav('/connect')}>
              返回连接页
            </Button>
          </Card>
        </div>
      )}
    </Card>
  );
}
