import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Button, Card, Descriptions, Segmented, Select, Slider, Space, Spin, Tag, Tooltip } from 'antd';
import { ArrowLeftOutlined, DownloadOutlined, PauseOutlined, CaretRightOutlined, FullscreenOutlined, MutedOutlined, SoundOutlined } from '@ant-design/icons';
import { useNavigate, useParams } from 'react-router-dom';
import dayjs from 'dayjs';
import { account, api, downloadURL, endLabels, fmtBytes, fmtDuration } from '../api';
import { parseRecording, REC_END, REC_KEY, REC_RESIZE, Renderer, type Recording } from '../rdpv';
import Screen, { type ScreenFit, type ScreenHandle } from '../components/Screen';
import Events, { readEvent, type AuditEvent } from '../components/Events';
import { AudioPlayer, REC_AUDIO } from '../audio';

const SPEEDS = [0.5, 1, 2, 4, 8];

export default function Player() {
  const { id = '' } = useParams();
  const nav = useNavigate();
  const view = useRef<ScreenHandle>(null);
  const box = useRef<HTMLDivElement>(null);
  const renderer = useRef<Renderer | null>(null);
  const cursor = useRef(0); // index of the next record to apply
  const [rec, setRec] = useState<Recording | null>(null);
  const [error, setError] = useState('');
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [time, setTime] = useState(0);
  const [size, setSize] = useState<[number, number]>([0, 0]);
  const [fit, setFit] = useState<ScreenFit>('contain');
  const audio = useRef(new AudioPlayer());
  const [muted, setMuted] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const hasAudio = useMemo(() => !!rec?.records.some((r) => r.kind === REC_AUDIO), [rec]);

  useEffect(() => {
    const a = audio.current;
    // Autoplay rules keep the context suspended until a click or key press.
    const unlock = () => {
      a.unlock();
      setBlocked(false);
    };
    a.unlock();
    window.setTimeout(() => setBlocked(!a.ready), 300);
    window.addEventListener('pointerdown', unlock);
    window.addEventListener('keydown', unlock);
    return () => {
      window.removeEventListener('pointerdown', unlock);
      window.removeEventListener('keydown', unlock);
      a.close();
    };
  }, []);

  useEffect(() => audio.current.setMuted(muted), [muted]);
  useEffect(() => {
    if (!playing) audio.current.reset();
  }, [playing, speed]);

  useEffect(() => {
    let dead = false;
    api
      .recording(id)
      .then((buf) => {
        if (dead) return;
        const r = parseRecording(buf);
        renderer.current = new Renderer(view.current!.screen, view.current!.overlay, (w, h) => setSize([w, h]));
        setRec(r);
        setPlaying(true);
      })
      .catch((e: Error) => !dead && setError(e.message));
    return () => {
      dead = true;
      renderer.current?.reset();
    };
  }, [id]);

  // seek replays from the key frame at or before ms.
  const seek = useCallback(
    async (ms: number) => {
      if (!rec || !renderer.current) return;
      renderer.current.reset();
      audio.current.reset();
      let from = 0;
      for (let i = 0; i < rec.records.length; i++) {
        const r = rec.records[i];
        if (r.time > ms) break;
        if (r.kind === REC_KEY) from = i;
      }
      // Always apply the first Resize so the canvas has the right size.
      const first = rec.records.findIndex((r) => r.kind === REC_RESIZE);
      if (first >= 0 && first < from) void renderer.current.push(rec.records[first]);
      let i = from;
      for (; i < rec.records.length && rec.records[i].time <= ms; i++) {
        if (rec.records[i].kind !== REC_AUDIO) void renderer.current.push(rec.records[i]);
      }
      cursor.current = i;
      setTime(ms);
      await renderer.current.idle();
    },
    [rec],
  );

  useEffect(() => {
    if (rec) void seek(0);
  }, [rec, seek]);

  useEffect(() => {
    if (!rec || !playing) return;
    let raf = 0;
    let last = performance.now();
    let t = time;
    const step = (now: number) => {
      t += (now - last) * speed;
      last = now;
      const end = Math.min(t, rec.duration);
      const r = renderer.current!;
      while (cursor.current < rec.records.length && rec.records[cursor.current].time <= end) {
        const next = rec.records[cursor.current++];
        // Sound only plays at normal speed; faster playback would garble it.
        if (next.kind === REC_AUDIO) {
          if (speed === 1) audio.current.push(next.payload);
        } else if (next.kind !== REC_END) void r.push(next);
      }
      setTime(end);
      if (end >= rec.duration) {
        setPlaying(false);
        return;
      }
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
    // time is intentionally only read when playback (re)starts
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rec, playing, speed]);

  const meta = rec?.meta;
  const events = useMemo(() => (rec ? rec.records.map(readEvent).filter((e): e is AuditEvent => e !== null) : []), [rec]);
  const marks = useMemo(() => {
    const significant = events.filter(e => e.action !== 'move');
    const step = Math.max(1, Math.ceil(significant.length / 40));
    return Object.fromEntries(significant.filter((_, i) => i % step === 0).map(e => [e.time, '|']));
  }, [events]);
  return (
    <Card
      title={
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => nav('/recordings')}>
            返回
          </Button>
          <span>{meta ? `${account(meta)} → ${meta.target}` : id}</span>
          {rec?.truncated && <Tag color="orange">文件被截断</Tag>}
        </Space>
      }
      extra={
        <Space>
          <Button icon={<FullscreenOutlined />} onClick={() => void box.current?.requestFullscreen()}>
            全屏
          </Button>
          <Button icon={<DownloadOutlined />} href={downloadURL(id)}>
            下载
          </Button>
        </Space>
      }
    >
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
      <div className="monitor-workspace playback-workspace">
        <div className="monitor-stage">
      <Spin spinning={!rec && !error}>
        <div ref={box} className="screen-box">
          <Screen ref={view} size={size} fit={fit} />
        </div>
      </Spin>
      <div className="playback-controls">
        <Button
          type="primary"
          icon={playing ? <PauseOutlined /> : <CaretRightOutlined />}
          disabled={!rec}
          onClick={async () => {
            if (!playing && rec && time >= rec.duration) await seek(0);
            setPlaying(!playing);
          }}
        />
        <span style={{ fontVariantNumeric: 'tabular-nums' }}>
          {fmtDuration(time)} / {fmtDuration(rec?.duration ?? 0)}
        </span>
        <Slider
          className="playback-seek"
          min={0}
          max={rec?.duration ?? 0}
          marks={marks}
          value={time}
          tooltip={{ formatter: (v) => fmtDuration(v ?? 0) }}
          disabled={!rec}
          onChange={(v) => {
            setPlaying(false);
            setTime(v);
          }}
          onChangeComplete={(v) => void seek(v)}
        />
        <Segmented size="small" value={fit} onChange={v => setFit(v as ScreenFit)} options={[{ value: 'contain', label: '适应窗口' }, { value: 'actual', label: '原始大小' }]} />
        {hasAudio && (
          <Tooltip title={blocked ? '浏览器阻止了自动播放，点击页面任意处开启声音' : speed !== 1 ? '只在 1× 速度播放声音' : muted ? '取消静音' : '静音'}>
            <Button
              icon={muted || blocked || speed !== 1 ? <MutedOutlined /> : <SoundOutlined />}
              danger={blocked}
              onClick={() => {
                audio.current.unlock();
                setBlocked(false);
                setMuted(!muted);
              }}
            />
          </Tooltip>
        )}
        <Select value={speed} onChange={setSpeed} options={SPEEDS.map((s) => ({ value: s, label: `${s}×` }))} style={{ width: 90 }} />
      </div>
      {meta && (
        <Descriptions size="small" column={{ xs: 1, sm: 2, md: 2, lg: 2, xl: 2, xxl: 3 }} style={{ marginTop: 16 }}>
          <Descriptions.Item label="开始时间">{dayjs(meta.started).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
          <Descriptions.Item label="客户端">{meta.remote_addr}</Descriptions.Item>
          <Descriptions.Item label="分辨率">{size[0] ? `${size[0]}×${size[1]}` : '-'}</Descriptions.Item>
          <Descriptions.Item label="大小">{fmtBytes(meta.size)}</Descriptions.Item>
          <Descriptions.Item label="结束">{endLabels[meta.end ?? ''] ?? meta.end ?? '-'}</Descriptions.Item>
          <Descriptions.Item label="登录方式">{meta.login_form ? '网关登录表单' : '直连凭据'}</Descriptions.Item>
          {meta.error && <Descriptions.Item label="错误">{meta.error}</Descriptions.Item>}
        </Descriptions>
      )}
        </div>
        <aside className="monitor-aside" aria-label="录像操作时间轴">
        <Events
          sidebar
          events={events}
          time={time}
          onSeek={(ms) => {
            setPlaying(false);
            void seek(ms);
          }}
        />
        </aside>
      </div>
    </Card>
  );
}
