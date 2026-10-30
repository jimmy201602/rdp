import { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Button, Empty, Input, List, Select, Space, Switch, Table, Tag, Tooltip } from 'antd';
import { fmtBytes, fmtDuration } from '../api';
import type { Rec } from '../rdpv';

export const REC_EVENT = 6;
export interface AuditEvent {
  time: number; kind: string; source: string; action: string;
  device?: number; path?: string; bytes?: number; status?: string;
  detail?: string; x?: number; y?: number;
}
export function readEvent(rec: Rec): AuditEvent | null {
  if (rec.kind !== REC_EVENT) return null;
  try {
    const e = JSON.parse(new TextDecoder().decode(rec.payload)) as AuditEvent;
    if (typeof e.kind !== 'string' || typeof e.action !== 'string') return null;
    return { ...e, time: rec.time };
  } catch { return null; }
}
const kinds: Record<string, string> = { keyboard: '键盘', mouse: '鼠标', clipboard: '剪贴板', file: '文件', device: '映射设备', system: '系统' };
const sources: Record<string, string> = { client: '原用户', target: '目标系统', admin: '监控端', gateway: '网关' };
const actions: Record<string, string> = {
  input: '按键（隐藏内容）', move: '移动', button_down: '按下鼠标', button_up: '释放鼠标', wheel: '滚轮',
  formats: '复制/格式公告', data: '剪贴板数据传送', file_data: '剪贴板文件数据',
  open: '打开', close: '关闭', read_upload: '读取映射文件 → 目标', write_download: '写入映射文件 ← 目标',
  delete: '标记删除', rename: '重命名', set_info: '修改属性', announce: '映射设备', remove: '取消映射',
  browse: '监控端浏览', admin_download: '映射盘 → 监控端下载', admin_upload: '监控端 → 映射盘上传', admin_delete: '监控端删除',
  events_dropped: '事件丢失',
};

const PAGE_SIZE = 20;
export function currentEventIndex(rows: { time: number }[], time?: number): number {
  if (time === undefined) return -1;
  let lo = 0, hi = rows.length - 1, found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (rows[mid].time <= time) { found = mid; lo = mid + 1; } else hi = mid - 1;
  }
  return found;
}
const timestamp = (ms: number) => `${fmtDuration(ms)}.${String(ms % 1000).padStart(3, '0')}`;
const failed = (status?: string) => status === 'failed' || !!(status?.startsWith('0x') && status !== '0x00000000');
const detail = (e: AuditEvent) => <>
  {e.device !== undefined && <span>设备 {e.device} </span>}{e.path}
  {e.kind === 'mouse' && ` (${e.x ?? 0}, ${e.y ?? 0})`}
  {e.bytes !== undefined && ` · ${fmtBytes(e.bytes)}`}{e.detail && ` · ${e.detail}`}
</>;

export default function Events({ events, time, onSeek, live = false, sidebar = false }: { events: AuditEvent[]; time?: number; onSeek?: (ms: number) => void; live?: boolean; sidebar?: boolean }) {
  const [kind, setKind] = useState('all');
  const [search, setSearch] = useState('');
  const [follow, setFollow] = useState(true);
  const [page, setPage] = useState(1);
  const list = useRef<HTMLDivElement>(null);
  const rows = useMemo(() => {
    const q = search.toLowerCase();
    const filtered = events.map((e, index) => ({ ...e, key: index })).filter(e =>
      (kind === 'all' || e.kind === kind) && (!q || `${e.path ?? ''} ${e.detail ?? ''} ${actions[e.action] ?? e.action}`.toLowerCase().includes(q)));
    return live ? filtered.reverse() : filtered;
  }, [events, kind, search, live]);
  const activeIndex = useMemo(() => live ? -1 : currentEventIndex(rows, time), [rows, time, live]);
  const activeKey = activeIndex >= 0 ? rows[activeIndex].key : -1;
  useEffect(() => { if (!follow) setPage(1); }, [kind, search]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (sidebar && follow) setPage(activeIndex >= 0 ? Math.floor(activeIndex / PAGE_SIZE) + 1 : 1);
  }, [sidebar, follow, activeIndex]);
  useEffect(() => {
    const box = list.current;
    if (!sidebar || !follow || !box) return;
    const item = box.querySelector<HTMLElement>('.event-timeline-item.is-current');
    if (!item) { if (activeIndex < 0) box.scrollTo({ top: 0 }); return; }
    const top = item.getBoundingClientRect().top - box.getBoundingClientRect().top + box.scrollTop;
    box.scrollTo({ top: Math.max(0, top - box.clientHeight / 2 + item.offsetHeight / 2), behavior: 'smooth' });
  }, [sidebar, follow, activeKey, activeIndex, page]);
  const pauseFollow = () => { if (follow) setFollow(false); };
  if (sidebar) return <section className="event-sidebar">
    <header className="event-sidebar-heading">
      <div><h3>操作时间轴</h3><span>{follow ? '跟随播放进度' : '已暂停跟随，可自由浏览'}</span></div>
      <div className="event-sidebar-actions">
        <span className="event-count">{rows.length} / {events.length}</span>
        <Tooltip title="开启后自动滚动并高亮当前播放位置的事件；手动滚动或翻页会暂停跟随">
          <Switch size="small" checked={follow} onChange={setFollow} checkedChildren="跟随" unCheckedChildren="跟随" aria-label="事件跟随播放" />
        </Tooltip>
      </div>
    </header>
    <div className="event-sidebar-filters">
      <Select aria-label="事件类型" value={kind} onChange={setKind} options={[{ value: 'all', label: '全部类型' }, ...Object.entries(kinds).map(([value, label]) => ({ value, label }))]} />
      <Input.Search aria-label="搜索操作事件" placeholder="文件路径 / 事件" value={search} onChange={e => setSearch(e.target.value)} allowClear />
    </div>
    <div ref={list} className="event-sidebar-list" onWheel={pauseFollow} onTouchMove={pauseFollow} onKeyDown={e => { if (['ArrowUp', 'ArrowDown', 'PageUp', 'PageDown', 'Home', 'End'].includes(e.key)) pauseFollow(); }}>
      <List dataSource={rows} rowKey="key" pagination={{ current: page, pageSize: PAGE_SIZE, size: 'small', showSizeChanger: false, hideOnSinglePage: true, onChange: p => { setFollow(false); setPage(p); } }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={events.length ? '没有匹配的事件' : '该录像暂无操作事件'} /> }}
        renderItem={e => <List.Item className={`event-timeline-item${e.key === activeKey ? ' is-current' : ''}${time !== undefined && e.time > time ? ' is-future' : ''}`}>
          <span className={`event-timeline-dot${failed(e.status) ? ' is-error' : ''}`} aria-hidden="true" />
          <div className="event-timeline-content">
            <div className="event-timeline-meta">
              <Button type="link" size="small" disabled={!onSeek} aria-current={e.key === activeKey ? 'time' : undefined} onClick={() => onSeek?.(e.time)} aria-label={`跳转到 ${timestamp(e.time)}`}>{timestamp(e.time)}</Button>
              <span>{kinds[e.kind] ?? e.kind} · {sources[e.source] ?? e.source}</span>
            </div>
            <div className="event-timeline-action">{actions[e.action] ?? e.action}{e.status && <Tag color={failed(e.status) ? 'red' : undefined}>{e.status}</Tag>}</div>
            <div className="event-timeline-detail">{detail(e)}</div>
          </div>
        </List.Item>} />
    </div>
    <details className="event-privacy-note"><summary>事件记录说明</summary>不保存键入原文或剪贴板正文；鼠标移动每 200ms 采样。文件读写表示数据方向，不等同于完成一次复制。旧录像没有操作事件。</details>
  </section>;
  return <section style={{ marginTop: 16 }}>
    <Space wrap style={{ marginBottom: 8 }}>
      <b>操作事件</b>
      <Select value={kind} onChange={setKind} style={{ width: 120 }} options={[{ value: 'all', label: '全部类型' }, ...Object.entries(kinds).map(([value, label]) => ({ value, label }))]} />
      <Input.Search placeholder="文件路径 / 事件" value={search} onChange={e => setSearch(e.target.value)} allowClear style={{ width: 210 }} />
      <span>{events.length} 条{live ? '（最近 500 条）' : ''}</span>
    </Space>
    <Alert type="info" message="不保存键入原文或剪贴板正文；鼠标移动每 200ms 采样。映射文件读取/写入表示数据方向，不等同于完成一次文件复制。旧录像没有操作事件。" style={{ marginBottom: 8 }} />
    <Table size="small" dataSource={rows} pagination={{ pageSize: 10, showSizeChanger: false }} scroll={{ x: 660 }}
      locale={{ emptyText: live ? '等待新事件（切换协同模式会重连）' : '该录像暂无事件' }}
      columns={[
        { title: '时间', dataIndex: 'time', width: 95, render: (ms: number) => <Button size="small" type="link" disabled={!onSeek} onClick={() => onSeek?.(ms)}>{fmtDuration(ms)}.{String(ms % 1000).padStart(3, '0')}</Button> },
        { title: '类型 / 来源', width: 140, render: (_, e) => <><Tag>{kinds[e.kind] ?? e.kind}</Tag>{sources[e.source] ?? e.source}</> },
        { title: '操作', width: 190, render: (_, e) => <span style={{ color: time !== undefined && e.time > time ? '#999' : undefined }}>{actions[e.action] ?? e.action}</span> },
        { title: '详细信息', render: (_, e) => <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{e.device !== undefined && `设备 ${e.device} `}{e.path}{e.kind === 'mouse' && ` (${e.x ?? 0}, ${e.y ?? 0})`}{e.bytes !== undefined && ` ${fmtBytes(e.bytes)}`} {e.detail} {e.status && <Tag color={e.status === 'failed' || (e.status.startsWith('0x') && e.status !== '0x00000000') ? 'red' : undefined}>{e.status}</Tag>}</div> },
      ]} />
  </section>;
}
