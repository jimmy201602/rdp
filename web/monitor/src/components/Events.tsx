import { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Button, Empty, Input, List, Select, Space, Switch, Table, Tag, Tooltip } from 'antd';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
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
const kinds = ['keyboard', 'mouse', 'clipboard', 'file', 'device', 'system'];
const sources = ['client', 'target', 'admin', 'gateway'];
const actions = [
  'input', 'move', 'button_down', 'button_up', 'wheel',
  'formats', 'data', 'file_data',
  'open', 'close', 'read_upload', 'write_download',
  'delete', 'rename', 'set_info', 'announce', 'remove',
  'browse', 'admin_download', 'admin_upload', 'admin_delete',
  'events_dropped',
];
type EventsT = TFunction<'events'>;
const label = (t: EventsT, group: 'kind' | 'source' | 'action', known: string[], value: string) =>
  known.includes(value) ? t(`${group}.${value}` as never) as string : value;

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
const detail = (t: EventsT, e: AuditEvent) => <>
  {e.device !== undefined && <span>{t('device', { id: e.device })} </span>}{e.path}
  {e.kind === 'mouse' && ` (${e.x ?? 0}, ${e.y ?? 0})`}
  {e.bytes !== undefined && ` · ${fmtBytes(e.bytes)}`}{e.detail && ` · ${e.detail}`}
</>;

export default function Events({ events, time, onSeek, live = false, sidebar = false }: { events: AuditEvent[]; time?: number; onSeek?: (ms: number) => void; live?: boolean; sidebar?: boolean }) {
  const { t } = useTranslation('events');
  const kindLabel = (v: string) => label(t, 'kind', kinds, v);
  const sourceLabel = (v: string) => label(t, 'source', sources, v);
  const actionLabel = (v: string) => label(t, 'action', actions, v);
  const kindOptions = [{ value: 'all', label: t('allKinds') }, ...kinds.map(value => ({ value, label: kindLabel(value) }))];
  const [kind, setKind] = useState('all');
  const [search, setSearch] = useState('');
  const [follow, setFollow] = useState(true);
  const [page, setPage] = useState(1);
  const list = useRef<HTMLDivElement>(null);
  const rows = useMemo(() => {
    const q = search.toLowerCase();
    const filtered = events.map((e, index) => ({ ...e, key: index })).filter(e =>
      (kind === 'all' || e.kind === kind) && (!q || `${e.path ?? ''} ${e.detail ?? ''} ${actionLabel(e.action)}`.toLowerCase().includes(q)));
    return live ? filtered.reverse() : filtered;
  }, [events, kind, search, live, t]); // eslint-disable-line react-hooks/exhaustive-deps
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
      <div><h3>{t('timeline')}</h3><span>{follow ? t('following') : t('followPaused')}</span></div>
      <div className="event-sidebar-actions">
        <span className="event-count">{rows.length} / {events.length}</span>
        <Tooltip title={t('followTooltip')}>
          <Switch size="small" checked={follow} onChange={setFollow} checkedChildren={t('follow')} unCheckedChildren={t('follow')} aria-label={t('followAria')} />
        </Tooltip>
      </div>
    </header>
    <div className="event-sidebar-filters">
      <Select aria-label={t('kindAria')} value={kind} onChange={setKind} options={kindOptions} />
      <Input.Search aria-label={t('searchAria')} placeholder={t('searchPlaceholder')} value={search} onChange={e => setSearch(e.target.value)} allowClear />
    </div>
    <div ref={list} className="event-sidebar-list" onWheel={pauseFollow} onTouchMove={pauseFollow} onKeyDown={e => { if (['ArrowUp', 'ArrowDown', 'PageUp', 'PageDown', 'Home', 'End'].includes(e.key)) pauseFollow(); }}>
      <List dataSource={rows} rowKey="key" pagination={{ current: page, pageSize: PAGE_SIZE, size: 'small', showSizeChanger: false, hideOnSinglePage: true, onChange: p => { setFollow(false); setPage(p); } }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={events.length ? t('empty.noMatch') : t('empty.noEvents')} /> }}
        renderItem={e => <List.Item className={`event-timeline-item${e.key === activeKey ? ' is-current' : ''}${time !== undefined && e.time > time ? ' is-future' : ''}`}>
          <span className={`event-timeline-dot${failed(e.status) ? ' is-error' : ''}`} aria-hidden="true" />
          <div className="event-timeline-content">
            <div className="event-timeline-meta">
              <Button type="link" size="small" disabled={!onSeek} aria-current={e.key === activeKey ? 'time' : undefined} onClick={() => onSeek?.(e.time)} aria-label={t('seekTo', { time: timestamp(e.time) })}>{timestamp(e.time)}</Button>
              <span>{kindLabel(e.kind)} · {sourceLabel(e.source)}</span>
            </div>
            <div className="event-timeline-action">{actionLabel(e.action)}{e.status && <Tag color={failed(e.status) ? 'red' : undefined}>{e.status}</Tag>}</div>
            <div className="event-timeline-detail">{detail(t, e)}</div>
          </div>
        </List.Item>} />
    </div>
    <details className="event-privacy-note"><summary>{t('privacy.summary')}</summary>{t('privacy.sidebar')}</details>
  </section>;
  return <section style={{ marginTop: 16 }}>
    <Space wrap style={{ marginBottom: 8 }}>
      <b>{t('title')}</b>
      <Select value={kind} onChange={setKind} style={{ width: 120 }} options={kindOptions} />
      <Input.Search placeholder={t('searchPlaceholder')} value={search} onChange={e => setSearch(e.target.value)} allowClear style={{ width: 210 }} />
      <span>{t('count', { count: events.length })}{live ? t('recent') : ''}</span>
    </Space>
    <Alert type="info" message={t('privacy.table')} style={{ marginBottom: 8 }} />
    <Table size="small" dataSource={rows} pagination={{ pageSize: 10, showSizeChanger: false }} scroll={{ x: 660 }}
      locale={{ emptyText: live ? t('empty.waitingLive') : t('empty.noRecordingEvents') }}
      columns={[
        { title: t('column.time'), dataIndex: 'time', width: 95, render: (ms: number) => <Button size="small" type="link" disabled={!onSeek} onClick={() => onSeek?.(ms)}>{fmtDuration(ms)}.{String(ms % 1000).padStart(3, '0')}</Button> },
        { title: t('column.kindSource'), width: 140, render: (_, e) => <><Tag>{kindLabel(e.kind)}</Tag>{sourceLabel(e.source)}</> },
        { title: t('column.action'), width: 190, render: (_, e) => <span style={{ color: time !== undefined && e.time > time ? '#999' : undefined }}>{actionLabel(e.action)}</span> },
        { title: t('column.detail'), render: (_, e) => <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{e.device !== undefined && `${t('device', { id: e.device })} `}{e.path}{e.kind === 'mouse' && ` (${e.x ?? 0}, ${e.y ?? 0})`}{e.bytes !== undefined && ` ${fmtBytes(e.bytes)}`} {e.detail} {e.status && <Tag color={e.status === 'failed' || (e.status.startsWith('0x') && e.status !== '0x00000000') ? 'red' : undefined}>{e.status}</Tag>}</div> },
      ]} />
  </section>;
}
