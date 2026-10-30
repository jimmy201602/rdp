import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, App, Button, Empty, Input, Spin, Table, Tooltip } from 'antd';
import { AppstoreOutlined, ArrowUpOutlined, DeleteOutlined, DownloadOutlined, FileOutlined, FolderFilled, HddOutlined, LeftOutlined, LinkOutlined, MenuOutlined, ReloadOutlined, RightOutlined, SearchOutlined, UploadOutlined, VerticalAlignMiddleOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { api, fmtBytes, type DriveEntry, type MappedDevice } from '../api';
import { columnPaths, sortedEntries, updateColumns, type DriveColumn, type FinderView } from './finderState';

type History = { paths: string[]; index: number };
const views = [
  { value: 'list', label: 'list', icon: <MenuOutlined /> },
  { value: 'icons', label: 'icons', icon: <AppstoreOutlined /> },
  { value: 'columns', label: 'columns', icon: <VerticalAlignMiddleOutlined rotate={90} /> },
] as const;
const entryIcon = (entry: DriveEntry) => entry.Attributes & 0x400 ? <LinkOutlined /> : entry.IsDir ? <FolderFilled className="finder-folder-icon" /> : <FileOutlined />;

export default function DriveBrowser({ id, ended, web = false }: { id: string; ended: boolean; web?: boolean }) {
  const { t } = useTranslation(['drive', 'common']);
  const { message, modal } = App.useApp();
  const [enabled, setEnabled] = useState(false);
  const [devices, setDevices] = useState<MappedDevice[]>([]);
  const [device, setDevice] = useState<number>();
  const [path, setPath] = useState('/');
  const [draft, setDraft] = useState('/');
  const [history, setHistory] = useState<History>({ paths: ['/'], index: 0 });
  const [entries, setEntries] = useState<DriveEntry[]>([]);
  const [view, setView] = useState<FinderView>('list');
  const [columns, setColumns] = useState<DriveColumn[]>([]);
  const columnsBox = useRef<HTMLDivElement>(null);
  const [selection, setSelection] = useState<string>();
  const [search, setSearch] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const pending = useRef(false);
  const mounted = useRef(true);
  const selectedDevice = devices.find(d => d.id === device);
  const available = !!selectedDevice?.accepted && selectedDevice.type === 8;
  const current = useRef({ device, path, ended, enabled, available });
  current.current = { device, path, ended, enabled, available };

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const loadDevices = useCallback(async () => {
    if (ended) return;
    try {
      const result = await api.devices(id);
      if (mounted.current) setDevices(result);
    } catch (e) { if (mounted.current) setError(String(e)); }
  }, [id, ended]);
  useEffect(() => {
    let disposed = false;
    void api.info().then(i => { if (!disposed) setEnabled(i.drive_control); }).catch(e => { if (!disposed) setError(String(e)); });
    void loadDevices();
    if (ended) return () => { disposed = true; };
    const timer = setInterval(() => void loadDevices(), 5000);
    return () => { disposed = true; clearInterval(timer); };
  }, [loadDevices, ended]);
  useEffect(() => {
    if (!available) { setEntries([]); setColumns([]); setSelection(undefined); setLoaded(false); }
  }, [available]);

  const canBrowse = enabled && available && !busy && !ended;
  const selected = entries.find(e => e.Name === selection);
  const canUseFile = canBrowse && !!selected && !selected.IsDir && !(selected.Attributes & 0x400);
  const rows = useMemo(() => sortedEntries(entries, search), [entries, search]);
  const visibleColumns = useMemo(() => columns.map(c => ({ ...c, entries: c.path === path ? rows : sortedEntries(c.entries) })), [columns, path, rows]);
  useEffect(() => {
    if (view === 'columns' && columnsBox.current) columnsBox.current.scrollLeft = columnsBox.current.scrollWidth;
  }, [view, path, columns.length]);
  const load = async (raw: string, selectedID = device, mode: 'push' | 'replace' | number = 'push', selectedName?: string, withParents = view === 'columns') => {
    if (selectedID === undefined || pending.current || ended || !enabled || !devices.some(d => d.id === selectedID && d.type === 8 && d.accepted)) return;
    const normalized = raw.replace(/\\/g, '/').replace(/\/+$/, '') || '/';
    const at = normalized.startsWith('/') ? normalized : `/${normalized}`;
    pending.current = true; setBusy(true); setError('');
    try {
      const result = await api.entries(id, selectedID, at);
      let nextColumns = selectedID === device ? columns : [];
      if (withParents) {
        const ancestors: DriveColumn[] = [];
        for (const parent of columnPaths(at).slice(0, -1)) {
          if (!mounted.current || current.current.ended || current.current.device !== selectedID || !current.current.available) return;
          const cached = nextColumns.find(c => c.path === parent);
          ancestors.push(cached ?? { path: parent, entries: await api.entries(id, selectedID, parent) });
        }
        nextColumns = ancestors;
      }
      if (!mounted.current || current.current.ended || current.current.device !== selectedID || !current.current.available) return;
      setColumns(updateColumns(nextColumns, at, result));
      setEntries(result); setPath(at); setDraft(at); setSelection(selectedName); setSearch(''); setLoaded(true);
      setHistory(h => typeof mode === 'number' ? { ...h, index: mode }
        : mode === 'replace' ? { paths: h.paths.map((p, i) => i === h.index ? at : p), index: h.index }
        : h.paths[h.index] === at ? h : { paths: [...h.paths.slice(0, h.index + 1), at], index: h.index + 1 });
    } catch (e) { if (mounted.current) setError(String(e)); }
    finally { pending.current = false; if (mounted.current) setBusy(false); }
  };
  const child = (name: string) => `${path.replace(/\/$/, '')}/${name}`;
  const act = async (fn: () => Promise<void>, refresh = true) => {
    const now = current.current;
    if (!mounted.current || pending.current || now.ended || !now.enabled || !now.available || now.device !== device || now.path !== path) return;
    pending.current = true; setBusy(true); setError('');
    try {
      await fn();
      if (refresh && mounted.current && !current.current.ended) {
        const result = await api.entries(id, device!, path);
        if (mounted.current && !current.current.ended && current.current.available) { setEntries(result); setColumns(c => updateColumns(c, path, result)); setSelection(undefined); }
      }
    } catch (e) { if (mounted.current) setError(String(e)); }
    finally { pending.current = false; if (mounted.current) setBusy(false); }
  };
  const chooseDevice = (value: number) => {
    if (pending.current || ended) return;
    current.current = { ...current.current, device: value, available: true };
    setDevice(value); setEntries([]); setColumns([]); setSelection(undefined); setPath('/'); setDraft('/'); setSearch(''); setLoaded(false); setError('');
    setHistory({ paths: ['/'], index: 0 });
    if (enabled) void load('/', value, 'replace');
  };
  const open = (entry: DriveEntry) => {
    if (canBrowse && entry.IsDir && !(entry.Attributes & 0x400)) void load(child(entry.Name));
  };
  const changeView = (next: FinderView) => {
    setView(next);
    if (next === 'columns' && canBrowse && loaded && columnPaths(path).some(p => !columns.some(c => c.path === p))) void load(path, device, 'replace', selection, true);
  };
  const selectColumnEntry = (entry: DriveEntry, at: string) => {
    if (!canBrowse) return;
    if (entry.IsDir && !(entry.Attributes & 0x400)) {
      const next = `${at.replace(/\/$/, '')}/${entry.Name}`;
      if (next !== path) void load(next);
    } else if (at !== path) void load(at, device, 'push', entry.Name);
    else setSelection(entry.Name);
  };
  const crumbs = [{ name: selectedDevice?.name || t('root'), path: '/' }, ...path.split('/').filter(Boolean).map((name, i, parts) => ({ name, path: '/' + parts.slice(0, i + 1).join('/') }))];
  const empty = search ? t('empty.noMatch') : !devices.length ? (web ? t('empty.noDevicesWeb') : t('empty.noDevices')) : !enabled ? t('empty.disabled') : device === undefined ? t('empty.selectDevice') : loaded ? t('empty.emptyFolder') : t('empty.waiting');

  return <section className="finder" aria-label={t('aria.browser')}>
    <header className="finder-titlebar">
      <h3>{t('title')}</h3>
      <span className="finder-titlebar-status">{ended ? t('sessionEnded') : t('disks', { count: devices.filter(d => d.type === 8).length })}</span>
    </header>
    <div className="finder-body">
      <nav className="finder-sidebar" aria-label={t('aria.devices')}>
        <div className="finder-sidebar-heading">{t('location')}<Tooltip title={t('refreshDevices')}><Button type="text" size="small" aria-label={t('refreshDevices')} icon={<ReloadOutlined />} disabled={busy || ended} onClick={() => void loadDevices()} /></Tooltip></div>
        {!devices.length && <div className="finder-sidebar-empty">{t('noDevices')}</div>}
        {devices.map(d => <button key={d.id} type="button" className={`finder-device${device === d.id ? ' is-selected' : ''}`} aria-pressed={device === d.id}
          disabled={busy || ended || d.type !== 8 || !d.accepted} title={`${d.name || d.id}${!d.accepted ? t('device.notAcceptedParen') : d.type !== 8 ? t('device.notDiskParen') : ''}`} onClick={() => chooseDevice(d.id)}>
          <HddOutlined /><span className="finder-device-label"><span>{d.name || t('device.disk', { id: d.id })}</span><small>{d.type !== 8 ? t('device.notDisk') : !d.accepted ? t('device.notAccepted') : t('device.device', { id: d.id })}</small></span>
        </button>)}
      </nav>
      <div className="finder-main">
        <div className="finder-toolbar" role="toolbar" aria-label={t('aria.toolbar')}>
          <Tooltip title={t('tool.back')}><Button size="small" type="text" aria-label={t('tool.back')} icon={<LeftOutlined />} disabled={!canBrowse || history.index === 0} onClick={() => void load(history.paths[history.index - 1], device, history.index - 1)} /></Tooltip>
          <Tooltip title={t('tool.forward')}><Button size="small" type="text" aria-label={t('tool.forward')} icon={<RightOutlined />} disabled={!canBrowse || history.index === history.paths.length - 1} onClick={() => void load(history.paths[history.index + 1], device, history.index + 1)} /></Tooltip>
          <Tooltip title={t('tool.up')}><Button size="small" type="text" aria-label={t('tool.up')} icon={<ArrowUpOutlined />} disabled={!canBrowse || path === '/'} onClick={() => void load(path.slice(0, path.lastIndexOf('/')) || '/')} /></Tooltip>
          <Tooltip title={t('tool.refresh')}><Button size="small" type="text" aria-label={t('tool.refresh')} icon={<ReloadOutlined />} disabled={!canBrowse} onClick={() => void load(path, device, 'replace')} /></Tooltip>
          <span className="finder-toolbar-divider" />
          <Tooltip title={t('tool.upload')}><Button size="small" type="text" aria-label={t('tool.upload')} icon={<UploadOutlined />} disabled={!canBrowse} onClick={() => fileInput.current?.click()} /></Tooltip>
          <Tooltip title={t('tool.download')}><Button size="small" type="text" aria-label={t('tool.download')} icon={<DownloadOutlined />} disabled={!canUseFile} onClick={() => {
            if (!selected) return;
            void act(async () => {
              const blob = await api.downloadFile(id, device!, child(selected.Name));
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a'); a.href = url; a.download = selected.Name; a.click();
              setTimeout(() => URL.revokeObjectURL(url), 1000);
            }, false);
          }} /></Tooltip>
          <Tooltip title={t('tool.delete')}><Button size="small" type="text" danger aria-label={t('tool.delete')} icon={<DeleteOutlined />} disabled={!canUseFile} onClick={() => {
            if (!selected) return;
            modal.confirm({ title: t('deleteConfirm.title', { name: selected.Name }), content: t('deleteConfirm.content', { path: child(selected.Name) }), okText: t('deleteConfirm.ok'), cancelText: t('common:action.cancel'), okButtonProps: { danger: true }, onOk: () => act(() => api.deleteFile(id, device!, child(selected.Name))) });
          }} /></Tooltip>
          <input ref={fileInput} type="file" hidden onChange={e => {
            const file = e.target.files?.[0]; e.target.value = '';
            if (!file || !canBrowse || device === undefined) return;
            if (file.size > 64 * 1024 * 1024) { void message.error(t('upload.tooLarge')); return; }
            modal.confirm({ title: t('upload.title', { path: child(file.name) }), content: t('upload.content'), okText: t('upload.ok'), cancelText: t('common:action.cancel'), onOk: () => act(() => api.uploadFile(id, device, child(file.name), file)) });
          }} />
        </div>
        <div className="finder-viewbar" role="group" aria-label={t('aria.views')}>
          {views.map(option => <Tooltip key={option.value} title={t(`view.${option.label}`)}><Button size="small" type="text" aria-label={t(`viewAria.${option.label}`)} aria-pressed={view === option.value} className={view === option.value ? 'is-active' : ''} icon={option.icon} disabled={busy} onClick={() => changeView(option.value)}>{t(`view.${option.label}`)}</Button></Tooltip>)}
        </div>
        <div className="finder-search"><Input size="small" prefix={<SearchOutlined />} placeholder={t('search')} aria-label={t('search')} value={search} onChange={e => { setSearch(e.target.value); setSelection(undefined); }} allowClear disabled={!loaded} /></div>
        <div className="finder-path"><Input size="small" variant="borderless" aria-label={t('aria.path')} value={draft} onChange={e => setDraft(e.target.value)} onPressEnter={() => void load(draft)} disabled={!canBrowse} /><Tooltip title={t('go')}><Button type="text" size="small" aria-label={t('go')} icon={<RightOutlined />} disabled={!canBrowse} onClick={() => void load(draft)} /></Tooltip></div>
        {error && <Alert type="error" showIcon message={error} />}
        {device !== undefined && !available && <Alert type="warning" message={t('deviceGone')} />}
        <div className={`finder-content finder-content-${view}`}>
          {view === 'list' ? <Table<DriveEntry> key={`${device}:${path}:${search}`} size="small" rowKey="Name" tableLayout="fixed" dataSource={rows} loading={busy}
            rowClassName={entry => entry.Name === selection ? 'finder-row-selected' : ''}
            onRow={entry => ({ tabIndex: canBrowse ? 0 : -1, 'aria-selected': entry.Name === selection,
              onClick: () => setSelection(entry.Name), onDoubleClick: () => open(entry),
              onKeyDown: e => { if (e.key === 'Enter') { setSelection(entry.Name); open(entry); } if (e.key === ' ') { e.preventDefault(); setSelection(entry.Name); } },
            })}
            pagination={{ pageSize: 50, size: 'small', simple: true, showSizeChanger: false, hideOnSinglePage: true }}
            locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={empty} /> }}
            columns={[
              { title: t('column.name'), dataIndex: 'Name', ellipsis: true, render: (name: string, entry) => <span className="finder-file-name" title={name}>{entryIcon(entry)}<span>{name}</span></span> },
              { title: t('column.size'), width: 76, align: 'right', render: (_, entry) => <span style={{ color: '#8e96a3' }}>{entry.IsDir ? '—' : fmtBytes(entry.Size)}</span> },
            ]} /> : <Spin spinning={busy}>
              {view === 'icons' ? (rows.length ? <div className="finder-icon-grid" role="group" aria-label={t('aria.iconList')}>
                {rows.map(entry => <button key={entry.Name} type="button" className={`finder-tile${selection === entry.Name ? ' is-selected' : ''}`} aria-pressed={selection === entry.Name} title={entry.Name} disabled={busy}
                  onClick={() => setSelection(entry.Name)} onDoubleClick={() => open(entry)} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); setSelection(entry.Name); open(entry); } }}>
                  {entryIcon(entry)}<span className="finder-tile-name">{entry.Name}</span><small>{entry.IsDir ? t('folder') : fmtBytes(entry.Size)}</small>
                </button>)}
              </div> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={empty} />)
              : (visibleColumns.length ? <div ref={columnsBox} className="finder-columns" aria-label={t('aria.columnList')}>
                {visibleColumns.map(c => <section key={c.path} className="finder-column" aria-label={c.path}>
                  <button type="button" className="finder-column-heading" title={c.path} disabled={!canBrowse} onClick={() => { if (c.path !== path) void load(c.path); }}>{c.path === '/' ? selectedDevice?.name || t('root') : c.path.split('/').pop()}</button>
                  <div className="finder-column-entries">
                    {c.entries.length ? c.entries.map(entry => {
                      const next = `${c.path.replace(/\/$/, '')}/${entry.Name}`;
                      const isSelected = c.path === path ? selection === entry.Name : path === next || path.startsWith(next + '/');
                      return <button key={entry.Name} type="button" className={`finder-column-entry${isSelected ? ' is-selected' : ''}`} aria-pressed={isSelected} title={entry.Name} disabled={!canBrowse} onClick={() => selectColumnEntry(entry, c.path)}>
                        {entryIcon(entry)}<span>{entry.Name}</span>{entry.IsDir && <RightOutlined className="finder-column-chevron" />}
                      </button>;
                    }) : <div className="finder-column-empty">{c.path === path && search ? t('column.noMatch') : t('column.empty')}</div>}
                  </div>
                </section>)}
              </div> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={empty} />)}
            </Spin>}
        </div>
        <div className="finder-breadcrumbs" aria-label={t('aria.breadcrumbs')}>{crumbs.map((c, i) => <span key={c.path}>{i > 0 && <RightOutlined style={{ fontSize: 8 }} />}<Button type="text" size="small" disabled={!canBrowse || path === c.path} onClick={() => void load(c.path)}>{c.name}</Button></span>)}</div>
        <footer className="finder-status"><span>{t('status.items', { count: entries.length, n: search ? `${rows.length} / ${entries.length}` : entries.length })}{selected ? t('status.selected') : ''}</span><span>{busy ? t('status.reading') : view === 'columns' ? t('status.columnsHint') : t('status.openHint')}</span></footer>
      </div>
    </div>
    <div className="finder-note">{enabled ? <><strong>{t('note.strong')}</strong>{t('note.rest')}</> : t('note.disabled')}</div>
  </section>;
}
