import type { DriveEntry } from '../api';

export type FinderView = 'list' | 'icons' | 'columns';
export interface DriveColumn { path: string; entries: DriveEntry[] }

export function columnPaths(path: string): string[] {
  const parts = path.split('/').filter(Boolean);
  return ['/', ...parts.map((_, i) => '/' + parts.slice(0, i + 1).join('/'))];
}

export function updateColumns(columns: DriveColumn[], path: string, entries: DriveEntry[]): DriveColumn[] {
  const ancestors = new Set(columnPaths(path).slice(0, -1));
  return [...columns.filter(c => ancestors.has(c.path)), { path, entries }];
}

export function sortedEntries(entries: DriveEntry[], search = ''): DriveEntry[] {
  const query = search.toLocaleLowerCase();
  return entries.filter(e => e.Name.toLocaleLowerCase().includes(query))
    .sort((a, b) => Number(b.IsDir) - Number(a.IsDir) || a.Name.localeCompare(b.Name, 'zh-CN', { numeric: true }));
}
