export interface SessionInfo {
  id: string;
  web?: boolean;
  remote_addr: string;
  user: string;
  domain?: string;
  client_name?: string;
  target: string;
  login_form?: boolean;
  width: number;
  height: number;
  started: string;
  server_bytes: number;
  frames: number;
  orders: number;
  decode_errors: number;
  viewers: number;
  controllers: number;
  injected: number;
  recording: boolean;
}

export interface RecordingMeta {
  id: string;
  remote_addr: string;
  user: string;
  domain?: string;
  client_name?: string;
  target: string;
  login_form?: boolean;
  width: number;
  height: number;
  started: string;
  duration_ms: number;
  size: number;
  end?: string;
  error?: string;
  complete: boolean;
}

export interface MonitorInfo {
  drive_control: boolean;
  events: boolean;
  control: boolean;
  recording: boolean;
  // login is true when the gateway runs with -web-users, user is the
  // logged-in account (empty when only a token is used) and web is true
  // when this browser may open its own RDP sessions.
  login: boolean;
  user: string;
  web: boolean;
}

export interface ConnectRequest {
  address: string;
  user: string;
  domain?: string;
  password: string;
  width: number;
  height: number;
  color_depth?: number;
  keyboard_layout?: number;
  experience?: string;
}

export interface WebSession {
  id: string;
  owner_key: string;
  width: number;
  height: number;
}

const TOKEN_KEY = 'rdpmon.token';

export const getToken = () => localStorage.getItem(TOKEN_KEY) ?? '';
export const setToken = (t: string) => {
  localStorage.setItem(TOKEN_KEY, t);
  tokenSessionReady = null;
};

// The API token travels only in the Authorization header. WebSocket and
// download URLs cannot carry headers, so the token is exchanged once for an
// HttpOnly cookie instead of being put in the URL (history, proxy logs).
let tokenSessionReady: Promise<void> | null = null;
export function tokenSession(): Promise<void> {
  const token = getToken();
  if (!token) return Promise.resolve();
  tokenSessionReady ??= fetch('/api/token-session', { method: 'POST', headers: { Authorization: `Bearer ${token}` } })
    .then(() => undefined)
    .catch(() => {
      tokenSessionReady = null;
    });
  return tokenSessionReady;
}

// The owner key of a browser-initiated session is kept in sessionStorage
// (not in the URL) so it is not shared or kept in the history.
const ownerKeyName = (id: string) => `rdpmon.owner.${id}`;
export const getOwnerKey = (id: string) => sessionStorage.getItem(ownerKeyName(id)) ?? '';
export const setOwnerKey = (id: string, key: string) => sessionStorage.setItem(ownerKeyName(id), key);
export const clearOwnerKey = (id: string) => sessionStorage.removeItem(ownerKeyName(id));

export class AuthError extends Error {
  constructor() {
    super('需要访问令牌');
  }
}

async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const r = await fetch(path, { ...init, headers });
  if (r.status === 401) throw new AuthError();
  if (token) void tokenSession();
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  return r;
}

const json = async <T>(path: string) => (await request(path)).json() as Promise<T>;

// postJSON sends a JSON body; credentials (login password, RDP password)
// are never stored, only sent once.
async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  return r.status === 204 ? (undefined as T) : ((await r.json()) as T);
}

export interface MappedDevice { id: number; type: number; name: string; accepted: boolean }
export interface DriveEntry { Name: string; Size: number; IsDir: boolean; Attributes: number; Modified: string }
const driveURL = (id: string, device: number, resource: string, path: string) =>
  `/api/sessions/${encodeURIComponent(id)}/drives/${device}/${resource}?${new URLSearchParams({ path })}`;

export const api = {
  devices: (id: string) => json<MappedDevice[]>(`/api/sessions/${encodeURIComponent(id)}/devices`),
  entries: (id: string, device: number, path: string) => json<DriveEntry[]>(driveURL(id, device, 'entries', path)),
  downloadFile: async (id: string, device: number, path: string) => (await request(driveURL(id, device, 'file', path))).blob(),
  uploadFile: async (id: string, device: number, path: string, file: File) => {
    await request(driveURL(id, device, 'file', path), { method: 'PUT', body: file });
  },
  deleteFile: async (id: string, device: number, path: string) => {
    await request(driveURL(id, device, 'file', path), { method: 'DELETE' });
  },
  login: (user: string, password: string) => postJSON<{ user: string }>('/api/login', { user, password }),
  logout: () => postJSON<void>('/api/logout', {}),
  connect: (req: ConnectRequest) => postJSON<WebSession>('/api/connect', req),
  info: () => json<MonitorInfo>('/api/info'),
  sessions: () => json<SessionInfo[]>('/api/sessions'),
  disconnect: async (id: string) => {
    await request(`/api/sessions/${encodeURIComponent(id)}/disconnect`, { method: 'POST' });
  },
  recordings: () => json<RecordingMeta[]>('/api/recordings'),
  recording: async (id: string) => (await request(`/api/recordings/${encodeURIComponent(id)}`)).arrayBuffer(),
  deleteRecording: async (id: string) => {
    await request(`/api/recordings/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
};

function withParams(path: string, params: Record<string, string>): string {
  const s = new URLSearchParams(params).toString();
  return s ? `${path}?${s}` : path;
}

// liveURL opens the live stream. owner is the key returned by
// api.connect: it marks this browser as the session's own client and
// always carries keyboard and mouse, independent of -monitor-control.
export function liveURL(id: string, control: boolean, owner = ''): string {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const params: Record<string, string> = {};
  if (control) params.control = '1';
  if (owner) params.owner = owner;
  return `${proto}//${location.host}` + withParams(`/api/sessions/${encodeURIComponent(id)}/live`, params);
}

export const downloadURL = (id: string) => withParams(`/api/recordings/${encodeURIComponent(id)}`, { download: '1' });

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const pad = (x: number) => String(x).padStart(2, '0');
  return h > 0 ? `${h}:${pad(m)}:${pad(s % 60)}` : `${pad(m)}:${pad(s % 60)}`;
}

export const account = (s: { user: string; domain?: string }) => (s.domain ? `${s.domain}\\${s.user}` : s.user || '-');

export const endLabels: Record<string, string> = {
  'client-closed': '客户端断开',
  'target-closed': '目标断开',
  'monitor-disconnect': '监控端强制断开',
  canceled: '网关停止',
  error: '错误',
  interrupted: '录像中断',
  recording: '录制中',
};
