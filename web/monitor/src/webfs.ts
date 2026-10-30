// BrowserFolder serves the gateway's file requests (monitor/webctl.go) from
// a folder the user picked with the File System Access API, so the remote
// desktop sees it as a redirected drive. Chromium-based browsers only, and
// only in a secure context (HTTPS or localhost).

export interface FSRequest {
  id: number;
  op: 'stat' | 'list' | 'read' | 'write' | 'create' | 'truncate' | 'remove' | 'rename';
  path: string;
  to?: string;
  off?: number;
  n?: number;
  size?: number;
  dir?: boolean;
  replace?: boolean;
  data?: string; // base64
}

interface FSEntry {
  name: string;
  dir: boolean;
  size: number;
  mtime: number;
}

export interface FSReply {
  t: 'fs';
  id: number;
  err?: string;
  detail?: string;
  entry?: FSEntry;
  entries?: FSEntry[];
  data?: string;
}

type DirHandle = FileSystemDirectoryHandle & {
  values(): AsyncIterable<FileSystemFileHandle | FileSystemDirectoryHandle>;
};
type Writable = {
  write(p: { type: 'write'; position: number; data: BufferSource } | { type: 'truncate'; size: number }): Promise<void>;
  close(): Promise<void>;
};
type FileHandle = FileSystemFileHandle & { createWritable(o: { keepExistingData: boolean }): Promise<Writable> };

export const folderSupported = () => typeof (window as unknown as { showDirectoryPicker?: unknown }).showDirectoryPicker === 'function';

export async function pickFolder(): Promise<FileSystemDirectoryHandle> {
  const pick = (window as unknown as { showDirectoryPicker: (o: object) => Promise<FileSystemDirectoryHandle> }).showDirectoryPicker;
  return pick({ mode: 'readwrite', id: 'rdp-drive' });
}

function toB64(buf: Uint8Array): string {
  let s = '';
  for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return btoa(s);
}

function fromB64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function errCode(e: unknown): string {
  const name = (e as DOMException)?.name;
  switch (name) {
    case 'NotFoundError':
    case 'TypeMismatchError':
      return 'notfound';
    case 'InvalidModificationError':
      return 'notempty';
    case 'NotAllowedError':
    case 'SecurityError':
    case 'NoModificationAllowedError':
      return 'denied';
  }
  return name || String(e);
}

const split = (p: string) => p.split('/').filter((x) => x && x !== '.');

export class BrowserFolder {
  // Writes to one file are kept open: every createWritable() copies the
  // whole file in Chromium, so reopening per 64 KiB chunk would be quadratic.
  private writers = new Map<string, { w: Writable; timer: number }>();

  constructor(readonly root: FileSystemDirectoryHandle) {}

  get name() {
    return this.root.name;
  }

  async permitted(): Promise<boolean> {
    const h = this.root as unknown as { queryPermission(o: object): Promise<string>; requestPermission(o: object): Promise<string> };
    if ((await h.queryPermission({ mode: 'readwrite' })) === 'granted') return true;
    return (await h.requestPermission({ mode: 'readwrite' })) === 'granted';
  }

  private async dir(parts: string[], create = false): Promise<DirHandle> {
    let d = this.root;
    for (const p of parts) d = await d.getDirectoryHandle(p, { create });
    return d as DirHandle;
  }

  private async parent(path: string): Promise<[DirHandle, string]> {
    const parts = split(path);
    const name = parts.pop();
    if (!name) throw new DOMException('root', 'NotAllowedError');
    return [await this.dir(parts), name];
  }

  private async file(path: string): Promise<FileHandle> {
    const [d, name] = await this.parent(path);
    return (await d.getFileHandle(name)) as FileHandle;
  }

  private async flush(path?: string) {
    const list = path === undefined ? [...this.writers.keys()] : this.writers.has(path) ? [path] : [];
    for (const p of list) {
      const w = this.writers.get(p)!;
      this.writers.delete(p);
      clearTimeout(w.timer);
      await w.w.close();
    }
  }

  private async writer(path: string): Promise<Writable> {
    let w = this.writers.get(path);
    if (!w) {
      w = { w: await (await this.file(path)).createWritable({ keepExistingData: true }), timer: 0 };
      this.writers.set(path, w);
    }
    clearTimeout(w.timer);
    w.timer = window.setTimeout(() => void this.flush(path).catch(() => undefined), 1500);
    return w.w;
  }

  private async entry(h: FileSystemFileHandle | FileSystemDirectoryHandle): Promise<FSEntry> {
    if (h.kind === 'directory') return { name: h.name, dir: true, size: 0, mtime: 0 };
    const f = await (h as FileSystemFileHandle).getFile();
    return { name: h.name, dir: false, size: f.size, mtime: f.lastModified };
  }

  private async stat(path: string): Promise<FSEntry> {
    const parts = split(path);
    if (!parts.length) return { name: this.root.name, dir: true, size: 0, mtime: 0 };
    const [d, name] = await this.parent(path);
    try {
      return await this.entry(await d.getFileHandle(name));
    } catch (e) {
      if (errCode(e) !== 'notfound') throw e;
    }
    return this.entry(await d.getDirectoryHandle(name));
  }

  private async exists(path: string): Promise<boolean> {
    try {
      await this.stat(path);
      return true;
    } catch (e) {
      if (errCode(e) === 'notfound') return false;
      throw e;
    }
  }

  private async copyFile(from: string, to: string) {
    const src = await (await this.file(from)).getFile();
    const [d, name] = await this.parent(to);
    const w = await ((await d.getFileHandle(name, { create: true })) as FileHandle).createWritable({ keepExistingData: false });
    await w.write({ type: 'write', position: 0, data: await src.arrayBuffer() });
    await w.close();
  }

  // Chromium's move() is file-only outside the origin private file system,
  // so folders are renamed by copying the tree and removing the original.
  private async copyDir(src: DirHandle, dst: FileSystemDirectoryHandle) {
    for await (const h of src.values()) {
      if (h.kind === 'directory') {
        await this.copyDir(h as DirHandle, await dst.getDirectoryHandle(h.name, { create: true }));
      } else {
        const data = await (await (h as FileSystemFileHandle).getFile()).arrayBuffer();
        const w = await ((await dst.getFileHandle(h.name, { create: true })) as FileHandle).createWritable({ keepExistingData: false });
        await w.write({ type: 'write', position: 0, data });
        await w.close();
      }
    }
  }

  async handle(req: FSRequest): Promise<FSReply> {
    const reply: FSReply = { t: 'fs', id: req.id };
    try {
      if (req.op !== 'write') await this.flush();
      switch (req.op) {
        case 'stat':
          reply.entry = await this.stat(req.path);
          break;
        case 'list': {
          const d = await this.dir(split(req.path));
          const handles: (FileSystemFileHandle | FileSystemDirectoryHandle)[] = [];
          for await (const h of d.values()) handles.push(h);
          reply.entries = await Promise.all(handles.map((h) => this.entry(h)));
          break;
        }
        case 'read': {
          const f = await (await this.file(req.path)).getFile();
          const off = req.off ?? 0;
          reply.data = toB64(new Uint8Array(await f.slice(off, off + (req.n ?? 0)).arrayBuffer()));
          break;
        }
        case 'write':
          await (await this.writer(req.path)).write({ type: 'write', position: req.off ?? 0, data: fromB64(req.data ?? '') });
          break;
        case 'create': {
          const [d, name] = await this.parent(req.path);
          if (req.dir) await d.getDirectoryHandle(name, { create: true });
          else await d.getFileHandle(name, { create: true });
          break;
        }
        case 'truncate': {
          const w = await (await this.file(req.path)).createWritable({ keepExistingData: true });
          await w.write({ type: 'truncate', size: req.size ?? 0 });
          await w.close();
          break;
        }
        case 'remove': {
          const [d, name] = await this.parent(req.path);
          await d.removeEntry(name);
          break;
        }
        case 'rename': {
          const to = req.to ?? '';
          if (await this.exists(to)) {
            if (!req.replace) throw new DOMException('exists', 'ExistsError');
            const [d, name] = await this.parent(to);
            await d.removeEntry(name);
          }
          const src = (await this.stat(req.path)).dir
            ? await (await this.parent(req.path))[0].getDirectoryHandle((await this.parent(req.path))[1])
            : await this.file(req.path);
          const [toDir, toName] = await this.parent(to);
          const movable = src as unknown as { move?: (d: FileSystemDirectoryHandle, n: string) => Promise<void> };
          let moved = false;
          if (movable.move) {
            try {
              await movable.move(toDir, toName);
              moved = true;
            } catch (e) {
              if (src.kind === 'file' || errCode(e) === 'notfound') throw e;
            }
          }
          if (!moved) {
            const [d, name] = await this.parent(req.path);
            if (src.kind === 'file') await this.copyFile(req.path, to);
            else await this.copyDir(src as DirHandle, await toDir.getDirectoryHandle(toName, { create: true }));
            await (d as unknown as { removeEntry(n: string, o: object): Promise<void> }).removeEntry(name, { recursive: true });
          }
          break;
        }
      }
    } catch (e) {
      reply.err = (e as DOMException)?.name === 'ExistsError' ? 'exists' : errCode(e);
      if (reply.err !== 'notfound') reply.detail = `${req.op} ${req.path}${req.to ? ' -> ' + req.to : ''}: ${(e as Error)?.name}: ${(e as Error)?.message}`;
    }
    return reply;
  }

  async close() {
    await this.flush().catch(() => undefined);
  }
}
