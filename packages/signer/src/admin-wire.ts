import { chmodSync, lstatSync, mkdirSync, unlinkSync } from 'node:fs';
import { connect, createServer, type Server, type Socket } from 'node:net';
import { dirname } from 'node:path';
import { assertUnixSocketPath, unixSocketPathProblem } from './platform.ts';

export const MAX_ADMIN_LINE = 64 * 1024;
const OP_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
const REQUEST_DEADLINE_MS = 10_000;

export class AdminError extends Error {}

export type AdminHandler = (params: Record<string, unknown>) => unknown | Promise<unknown>;

export class AdminOps {
  private readonly table = new Map<string, AdminHandler>();

  register(op: string, handler: AdminHandler): this {
    if (!OP_RE.test(op)) throw new Error(`bad admin op name "${op}"`);
    if (this.table.has(op)) throw new Error(`admin op "${op}" registered twice`);
    this.table.set(op, handler);
    return this;
  }

  ops(): string[] {
    return [...this.table.keys()].sort();
  }

  async dispatch(op: string, params: Record<string, unknown>): Promise<unknown> {
    const h = this.table.get(op);
    if (!h) throw new AdminError(`unknown admin command "${op}"`);
    return h(params);
  }
}

export type AdminListen = { fd: number } | { path: string };

export interface AdminServerOptions {
  listen: AdminListen;
  ops: AdminOps;
  onRequest?: (op: string, ok: boolean) => void;
}

export async function startAdminServer(opts: AdminServerOptions): Promise<Server> {
  const server = createServer((socket) => serveAdmin(socket, opts));
  await listenOn(server, opts.listen);
  return server;
}

export async function listenOn(server: Server, listen: AdminListen): Promise<void> {
  if ('path' in listen) {
    assertUnixSocketPath(listen.path, 'admin socket');
    const dir = dirname(listen.path);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
    removeDeadSocket(listen.path);
  }
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    const done = () => {
      server.off('error', reject);
      resolve();
    };
    if ('fd' in listen) server.listen({ fd: listen.fd }, done);
    else server.listen(listen.path, done);
  });
  if ('path' in listen) chmodSync(listen.path, 0o600);
}

function removeDeadSocket(path: string): void {
  try {
    if (!lstatSync(path).isSocket()) throw new Error(`${path} exists and is not a socket`);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw err;
  }
  unlinkSync(path);
}

function serveAdmin(socket: Socket, opts: AdminServerOptions): void {
  let buf = Buffer.alloc(0);
  let handled = false;
  const deadline = setTimeout(() => socket.destroy(), REQUEST_DEADLINE_MS);
  socket.on('error', () => socket.destroy());
  socket.on('close', () => clearTimeout(deadline));
  const reply = (res: { ok: true; result: unknown } | { ok: false; error: string }) => {
    if (!socket.destroyed) socket.end(`${JSON.stringify(res)}\n`);
  };
  socket.on('data', (chunk: Buffer) => {
    if (handled) return;
    buf = Buffer.concat([buf, chunk]);
    const nl = buf.indexOf(0x0a);
    if (nl < 0) {
      if (buf.length > MAX_ADMIN_LINE) {
        handled = true;
        reply({ ok: false, error: 'request too large' });
      }
      return;
    }
    handled = true;
    clearTimeout(deadline);
    let op = '(malformed)';
    let params: Record<string, unknown> = {};
    try {
      const req = JSON.parse(buf.subarray(0, nl).toString('utf8')) as unknown;
      if (!isPlainObject(req) || typeof req.op !== 'string' || !OP_RE.test(req.op)) {
        throw new AdminError('malformed request');
      }
      if (req.params !== undefined && !isPlainObject(req.params)) {
        throw new AdminError('malformed request');
      }
      op = req.op;
      params = (req.params as Record<string, unknown> | undefined) ?? {};
    } catch {
      opts.onRequest?.(op, false);
      return reply({ ok: false, error: 'malformed request' });
    }
    Promise.resolve()
      .then(() => opts.ops.dispatch(op, params))
      .then(
        (result) => {
          opts.onRequest?.(op, true);
          reply({ ok: true, result: result ?? null });
        },
        (err: unknown) => {
          opts.onRequest?.(op, false);
          reply({ ok: false, error: err instanceof AdminError ? err.message : 'internal error' });
        },
      );
  });
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return (
    typeof v === 'object' &&
    v !== null &&
    !Array.isArray(v) &&
    Object.getPrototypeOf(v) === Object.prototype
  );
}

export class AdminCallError extends Error {
  readonly code: 'permission' | 'unreachable' | 'refused' | 'protocol';
  constructor(code: AdminCallError['code'], message: string) {
    super(message);
    this.code = code;
  }
}

export function adminCall<T = unknown>(
  socketPath: string,
  op: string,
  params: Record<string, unknown> = {},
  opts: { timeoutMs?: number } = {},
): Promise<T> {
  return new Promise((resolve, reject) => {
    const tooLong = unixSocketPathProblem(socketPath, 'admin socket');
    if (tooLong) {
      reject(new AdminCallError('unreachable', tooLong));
      return;
    }
    const socket = connect(socketPath);
    let buf = Buffer.alloc(0);
    let settled = false;
    const finish = (err: AdminCallError | null, value?: T) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (err) reject(err);
      else resolve(value as T);
    };
    const timer = setTimeout(
      () => finish(new AdminCallError('protocol', 'the service did not answer in time')),
      opts.timeoutMs ?? 60_000,
    );
    socket.once('connect', () => socket.write(`${JSON.stringify({ op, params })}\n`));
    socket.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EACCES' || err.code === 'EPERM') {
        finish(new AdminCallError('permission', `permission denied on ${socketPath}`));
      } else if (err.code === 'ENOENT' || err.code === 'ECONNREFUSED') {
        finish(new AdminCallError('unreachable', `nothing is listening on ${socketPath}`));
      } else {
        finish(new AdminCallError('unreachable', `cannot reach ${socketPath} (${err.code})`));
      }
    });
    socket.on('data', (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 16 * MAX_ADMIN_LINE) {
        finish(new AdminCallError('protocol', 'response too large'));
      }
    });
    socket.on('end', () => {
      let res: unknown;
      try {
        res = JSON.parse(buf.toString('utf8'));
      } catch {
        return finish(new AdminCallError('protocol', 'malformed response'));
      }
      if (!isPlainObject(res) || typeof res.ok !== 'boolean') {
        return finish(new AdminCallError('protocol', 'malformed response'));
      }
      if (res.ok) return finish(null, res.result as T);
      finish(new AdminCallError('refused', typeof res.error === 'string' ? res.error : 'refused'));
    });
  });
}
