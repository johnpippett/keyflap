import {
  createServer as createHttpServer,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  request,
  type ServerResponse,
} from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { assertUnixSocketPath } from '@aab/signer/platform';
import {
  allowedHostsFor,
  approverOriginUrl,
  isLoopback,
  loadPageFiles,
  STATIC,
  securityHeaders,
} from './page-files.ts';

export interface ApproverFrontOptions {
  origin: string;
  listen: { fds: readonly number[] } | { host: string; port: number };
  tls?: { cert: string | Buffer; key: string | Buffer };
  upstream: string;
  pageDir?: string;
  log?: (line: string) => void;
}

const MAX_REQUEST_BODY = 16 * 1024;
const MAX_JSON_RESPONSE = 256 * 1024;
const MAX_FRAME_RESPONSE = 8 * 1024 * 1024;
const MAX_PATH = 2048;
const UPSTREAM_TIMEOUT_MS = 35_000;
const JSON_TYPE = 'application/json; charset=utf-8';
const FRAME_PATH = '/api/handoff/frame';
const DEVICE_COOKIE =
  /^__Host-aab_device=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=\d{1,9}$/;
const FORWARD = [
  'content-type',
  'content-length',
  'cookie',
  'origin',
  'sec-fetch-site',
  'authorization',
];

class Refused extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

interface Upstream {
  status: number;
  type: string;
  cookie: string | null;
  body: Buffer;
}

export class ApproverFront {
  listenUrl = '';
  private readonly opts: ApproverFrontOptions;
  private readonly host: string;
  private readonly files: Map<string, Buffer>;
  private readonly allowedHosts: Set<string>;
  private servers: ReturnType<typeof createHttpServer>[] = [];

  private constructor(opts: ApproverFrontOptions) {
    this.opts = opts;
    this.host = approverOriginUrl(opts.origin).host;
    assertUnixSocketPath(opts.upstream, 'approver API socket');
    if (!opts.tls && 'host' in opts.listen && !isLoopback(opts.listen.host)) {
      throw new Error('without TLS the approver must listen on loopback, behind a TLS proxy');
    }
    this.files = loadPageFiles(opts.pageDir);
    this.allowedHosts = new Set([this.host]);
  }

  static async start(opts: ApproverFrontOptions): Promise<ApproverFront> {
    const f = new ApproverFront(opts);
    await f.listen();
    return f;
  }

  private async listen(): Promise<void> {
    const handler = (req: IncomingMessage, res: ServerResponse) => {
      this.handle(req, res).catch(() => {
        if (!res.headersSent) this.sendJson(res, 502, { error: 'core_unavailable' });
        else res.destroy();
      });
    };
    const l = this.opts.listen;
    const targets: ({ fd: number } | { host: string; port: number })[] =
      'fds' in l ? l.fds.map((fd) => ({ fd })) : [l];
    if (targets.length === 0) throw new Error('the approver front needs a listener');
    for (const target of targets) {
      const server = this.opts.tls
        ? createHttpsServer({ cert: this.opts.tls.cert, key: this.opts.tls.key }, handler)
        : createHttpServer(handler);
      server.headersTimeout = 10_000;
      server.requestTimeout = 40_000;
      try {
        await new Promise<void>((resolve, reject) => {
          server.once('error', reject);
          if ('fd' in target) server.listen({ fd: target.fd }, () => resolve());
          else server.listen(target.port, target.host, () => resolve());
        });
      } catch (err) {
        await this.close();
        throw err;
      }
      this.servers.push(server);
      const addr = server.address() as AddressInfo;
      if (this.listenUrl === '') {
        const host = addr.family === 'IPv6' ? `[${addr.address}]` : addr.address;
        this.listenUrl = `${this.opts.tls ? 'https' : 'http'}://${host}:${addr.port}`;
      }
      const configured = 'fd' in target ? { host: addr.address, port: addr.port } : target;
      for (const h of allowedHostsFor(
        this.opts.origin,
        { ...configured, tls: this.opts.tls !== undefined },
        addr.port,
      )) {
        this.allowedHosts.add(h);
      }
    }
  }

  async close(): Promise<void> {
    const servers = this.servers;
    this.servers = [];
    for (const s of servers) {
      s.closeAllConnections?.();
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
  }

  private sendJson(res: ServerResponse, status: number, body: unknown): void {
    this.send(res, status, JSON_TYPE, Buffer.from(JSON.stringify(body)));
  }

  private send(
    res: ServerResponse,
    status: number,
    type: string,
    body: Buffer,
    extra: OutgoingHttpHeaders = {},
  ): void {
    res.writeHead(status, {
      ...securityHeaders(this.opts.origin),
      'content-type': type,
      'content-length': body.length,
      ...extra,
    });
    res.end(body);
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (!this.allowedHosts.has(req.headers.host ?? '')) throw new Refused(421, 'bad_host');
      const url = req.url ?? '/';
      const path = url.split('?')[0] as string;
      const method = req.method ?? 'GET';
      if ((method === 'GET' || method === 'HEAD') && Object.hasOwn(STATIC, path)) {
        const s = STATIC[path] as { file: string; type: string };
        this.send(res, 200, s.type, this.files.get(s.file) as Buffer);
        return;
      }
      if (!path.startsWith('/api/') || url.length > MAX_PATH) throw new Refused(404, 'not_found');
      if (method !== 'GET' && method !== 'POST') throw new Refused(404, 'not_found');
      const up = await this.forward(req, method, url, path);
      this.send(res, up.status, up.type, up.body, up.cookie ? { 'set-cookie': up.cookie } : {});
    } catch (err) {
      if (err instanceof Refused) return this.sendJson(res, err.status, { error: err.message });
      throw err;
    }
  }

  private async readBody(req: IncomingMessage): Promise<Buffer> {
    if (Number(req.headers['content-length'] ?? 0) > MAX_REQUEST_BODY) {
      throw new Refused(413, 'too_large');
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of req) {
      size += (c as Buffer).length;
      if (size > MAX_REQUEST_BODY) throw new Refused(413, 'too_large');
      chunks.push(c as Buffer);
    }
    return Buffer.concat(chunks);
  }

  private async forward(
    req: IncomingMessage,
    method: string,
    url: string,
    path: string,
  ): Promise<Upstream> {
    const body = method === 'POST' ? await this.readBody(req) : Buffer.alloc(0);
    const headers: OutgoingHttpHeaders = { host: this.host };
    for (const name of FORWARD) {
      const v = req.headers[name];
      if (typeof v === 'string') headers[name] = v;
    }
    if (method === 'POST') headers['content-length'] = body.length;
    else delete headers['content-length'];
    const frame = method === 'GET' && path === FRAME_PATH;
    const max = frame ? MAX_FRAME_RESPONSE : MAX_JSON_RESPONSE;

    const up = await new Promise<Upstream>((resolve, reject) => {
      const r = request(
        {
          socketPath: this.opts.upstream,
          path: url,
          method,
          headers,
          timeout: UPSTREAM_TIMEOUT_MS,
        },
        (res) => {
          const status = res.statusCode ?? 0;
          const type = res.headers['content-type'] ?? '';
          const cookies = res.headers['set-cookie'] ?? [];
          const declared = Number(res.headers['content-length'] ?? 0);
          const ok =
            ((status >= 200 && status < 300) || (status >= 400 && status < 600)) &&
            (type === JSON_TYPE || (frame && status === 200 && type === 'image/jpeg')) &&
            cookies.length <= 1 &&
            cookies.every((c) => DEVICE_COOKIE.test(c)) &&
            declared <= max;
          if (!ok) {
            res.destroy();
            reject(new Refused(502, 'bad_upstream_response'));
            return;
          }
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (c: Buffer) => {
            size += c.length;
            if (size > max) {
              res.destroy();
              reject(new Refused(502, 'bad_upstream_response'));
              return;
            }
            chunks.push(c);
          });
          res.on('end', () =>
            resolve({ status, type, cookie: cookies[0] ?? null, body: Buffer.concat(chunks) }),
          );
          res.on('error', () => reject(new Refused(502, 'core_unavailable')));
        },
      );
      r.on('timeout', () => r.destroy(new Error('timeout')));
      r.on('error', () => reject(new Refused(502, 'core_unavailable')));
      r.end(body);
    });
    if (up.type === JSON_TYPE) {
      try {
        JSON.parse(up.body.toString('utf8'));
      } catch {
        throw new Refused(502, 'bad_upstream_response');
      }
    }
    return up;
  }
}
