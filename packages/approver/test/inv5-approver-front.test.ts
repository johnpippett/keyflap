import { mkdtempSync, rmSync } from 'node:fs';
import {
  createServer,
  type IncomingHttpHeaders,
  type OutgoingHttpHeaders,
  request,
  type Server,
} from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { ApproverFront } from '../src/front.ts';
import { loadPageFiles, PAGE_DIR } from '../src/page-files.ts';
import { PhoneApprover } from '../src/phone.ts';

const HOST = 'approver.localhost';
const COOKIE = `__Host-aab_device=${'t'.repeat(43)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=31536000`;

interface Res {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

function http(
  port: number,
  path: string,
  o: { method?: string; headers?: OutgoingHttpHeaders; body?: string | Buffer; host?: string } = {},
): Promise<Res> {
  return new Promise((resolve, reject) => {
    const r = request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: o.method ?? 'GET',
        headers: { host: o.host ?? `${HOST}:${port}`, ...o.headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks),
          }),
        );
      },
    );
    r.on('error', reject);
    r.end(o.body);
  });
}

interface Seen {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: string;
}

function fakeCore(socket: string) {
  const seen: Seen[] = [];
  let answer: { status: number; headers: OutgoingHttpHeaders; body: string | Buffer } = {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: '{"ok":true}',
  };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      seen.push({
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString(),
      });
      res.writeHead(answer.status, answer.headers);
      res.end(answer.body);
    });
  });
  return {
    seen,
    set(a: Partial<typeof answer>) {
      answer = { ...answer, ...a };
    },
    listen: () => new Promise<void>((r) => server.listen(socket, () => r())),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

describe('invariant 5: the front serves the page; the core only answers the API', () => {
  const dir = mkdtempSync(join(tmpdir(), 'keyflap-front-'));
  const socket = join(dir, 'api.sock');
  const core = fakeCore(socket);
  let front: ApproverFront;
  let port: number;

  beforeAll(async () => {
    await core.listen();
    front = await ApproverFront.start({
      origin: `http://${HOST}`,
      listen: { host: '127.0.0.1', port: 0 },
      upstream: socket,
    });
    port = Number(new URL(front.listenUrl).port);
  });
  afterAll(async () => {
    await front.close();
    await core.close();
    rmSync(dir, { recursive: true, force: true });
  });
  afterEach(() => {
    core.seen.length = 0;
    core.set({
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: '{"ok":true}',
    });
  });

  it('page files are its own, with its own security headers; the core is never asked', async () => {
    for (const [path, file] of [
      ['/', 'app.html'],
      ['/app.js', 'app.js'],
      ['/approval-check.js', 'approval-check.js'],
      ['/handoff.js', 'handoff.js'],
      ['/handoff-zoom.js', 'handoff-zoom.js'],
      ['/sw.js', 'sw.js'],
    ] as const) {
      const r = await http(port, path);
      expect(r.status).toBe(200);
      expect(r.body.equals(loadPageFiles(PAGE_DIR).get(file) as Buffer)).toBe(true);
      expect(r.headers['content-security-policy']).toContain("script-src 'self'");
      expect(r.headers['x-content-type-options']).toBe('nosniff');
    }
    expect(core.seen).toHaveLength(0);
  });

  it('anything outside /api/ and the page files is 404, never forwarded', async () => {
    for (const path of ['/evil.js', '/sw2.js', '/api', '/handoff/x', '/%2e%2e/api/state']) {
      expect((await http(port, path)).status).toBe(404);
    }
    expect((await http(port, '/', { method: 'POST', body: '{}' })).status).toBe(404);
    expect((await http(port, '/api/state', { method: 'PUT' })).status).toBe(404);
    expect(core.seen).toHaveLength(0);
  });

  it('forwards only the headers the API reads, with Host set to the origin', async () => {
    const r = await http(port, '/api/decide', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: '__Host-aab_device=abc',
        origin: `http://${HOST}`,
        'sec-fetch-site': 'same-origin',
        'x-forwarded-for': '1.2.3.4',
        'x-evil': 'yes',
      },
      body: '{"id":"r1","decision":"deny"}',
    });
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body.toString())).toEqual({ ok: true });
    const s = core.seen[0] as Seen;
    expect(s.method).toBe('POST');
    expect(s.url).toBe('/api/decide');
    expect(s.body).toBe('{"id":"r1","decision":"deny"}');
    expect(s.headers.host).toBe(HOST);
    expect(s.headers.cookie).toBe('__Host-aab_device=abc');
    expect(s.headers.origin).toBe(`http://${HOST}`);
    expect(s.headers['x-evil']).toBeUndefined();
    expect(s.headers['x-forwarded-for']).toBeUndefined();
    await http(port, '/api/handoff/frame?id=abc');
    expect(core.seen[1]?.url).toBe('/api/handoff/frame?id=abc');
  });

  it("refuses a request body over 16 KiB, and a Host that isn't the approver's", async () => {
    const big = `{"x":"${'a'.repeat(17 * 1024)}"}`;
    const r = await http(port, '/api/decide', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: big,
    });
    expect(r.status).toBe(413);
    expect((await http(port, '/', { host: 'evil.localhost' })).status).toBe(421);
    expect((await http(port, '/api/state', { host: 'evil.localhost' })).status).toBe(421);
    expect(core.seen).toHaveLength(0);
  });

  it('a core answer that is not plain JSON never reaches the phone', async () => {
    const bad: { status?: number; headers?: OutgoingHttpHeaders; body?: string }[] = [
      { headers: { 'content-type': 'text/html; charset=utf-8' }, body: '<script>steal()</script>' },
      { headers: { 'content-type': 'text/javascript' }, body: 'steal()' },
      { headers: { 'content-type': 'application/javascript' }, body: 'steal()' },
      { headers: { 'content-type': 'image/svg+xml' }, body: '<svg onload="steal()"/>' },
      { headers: {}, body: '{}' },
      { headers: { 'content-type': 'application/json; charset=utf-8' }, body: '<html>' },
      { headers: { 'content-type': 'image/jpeg' }, body: 'jpeg' },
      {
        status: 302,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          location: 'https://evil.example/',
        },
        body: '{}',
      },
      {
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'set-cookie': 'session=1; Path=/',
        },
        body: '{}',
      },
      {
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'set-cookie': [COOKIE, COOKIE],
        },
        body: '{}',
      },
      {
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'set-cookie': `${COOKIE}; Domain=evil.example`,
        },
        body: '{}',
      },
      {
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: `{"x":"${'a'.repeat(300 * 1024)}"}`,
      },
    ];
    for (const a of bad) {
      core.set({ status: a.status ?? 200, headers: a.headers ?? {}, body: a.body ?? '' });
      const r = await http(port, '/api/state');
      expect(r.status, JSON.stringify(a.headers)).toBe(502);
      expect(r.headers['content-type']).toBe('application/json; charset=utf-8');
      expect(r.headers['set-cookie']).toBeUndefined();
      expect(r.body.toString()).not.toContain('steal');
    }
  });

  it("keeps the core's status, the device cookie and frames; drops every other core header", async () => {
    core.set({
      status: 403,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'set-cookie': COOKIE,
        'service-worker-allowed': '/',
        'content-security-policy': "script-src 'unsafe-inline' *",
        'access-control-allow-origin': '*',
        link: '</evil.js>; rel=preload',
      },
      body: '{"error":"bad_origin"}',
    });
    const r = await http(port, '/api/pair/status', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(r.status).toBe(403);
    expect(r.headers['set-cookie']).toEqual([COOKIE]);
    expect(r.headers['service-worker-allowed']).toBeUndefined();
    expect(r.headers['access-control-allow-origin']).toBeUndefined();
    expect(r.headers.link).toBeUndefined();
    expect(r.headers['content-security-policy']).not.toContain('unsafe-inline');

    const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xd9]);
    core.set({ status: 200, headers: { 'content-type': 'image/jpeg' }, body: jpeg });
    const f = await http(port, '/api/handoff/frame?id=x');
    expect(f.status).toBe(200);
    expect(f.headers['content-type']).toBe('image/jpeg');
    expect(f.body.equals(jpeg)).toBe(true);
  });

  it('a core that is down is a 502, not a hang', async () => {
    await core.close();
    try {
      const r = await http(port, '/api/state');
      expect(r.status).toBe(502);
      expect(JSON.parse(r.body.toString())).toEqual({ error: 'core_unavailable' });
    } finally {
      await core.listen();
    }
  });
});

describe('the real phone approver behind the front (apiOnly on a Unix socket)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'keyflap-front-real-'));
  const socket = join(dir, 'api.sock');
  let approver: PhoneApprover;
  let front: ApproverFront;
  let port: number;

  beforeAll(async () => {
    approver = await PhoneApprover.start({
      dir: join(dir, 'approver'),
      origin: `http://${HOST}`,
      listen: { path: socket },
      apiOnly: true,
      auditBefore: () => {},
      signer: {
        listApprovers: async () => ({ approvers: [] }),
        addApprover: async () => ({ added: true }),
      },
    });
    front = await ApproverFront.start({
      origin: `http://${HOST}`,
      listen: { host: '127.0.0.1', port: 0 },
      upstream: socket,
    });
    port = Number(new URL(front.listenUrl).port);
  });
  afterAll(async () => {
    await front.close();
    await approver.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('answers the API through the front, and serves no page of its own', async () => {
    expect((await http(port, '/api/state')).status).toBe(401);
    expect((await http(port, '/')).status).toBe(200);
    const direct = (path: string, host: string) =>
      new Promise<number>((resolve, reject) => {
        const r = request({ socketPath: socket, path, headers: { host } }, (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        });
        r.on('error', reject);
        r.end();
      });
    expect(await direct('/', HOST)).toBe(404);
    expect(await direct('/app.js', HOST)).toBe(404);
    expect(await direct('/api/state', HOST)).toBe(401);
    expect(await direct('/api/state', `127.0.0.1:${port}`)).toBe(421);
  });

  it('a socket listener without apiOnly, or with TLS, is refused', async () => {
    const base = {
      dir: join(dir, 'other'),
      origin: `http://${HOST}`,
      auditBefore: () => {},
      signer: {
        listApprovers: async () => ({ approvers: [] }),
        addApprover: async () => ({ added: true as const }),
      },
    };
    await expect(
      PhoneApprover.start({ ...base, listen: { path: join(dir, 'x.sock') } }),
    ).rejects.toThrow(/apiOnly/);
    await expect(
      PhoneApprover.start({
        ...base,
        listen: { path: join(dir, 'y.sock') },
        apiOnly: true,
        tls: { cert: 'x', key: 'y' },
      }),
    ).rejects.toThrow(/apiOnly/);
  });
});
