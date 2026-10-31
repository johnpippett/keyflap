import { spawn } from 'node:child_process';
import { closeSync, openSync, readdirSync, readFileSync, readSync } from 'node:fs';
import { request } from 'node:http';
import { connect, createServer } from 'node:net';
import { join } from 'node:path';

export type Attempt =
  | { kind: 'read'; path: string }
  | { kind: 'list'; path: string }
  | { kind: 'open'; path: string }
  | { kind: 'write'; path: string }
  | { kind: 'create'; dir: string }
  | { kind: 'connect'; path: string }
  | { kind: 'tcp'; port: number; host?: string }
  | { kind: 'bind'; port: number; host: string }
  | { kind: 'devtools'; port: number }
  | { kind: 'own-child'; file: string };

export interface Outcome {
  attempt: Attempt;
  ok: boolean;
  code?: string;
  detail?: string;
}

const code = (err: unknown) => (err as NodeJS.ErrnoException).code ?? String(err);

function connectUnix(path: string): Promise<Omit<Outcome, 'attempt'>> {
  return new Promise((resolve) => {
    const s = connect(path);
    const t = setTimeout(() => {
      s.destroy();
      resolve({ ok: false, code: 'TIMEOUT' });
    }, 3_000);
    s.once('connect', () => {
      clearTimeout(t);
      s.destroy();
      resolve({ ok: true });
    });
    s.once('error', (e) => {
      clearTimeout(t);
      resolve({ ok: false, code: code(e) });
    });
  });
}

function connectTcp(port: number, host: string): Promise<Omit<Outcome, 'attempt'>> {
  return new Promise((resolve) => {
    const s = connect(port, host);
    const t = setTimeout(() => {
      s.destroy();
      resolve({ ok: false, code: 'TIMEOUT' });
    }, 3_000);
    s.once('connect', () => {
      clearTimeout(t);
      s.destroy();
      resolve({ ok: true });
    });
    s.once('error', (e) => {
      clearTimeout(t);
      resolve({ ok: false, code: code(e) });
    });
  });
}

function bindTcp(port: number, host: string): Promise<Omit<Outcome, 'attempt'>> {
  return new Promise((resolve) => {
    const s = createServer();
    s.once('error', (e) => resolve({ ok: false, code: code(e) }));
    s.listen({ port, host, exclusive: true }, () => s.close(() => resolve({ ok: true })));
  });
}

function devtools(port: number): Promise<Omit<Outcome, 'attempt'>> {
  return new Promise((resolve) => {
    const req = request(
      { host: '127.0.0.1', port, path: '/json/version', method: 'GET', timeout: 3_000 },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c: string) => {
          if (body.length < 4096) body += c;
        });
        res.on('end', () => {
          const isDevtools = /webSocketDebuggerUrl|"Browser"\s*:/.test(body);
          resolve({ ok: isDevtools, detail: `http ${res.statusCode}` });
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolve({ ok: false, code: code(e) }));
    req.end();
  });
}

async function ownChild(file: string): Promise<Omit<Outcome, 'attempt'>> {
  const child = spawn('sleep', ['30'], { stdio: 'ignore' });
  try {
    await new Promise((r) => setTimeout(r, 100));
    const p = join('/proc', String(child.pid), file);
    if (file === 'fd') readdirSync(p);
    else if (file === 'mem') closeSync(openSync(p, 'r'));
    else readFileSync(p);
    return { ok: true };
  } catch (e) {
    return { ok: false, code: code(e) };
  } finally {
    child.kill();
  }
}

export async function run(a: Attempt): Promise<Outcome> {
  try {
    switch (a.kind) {
      case 'read': {
        const b = readFileSync(a.path);
        return { attempt: a, ok: true, detail: `${b.length} bytes` };
      }
      case 'list': {
        const n = readdirSync(a.path).length;
        return { attempt: a, ok: true, detail: `${n} entries` };
      }
      case 'open': {
        const fd = openSync(a.path, 'r');
        try {
          readSync(fd, Buffer.alloc(1), 0, 1, null);
        } catch {}
        closeSync(fd);
        return { attempt: a, ok: true };
      }
      case 'write': {
        closeSync(openSync(a.path, 'r+'));
        return { attempt: a, ok: true };
      }
      case 'create': {
        closeSync(openSync(join(a.dir, `.isolation-probe-${process.pid}`), 'wx'));
        return { attempt: a, ok: true };
      }
      case 'connect':
        return { attempt: a, ...(await connectUnix(a.path)) };
      case 'tcp':
        return { attempt: a, ...(await connectTcp(a.port, a.host ?? '127.0.0.1')) };
      case 'devtools':
        return { attempt: a, ...(await devtools(a.port)) };
      case 'bind':
        return { attempt: a, ...(await bindTcp(a.port, a.host)) };
      case 'own-child':
        return { attempt: a, ...(await ownChild(a.file)) };
    }
  } catch (e) {
    return { attempt: a, ok: false, code: code(e) };
  }
}

if (process.argv[2]) {
  const attempts = JSON.parse(process.argv[2]) as Attempt[];
  const out: Outcome[] = [];
  for (const a of attempts) out.push(await run(a));
  process.stdout.write(`${JSON.stringify(out)}\n`);
}
