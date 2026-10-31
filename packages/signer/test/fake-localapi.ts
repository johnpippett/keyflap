import { mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { tailscaleStatus } from '@aab/sources/testing';

export type FakeLocalApiMode = 'ok' | 'hang' | 'huge' | 'error';

export interface FakeLocalApiRequest {
  method: string;
  path: string;
  authorization: string | undefined;
  secTailscale: string | undefined;
}

export interface FakeLocalApi {
  dir: string;
  port: number;
  token: string;
  serve(config: unknown): void;
  status(status: unknown): void;
  set(mode: FakeLocalApiMode): void;
  requests(): FakeLocalApiRequest[];
  close(): Promise<void>;
}

export const FAKE_PROOF_TOKEN = 'fake-proof-0123456789';

const ROUTES = {
  serve: '/localapi/v0/serve-config',
  status: '/localapi/v0/status?peers=false',
} as const;

export async function fakeLocalApi(
  config: unknown,
  status: unknown = tailscaleStatus({ onTailnet: true }),
): Promise<FakeLocalApi> {
  const bodies = { serve: JSON.stringify(config), status: JSON.stringify(status) };
  let mode: FakeLocalApiMode = 'ok';
  const seen: FakeLocalApiRequest[] = [];
  const expected = `Basic ${Buffer.from(`:${FAKE_PROOF_TOKEN}`).toString('base64')}`;
  const server = createServer((req, res) => {
    seen.push({
      method: req.method ?? '',
      path: req.url ?? '',
      authorization: req.headers.authorization,
      secTailscale: req.headers['sec-tailscale'] as string | undefined,
    });
    if (mode === 'hang') return;
    if (req.headers.authorization === undefined) {
      res.writeHead(401).end('auth required\n');
      return;
    }
    if (req.headers.authorization !== expected) {
      res.writeHead(403).end('bad password\n');
      return;
    }
    const route = req.url === ROUTES.serve ? 'serve' : req.url === ROUTES.status ? 'status' : null;
    if (route === null) {
      res.writeHead(404).end('not found\n');
      return;
    }
    if (mode === 'error') {
      res.writeHead(500).end('backend error\n');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(mode === 'huge' ? 'x'.repeat(2 * 1024 * 1024) : bodies[route]);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  const dir = mkdtempSync(join(tmpdir(), 'keyflap-fake-localapi-'));
  symlinkSync(String(port), join(dir, 'ipnport'));
  writeFileSync(join(dir, `sameuserproof-${port}`), `${FAKE_PROOF_TOKEN}\n`, { mode: 0o640 });
  return {
    dir,
    port,
    token: FAKE_PROOF_TOKEN,
    serve(c) {
      bodies.serve = JSON.stringify(c);
    },
    status(st) {
      bodies.status = JSON.stringify(st);
    },
    set(m) {
      mode = m;
    },
    requests: () => [...seen],
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
