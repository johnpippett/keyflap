import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApproverFront, type ApproverFrontOptions } from '../src/front.ts';
import { PAGE_DIR } from '../src/page-files.ts';

const HOST = 'approver.localhost';

function get(port: number, path: string): Promise<{ status: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const r = request(
      { host: '127.0.0.1', port, path, headers: { host: `${HOST}:${port}` } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }));
      },
    );
    r.on('error', reject);
    r.end();
  });
}

describe('the service-mode front at startup', () => {
  let dir: string;
  let started: ApproverFront | null;

  const start = (over: Partial<ApproverFrontOptions>): Promise<ApproverFront> =>
    ApproverFront.start({
      origin: `http://${HOST}`,
      listen: { host: '127.0.0.1', port: 0 },
      upstream: join(dir, 'api.sock'),
      ...over,
    }).then((front) => {
      started = front;
      return front;
    });

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'keyflap-front-start-'));
    started = null;
  });
  afterEach(async () => {
    await started?.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('without TLS it listens on loopback only, whatever address it is told to bind', async () => {
    for (const host of ['0.0.0.0', '::', '192.168.1.5', 'approver.example']) {
      const refusal = await start({ origin: 'https://approver.example', listen: { host, port: 0 } })
        .then(() => null)
        .catch((e: Error) => e);
      expect(refusal?.message ?? `it listened on ${host}`).toMatch(/loopback/);
      await started?.close();
      started = null;
    }
    const front = await start({});
    expect(front.listenUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });

  it('serves the page files it read at start, whatever happens to them on disk afterwards', async () => {
    const pageDir = join(dir, 'page');
    cpSync(PAGE_DIR, pageDir, { recursive: true });
    const front = await start({ pageDir });
    const port = Number(new URL(front.listenUrl).port);
    const before = await get(port, '/app.js');
    expect(before.status).toBe(200);

    writeFileSync(join(pageDir, 'app.js'), 'document.body.textContent = "swapped";');
    rmSync(join(pageDir, 'handoff.js'));
    const after = await get(port, '/app.js');
    expect(after.status).toBe(200);
    expect(after.body.equals(before.body)).toBe(true);
    expect((await get(port, '/handoff.js')).status).toBe(200);
  });
});
