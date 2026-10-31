import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import type { Daemon } from '@aab/core';
import { FAKE_TAILSCALE, fakeTailscale, serveConfig, tailscaleStatus } from '@aab/sources/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runDaemon } from '../src/daemon.ts';
import { tmpDir } from './helpers.ts';

const HOST = 'box.tail1.ts.net';

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

function onPath(dir: string, fake: ReturnType<typeof fakeTailscale>): string {
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  const script = join(bin, 'tailscale');
  writeFileSync(
    script,
    `#!/bin/sh\nexport KEYFLAP_FAKE_TAILSCALE_DIR=${fake.dir}\nexec ${process.execPath} ${FAKE_TAILSCALE} "$@"\n`,
  );
  chmodSync(script, 0o755);
  return bin;
}

describe('invariant 5 (the approval address): the dev daemon watches a Tailscale origin', () => {
  let daemon: Daemon | undefined;
  const savedPath = process.env.PATH;
  const stderr: string[] = [];
  afterEach(async () => {
    vi.restoreAllMocks();
    process.env.PATH = savedPath;
    await daemon?.stop();
    daemon = undefined;
    stderr.length = 0;
  });

  async function start(dataDir: string, port: number, pathDir: string | null) {
    process.env.PATH = pathDir ? `${pathDir}:${savedPath}` : '/nonexistent-bin';
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
    daemon = await runDaemon({
      dataDir,
      mcpPort: 0,
      headed: false,
      unprotected: true,
      passphrase: 'address-test-passphrase',
      phone: {
        origin: `https://${HOST}:${port}`,
        listen: { host: '127.0.0.1', port },
        tlsCert: null,
        tlsKey: null,
        pair: false,
        apns: null,
      },
    });
    return { text: () => stderr.join('') };
  }

  it('a correct serve config: watched, and pairing is offered as before', async () => {
    const dataDir = tmpDir();
    const port = await freePort();
    const fake = fakeTailscale(
      serveConfig({ host: HOST, port, target: `http://127.0.0.1:${port}` }),
    );
    const { text } = await start(dataDir, port, onPath(dataDir, fake));
    expect(text()).toContain('No phone paired yet. Open this one-time link');
    expect(existsSync(join(dataDir, 'approver', 'pairing-url'))).toBe(true);
    const d = daemon as Daemon;
    expect((await d.signer.client.approverAddress({ pending: false })).state).toMatchObject({
      kind: 'ok',
    });
    expect(fake.calls().map((c) => c.argv.join(' '))).toContain('serve status --json');
  });

  it('a wrong serve config: no pairing link, the fix in the log, the trip in the audit chain', async () => {
    const dataDir = tmpDir();
    const port = await freePort();
    const fake = fakeTailscale(serveConfig({ host: HOST, port, target: 'http://127.0.0.1:9999' }));
    const { text } = await start(dataDir, port, onPath(dataDir, fake));
    expect(text()).toContain('Approval address: off: it was changed at 20');
    expect(text()).toContain(`${HOST}:${port} proxies to "http://127.0.0.1:9999"`);
    expect(text()).toContain(`keyflap approver pair --approver-origin https://${HOST}:${port}`);
    expect(text()).not.toContain('one-time link');
    expect(existsSync(join(dataDir, 'approver', 'pairing-url'))).toBe(false);
    const tripped = (daemon as Daemon).broker.audit
      .all()
      .filter((r) => r.event_type === 'approver.address_tripped');
    expect(tripped).toHaveLength(1);
  });

  it('a Tailscale restart (not running, then off the tailnet) pauses and resumes by itself: no trip, and the open pairing link keeps working', async () => {
    const dataDir = tmpDir();
    const port = await freePort();
    const correct = serveConfig({ host: HOST, port, target: `http://127.0.0.1:${port}` });
    const fake = fakeTailscale(correct);
    await start(dataDir, port, onPath(dataDir, fake));
    const d = daemon as Daemon;
    const pairingUrl = join(dataDir, 'approver', 'pairing-url');
    expect(existsSync(pairingUrl)).toBe(true);
    const state = async () => (await d.signer.client.approverAddress({ pending: true })).state;
    const waitFor = async (pred: (s: Awaited<ReturnType<typeof state>>) => boolean) => {
      const until = Date.now() + 15_000;
      for (;;) {
        const s = await state();
        if (pred(s)) return s;
        if (Date.now() > until) throw new Error(`still ${JSON.stringify(s)}`);
        await new Promise((r) => setTimeout(r, 50));
      }
    };

    fake.set('down', true);
    await waitFor((s) => s.kind === 'paused' && s.detail === 'Tailscale is not running');
    fake.status(tailscaleStatus({ onTailnet: false }));
    fake.serveRaw('null');
    fake.set('down', false);
    await waitFor((s) => s.kind === 'paused' && s.detail === 'Tailscale is not connected');
    await new Promise((r) => setTimeout(r, 1_500));
    expect(existsSync(pairingUrl)).toBe(true);
    fake.serve(correct);
    fake.status(tailscaleStatus({ onTailnet: true }));
    await waitFor((s) => s.kind === 'ok');
    await new Promise((r) => setTimeout(r, 1_500));
    expect(existsSync(pairingUrl)).toBe(true);
    const events = d.broker.audit.all().map((r) => r.event_type);
    expect(events).not.toContain('approver.address_tripped');
    expect(events).toContain('approver.address_readable');
  }, 30_000);

  it('no tailscale on PATH: paused, never silently unwatched', async () => {
    const dataDir = tmpDir();
    const { text } = await start(dataDir, await freePort(), null);
    expect(text()).toContain('Approval address: unreadable: no tailscale CLI configured');
    expect(text()).toContain('install Tailscale');
    expect(existsSync(join(dataDir, 'approver', 'pairing-url'))).toBe(false);
  });
});
