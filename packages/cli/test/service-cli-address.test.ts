import { writeFileSync } from 'node:fs';
import type { Server } from 'node:net';
import { join } from 'node:path';
import { AdminError, AdminOps, startAdminServer } from '@aab/signer/admin-wire';
import type { AddressState } from '@aab/signer/approver-address';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runServiceCommand, ServiceCliError } from '../src/service/cli.ts';
import { SYSTEMD_MANAGER } from '../src/service/manager.ts';
import { SERVICE_PATHS, type ServicePaths } from '../src/service/paths.ts';
import { tmpDir } from './helpers.ts';
import { FakeSystem } from './setup-fakes.ts';

const ORIGIN = 'https://b.tail1.ts.net:8766';
const WRONG = {
  kind: 'latched',
  at: Date.UTC(2026, 9, 30, 8),
  seen: 'b.tail1.ts.net:8766 proxies to http://127.0.0.1:9999',
} as const satisfies AddressState;
const TRIPPED =
  'off: it was changed at 2026-10-30T08:00:00.000Z (b.tail1.ts.net:8766 proxies to http://127.0.0.1:9999), so phones were signed out to be safe';

describe('service CLI: the approval address in status, before pairing, and trust', () => {
  const dir = tmpDir();
  const paths: ServicePaths = {
    ...SERVICE_PATHS,
    adminSocket: join(dir, 'c', 'admin.sock'),
    signerAdminSocket: join(dir, 's', 'admin.sock'),
    signerConfig: join(dir, 'signer.json'),
  };
  const signerJson = {
    storePath: '/var/lib/keyflap/signer/keys.enc.json',
    approverAddress: { origin: ORIGIN, target: 'http://127.0.0.1:8766' },
  };
  const sys = new FakeSystem();
  sys.file(paths.signerConfig, JSON.stringify(signerJson), 0o644, 0);
  let state: AddressState = { kind: 'ok', checkedAt: 1 };
  const calls: string[] = [];
  const servers: Server[] = [];

  beforeAll(async () => {
    writeFileSync(paths.signerConfig, JSON.stringify(signerJson), { mode: 0o644 });
    const core = new AdminOps()
      .register('status', () => {
        calls.push('core status');
        return { mode: 'service', mcpUrl: 'http://127.0.0.1:8765/mcp', signer: 'ok' };
      })
      .register('status.report', () => ({ text: 'Agents: 1\n' }))
      .register('approver.pair', () => {
        calls.push('approver.pair');
        return { url: `${ORIGIN}/pair#CODE`, origin: ORIGIN, validMinutes: 10 };
      });
    const signer = new AdminOps()
      .register('status', () => ({
        approvers: 1,
        phoneLatched: false,
        sources: [],
        address: state,
      }))
      .register('approver.address.clear', () => {
        calls.push('approver.address.clear');
        return { state };
      });
    servers.push(await startAdminServer({ listen: { path: paths.adminSocket }, ops: core }));
    servers.push(
      await startAdminServer({ listen: { path: paths.signerAdminSocket }, ops: signer }),
    );
  });
  afterAll(async () => {
    for (const s of servers) await new Promise((r) => s.close(r));
  });

  const run = async (cmd: Parameters<typeof runServiceCommand>[0]) => {
    const chunks: string[] = [];
    await runServiceCommand(cmd, (t) => chunks.push(t), paths, SYSTEMD_MANAGER, sys);
    return chunks.join('');
  };
  const status = () => run({ kind: 'status', dataDir: '/unused', json: false });
  const pair = () => run({ kind: 'approver-pair', dataDir: '/unused', phone: null });

  it('status shows what is watched, and the fix on the next line when it is wrong', async () => {
    expect(await status()).toContain(
      `Address:     ok (${ORIGIN} -> http://127.0.0.1:8766, watched)\nAgents: 1\n`,
    );
    state = WRONG;
    expect(await status()).toContain(
      [
        `Address:     ${TRIPPED}`,
        '             fix: sudo tailscale serve --bg --https=8766 http://127.0.0.1:8766, then sudo keyflap approver pair',
        'Agents: 1',
      ].join('\n'),
    );
    state = { kind: 'paused', since: 1, detail: 'tailscale exited 1' };
    expect(await status()).toContain(
      'Address:     unreadable: tailscale exited 1\n             fix: start Tailscale (tailscale up), then sudo keyflap doctor\n',
    );
    state = { kind: 'unwatched' };
    expect(await status()).toContain(
      'Address:     not watched (not a Tailscale name)\nAgents: 1\n',
    );
  });

  it('after a trip, status says in the past tense what was seen, and what is there now', async () => {
    state = { ...WRONG, latest: { checkedAt: 2, verdict: { kind: 'ok' } } };
    expect(await status()).toContain(
      [
        `Address:     ${TRIPPED}. It is right again now`,
        '             fix: pair your phone again to turn approvals back on: sudo keyflap approver pair',
        'Agents: 1',
      ].join('\n'),
    );
    state = { ...WRONG, latest: { checkedAt: 2, verdict: { kind: 'mismatch', seen: WRONG.seen } } };
    expect(await status()).toContain(
      [
        `Address:     ${TRIPPED}. It is still wrong`,
        '             fix: sudo tailscale serve --bg --https=8766 http://127.0.0.1:8766, then sudo keyflap approver pair',
      ].join('\n'),
    );
    state = {
      ...WRONG,
      latest: {
        checkedAt: 2,
        verdict: { kind: 'mismatch', seen: 'b.tail1.ts.net:8766 is on Funnel' },
      },
    };
    expect(await status()).toContain(
      [
        `Address:     ${TRIPPED}. Now: b.tail1.ts.net:8766 is on Funnel`,
        '             fix: sudo tailscale serve reset (it clears every serve setting on this computer), then sudo tailscale serve --bg --https=8766 http://127.0.0.1:8766, then sudo keyflap approver pair',
      ].join('\n'),
    );
    state = { ...WRONG, latest: { checkedAt: 2, verdict: { kind: 'offline' } } };
    expect(await status()).toContain(
      [
        `Address:     ${TRIPPED}. Now Tailscale is not connected`,
        '             fix: sudo tailscale serve --bg --https=8766 http://127.0.0.1:8766, then sudo keyflap approver pair',
      ].join('\n'),
    );
    state = {
      ...WRONG,
      latest: { checkedAt: 2, verdict: { kind: 'unreadable', detail: 'Tailscale is not running' } },
    };
    expect(await status()).toContain(
      `Address:     ${TRIPPED}. Now it can't be read: Tailscale is not running\n`,
    );
  });

  it('a pause inside its grace says it is waiting, and sends nobody to the installer', async () => {
    const now = Date.now();
    const holding = (detail: string): AddressState => ({
      kind: 'paused',
      since: now,
      detail,
      graceUntil: now + 60_000,
    });
    const wait =
      '             fix: wait a moment: approvals resume by themselves once Tailscale answers\n';
    state = holding("Tailscale's token cannot be read");
    expect(await status()).toContain(
      `Address:     waiting for Tailscale: Tailscale is not answering yet\n${wait}`,
    );
    state = holding('Tailscale is not running');
    expect(await status()).toContain(
      `Address:     waiting for Tailscale: Tailscale is not running\n${wait}`,
    );
    state = holding('Tailscale is not connected');
    expect(await status()).toContain(
      `Address:     waiting for Tailscale: Tailscale is not connected yet\n${wait}`,
    );
    state = {
      kind: 'paused',
      since: now - 60_000,
      detail: "Tailscale's token cannot be read",
      graceUntil: now - 30_000,
    };
    expect(await status()).toContain(
      "Address:     unreadable: Tailscale's token cannot be read\n             fix: install Tailscale at a root-only path",
    );
    state = { kind: 'paused', since: 1, detail: 'Tailscale is not connected', graceUntil: 2 };
    expect(await status()).toContain(
      'Address:     paused: Tailscale is not connected\n             fix: start Tailscale (tailscale up), then sudo keyflap doctor\n',
    );
  });

  it('what the serve setting said reaches the terminal as plain, short text', async () => {
    const trick = `x\u001b[2J\u202e). It is right again now${'a'.repeat(400)}`;
    state = {
      ...WRONG,
      seen: trick,
      latest: { checkedAt: 2, verdict: { kind: 'mismatch', seen: trick } },
    };
    const out = await status();
    const line = out.split('\n').find((l) => l.startsWith('Address:')) ?? '';
    expect(line).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u);
    expect(line.length).toBeLessThan(500);
    expect(line).toContain('(x[2J). It is right again now');
  });

  it('pair asks the signer to re-check first, and refuses with the fix while the address is wrong', async () => {
    state = WRONG;
    calls.length = 0;
    const err = await pair().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ServiceCliError);
    expect((err as Error).message).toBe(
      [
        `the approval address is ${TRIPPED}.`,
        '  Approvals are off until it is fixed at this computer.',
        '  fix: sudo tailscale serve --bg --https=8766 http://127.0.0.1:8766, then sudo keyflap approver pair',
      ].join('\n'),
    );
    expect(calls).toEqual(['approver.address.clear']);

    state = { kind: 'paused', since: 1, detail: 'no tailscale CLI configured' };
    await expect(pair()).rejects.toThrow(
      /^the approval address is unreadable: no tailscale CLI configured\.\n {2}Approvals are off until it is fixed at this computer\.\n {2}fix: install Tailscale at a root-only path/,
    );

    state = { kind: 'ok', checkedAt: 2 };
    calls.length = 0;
    expect(await pair()).toContain(`${ORIGIN}/pair#CODE`);
    expect(calls).toEqual(['approver.address.clear', 'approver.pair']);
  });

  it('nothing pins tailscale: it runs only from a root-only path', async () => {
    await expect(run({ kind: 'password-source-trust', tool: 'tailscale' })).rejects.toThrow(
      /unknown tool "tailscale" \(known: pass-cli, op\)/,
    );
  });

  it('a signer that cannot clear is a refusal, never a pairing link', async () => {
    const s = servers[1] as Server;
    await new Promise((r) => s.close(r));
    const broken = new AdminOps()
      .register('status', () => ({ approvers: 1, address: state }))
      .register('approver.address.clear', () => {
        throw new AdminError('admin_required');
      });
    servers[1] = await startAdminServer({ listen: { path: paths.signerAdminSocket }, ops: broken });
    calls.length = 0;
    await expect(pair()).rejects.toThrow(ServiceCliError);
    expect(calls).not.toContain('approver.pair');
  });
});
