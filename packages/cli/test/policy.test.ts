import { rmSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { AgentRegistry, ALL_AGENTS, AuditLog, openDb, PolicyStore } from '@aab/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runCli, tmpDir } from './helpers.ts';

describe('keyflap policy / status / audit', () => {
  let dir: string;
  let db: DatabaseSync;
  let store: PolicyStore;
  let agentId: string;
  const cli = (...args: string[]) => runCli([...args, '--data-dir', dir]);
  const target = { origin: 'https://login.example.com', host: 'login.example.com' };

  beforeAll(() => {
    dir = tmpDir();
    db = openDb(join(dir, 'broker.sqlite'));
    store = new PolicyStore(db);
    agentId = new AgentRegistry(db).add('policy-bot').id;
  });
  afterAll(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('set writes a rule the open connection resolves at once, and audits it', async () => {
    const r = await cli('policy', 'set', 'Example.com', '--deny');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('example.com (all agents): deny');
    expect(store.resolve(agentId, target).mode).toBe('deny');
    const last = new AuditLog(db).all().at(-1);
    expect(last?.event_type).toBe('policy.set');
    expect(JSON.parse(last?.payload_json ?? '{}')).toEqual({
      pattern: 'example.com',
      agentId: '*',
      mode: 'deny',
    });
  });

  it('per-agent allow-for with a session TTL; updating keeps fields not given', async () => {
    expect(
      (
        await cli(
          'policy',
          'set',
          'https://login.example.com',
          '--agent',
          agentId,
          '--allow-for',
          '30m',
          '--session-ttl',
          '2h',
        )
      ).code,
    ).toBe(0);
    expect(store.get('https://login.example.com', agentId)).toMatchObject({
      mode: 'allow-for',
      allowForMs: 30 * 60_000,
      sessionTtlMs: 2 * 3_600_000,
    });
    expect(
      (await cli('policy', 'set', 'https://login.example.com', '--agent', agentId, '--ask')).code,
    ).toBe(0);
    expect(store.get('https://login.example.com', agentId)).toMatchObject({
      mode: 'ask',
      allowForMs: null,
      sessionTtlMs: 2 * 3_600_000,
    });
    expect(store.resolve(agentId, target).mode).toBe('deny');
  });

  it('allow-for takes a window of exactly 24 hours and says the limit when it is exceeded', async () => {
    const ok = await cli('policy', 'set', 'example.net', '--allow-for', '24h');
    expect(ok.code).toBe(0);
    expect(store.get('example.net', ALL_AGENTS)).toMatchObject({
      mode: 'allow-for',
      allowForMs: 24 * 3_600_000,
    });
    const over = await cli('policy', 'set', 'example.net', '--allow-for', '24h1s');
    expect(over.code).toBe(1);
    expect(over.stderr).toMatch(/between 1s and 24h/);
    expect(store.get('example.net', ALL_AGENTS)?.allowForMs).toBe(24 * 3_600_000);
    expect(store.remove('example.net', ALL_AGENTS)).toBe(true);
  });

  it('refuses unknown agents, public suffixes, bad origins and out-of-range durations', async () => {
    for (const args of [
      ['example.net', '--ask', '--agent', 'no-such-agent'],
      ['com', '--deny'],
      ['http://example.net', '--deny'],
      ['example.net', '--allow-for', '24h1s'],
      ['example.net', '--session-ttl', '31d'],
    ]) {
      const r = await cli('policy', 'set', ...args);
      expect(r.code, args.join(' ')).toBe(1);
      expect(r.stdout).toBe('');
    }
    const usage = await cli('policy', 'set', 'example.net');
    expect(usage.code).toBe(2);
  });

  it('list (table and JSON) and remove', async () => {
    const table = await cli('policy', 'list');
    expect(table.code).toBe(0);
    expect(table.stdout).toMatch(/^SITE\s+AGENT\s+MODE\s+SESSION TTL$/m);
    expect(table.stdout).toMatch(/example\.com\s+\* \(all\)\s+deny\s+-/);
    expect(table.stdout).toContain(`policy-bot ${agentId}`);
    const json = JSON.parse((await cli('policy', 'list', '--json')).stdout);
    expect(json).toEqual([
      expect.objectContaining({ site: 'example.com', agentId: ALL_AGENTS, mode: 'deny' }),
      expect.objectContaining({
        site: 'https://login.example.com',
        agentId,
        agentName: 'policy-bot',
        mode: 'ask',
        sessionTtlMs: 7_200_000,
      }),
    ]);
    expect((await cli('policy', 'remove', 'example.com')).code).toBe(0);
    expect(store.resolve(agentId, target).mode).toBe('ask');
    const again = await cli('policy', 'remove', 'example.com');
    expect(again.code).toBe(1);
    expect(again.stderr).toMatch(/no rule/);
    expect(new AuditLog(db).all().at(-1)?.event_type).toBe('policy.removed');
  });

  it('status and audit verify / tail; a broken chain is reported and exits 1', async () => {
    const s = await cli('status');
    expect(s.code).toBe(0);
    expect(s.stdout).toContain('Agents:      1 active (policy-bot)');
    expect(s.stdout).toContain('Credentials: 0 passkeys, 0 password items');
    expect(s.stdout).toContain('Policies:    1 rules');
    expect(s.stdout).toMatch(/Audit log:\s+\d+ entries, hash chain intact/);
    expect(s.stdout).toContain('policy.removed');
    const js = JSON.parse((await cli('status', '--json')).stdout);
    expect(js.audit.intact).toBe(true);
    expect(js.agents).toEqual([{ id: agentId, name: 'policy-bot' }]);

    expect((await cli('audit', 'verify')).stdout).toMatch(/intact/);
    const tail = JSON.parse((await cli('audit', 'tail', '--limit', '2', '--json')).stdout);
    expect(tail).toHaveLength(2);
    expect(tail[1].event).toBe('policy.removed');

    db.exec('DROP TRIGGER audit_no_update');
    db.prepare(`UPDATE audit SET payload_json = '{}' WHERE seq = 1`).run();
    const v = await cli('audit', 'verify');
    expect(v.code).toBe(1);
    expect(v.stdout).toMatch(/BROKEN at seq 1/);
    expect((await cli('status')).stdout).toContain('HASH CHAIN BROKEN at seq 1');
  });
});
