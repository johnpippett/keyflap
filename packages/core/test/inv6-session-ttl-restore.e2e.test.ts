import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openDb, SessionStateRepo } from '../src/db.ts';
import { addPasswordItem } from '../src/passwords.ts';
import { keyflap, type PersistHarness, startPersistHarness, until } from './persist-harness.ts';

const PW = 'ttl-restore-pw-9Q!';

describe('invariant 6: session TTL survives restarts and restore fails closed', () => {
  let h: PersistHarness;

  beforeAll(async () => {
    h = await startPersistHarness({ rp: { users: [{ username: 'alice', password: PW }] } });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: PW },
    );
  });
  afterAll(async () => h?.close());

  const login = async () => {
    await h.intent('sign me in to the test RP');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
  };
  const signedIn = async () =>
    (await h.mcp.ok<{ url: string }>('browser_open', { url: `${h.rp.url}account` })).url ===
    `${h.rp.url}account`;
  const rpCookies = async () =>
    (await (await h.context()).cookies()).filter((c) => c.domain.endsWith('rp.localhost'));
  const cleared = (via: string) =>
    h.auditEvents().filter((e) => e.type === 'session.cleared' && e.payload.via === via);
  const setTtl = (ms: number | null) =>
    h.daemon.broker.policy.set('rp.localhost', h.agent.id, { sessionTtlMs: ms });
  const offline = <T>(fn: (repo: SessionStateRepo) => T): T => {
    const db = openDb(join(h.dataDir, 'broker.sqlite'));
    try {
      return fn(new SessionStateRepo(db));
    } finally {
      db.close();
    }
  };

  it('a TTL that ran out while stopped: cleared before the first agent call', async () => {
    await login();
    const clock = h.daemon.sessionTtl.tracked().find((t) => t.origin === h.rp.origin);
    expect(clock).toBeDefined();
    setTtl(2_000);
    const before = cleared('restore').length;
    await h.stop();
    expect(offline((r) => r.clocks(h.agent.id)).map((c) => c.origin)).toContain(h.rp.origin);
    await until(() => Date.now() > (clock?.at ?? 0) + 2_500);
    await h.start();
    await h.mcp.ok('auth_status');
    expect(await rpCookies()).toEqual([]);
    expect(cleared('restore').length).toBe(before + 1);
    expect(cleared('restore').at(-1)?.payload).toEqual({
      agentId: h.agent.id,
      origin: h.rp.origin,
      ttlMs: 2_000,
      cookies: expect.any(Number),
      pages: 0,
      via: 'restore',
    });
    expect(await signedIn()).toBe(false);
    expect(h.daemon.sessionTtl.tracked().some((t) => t.origin === h.rp.origin)).toBe(false);
    setTtl(null);
  });

  it('a TTL whose clock row is gone is cleared (fail closed)', async () => {
    await login();
    setTtl(3_600_000);
    const before = cleared('restore').length;
    await h.stop();
    offline((r) => r.deleteClocks(h.agent.id));
    await h.start();
    await h.mcp.ok('auth_status');
    expect(await rpCookies()).toEqual([]);
    expect(cleared('restore').length).toBe(before + 1);
    expect(await signedIn()).toBe(false);
    setTtl(null);
  });

  it('a live clock keeps the session; the sweeper clears it at the deadline', async () => {
    await login();
    setTtl(6_000);
    await h.restart({ sessionSweepMs: 200 });
    expect(await signedIn()).toBe(true);
    const before = cleared('ttl').length;
    await until(() => cleared('ttl').length > before, 15_000);
    expect(cleared('ttl').at(-1)?.payload).toMatchObject({
      agentId: h.agent.id,
      origin: h.rp.origin,
      ttlMs: 6_000,
      via: 'ttl',
    });
    expect(await signedIn()).toBe(false);
    setTtl(null);
  });

  it("an unloaded agent's saved file is rewritten on expiry, with no browser", async () => {
    await login();
    setTtl(3_000);
    await h.restart({ sessionSweepMs: 200 });
    const before = cleared('ttl').length;
    await until(() => cleared('ttl').length > before, 15_000);
    expect(h.daemon.sessions.peek(h.agent.id)).toBeUndefined();
    expect(cleared('ttl').at(-1)?.payload).toMatchObject({ pages: 0, via: 'ttl' });
    const loaded = h.daemon.persistence?.store.load(h.agent.id);
    const cookies = loaded?.kind === 'ok' ? loaded.plain.state.cookies : [];
    expect(cookies.filter((c) => c.domain.endsWith('rp.localhost'))).toEqual([]);
    expect(
      h.daemon.persistence?.repo.index(h.agent.id).some((r) => r.site === 'rp.localhost'),
    ).toBe(false);
    setTtl(null);
  });

  it('queued `keyflap sessions clear` requests are applied: by the sweeper, and at the next start', async () => {
    await h.restart({ sessionSweepMs: 200 });
    await login();
    let r = await keyflap(
      h.dataDir,
      'sessions',
      'clear',
      '--agent',
      h.agent.id,
      '--site',
      'rp.localhost',
    );
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain('Queued');
    await until(() => cleared('admin').length > 0, 10_000);
    expect(cleared('admin').at(-1)?.payload).toMatchObject({
      agentId: h.agent.id,
      site: 'rp.localhost',
      via: 'admin',
    });
    expect(await signedIn()).toBe(false);

    await login();
    const before = cleared('admin').length;
    await h.stop();
    r = await keyflap(h.dataDir, 'sessions', 'clear', '--agent', h.agent.id);
    expect(r.code, r.out).toBe(0);
    await h.start();
    await h.mcp.ok('auth_status');
    expect(await rpCookies()).toEqual([]);
    expect(cleared('admin').length).toBe(before + 1);
    expect(offline((q) => q.clearRequests())).toEqual([]);
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});
