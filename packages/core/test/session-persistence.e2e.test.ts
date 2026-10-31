import { copyFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { TOOL_NAMES } from '@aab/mcp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openDb } from '../src/db.ts';
import { addPasswordItem } from '../src/passwords.ts';
import { PolicyStore } from '../src/policy.ts';
import { keyflap, type PersistHarness, startPersistHarness, until } from './persist-harness.ts';

const PW = 'persist-pw-Zk3!';

describe('persistent browser state across daemon restarts', () => {
  let h: PersistHarness;

  beforeAll(async () => {
    h = await startPersistHarness({
      rp: { users: [{ username: 'alice', password: PW }] },
      daemon: { highRiskDomains: ['bank.localhost'] },
    });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: PW },
    );
  });
  afterAll(async () => h?.close());

  const signedIn = async () => {
    const r = await h.mcp.ok<{ url: string }>('browser_open', { url: `${h.rp.url}account` });
    return r.url === `${h.rp.url}account`;
  };

  it('a broker login survives a restart: signed in, no approval, no prompt; storage too', async () => {
    await h.intent('sign me in to the test RP');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    const page = h.page();
    await page.evaluate(async () => {
      localStorage.setItem('ls-marker', 'kept');
      await new Promise<void>((resolve, reject) => {
        const open = indexedDB.open('persist-db', 1);
        open.onupgradeneeded = () => open.result.createObjectStore('s');
        open.onsuccess = () => {
          const tx = open.result.transaction('s', 'readwrite');
          tx.objectStore('s').put({ nested: { list: ['idb-kept'] } }, 'k');
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        };
        open.onerror = () => reject(open.error);
      });
    });
    await until(() => existsSync(h.stateFile()));
    const approvals = h.approver.seen.length;
    const logins = h.rp.logins.length;

    await h.stop();
    const before = h.rp.requests.length;
    await h.start();
    expect(await h.mcp.ok('auth_status')).toMatchObject({ origin: null });
    expect(h.rp.requests.length).toBe(before);

    expect(await signedIn()).toBe(true);
    const snap = await h.mcp.ok<{ snapshot: string }>('browser_snapshot');
    expect(snap.snapshot).toContain('Signed in as alice');
    expect(h.approver.seen.length).toBe(approvals);
    expect(h.rp.logins.length).toBe(logins);
    const stored = await h.page().evaluate(async () => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const open = indexedDB.open('persist-db', 1);
        open.onsuccess = () => resolve(open.result);
        open.onerror = () => reject(open.error);
      });
      const v = await new Promise<unknown>((resolve) => {
        const r = db.transaction('s').objectStore('s').get('k');
        r.onsuccess = () => resolve(r.result);
      });
      return { ls: localStorage.getItem('ls-marker'), idb: v };
    });
    expect(stored).toEqual({ ls: 'kept', idb: { nested: { list: ['idb-kept'] } } });

    const restored = h.auditEvents().find((e) => e.type === 'browser_state.restored')?.payload;
    expect(restored).toMatchObject({ agentId: h.agent.id, sites: ['rp.localhost'] });
    expect(restored?.cookies).toBeGreaterThan(0);
    expect(JSON.stringify(restored)).not.toMatch(/sid|ls-marker|persist-db|kept/);
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });

  it('a deny rule added while stopped drops the site at restore', async () => {
    await h.stop();
    const db = openDb(join(h.dataDir, 'broker.sqlite'));
    new PolicyStore(db).set('rp.localhost', '*', { mode: 'deny' });
    db.close();
    await h.start();
    try {
      expect(await signedIn()).toBe(false);
      const restored = h
        .auditEvents()
        .filter((e) => e.type === 'browser_state.restored')
        .at(-1);
      expect((restored?.payload.dropped as { deny: unknown[] } | undefined)?.deny).toEqual([
        expect.objectContaining({ site: 'rp.localhost' }),
      ]);
    } finally {
      h.daemon.broker.policy.remove('rp.localhost', '*');
    }
  });

  it('high-risk sites are kept only with the owner opt-in; removing it drops the site', async () => {
    const ctx = await h.context();
    const bank = { name: 'bank_sid', value: 'b1', domain: 'bank.localhost', path: '/' };
    await ctx.addCookies([bank]);
    await h.restart();
    await h.mcp.ok('auth_status');
    let names = (await (await h.context()).cookies()).map((c) => c.name);
    expect(names).not.toContain('bank_sid');
    const dropped = h
      .auditEvents()
      .filter((e) => e.type === 'browser_state.restored')
      .at(-1);
    expect(JSON.stringify(dropped?.payload)).not.toContain('bank_sid');

    expect(h.daemon.optins.add(h.agent.id, 'bank.localhost', 'cli')).toBe(true);
    await (await h.context()).addCookies([bank]);
    await h.restart();
    await h.mcp.ok('auth_status');
    names = (await (await h.context()).cookies()).map((c) => c.name);
    expect(names).toContain('bank_sid');

    await h.daemon.sessionTtl.sweep();
    expect(h.daemon.optins.remove(h.agent.id, 'bank.localhost', 'cli')).toBe(true);
    await h.daemon.sessionTtl.sweep();
    const loaded = h.daemon.persistence?.store.load(h.agent.id);
    expect(loaded?.kind).toBe('ok');
    if (loaded?.kind === 'ok') {
      expect(loaded.plain.state.cookies.some((c) => c.name === 'bank_sid')).toBe(false);
    }
    const types = h.auditEvents().map((e) => e.type);
    expect(types).toContain('session.keep_set');
    expect(types).toContain('session.keep_removed');
  });

  it('no MCP tool can write an opt-in', async () => {
    expect(TOOL_NAMES.filter((t) => /keep|persist|session|optin/i.test(t))).toEqual([]);
    const before = h.daemon.optins.list();
    for (const name of TOOL_NAMES) {
      const r = await h.mcp.call(name, { site: 'bank.localhost', keep: true, keepSignedIn: true });
      expect(r.isError, name).toBe(true);
    }
    expect(h.daemon.optins.list()).toEqual(before);
  });

  it('a revoke (daemon registry) deletes the file, without a final save', async () => {
    const other = h.daemon.registry.add('revoked-agent');
    const m = await h.connect(other);
    await m.ok('browser_open', { url: `${h.rp.url}` });
    await h.daemon.sessions.save(other.id, 'full');
    expect(existsSync(h.stateFile(other.id))).toBe(true);
    h.daemon.registry.revoke(other.id);
    await until(() => !existsSync(h.stateFile(other.id)));
    await until(() =>
      h
        .auditEvents()
        .some(
          (e) =>
            e.type === 'browser_state.deleted' &&
            e.payload.agentId === other.id &&
            e.payload.reason === 'revoked',
        ),
    );
    await h.daemon.sessions.save(other.id, 'full');
    expect(existsSync(h.stateFile(other.id))).toBe(false);
  });

  it('a dev CLI revoke from another process: the daemon never re-saves that agent', async () => {
    const other = h.daemon.registry.add('cli-revoked-agent');
    const m = await h.connect(other);
    await m.ok('browser_open', { url: `${h.rp.url}` });
    await h.daemon.sessions.save(other.id, 'full');
    const file = h.stateFile(other.id);
    expect(existsSync(file)).toBe(true);
    expect((await keyflap(h.dataDir, 'agent', 'revoke', other.id)).code).toBe(0);
    expect(existsSync(file)).toBe(false);
    expect(h.daemon.sessions.peek(other.id)).toBeDefined();
    h.daemon.sessions.peek(other.id)?.markDirty();
    await h.daemon.sessions.save(other.id, 'full');
    expect(existsSync(file)).toBe(false);
    await h.stop();
    expect(existsSync(file)).toBe(false);
    await h.start();
  });

  it('files of inactive or unknown agents are deleted at start', async () => {
    const ghost = '55555555-5555-4555-8555-555555555555';
    await h.daemon.sessions.save(h.agent.id, 'full');
    await h.stop();
    copyFileSync(h.stateFile(), h.stateFile(ghost));
    await h.start();
    expect(existsSync(h.stateFile(ghost))).toBe(false);
    expect(
      h
        .auditEvents()
        .some(
          (e) =>
            e.type === 'browser_state.deleted' &&
            e.payload.agentId === ghost &&
            e.payload.reason === 'agent_inactive',
        ),
    ).toBe(true);
  });

  it('--ephemeral-browser: nothing restored or saved, files kept for later', async () => {
    await h.intent('sign me in to the test RP');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    await h.daemon.sessions.save(h.agent.id, 'full');
    await h.restart({ browserState: { persist: false } });
    expect(h.daemon.persistence).toBeNull();
    expect(await signedIn()).toBe(false);
    await h.stop();
    expect(existsSync(h.stateFile())).toBe(true);
    await h.start();
    expect(await signedIn()).toBe(true);
  });
});
