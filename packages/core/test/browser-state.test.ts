import { randomBytes } from 'node:crypto';
import { readFileSync, renameSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agents.ts';
import {
  BrowserStateStore,
  decryptState,
  encryptState,
  filterState,
  type SavedCookie,
  type SavedState,
  SessionPersistence,
  type StatePlain,
  trimPlain,
} from '../src/browser-state.ts';
import { openDb, PersistOptins, SessionStateRepo } from '../src/db.ts';
import { PolicyStore } from '../src/policy.ts';
import { secretForms } from '../src/scrub.ts';
import { tmpDir } from './harness.ts';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';

const cookie = (name: string, value: string, domain: string): SavedCookie => ({
  name,
  value,
  domain,
  path: '/',
  expires: -1,
  httpOnly: false,
  secure: false,
  sameSite: 'Lax',
});
const plainOf = (state: SavedState, visited: string[] = []): StatePlain => ({
  v: 1,
  savedAt: 1,
  state,
  visited,
});
const none = () => null;

describe('encryption at rest', () => {
  const key = randomBytes(32);
  it('round-trips, and binds the file to the agent (AAD)', () => {
    const pt = Buffer.from('{"hello":"world"}');
    const f = encryptState(key, A, pt);
    expect(Object.keys(f).sort()).toEqual(['ct', 'iv', 'tag', 'v']);
    expect(decryptState(key, A, f)?.toString()).toBe('{"hello":"world"}');
    expect(decryptState(key, B, f)).toBeNull();
    expect(decryptState(randomBytes(32), A, f)).toBeNull();
    expect(encryptState(key, A, pt).iv).not.toBe(f.iv);
  });

  it('a tampered file, extra fields or another version decrypt to nothing', () => {
    const f = encryptState(key, A, Buffer.from('x'.repeat(64)));
    const ct = Buffer.from(f.ct, 'base64');
    ct[0] = (ct[0] as number) ^ 1;
    expect(decryptState(key, A, { ...f, ct: ct.toString('base64') })).toBeNull();
    expect(decryptState(key, A, { ...f, extra: 1 })).toBeNull();
    expect(decryptState(key, A, { ...f, v: 2 })).toBeNull();
    expect(decryptState(key, A, null)).toBeNull();
  });
});

describe('BrowserStateStore', () => {
  let dir: string;
  let store: BrowserStateStore;
  const key = randomBytes(32);
  beforeEach(() => {
    dir = join(tmpDir(), 'browser-state');
    store = new BrowserStateStore({ dir, key });
  });
  const state: SavedState = {
    cookies: [cookie('sid', 'abc', 'rp.localhost')],
    origins: [{ origin: 'http://rp.localhost:3000', localStorage: [{ name: 'k', value: 'v' }] }],
  };

  it('writes 0600 files in a 0700 dir; no names or values in plaintext; loads them back', () => {
    store.write(A, plainOf(state));
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    const path = store.pathFor(A);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const raw = readFileSync(path, 'utf8');
    expect(Object.keys(JSON.parse(raw)).sort()).toEqual(['ct', 'iv', 'tag', 'v']);
    for (const s of ['sid', 'abc', 'rp.localhost', 'localStorage']) expect(raw).not.toContain(s);
    expect(store.load(A)).toEqual({ kind: 'ok', plain: plainOf(state) });
    expect(store.agentIds()).toEqual([A]);
  });

  it("an agent's file renamed to another agent's is discarded", () => {
    store.write(A, plainOf(state));
    renameSync(store.pathFor(A), store.pathFor(B));
    expect(store.load(B)).toEqual({ kind: 'discarded', reason: 'undecryptable' });
    expect(store.load(A)).toEqual({ kind: 'none' });
  });

  it('tampered, malformed, symlinked or wrongly shaped files are discarded', () => {
    store.write(A, plainOf(state));
    const path = store.pathFor(A);
    const f = JSON.parse(readFileSync(path, 'utf8'));
    f.tag = Buffer.alloc(16).toString('base64');
    writeFileSync(path, JSON.stringify(f));
    expect(store.load(A)).toMatchObject({ kind: 'discarded', reason: 'undecryptable' });
    writeFileSync(path, 'not json');
    expect(store.load(A)).toMatchObject({ kind: 'discarded', reason: 'malformed' });
    writeFileSync(
      path,
      JSON.stringify(encryptState(key, A, Buffer.from(JSON.stringify({ v: 1, state: 'nope' })))),
    );
    expect(store.load(A)).toMatchObject({ kind: 'discarded', reason: 'malformed' });
    const target = join(dir, '..', 'elsewhere');
    writeFileSync(target, '{}');
    store.delete(A);
    symlinkSync(target, path);
    expect(store.load(A)).toMatchObject({ kind: 'discarded', reason: 'not_regular_file' });
  });

  it('agent ids must be UUIDs before they touch a path', () => {
    for (const bad of ['../x', 'a/b', '', 'test-agent', `${A}/..`, `${A}.state`]) {
      expect(() => store.pathFor(bad)).toThrow(/bad agent id/);
    }
  });

  it('refuses plaintext over the cap', () => {
    const small = new BrowserStateStore({ dir, key, maxBytes: 100 });
    expect(() => small.write(A, plainOf(state))).toThrow(/too_large/);
  });
});

describe('save / restore filters', () => {
  const SECRET = 'p@ss wörd/+&?#"x';

  it('drops cookies, localStorage and nested IndexedDB holding any spelling of a secret', () => {
    for (const form of secretForms(SECRET)) {
      const state: SavedState = {
        cookies: [
          cookie('ok', 'fine', 'a.example'),
          cookie('leak', `pre${form}post`, 'a.example'),
          cookie(`n${form}`, 'v', 'a.example'),
        ],
        origins: [
          { origin: 'https://a.example', localStorage: [{ name: 'x', value: `[${form}]` }] },
          {
            origin: 'https://b.example',
            localStorage: [{ name: 'ok', value: 'ok' }],
            indexedDB: [
              { name: 'db', stores: [{ records: [{ value: { deep: [{ t: form }] } }] }] },
            ],
          },
          { origin: 'https://c.example', localStorage: [{ name: 'keep', value: 'me' }] },
        ],
      };
      const { state: out, report } = filterState(state, [], { secrets: [SECRET], verdict: none });
      expect(
        out.cookies.map((c) => c.name),
        form,
      ).toEqual(['ok']);
      expect(
        out.origins.map((o) => o.origin),
        form,
      ).toEqual(['https://c.example']);
      expect(report.dropped.secret).toEqual({ cookies: 2, origins: 2 });
      expect(JSON.stringify(out)).not.toContain(form);
    }
  });

  it('with no secrets nothing is dropped for them', () => {
    const state: SavedState = { cookies: [cookie('a', SECRET, 'x.example')], origins: [] };
    expect(filterState(state, [], { secrets: [], verdict: none }).state).toEqual(state);
  });

  it('a site-level verdict drops all of its cookies and origins, subdomains included', () => {
    const state: SavedState = {
      cookies: [
        cookie('a', '1', '.deny.example'),
        cookie('b', '1', 'app.deny.example'),
        cookie('c', '1', 'keep.example'),
      ],
      origins: [
        { origin: 'https://app.deny.example', localStorage: [{ name: 'k', value: 'v' }] },
        { origin: 'https://keep.example', localStorage: [{ name: 'k', value: 'v' }] },
      ],
    };
    const seen: Record<string, string[]> = {};
    const { state: out, report } = filterState(state, ['https://login.deny.example'], {
      secrets: [],
      verdict: (site, known) => {
        seen[site] = [...known].sort();
        return site === 'deny.example' ? { reason: 'deny' } : null;
      },
    });
    expect(out.cookies.map((c) => c.name)).toEqual(['c']);
    expect(out.origins.map((o) => o.origin)).toEqual(['https://keep.example']);
    expect(report.dropped.deny).toEqual([{ site: 'deny.example', cookies: 2, origins: 1 }]);
    expect(report.sites).toEqual(['keep.example']);
    expect(seen['deny.example']).toEqual(
      ['https://deny.example', 'https://app.deny.example', 'https://login.deny.example'].sort(),
    );
  });

  it('a verdict that throws drops the site (fail closed)', () => {
    const state: SavedState = { cookies: [cookie('a', '1', 'x.example')], origins: [] };
    const r = filterState(state, [], {
      secrets: [],
      verdict: () => {
        throw new Error('db gone');
      },
    });
    expect(r.state.cookies).toEqual([]);
  });
});

describe('SessionPersistence verdicts (policy, high-risk + opt-in, TTL, clears)', () => {
  let db: ReturnType<typeof openDb>;
  let p: SessionPersistence;
  let repo: SessionStateRepo;
  let policy: PolicyStore;
  let optins: PersistOptins;
  let agentId: string;
  let now = 1_000_000;
  const audits: { e: string; f: Record<string, unknown> }[] = [];
  const key = randomBytes(32);

  beforeEach(() => {
    db = openDb(':memory:');
    repo = new SessionStateRepo(db);
    policy = new PolicyStore(db);
    optins = new PersistOptins(db, { audit: (e, f) => audits.push({ e, f }) });
    const reg = new AgentRegistry(db);
    agentId = reg.add('persist-bot').id;
    p = new SessionPersistence({
      store: new BrowserStateStore({ dir: join(tmpDir(), 'bs'), key }),
      repo,
      optins,
      policy,
      highRiskDomains: ['bank.localhost'],
      isActive: (id) => reg.byId(id) !== null,
      audit: (e, f) => audits.push({ e, f }),
      now: () => now,
    });
    audits.length = 0;
  });
  afterEach(() => db.close());

  const v = (site: string, known: string[] = []) => p.verdictFor(agentId)(site, known);

  it('deny from any known origin, by domain or exact origin', () => {
    expect(v('example.com')).toBeNull();
    policy.set('https://login.example.com', agentId, { mode: 'deny' });
    expect(v('example.com')).toBeNull();
    expect(v('example.com', ['https://login.example.com'])).toEqual({ reason: 'deny' });
    policy.set('example.org', '*', { mode: 'deny' });
    expect(v('example.org')).toEqual({ reason: 'deny' });
  });

  it('high-risk sites are kept only with the owner opt-in for this agent (or all agents)', () => {
    expect(v('paypal.com')).toEqual({ reason: 'highRisk' });
    expect(v('bank.localhost')).toEqual({ reason: 'highRisk' });
    optins.add(agentId, 'paypal.com', 'cli');
    expect(v('paypal.com')).toBeNull();
    expect(p.verdictFor('33333333-3333-4333-8333-333333333333')('paypal.com', [])).toEqual({
      reason: 'highRisk',
    });
    optins.add('*', 'bank.localhost', 'admin');
    expect(v('bank.localhost')).toBeNull();
    optins.remove(agentId, 'paypal.com', 'cli');
    expect(v('paypal.com')).toEqual({ reason: 'highRisk' });
    expect(audits.map((a) => a.e)).toEqual([
      'session.keep_set',
      'session.keep_set',
      'session.keep_removed',
    ]);
    optins.add(agentId, 'paypal.com', 'cli');
    policy.set('paypal.com', agentId, { mode: 'deny' });
    expect(v('paypal.com')).toEqual({ reason: 'deny' });
  });

  it("the owner's ask-strong rule makes a site high-risk for saving (review L8)", () => {
    expect(v('strong.example')).toBeNull();
    policy.set('strong.example', agentId, { mode: 'ask-strong' });
    expect(v('strong.example')).toEqual({ reason: 'highRisk' });
    policy.remove('strong.example', agentId);
    policy.set('https://login.strong.example', '*', { mode: 'ask-strong' });
    expect(v('strong.example')).toBeNull();
    expect(v('strong.example', ['https://login.strong.example'])).toEqual({ reason: 'highRisk' });
    optins.add(agentId, 'strong.example', 'cli');
    expect(v('strong.example', ['https://login.strong.example'])).toBeNull();
  });

  it('a non-canonical origin meets the rules for its canonical site (review L2)', () => {
    policy.set('example.org', '*', { mode: 'deny' });
    expect(v('example.org', ['https://EXAMPLE.org.'])).toEqual({ reason: 'deny' });
    expect(v('paypal.com', ['https://www.paypal.com.'])).toEqual({ reason: 'highRisk' });
  });

  it('TTL: no clock or an expired one drops the site; a live one keeps it', () => {
    policy.set('ttl.example', agentId, { sessionTtlMs: 5_000 });
    expect(v('ttl.example')).toEqual({
      reason: 'ttl',
      ttlMs: 5_000,
      origin: 'https://ttl.example',
    });
    repo.upsertClock({
      agentId,
      origin: 'https://app.ttl.example',
      host: 'app.ttl.example',
      startedAt: now - 1_000,
    });
    expect(v('ttl.example')).toBeNull();
    now += 4_500;
    expect(v('ttl.example')).toEqual({
      reason: 'ttl',
      ttlMs: 5_000,
      origin: 'https://app.ttl.example',
    });
    expect(v('other.example')).toBeNull();
  });

  it('queued clears name sites', () => {
    expect(p.verdictFor(agentId, new Set(['gone.example']))('gone.example', [])).toEqual({
      reason: 'cleared',
    });
  });

  it('restore: drops TTL-expired and cleared sites before the context, audits, writes back', () => {
    const state: SavedState = {
      cookies: [
        cookie('a', '1', 'ttl.example'),
        cookie('b', '1', 'keep.example'),
        cookie('c', '1', 'gone.example'),
      ],
      origins: [],
    };
    p.store.write(agentId, plainOf(state));
    policy.set('ttl.example', agentId, { sessionTtlMs: 5_000 });
    const req = repo.queueClear({ agentId, site: 'gone.example', via: 'cli', now });
    const r = p.restore(agentId);
    expect(r.state?.cookies.map((c) => c.name)).toEqual(['b']);
    r.finish(true);
    expect(audits.find((a) => a.e === 'session.cleared' && a.f.via === 'restore')?.f).toEqual({
      agentId,
      origin: 'https://ttl.example',
      ttlMs: 5_000,
      cookies: 1,
      pages: 0,
      via: 'restore',
    });
    expect(audits.find((a) => a.e === 'session.cleared' && a.f.via === 'admin')?.f).toMatchObject({
      agentId,
      site: 'gone.example',
      cookies: 1,
    });
    const restored = audits.find((a) => a.e === 'browser_state.restored')?.f;
    expect(restored).toMatchObject({ agentId, sites: ['keep.example'], cookies: 1, origins: 0 });
    expect(JSON.stringify(restored)).not.toMatch(/"(a|b|c)"|"1"/);
    expect(repo.clearRequests()).toEqual([]);
    expect(req).toBeGreaterThan(0);
    const back = p.store.load(agentId);
    expect(back.kind === 'ok' && back.plain.state.cookies.map((c) => c.name)).toEqual(['b']);
  });

  it('restore: a whole-agent clear restores nothing and deletes the file', () => {
    p.store.write(agentId, plainOf({ cookies: [cookie('a', '1', 'x.example')], origins: [] }));
    repo.queueClear({ agentId, site: null, via: 'cli', now });
    expect(p.restore(agentId).state).toBeNull();
    expect(p.store.load(agentId)).toEqual({ kind: 'none' });
  });

  it('save: never writes for an inactive agent; files of inactive agents go at start', () => {
    const ghost = '44444444-4444-4444-8444-444444444444';
    const r = p.save(
      ghost,
      { state: { cookies: [cookie('a', '1', 'x.example')], origins: [] }, visited: [] },
      [],
    );
    expect(r.written).toBe(false);
    expect(p.store.load(ghost)).toEqual({ kind: 'none' });
    p.store.write(ghost, plainOf({ cookies: [cookie('a', '1', 'x.example')], origins: [] }));
    p.cleanupInactive();
    expect(p.store.load(ghost)).toEqual({ kind: 'none' });
    expect(audits.at(-1)).toEqual({
      e: 'browser_state.deleted',
      f: { agentId: ghost, reason: 'agent_inactive' },
    });
  });

  it('save: filters secrets and high-risk sites, indexes counts', () => {
    const r = p.save(
      agentId,
      {
        state: {
          cookies: [
            cookie('sid', 'abc', 'site.example'),
            cookie('leak', 'hunter2-secret', 'site.example'),
            cookie('pp', '1', '.paypal.com'),
          ],
          origins: [],
        },
        visited: ['https://site.example'],
      },
      ['hunter2-secret'],
    );
    expect(r.written).toBe(true);
    const back = p.store.load(agentId);
    expect(back.kind === 'ok' && back.plain.state.cookies.map((c) => c.name)).toEqual(['sid']);
    expect(repo.index(agentId)).toMatchObject([{ site: 'site.example', cookies: 1, origins: 0 }]);
    expect(audits.find((a) => a.e === 'browser_state.filtered')?.f).toEqual({
      agentId,
      secret: { cookies: 1, origins: 0 },
    });
  });
});

describe('size cap', () => {
  it('trims IndexedDB of the largest origins first, then localStorage; never cookies', () => {
    const big = (n: number) => 'x'.repeat(n);
    const plain = plainOf({
      cookies: [cookie('sid', big(200), 'a.example')],
      origins: [
        {
          origin: 'https://a.example',
          localStorage: [{ name: 'l', value: big(300) }],
          indexedDB: [{ v: big(1000) }],
        },
        {
          origin: 'https://b.example',
          localStorage: [{ name: 'l', value: big(100) }],
          indexedDB: [{ v: big(400) }],
        },
      ],
    });
    const full = Buffer.byteLength(JSON.stringify(plain));
    let t = trimPlain(plain, full - 900);
    expect(t.trimmed).toBe(1);
    expect(t.plain.state.origins.map((o) => [o.origin, !!o.indexedDB])).toEqual([
      ['https://a.example', false],
      ['https://b.example', true],
    ]);
    t = trimPlain(plain, full - 1_500);
    expect(t.plain.state.origins.map((o) => o.origin)).toEqual(['https://b.example']);
    expect(t.plain.state.origins[0]?.indexedDB).toBeUndefined();
    expect(t.plain.state.cookies).toEqual(plain.state.cookies);
    expect(() => trimPlain(plain, 100)).toThrow(/too_large/);
    expect(trimPlain(plain, full)).toEqual({ plain, trimmed: 0 });
  });
});
