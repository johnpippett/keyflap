import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { openDb } from '../src/db.ts';
import {
  ALL_AGENTS,
  normalizePattern,
  type PolicyRule,
  PolicyStore,
  parseDuration,
  patternMatches,
  resolvePolicy,
} from '../src/policy.ts';
import { tmpDir } from './harness.ts';

const target = (origin: string) => ({ origin, host: new URL(origin).hostname });

describe('policy patterns', () => {
  it('normalizes origins and domains', () => {
    expect(normalizePattern('https://App.Example.com')).toBe('https://app.example.com');
    expect(normalizePattern('https://app.example.com/')).toBe('https://app.example.com');
    expect(normalizePattern('https://example.com:8443')).toBe('https://example.com:8443');
    expect(normalizePattern('http://rp.localhost:3000')).toBe('http://rp.localhost:3000');
    expect(normalizePattern('Example.COM.')).toBe('example.com');
    expect(normalizePattern('  login.example.co.uk ')).toBe('login.example.co.uk');
    expect(normalizePattern('bücher.de')).toBe('xn--bcher-kva.de');
    expect(normalizePattern('rp.localhost')).toBe('rp.localhost');
  });

  it.each([
    ['', 'empty'],
    ['*', 'wildcard'],
    ['*.example.com', 'wildcard'],
    ['com', 'public suffix'],
    ['co.uk', 'public suffix'],
    ['github.io', 'private-section public suffix'],
    ['localhost', 'no registrable domain'],
    ['127.0.0.1', 'IP'],
    ['https://127.0.0.1', 'IP origin'],
    ['http://example.com', 'plain http'],
    ['https://example.com/login', 'path'],
    ['https://example.com/?a=1', 'query'],
    ['https://user@example.com', 'credentials'],
    ['example.com:443', 'port without scheme'],
    ['example.com/login', 'path without scheme'],
    ['exa mple.com', 'whitespace'],
    ['ftp://example.com', 'scheme'],
    ['-bad-.com', 'bad label'],
  ])('refuses %j (%s)', (p) => {
    expect(() => normalizePattern(p)).toThrow();
  });

  it('a domain covers itself and its subdomains on label boundaries; an origin only itself', () => {
    expect(patternMatches('example.com', target('https://example.com'))).toBe(true);
    expect(patternMatches('example.com', target('https://a.b.example.com'))).toBe(true);
    expect(patternMatches('example.com', target('https://notexample.com'))).toBe(false);
    expect(patternMatches('example.com', target('https://example.com.evil.net'))).toBe(false);
    expect(patternMatches('https://example.com', target('https://example.com'))).toBe(true);
    expect(patternMatches('https://example.com', target('https://www.example.com'))).toBe(false);
    expect(patternMatches('https://example.com', target('https://example.com:8443'))).toBe(false);
  });
});

describe('durations', () => {
  it('parses s/m/h/d and combinations', () => {
    expect(parseDuration('30m')).toBe(30 * 60_000);
    expect(parseDuration('2h')).toBe(2 * 3_600_000);
    expect(parseDuration('1h30m')).toBe(90 * 60_000);
    expect(parseDuration('45s')).toBe(45_000);
    expect(parseDuration('7d')).toBe(7 * 86_400_000);
  });
  it.each(['', '30', 'm', '-5m', '1.5h', '30 m', '1w', 'off'])('refuses %j', (d) => {
    expect(() => parseDuration(d)).toThrow();
  });
});

const rule = (
  pattern: string,
  mode: PolicyRule['mode'],
  o: { agentId?: string; allowForMs?: number; sessionTtlMs?: number } = {},
): PolicyRule => ({
  pattern,
  agentId: o.agentId ?? ALL_AGENTS,
  mode,
  allowForMs: o.allowForMs ?? null,
  sessionTtlMs: o.sessionTtlMs ?? null,
  updatedAt: 0,
});

describe('resolution: every matching rule applies, the strictest wins', () => {
  const t = target('https://app.example.com');

  it('defaults to ask with no TTL', () => {
    expect(resolvePolicy([], 'a1', t)).toEqual({
      mode: 'ask',
      allowForMs: null,
      sessionTtlMs: null,
      matched: [],
    });
  });

  it('deny always wins, whatever is narrower or agent-specific', () => {
    const rules = [
      rule('example.com', 'deny'),
      rule('https://app.example.com', 'allow-for', { agentId: 'a1', allowForMs: 60_000 }),
    ];
    expect(resolvePolicy(rules, 'a1', t).mode).toBe('deny');
  });

  it('a narrower ask carves an exception out of a broader allow-for, never the reverse', () => {
    const carve = [
      rule('example.com', 'allow-for', { allowForMs: 60_000 }),
      rule('app.example.com', 'ask'),
    ];
    expect(resolvePolicy(carve, 'a1', t).mode).toBe('ask');
    expect(resolvePolicy(carve, 'a1', target('https://www.example.com')).mode).toBe('allow-for');
    const noWeaken = [
      rule('example.com', 'ask-strong'),
      rule('https://app.example.com', 'allow-for', { agentId: 'a1', allowForMs: 60_000 }),
    ];
    expect(resolvePolicy(noWeaken, 'a1', t).mode).toBe('ask-strong');
  });

  it('agent rules apply only to that agent; * to everyone', () => {
    const rules = [rule('example.com', 'allow-for', { agentId: 'a1', allowForMs: 60_000 })];
    expect(resolvePolicy(rules, 'a1', t).mode).toBe('allow-for');
    expect(resolvePolicy(rules, 'a2', t).mode).toBe('ask');
    expect(resolvePolicy([rule('example.com', 'deny', { agentId: 'a2' })], 'a1', t).mode).toBe(
      'ask',
    );
  });

  it('the shortest allow-for window and the shortest TTL win; TTL-only rules leave the mode', () => {
    const rules = [
      rule('example.com', 'allow-for', { allowForMs: 3_600_000, sessionTtlMs: 7_200_000 }),
      rule('app.example.com', 'allow-for', { agentId: 'a1', allowForMs: 600_000 }),
      rule('https://app.example.com', 'none', { sessionTtlMs: 1_800_000 }),
    ];
    const p = resolvePolicy(rules, 'a1', t);
    expect(p).toMatchObject({ mode: 'allow-for', allowForMs: 600_000, sessionTtlMs: 1_800_000 });
    expect(p.matched).toHaveLength(3);
    expect(resolvePolicy(rules, 'a2', t).allowForMs).toBe(3_600_000);
  });

  it('a rule for another site never matches', () => {
    expect(resolvePolicy([rule('example.net', 'deny')], 'a1', t).mode).toBe('ask');
  });
});

describe('PolicyStore (SQLite, read on every resolve)', () => {
  it('upserts, keeps unspecified fields, removes empty rules, and fails closed on unknown modes', () => {
    const db = openDb(join(tmpDir(), 'db.sqlite'));
    const store = new PolicyStore(db, { now: () => 42 });
    expect(store.set('Example.com', ALL_AGENTS, { mode: 'deny' })).toMatchObject({
      pattern: 'example.com',
      mode: 'deny',
      sessionTtlMs: null,
    });
    store.set('example.com', ALL_AGENTS, { sessionTtlMs: 60_000 });
    expect(store.get('example.com', ALL_AGENTS)).toMatchObject({
      mode: 'deny',
      sessionTtlMs: 60_000,
    });
    store.set('example.com', ALL_AGENTS, { mode: 'allow-for', allowForMs: 120_000 });
    expect(store.get('example.com', ALL_AGENTS)).toMatchObject({
      mode: 'allow-for',
      allowForMs: 120_000,
      sessionTtlMs: 60_000,
    });
    store.set('example.com', ALL_AGENTS, { mode: 'ask' });
    expect(store.get('example.com', ALL_AGENTS)?.allowForMs).toBeNull();

    store.set('https://shop.example.net', 'a1', { sessionTtlMs: 60_000 });
    expect(store.get('https://shop.example.net', 'a1')?.mode).toBe('none');
    expect(store.set('https://shop.example.net', 'a1', { sessionTtlMs: null })).toBeNull();
    expect(store.get('https://shop.example.net', 'a1')).toBeNull();

    expect(() => store.set('example.com', 'a1', { mode: 'allow-for' })).toThrow(/duration/);
    expect(() =>
      store.set('example.com', 'a1', { mode: 'allow-for', allowForMs: 24 * 3_600_000 + 1 }),
    ).toThrow(/between 1s and 24h/);
    expect(() => store.set('example.com', 'a1', { mode: 'ask', allowForMs: 1000 })).toThrow();
    expect(() => store.set('example.com', 'a1', { sessionTtlMs: 31 * 86_400_000 })).toThrow();

    expect(store.remove('EXAMPLE.com', ALL_AGENTS)).toBe(true);
    expect(store.remove('example.com', ALL_AGENTS)).toBe(false);

    db.prepare(
      `INSERT INTO policies (origin_pattern, agent_id, mode, updated_at) VALUES ('example.org', '*', 'allow-forever', 0)`,
    ).run();
    expect(store.resolve('a1', target('https://www.example.org')).mode).toBe('deny');
    expect(store.list().map((r) => r.pattern)).not.toContain('example.org');
    db.close();
  });

  it('allow-for takes a window of exactly 24 hours and nothing longer', () => {
    const db = openDb(join(tmpDir(), 'db.sqlite'));
    const store = new PolicyStore(db);
    const cap = 24 * 3_600_000;
    expect(store.set('example.com', 'a1', { mode: 'allow-for', allowForMs: cap })).toMatchObject({
      mode: 'allow-for',
      allowForMs: cap,
    });
    expect(store.resolve('a1', target('https://example.com')).allowForMs).toBe(cap);
    expect(() =>
      store.set('example.com', 'a1', { mode: 'allow-for', allowForMs: cap + 1 }),
    ).toThrow(/between 1s and 24h/);
    expect(store.get('example.com', 'a1')?.allowForMs).toBe(cap);
    expect(parseDuration('24h')).toBe(cap);
    expect(parseDuration('1d')).toBe(cap);
    db.close();
  });

  it('a second connection (the CLI) sees and changes what the first (the daemon) resolves', () => {
    const path = join(tmpDir(), 'db.sqlite');
    const daemon = new PolicyStore(openDb(path));
    const cliDb = openDb(path);
    const cli = new PolicyStore(cliDb);
    const t = target('https://example.com');
    expect(daemon.resolve('a1', t).mode).toBe('ask');
    cli.set('example.com', ALL_AGENTS, { mode: 'deny' });
    expect(daemon.resolve('a1', t).mode).toBe('deny');
    cli.remove('example.com', ALL_AGENTS);
    expect(daemon.resolve('a1', t).mode).toBe('ask');
    cliDb.close();
  });

  it('adds allow_for_ms to a database created before M5', async () => {
    const { DatabaseSync } = await import('node:sqlite');
    const path = join(tmpDir(), 'old.sqlite');
    const old = new DatabaseSync(path);
    old.exec(`CREATE TABLE policies (origin_pattern TEXT NOT NULL, agent_id TEXT NOT NULL,
      mode TEXT NOT NULL, session_ttl INTEGER, updated_at INTEGER NOT NULL,
      PRIMARY KEY (origin_pattern, agent_id))`);
    old.close();
    const db = openDb(path);
    const store = new PolicyStore(db);
    store.set('example.com', 'a1', { mode: 'allow-for', allowForMs: 60_000 });
    expect(store.get('example.com', 'a1')?.allowForMs).toBe(60_000);
    db.close();
  });
});
