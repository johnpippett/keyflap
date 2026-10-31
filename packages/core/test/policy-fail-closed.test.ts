import { describe, expect, it } from 'vitest';
import { openDb } from '../src/db.ts';
import { ALL_AGENTS, type PolicyRule, PolicyStore, resolvePolicy } from '../src/policy.ts';

const target = { origin: 'https://app.example.com', host: 'app.example.com' };
const asked = { mode: 'ask', allowForMs: null };

const allowFor = (pattern: string, allowForMs: number | null): PolicyRule => ({
  pattern,
  agentId: ALL_AGENTS,
  mode: 'allow-for',
  allowForMs,
  sessionTtlMs: null,
  updatedAt: 0,
});

describe('policy fails closed on a malformed allow-for window', () => {
  it.each([
    ['null', null],
    ['zero', 0],
    ['negative', -1],
  ])('an allow-for rule whose window is %s never grants: it reads as ask', (_name, window) => {
    expect(resolvePolicy([allowFor('example.com', window)], 'a1', target)).toMatchObject(asked);
  });

  it('a malformed rule makes a valid allow-for rule ask, in either order', () => {
    const valid = allowFor('app.example.com', 60_000);
    const broken = allowFor('example.com', 0);
    expect(resolvePolicy([valid], 'a1', target)).toMatchObject({
      mode: 'allow-for',
      allowForMs: 60_000,
    });
    expect(resolvePolicy([valid, broken], 'a1', target)).toMatchObject(asked);
    expect(resolvePolicy([broken, valid], 'a1', target)).toMatchObject(asked);
  });

  it('a stored row with no window, a zero window or a negative window resolves to ask', () => {
    const db = openDb(':memory:');
    const store = new PolicyStore(db);
    const insert = db.prepare(
      'INSERT INTO policies (origin_pattern, agent_id, mode, allow_for_ms, session_ttl, updated_at) VALUES (?, ?, ?, ?, NULL, 0)',
    );
    const valid = store.set('good.example.com', ALL_AGENTS, {
      mode: 'allow-for',
      allowForMs: 5000,
    });
    expect(valid?.allowForMs).toBe(5000);
    expect(
      store.resolve('a1', { origin: 'https://good.example.com', host: 'good.example.com' }),
    ).toMatchObject({ mode: 'allow-for', allowForMs: 5000 });
    insert.run('null.example.com', ALL_AGENTS, 'allow-for', null);
    insert.run('zero.example.com', ALL_AGENTS, 'allow-for', 0);
    insert.run('negative.example.com', ALL_AGENTS, 'allow-for', -1);
    for (const host of ['null', 'zero', 'negative'].map((n) => `${n}.example.com`)) {
      expect(store.resolve('a1', { origin: `https://${host}`, host })).toMatchObject(asked);
    }
    db.close();
  });
});
