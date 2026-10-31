import { createHash } from 'node:crypto';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agents.ts';
import { openDb } from '../src/db.ts';
import { tmpDir } from './harness.ts';

describe('agent registry', () => {
  let dir: string;
  let db: DatabaseSync;
  let registry: AgentRegistry;

  beforeEach(() => {
    dir = tmpDir();
    db = openDb(join(dir, 'broker.sqlite'));
    registry = new AgentRegistry(db);
  });
  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('add returns a fresh token once; only its SHA-256 is stored', () => {
    const a = registry.add('claude-code');
    expect(a.name).toBe('claude-code');
    expect(a.token).toMatch(/^aab_agent_[A-Za-z0-9_-]{43}$/);
    const b = registry.add('other');
    expect(b.token).not.toBe(a.token);
    expect(b.id).not.toBe(a.id);

    const row = db.prepare('SELECT * FROM agents WHERE id = ?').get(a.id) as Record<
      string,
      unknown
    >;
    expect(row.token_hash).toBe(createHash('sha256').update(a.token).digest('hex'));
    expect(JSON.stringify(db.prepare('SELECT * FROM agents').all())).not.toContain(a.token);
  });

  it('byToken resolves the token to {id, name} and nothing else resolves', () => {
    const a = registry.add('claude-code');
    expect(registry.byToken(a.token)).toEqual({ id: a.id, name: 'claude-code' });
    const flipped = a.token.slice(0, -1) + (a.token.endsWith('A') ? 'B' : 'A');
    for (const t of [
      flipped,
      '',
      'aab_agent_',
      a.token.slice(10),
      `${a.token} `,
      a.token.toUpperCase(),
      createHash('sha256').update(a.token).digest('hex'),
      undefined,
      null,
      42,
    ]) {
      expect(registry.byToken(t)).toBeNull();
    }
  });

  it('revoke: the token and id stop resolving at once; listeners are told', () => {
    const a = registry.add('claude-code');
    const b = registry.add('other');
    const revoked: string[] = [];
    registry.onRevoke((id) => revoked.push(id));
    expect(registry.revoke(a.id)).toBe(true);
    expect(registry.byToken(a.token)).toBeNull();
    expect(registry.byId(a.id)).toBeNull();
    expect(registry.byToken(b.token)).toEqual({ id: b.id, name: 'other' });
    expect(revoked).toEqual([a.id]);
    expect(registry.revoke(a.id)).toBe(false);
    expect(registry.revoke('nope')).toBe(false);
    expect(revoked).toEqual([a.id]);
  });

  it('list shows agents with created/revoked times, never tokens', () => {
    const a = registry.add('one');
    const b = registry.add('two');
    registry.revoke(a.id);
    const list = registry.list();
    expect(list.map((x) => [x.id, x.name, x.revokedAt === null])).toEqual([
      [a.id, 'one', false],
      [b.id, 'two', true],
    ]);
    expect(JSON.stringify(list)).not.toContain('aab_agent_');
  });

  it('names: printable, bounded, unique among active agents (they appear in prompts)', () => {
    for (const bad of [
      '',
      ' padded',
      'x'.repeat(65),
      'line\nbreak',
      'esc\u001b[31m',
      'bidi\u202eevil',
    ]) {
      expect(() => registry.add(bad)).toThrow(/agent name/);
    }
    const a = registry.add('dup');
    expect(() => registry.add('dup')).toThrow(/already exists/);
    registry.revoke(a.id);
    expect(registry.add('dup').name).toBe('dup');
  });

  it('migrates an M1 database: adds token_hash/revoked_at, keeps rows', () => {
    const path = join(dir, 'old.sqlite');
    const old = new DatabaseSync(path);
    old.exec(`CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT,
      created_at INTEGER NOT NULL);
      INSERT INTO agents (id, name, created_at) VALUES ('dev', 'dev-agent', 1);`);
    old.close();

    const migrated = openDb(path);
    const cols = (migrated.prepare('PRAGMA table_info(agents)').all() as { name: string }[]).map(
      (c) => c.name,
    );
    expect(cols).toEqual(expect.arrayContaining(['token_hash', 'revoked_at']));
    const reg = new AgentRegistry(migrated);
    expect(reg.byId('dev')).toBeNull();
    expect(reg.list()).toEqual([]);
    const a = reg.add('dev-agent');
    expect(reg.byToken(a.token)?.id).toBe(a.id);
    migrated.close();
    const again = openDb(path);
    expect(new AgentRegistry(again).byToken(a.token)?.name).toBe('dev-agent');
    again.close();
  });
});
