import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import {
  AgentRegistry,
  AuditLog,
  openDb,
  PersistOptins,
  PolicyStore,
  SessionStateRepo,
} from '@aab/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { normalizeSite } from '../src/sessions.ts';
import { runCli, tmpDir } from './helpers.ts';

describe('keyflap sessions', () => {
  let dir: string;
  let db: DatabaseSync;
  let repo: SessionStateRepo;
  let agentId: string;
  let otherId: string;
  const cli = (...args: string[]) => runCli([...args, '--data-dir', dir]);
  const lastAudit = () => {
    const r = new AuditLog(db).all().at(-1);
    return { type: r?.event_type, payload: JSON.parse(r?.payload_json ?? '{}') };
  };

  beforeAll(() => {
    dir = tmpDir();
    db = openDb(join(dir, 'broker.sqlite'));
    repo = new SessionStateRepo(db);
    const reg = new AgentRegistry(db);
    agentId = reg.add('sessions-bot').id;
    otherId = reg.add('other-bot').id;
  });
  afterAll(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('normalizes sites to their registrable domain and refuses public suffixes', () => {
    expect(normalizeSite('https://app.Example.com')).toBe('example.com');
    expect(normalizeSite('login.example.co.uk')).toBe('example.co.uk');
    expect(normalizeSite('rp.localhost')).toBe('rp.localhost');
    expect(() => normalizeSite('co.uk')).toThrow();
    expect(() => normalizeSite('10.0.0.1')).toThrow();
  });

  it('list reads the index: counts, save time and the TTL deadline, never values', async () => {
    const t0 = Date.UTC(2026, 9, 13, 12, 0, 0);
    repo.setIndex(agentId, [{ site: 'example.com', cookies: 3, origins: 1, savedAt: t0 }]);
    repo.upsertClock({
      agentId,
      origin: 'https://app.example.com',
      host: 'app.example.com',
      startedAt: t0,
    });
    new PolicyStore(db).set('example.com', agentId, { sessionTtlMs: 2 * 3_600_000 });
    const r = await cli('sessions', 'list');
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/sessions-bot \(\w{8}\)\s+example\.com\s+3\s+1\s+2026-10-13T12:00:00/);
    expect(r.stdout).toContain(new Date(t0 + 2 * 3_600_000).toISOString());
    const j = JSON.parse((await cli('sessions', 'list', '--json', '--agent', agentId)).stdout);
    expect(j.sessions).toEqual([
      {
        agentId,
        agentName: 'sessions-bot',
        site: 'example.com',
        cookies: 3,
        origins: 1,
        savedAt: t0,
        ttlDeadline: t0 + 2 * 3_600_000,
      },
    ]);
    expect(
      JSON.parse((await cli('sessions', 'list', '--json', '--agent', otherId)).stdout).sessions,
    ).toEqual([]);
  });

  it('clear queues a request (one row per agent for --all) and audits it', async () => {
    let r = await cli('sessions', 'clear', '--agent', agentId, '--site', 'https://www.example.com');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('Queued: example.com');
    expect(repo.clearRequests(agentId)).toMatchObject([
      { agentId, site: 'example.com', via: 'cli' },
    ]);
    expect(lastAudit()).toEqual({
      type: 'session.clear_requested',
      payload: { agentId, site: 'example.com', via: 'cli' },
    });
    r = await cli('sessions', 'clear', '--all');
    expect(r.code).toBe(0);
    expect(
      repo
        .clearRequests()
        .filter((q) => q.site === null)
        .map((q) => q.agentId)
        .sort(),
    ).toEqual([agentId, otherId].sort());
    expect(lastAudit().payload).toEqual({ agentId: '*', via: 'cli' });
    expect((await cli('sessions', 'clear', '--agent', 'nope')).code).toBe(1);
    expect((await cli('sessions', 'clear', '--agent', agentId, '--site', 'co.uk')).code).toBe(1);
    for (const q of repo.clearRequests()) repo.deleteClearRequest(q.id);
  });

  it('keep / unkeep write the owner opt-in and audit it; list shows kept sites', async () => {
    const optins = new PersistOptins(db);
    let r = await cli('sessions', 'keep', 'https://www.paypal.com', '--agent', agentId);
    expect(r.code).toBe(0);
    expect(optins.has(agentId, 'paypal.com')).toBe(true);
    expect(optins.has(otherId, 'paypal.com')).toBe(false);
    expect(lastAudit()).toEqual({
      type: 'session.keep_set',
      payload: { agentId, site: 'paypal.com', via: 'cli' },
    });
    r = await cli('sessions', 'keep', 'mail.google.com');
    expect(optins.has(otherId, 'google.com')).toBe(true);
    expect(lastAudit().payload).toEqual({ agentId: '*', site: 'google.com', via: 'cli' });
    expect((await cli('sessions', 'list')).stdout).toContain('paypal.com');
    r = await cli('sessions', 'unkeep', 'paypal.com', '--agent', agentId);
    expect(r.code).toBe(0);
    expect(optins.has(agentId, 'paypal.com')).toBe(false);
    expect(lastAudit()).toEqual({
      type: 'session.keep_removed',
      payload: { agentId, site: 'paypal.com', via: 'cli' },
    });
    expect((await cli('sessions', 'unkeep', 'paypal.com', '--agent', agentId)).stdout).toContain(
      'was not kept',
    );
    expect((await cli('sessions', 'keep', 'example.com', '--agent', 'nope')).code).toBe(1);
  });

  it('dev revoke deletes the agent file, clocks, index rows and opt-ins', async () => {
    const stateDir = join(dir, 'browser-state');
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    const file = join(stateDir, `${agentId}.state`);
    writeFileSync(file, '{"v":1,"iv":"","tag":"","ct":""}', { mode: 0o600 });
    const otherFile = join(stateDir, `${otherId}.state`);
    writeFileSync(otherFile, '{}', { mode: 0o600 });
    new PersistOptins(db).add(agentId, 'chase.com', 'cli');
    expect(repo.clocks(agentId)).not.toHaveLength(0);
    const r = await cli('agent', 'revoke', agentId);
    expect(r.code).toBe(0);
    expect(existsSync(file)).toBe(false);
    expect(existsSync(otherFile)).toBe(true);
    expect(repo.clocks(agentId)).toEqual([]);
    expect(repo.index(agentId)).toEqual([]);
    expect(new PersistOptins(db).list().some((o) => o.agentId === agentId)).toBe(false);
    expect(lastAudit()).toEqual({
      type: 'browser_state.deleted',
      payload: { agentId, reason: 'revoked' },
    });
  });

  it('status shows the saved-sessions line', async () => {
    repo.setIndex(otherId, [
      { site: 'a.example', cookies: 1, origins: 0, savedAt: 1 },
      { site: 'b.example', cookies: 1, origins: 0, savedAt: 1 },
    ]);
    const r = await cli('status');
    expect(r.stdout).toContain('Saved sessions: 1 agents, 2 sites');
    expect(JSON.parse((await cli('status', '--json')).stdout).savedSessions).toEqual({
      agents: 1,
      sites: 2,
    });
  });
});
