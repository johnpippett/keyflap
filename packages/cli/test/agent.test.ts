import { rmSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { AgentRegistry, AuditLog, loadOrCreateHostToken, openDb } from '@aab/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { claudeCodePaths, homeRelative, shellQuote } from '../src/agent.ts';
import { runCli, tmpDir } from './helpers.ts';

const TOKEN_RE = /aab_agent_[A-Za-z0-9_-]{43}/g;

describe('keyflap agent', () => {
  let dir: string;
  let db: DatabaseSync;
  let registry: AgentRegistry;
  let hostToken: string;

  beforeAll(() => {
    dir = tmpDir();
    db = openDb(join(dir, 'broker.sqlite'));
    registry = new AgentRegistry(db);
    hostToken = loadOrCreateHostToken(join(dir, 'host-token'));
  });

  afterAll(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('add prints the token once and a Claude Code snippet; the token resolves', async () => {
    const r = await runCli(['agent', 'add', 'claude-code', '--data-dir', dir]);
    expect(r.code).toBe(0);
    const tokens = [...new Set(r.stdout.match(TOKEN_RE))];
    expect(tokens).toHaveLength(1);
    const token = tokens[0] as string;
    const agent = registry.byToken(token);
    expect(agent?.name).toBe('claude-code');
    expect(r.stdout).toContain(`--agent ${agent?.id}`);
    expect(r.stdout).toContain('"url": "http://127.0.0.1:8765/mcp"');
    // biome-ignore lint/suspicious/noTemplateCurlyInString: literal Claude Code env reference
    expect(r.stdout).toContain('"Authorization": "Bearer ${KEYFLAP_AGENT_TOKEN}"');
    expect(r.stdout).toContain('"UserPromptSubmit"');
    expect(r.stdout).toContain('"denyRead"');
    expect(r.stdout).toContain(`Read(/${dir}/**)`);
    expect(r.stdout).not.toContain(hostToken);
  });

  it('duplicate active names and bad names fail with exit 1', async () => {
    const r = await runCli(['agent', 'add', 'claude-code', '--data-dir', dir]);
    expect(r.code).toBe(1);
    expect(r.stdout).toBe('');
    expect(r.stderr).toMatch(/already exists/);
    const bad = await runCli(['agent', 'add', 'evil\u202ename', '--data-dir', dir]);
    expect(bad.code).toBe(1);
  });

  it('list shows id, name, created, revoked — never tokens', async () => {
    const added = await runCli(['agent', 'add', 'other', '--data-dir', dir]);
    const token = (added.stdout.match(TOKEN_RE) as string[])[0] as string;
    const r = await runCli(['agent', 'list', '--data-dir', dir]);
    expect(r.code).toBe(0);
    expect(r.stdout).not.toMatch(TOKEN_RE);
    expect(r.stdout).not.toContain(token.slice('aab_agent_'.length));
    expect(r.stdout).toMatch(/^ID\s+NAME\s+CREATED\s+REVOKED$/m);
    expect(r.stdout).toMatch(/claude-code/);
    expect(r.stdout).toMatch(/other/);

    const j = await runCli(['agent', 'list', '--data-dir', dir, '--json']);
    const rows = JSON.parse(j.stdout) as Record<string, unknown>[];
    expect(rows.map((x) => x.name)).toEqual(['claude-code', 'other']);
    for (const row of rows) {
      expect(Object.keys(row).sort()).toEqual(['createdAt', 'id', 'name', 'revokedAt']);
    }
    expect(j.stdout).not.toMatch(TOKEN_RE);
  });

  it('revoke takes effect on the other connection at once; unknown ids exit 1', async () => {
    const added = await runCli(['agent', 'add', 'to-revoke', '--data-dir', dir]);
    const token = (added.stdout.match(TOKEN_RE) as string[])[0] as string;
    const agent = registry.byToken(token);
    expect(agent).not.toBeNull();

    const r = await runCli(['agent', 'revoke', agent?.id as string, '--data-dir', dir]);
    expect(r.code).toBe(0);
    expect(registry.byToken(token)).toBeNull();
    expect(registry.byId(agent?.id)).toBeNull();

    const again = await runCli(['agent', 'revoke', agent?.id as string, '--data-dir', dir]);
    expect(again.code).toBe(1);
    expect(again.stderr).toMatch(/no active agent/);

    const list = await runCli(['agent', 'list', '--data-dir', dir, '--json']);
    const row = (JSON.parse(list.stdout) as { id: string; revokedAt: number | null }[]).find(
      (x) => x.id === agent?.id,
    );
    expect(row?.revokedAt).toEqual(expect.any(Number));
  });

  it('admin actions are audited, and the shared hash chain stays intact', async () => {
    const audit = new AuditLog(db);
    audit.append('test.marker', {});
    await Promise.all([
      runCli(['agent', 'add', 'a1', '--data-dir', dir]),
      runCli(['agent', 'add', 'a2', '--data-dir', dir]),
    ]);
    audit.append('test.marker', {});
    const types = audit.all().map((r) => r.event_type);
    expect(types.filter((t) => t === 'agent.added').length).toBeGreaterThanOrEqual(5);
    expect(types).toContain('agent.revoked');
    expect(audit.verify()).toBeNull();
    for (const r of audit.all()) expect(r.payload_json).not.toMatch(/aab_agent_/);
  });
});

describe('snippet helpers', () => {
  it('shellQuote', () => {
    expect(shellQuote('/usr/bin/node')).toBe('/usr/bin/node');
    expect(shellQuote('/a b/c')).toBe("'/a b/c'");
    expect(shellQuote("it's")).toBe("'it'\\''s'");
  });

  it('paths for Claude Code settings', async () => {
    const { homedir } = await import('node:os');
    expect(homeRelative(join(homedir(), '.keyflap'))).toBe('~/.keyflap');
    expect(claudeCodePaths(join(homedir(), '.keyflap'))).toEqual({
      sandbox: '~/.keyflap/**',
      rule: '~/.keyflap/**',
    });
    expect(claudeCodePaths('/srv/keyflap')).toEqual({
      sandbox: '/srv/keyflap/**',
      rule: '//srv/keyflap/**',
    });
  });
});
