import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MCP_PORT,
  defaultDataDir,
  parseCli,
  parseDurationArg,
  UsageError,
} from '../src/args.ts';
import { DaemonStartError, takeOnePasswordEnv } from '../src/daemon.ts';

describe('keyflap argument parsing', () => {
  it('help', () => {
    expect(parseCli([])).toEqual({ kind: 'help' });
    expect(parseCli(['--help'])).toEqual({ kind: 'help' });
    expect(parseCli(['help'])).toEqual({ kind: 'help' });
  });

  it('daemon defaults and options', () => {
    expect(parseCli(['daemon', '--unprotected'])).toEqual({
      kind: 'daemon',
      dataDir: defaultDataDir(),
      mcpPort: DEFAULT_MCP_PORT,
      headed: false,
      unprotected: true,
      phone: null,
      highRisk: [],
      passwordSource: null,
      ephemeralBrowser: false,
    });
    expect(defaultDataDir('/home/u', () => false)).toBe('/home/u/.keyflap');
    expect(
      parseCli(['daemon', '--unprotected', '--data-dir', 'rel/dir', '--mcp-port', '0', '--headed']),
    ).toEqual({
      kind: 'daemon',
      dataDir: resolve('rel/dir'),
      mcpPort: 0,
      headed: true,
      unprotected: true,
      phone: null,
      highRisk: [],
      passwordSource: null,
      ephemeralBrowser: false,
    });
    expect(parseCli(['daemon', '--unprotected', '--mcp-port=9000']).kind).toBe('daemon');
    expect(parseCli(['daemon', '--unprotected', '--ephemeral-browser'])).toMatchObject({
      ephemeralBrowser: true,
    });
  });

  it('daemon password source', () => {
    const base = ['daemon', '--unprotected'];
    expect(parseCli([...base, '--password-source', 'proton-pass'])).toMatchObject({
      passwordSource: { kind: 'proton-pass', bin: null, vault: null },
    });
    expect(
      parseCli([
        ...base,
        '--password-source=proton-pass',
        '--proton-pass-vault',
        'Agent',
        '--proton-pass-bin',
        'bin/pass-cli',
      ]),
    ).toMatchObject({
      passwordSource: { kind: 'proton-pass', bin: resolve('bin/pass-cli'), vault: 'Agent' },
    });
    expect(() => parseCli([...base, '--password-source', 'bitwarden'])).toThrow(/proton-pass/);
    expect(parseCli([...base, '--password-source', '1password'])).toMatchObject({
      passwordSource: { kind: '1password', bin: null, vault: null },
    });
    expect(
      parseCli([
        ...base,
        '--password-source=1password',
        '--1password-vault',
        'Agent',
        '--op-bin',
        'bin/op',
      ]),
    ).toMatchObject({
      passwordSource: { kind: '1password', bin: resolve('bin/op'), vault: 'Agent' },
    });
    expect(() => parseCli([...base, '--1password-vault', 'Agent'])).toThrow(
      /needs --password-source 1password/,
    );
    expect(() => parseCli([...base, '--password-source', 'proton-pass', '--op-bin', 'x'])).toThrow(
      /--op-bin needs --password-source 1password/,
    );
    expect(() =>
      parseCli([...base, '--password-source', '1password', '--proton-pass-vault', 'A']),
    ).toThrow(/--proton-pass-vault needs --password-source proton-pass/);
    expect(() =>
      parseCli([...base, '--password-source', '1password', '--1password-vault', '']),
    ).toThrow(/vault name/);
    expect(() => parseCli([...base, '--proton-pass-vault', 'Agent'])).toThrow(
      /needs --password-source/,
    );
    expect(() => parseCli([...base, '--proton-pass-bin', 'x'])).toThrow(/needs --password-source/);
  });

  it('same-user daemon requires --unprotected', () => {
    expect(() => parseCli(['daemon'])).toThrow(/--unprotected/);
    expect(() => parseCli(['daemon', '--headed'])).toThrow(UsageError);
  });

  it('daemon phone approver options', () => {
    expect(
      parseCli([
        'daemon',
        '--unprotected',
        '--approver',
        'phone',
        '--approver-origin',
        'https://broker.tail1234.ts.net',
        '--high-risk',
        'Example.COM',
        '--high-risk',
        'bank.test',
      ]),
    ).toMatchObject({
      phone: {
        origin: 'https://broker.tail1234.ts.net',
        listen: { host: '127.0.0.1', port: 8766 },
        tlsCert: null,
        tlsKey: null,
        pair: false,
      },
      highRisk: ['example.com', 'bank.test'],
    });
    expect(
      parseCli([
        'daemon',
        '--unprotected',
        '--approver=phone',
        '--approver-origin=https://phone.example.net:8443',
        '--approver-listen=[::]:8443',
        '--tls-cert=c.pem',
        '--tls-key=k.pem',
        '--pair',
      ]),
    ).toMatchObject({
      phone: {
        origin: 'https://phone.example.net:8443',
        listen: { host: '::', port: 8443 },
        tlsCert: resolve('c.pem'),
        tlsKey: resolve('k.pem'),
        pair: true,
      },
    });
    const bad = [
      ['--approver', 'phone'],
      ['--approver', 'phone', '--approver-origin', 'http://broker.example.net'],
      ['--approver', 'phone', '--approver-origin', 'https://b.example.net/path'],
      ['--approver', 'phone', '--approver-origin', 'https://b.example.net', '--tls-cert', 'c'],
      [
        '--approver',
        'phone',
        '--approver-origin',
        'https://b.example.net',
        '--approver-listen',
        'x',
      ],
      ['--approver', 'sms'],
      ['--pair'],
      ['--approver-origin', 'https://b.example.net'],
      ['--high-risk', 'not a domain'],
    ];
    for (const b of bad)
      expect(() => parseCli(['daemon', '--unprotected', ...b]), b.join(' ')).toThrow(UsageError);
    const phone = [
      'daemon',
      '--unprotected',
      '--approver',
      'phone',
      '--approver-origin',
      'https://b.example.net',
    ];
    const apns = [
      '--apns-key',
      'AuthKey.p8',
      '--apns-key-id',
      'ABCDE12345',
      '--apns-team-id',
      'TEAM123456',
      '--apns-bundle-id',
      'me.example.Keyflap',
    ];
    expect(parseCli(phone)).toMatchObject({ phone: { apns: null } });
    expect(parseCli([...phone, ...apns, '--apns-sandbox'])).toMatchObject({
      phone: {
        apns: {
          keyFile: resolve('AuthKey.p8'),
          keyId: 'ABCDE12345',
          teamId: 'TEAM123456',
          bundleId: 'me.example.Keyflap',
          sandbox: true,
          generic: false,
        },
      },
    });
    const badApns = [
      apns.slice(0, 6),
      [...apns.slice(0, 2), '--apns-key-id', 'short', ...apns.slice(4)],
      [...apns.slice(0, 4), '--apns-team-id', 'lower12345', ...apns.slice(6)],
      [...apns.slice(0, 6), '--apns-bundle-id', 'nodots'],
      ['--apns-sandbox'],
      ['--apns-generic'],
    ];
    for (const b of badApns)
      expect(() => parseCli([...phone, ...b]), b.join(' ')).toThrow(UsageError);
    expect(() => parseCli(['daemon', '--unprotected', ...apns])).toThrow(/needs --approver phone/);
    expect(parseCli(['approver', 'qr'])).toMatchObject({ kind: 'approver-qr' });
    expect(parseCli(['approver', 'list', '--json'])).toMatchObject({
      kind: 'approver-list',
      json: true,
    });
    expect(parseCli(['approver', 'remove', 'abc'])).toMatchObject({
      kind: 'approver-remove',
      id: 'abc',
    });
    expect(() => parseCli(['approver', 'add'])).toThrow(UsageError);
  });

  it('rejects bad ports and unknown flags', () => {
    for (const p of ['-1', '65536', 'abc', '80.5', '']) {
      expect(() => parseCli(['daemon', '--unprotected', '--mcp-port', p])).toThrow(UsageError);
    }
    expect(() => parseCli(['daemon', '--unprotected', '--bogus'])).toThrow(UsageError);
    expect(() => parseCli(['daemon', '--unprotected', 'extra'])).toThrow(UsageError);
    expect(() => parseCli(['daemon', '--unprotected', '--data-dir', ''])).toThrow(UsageError);
    expect(() => parseCli(['agent', 'add', 'x', '--mcp-port', '0'])).toThrow(UsageError);
  });

  it('agent subcommands', () => {
    expect(parseCli(['agent', 'add', 'claude-code', '--data-dir', '/d'])).toEqual({
      kind: 'agent-add',
      dataDir: '/d',
      name: 'claude-code',
      mcpPort: DEFAULT_MCP_PORT,
    });
    expect(parseCli(['agent', 'list', '--json'])).toEqual({
      kind: 'agent-list',
      dataDir: defaultDataDir(),
      json: true,
    });
    expect(parseCli(['agent', 'revoke', 'abc'])).toEqual({
      kind: 'agent-revoke',
      dataDir: defaultDataDir(),
      id: 'abc',
    });
    expect(() => parseCli(['agent'])).toThrow(UsageError);
    expect(() => parseCli(['agent', 'add'])).toThrow(UsageError);
    expect(() => parseCli(['agent', 'add', 'a', 'b'])).toThrow(UsageError);
    expect(() => parseCli(['agent', 'revoke'])).toThrow(UsageError);
    expect(() => parseCli(['agent', 'delete', 'x'])).toThrow(UsageError);
  });

  it('hook claude-code', () => {
    expect(parseCli(['hook', 'claude-code', '--agent', 'id-1'])).toEqual({
      kind: 'hook-claude-code',
      dataDir: defaultDataDir(),
      agentId: 'id-1',
      service: false,
    });
    expect(parseCli(['hook', 'claude-code', '--agent', 'x', '--data-dir', '/tmp/d'])).toEqual({
      kind: 'hook-claude-code',
      dataDir: join('/tmp', 'd'),
      agentId: 'x',
      service: false,
    });
    expect(parseCli(['hook', 'claude-code', '--agent', 'x', '--service'])).toMatchObject({
      agentId: 'x',
      service: true,
    });
    expect(() =>
      parseCli(['hook', 'claude-code', '--agent', 'x', '--service', '--data-dir', '/tmp/d']),
    ).toThrow(UsageError);
    expect(() => parseCli(['hook', 'claude-code'])).toThrow(UsageError);
    expect(() => parseCli(['hook', 'claude-code', '--agent', ''])).toThrow(UsageError);
    expect(() => parseCli(['hook', 'cursor', '--agent', 'x'])).toThrow(UsageError);
  });

  it('status and approver pair', () => {
    expect(parseCli(['status'])).toEqual({
      kind: 'status',
      dataDir: defaultDataDir(),
      json: false,
    });
    expect(parseCli(['status', '--json'])).toMatchObject({ kind: 'status', json: true });
    expect(parseCli(['approver', 'pair'])).toEqual({
      kind: 'approver-pair',
      phone: null,
      dataDir: defaultDataDir(),
    });
    expect(
      parseCli(['approver', 'pair', '--approver-origin', 'https://b.tail1.ts.net:8766']),
    ).toMatchObject({
      kind: 'approver-pair',
      phone: { origin: 'https://b.tail1.ts.net:8766', listen: { host: '127.0.0.1', port: 8766 } },
    });
    expect(() => parseCli(['approver', 'pair', '--approver-listen', '127.0.0.1:1'])).toThrow(
      /--approver-listen needs --approver-origin/,
    );
    expect(() => parseCli(['approver', 'trust', 'tailscale'])).toThrow(UsageError);
    expect(() => parseCli(['approver', 'pair', 'x'])).toThrow(UsageError);
    expect(() => parseCli(['status', 'x'])).toThrow(UsageError);
  });

  it('unknown command', () => {
    expect(() => parseCli(['frobnicate'])).toThrow(UsageError);
  });
});

describe('keyflap policy / status / audit argument parsing (M5)', () => {
  it('policy set: one mode and/or a session TTL, optional agent', () => {
    expect(parseCli(['policy', 'set', 'example.com', '--deny'])).toEqual({
      kind: 'policy-set',
      dataDir: defaultDataDir(),
      site: 'example.com',
      agent: null,
      mode: 'deny',
      allowForMs: null,
      sessionTtlMs: undefined,
    });
    expect(
      parseCli([
        'policy',
        'set',
        'https://app.example.com',
        '--allow-for',
        '1h30m',
        '--agent',
        'a1',
        '--session-ttl',
        '2h',
      ]),
    ).toMatchObject({
      mode: 'allow-for',
      allowForMs: 90 * 60_000,
      agent: 'a1',
      sessionTtlMs: 2 * 3_600_000,
    });
    expect(parseCli(['policy', 'set', 'example.com', '--session-ttl', 'off'])).toMatchObject({
      mode: null,
      sessionTtlMs: null,
    });
    expect(parseCli(['policy', 'set', 'example.com', '--ask-strong'])).toMatchObject({
      mode: 'ask-strong',
    });
    expect(() => parseCli(['policy', 'set', 'example.com'])).toThrow(/give a mode/);
    expect(() => parseCli(['policy', 'set', 'example.com', '--deny', '--ask'])).toThrow(
      /give one of/,
    );
    expect(() => parseCli(['policy', 'set', 'example.com', '--allow-for', '30'])).toThrow(
      /duration/,
    );
    expect(() => parseCli(['policy', 'set', 'example.com', '--allow-for'])).toThrow(UsageError);
    expect(() => parseCli(['policy', 'set', 'example.com', '--session-ttl', 'soon'])).toThrow(
      /duration/,
    );
    expect(() => parseCli(['policy', 'set', '--deny'])).toThrow(UsageError);
    expect(() => parseCli(['policy', 'set', 'example.com', '--deny', '--agent', ''])).toThrow(
      /--agent/,
    );
  });

  it('policy list / remove, status, audit', () => {
    expect(parseCli(['policy', 'list', '--json', '--agent', 'a1'])).toEqual({
      kind: 'policy-list',
      dataDir: defaultDataDir(),
      agent: 'a1',
      json: true,
    });
    expect(parseCli(['policy', 'remove', 'example.com'])).toEqual({
      kind: 'policy-remove',
      dataDir: defaultDataDir(),
      site: 'example.com',
      agent: null,
    });
    expect(() => parseCli(['policy', 'delete', 'x'])).toThrow(UsageError);
    expect(parseCli(['status', '--json'])).toEqual({
      kind: 'status',
      dataDir: defaultDataDir(),
      json: true,
    });
    expect(parseCli(['audit', 'verify'])).toEqual({
      kind: 'audit-verify',
      dataDir: defaultDataDir(),
    });
    expect(parseCli(['audit', 'tail', '--limit', '5'])).toEqual({
      kind: 'audit-tail',
      dataDir: defaultDataDir(),
      limit: 5,
      json: false,
    });
    expect(() => parseCli(['audit', 'tail', '--limit', '0'])).toThrow(/--limit/);
    expect(() => parseCli(['audit', 'rewrite'])).toThrow(UsageError);
  });

  it('durations', () => {
    expect(parseDurationArg('45s', 'x')).toBe(45_000);
    expect(parseDurationArg('7d', 'x')).toBe(7 * 86_400_000);
    expect(() => parseDurationArg('1.5h', 'x')).toThrow(UsageError);
  });

  it('sessions list | clear | keep | unkeep', () => {
    expect(parseCli(['sessions', 'list'])).toEqual({
      kind: 'sessions-list',
      dataDir: defaultDataDir(),
      agent: null,
      json: false,
    });
    expect(parseCli(['sessions', 'list', '--agent', 'a1', '--json'])).toMatchObject({
      agent: 'a1',
      json: true,
    });
    expect(parseCli(['sessions', 'clear', '--agent', 'a1'])).toEqual({
      kind: 'sessions-clear',
      dataDir: defaultDataDir(),
      agent: 'a1',
      all: false,
      site: null,
    });
    expect(parseCli(['sessions', 'clear', '--all', '--site', 'example.com'])).toMatchObject({
      agent: null,
      all: true,
      site: 'example.com',
    });
    expect(() => parseCli(['sessions', 'clear'])).toThrow(/exactly one of --agent ID or --all/);
    expect(() => parseCli(['sessions', 'clear', '--all', '--agent', 'a1'])).toThrow(/exactly one/);
    expect(parseCli(['sessions', 'keep', 'bank.example'])).toEqual({
      kind: 'sessions-keep',
      dataDir: defaultDataDir(),
      site: 'bank.example',
      agent: null,
    });
    expect(parseCli(['sessions', 'unkeep', 'bank.example', '--agent', 'a1'])).toMatchObject({
      kind: 'sessions-unkeep',
      agent: 'a1',
    });
    expect(() => parseCli(['sessions', 'keep'])).toThrow(/expected 1 argument/);
    expect(() => parseCli(['sessions', 'nope'])).toThrow(/unknown sessions subcommand/);
  });
});

describe('1Password token in dev mode', () => {
  it('is taken from the environment and removed from it (Chromium inherits ours)', () => {
    const env: NodeJS.ProcessEnv = {
      HOME: '/home/me',
      OP_SERVICE_ACCOUNT_TOKEN: 'ops_dev',
      OP_CONNECT_TOKEN: 'connect',
      OP_SESSION_me: 'session',
      PATH: '/usr/bin',
    };
    expect(takeOnePasswordEnv(env)).toEqual({
      HOME: '/home/me',
      OP_SERVICE_ACCOUNT_TOKEN: 'ops_dev',
    });
    expect(env.OP_SERVICE_ACCOUNT_TOKEN).toBeUndefined();
    expect(() => takeOnePasswordEnv({ HOME: '/home/me' })).toThrow(DaemonStartError);
  });
});
