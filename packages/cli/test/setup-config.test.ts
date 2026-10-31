import { describe, expect, it } from 'vitest';
import { parseCli } from '../src/args.ts';
import {
  denyPaths,
  inspectClaude,
  jsonDiff,
  lineDiff,
  mergeMcp,
  mergeSettings,
} from '../src/setup/claude-config.ts';
import { daemonCommand, emptyState } from '../src/setup/state.ts';
import { parseTailscaleStatus, serveState } from '../src/setup/tailscale.ts';

const CFG = {
  hookCommand:
    '/usr/bin/node /r/main.ts hook claude-code --agent 0b9d6c1e-2f4a-4c3b-9e8d-7a6b5c4d3e2f',
  denyDir: '/home/u/.keyflap',
  home: '/home/u',
};

describe('Claude Code config merge', () => {
  it('adds hook, sandbox and deny rules to an empty settings file', () => {
    const { doc, notes } = mergeSettings(undefined, CFG);
    expect(notes).toEqual([]);
    expect(doc).toEqual({
      hooks: { UserPromptSubmit: [{ hooks: [{ type: 'command', command: CFG.hookCommand }] }] },
      sandbox: {
        enabled: true,
        failIfUnavailable: true,
        allowUnsandboxedCommands: false,
        filesystem: { denyRead: ['~/.keyflap/**'], denyWrite: ['~/.keyflap/**'] },
      },
      permissions: { deny: ['Read(~/.keyflap/**)', 'Edit(~/.keyflap/**)'] },
    });
  });

  it('is idempotent and keeps everything else', () => {
    const start = {
      env: { FOO: '1' },
      hooks: { UserPromptSubmit: [{ hooks: [{ type: 'command', command: 'my-own-hook' }] }] },
      sandbox: { filesystem: { denyRead: ['~/.ssh/**'] }, excludedCommands: ['docker'] },
    };
    const once = mergeSettings(start, CFG).doc;
    const twice = mergeSettings(once, CFG);
    expect(twice.doc).toEqual(once);
    expect(twice.notes).toEqual([]);
    expect(once.env).toEqual({ FOO: '1' });
    expect((once.hooks as { UserPromptSubmit: unknown[] }).UserPromptSubmit).toHaveLength(2);
    expect((once.sandbox as { filesystem: { denyRead: string[] } }).filesystem.denyRead).toEqual([
      '~/.ssh/**',
      '~/.keyflap/**',
    ]);
    expect((once.sandbox as { excludedCommands: string[] }).excludedCommands).toEqual(['docker']);
  });

  it('replaces an earlier keyflap hook in place instead of adding a second one', () => {
    const old = {
      hooks: {
        UserPromptSubmit: [
          {
            hooks: [
              {
                type: 'command',
                command: 'aab hook claude-code --agent 11111111-1111-4111-8111-111111111111',
              },
            ],
          },
        ],
      },
    };
    const { doc, notes } = mergeSettings(old, CFG);
    expect(doc.hooks).toEqual({
      UserPromptSubmit: [{ hooks: [{ type: 'command', command: CFG.hookCommand }] }],
    });
    expect(notes).toEqual(['replaces the earlier keyflap hook command']);
  });

  it('forces the sandbox switches the protection depends on, and says so', () => {
    const { doc, notes } = mergeSettings(
      { sandbox: { enabled: false, allowUnsandboxedCommands: true } },
      CFG,
    );
    expect(doc.sandbox).toMatchObject({ enabled: true, allowUnsandboxedCommands: false });
    expect(notes).toEqual([
      'sets sandbox.enabled to true (was false)',
      'sets sandbox.allowUnsandboxedCommands to false (was true)',
    ]);
  });

  it('refuses shapes it does not understand rather than guessing', () => {
    expect(() => mergeSettings({ hooks: [] }, CFG)).toThrow(/hooks is not an object/);
    expect(() => mergeSettings({ permissions: { deny: 'x' } }, CFG)).toThrow(
      /deny is not an array/,
    );
    expect(() => mergeSettings([], CFG)).toThrow(/not a JSON object/);
  });

  it('mcpServers: user scope, or a project entry inside ~/.claude.json', () => {
    const entry = { type: 'http', url: 'http://127.0.0.1:8765/mcp', headersHelper: 'h' };
    const user = mergeMcp({ numStartups: 3, mcpServers: { x: { command: 'y' } } }, entry);
    expect(user.doc).toEqual({
      numStartups: 3,
      mcpServers: { x: { command: 'y' }, keyflap: entry },
    });
    const proj = mergeMcp({ projects: { '/p': { allowedTools: [] } } }, entry, { project: '/p' });
    expect(proj.doc).toEqual({
      projects: { '/p': { allowedTools: [], mcpServers: { keyflap: entry } } },
    });
    const again = mergeMcp({ mcpServers: { keyflap: { type: 'http', url: 'old' } } }, entry);
    expect(again.notes).toEqual(['replaces the existing "keyflap" MCP server entry']);
  });

  it('deny paths: ~/ inside home, //abs for permission rules outside it', () => {
    expect(denyPaths('/home/u/.keyflap', '/home/u')).toEqual({
      sandbox: '~/.keyflap/**',
      rule: '~/.keyflap/**',
    });
    expect(denyPaths('/var/lib/keyflap/hook', '/home/u')).toEqual({
      sandbox: '/var/lib/keyflap/hook/**',
      rule: '//var/lib/keyflap/hook/**',
    });
  });

  it('the preview diff shows only changed keys', () => {
    expect(lineDiff(['a', 'b', 'c'], ['a', 'x', 'c'])).toEqual(['  a', '- b', '+ x', '  c']);
    const d = jsonDiff({ keep: 1, change: [1] }, { keep: 1, change: [1, 2] });
    expect(d.join('\n')).toContain('+   2');
    expect(d.join('\n')).not.toContain('keep');
  });
});

describe('inspectClaude (keyflap doctor)', () => {
  const settings = mergeSettings(undefined, CFG).doc;
  const mcp = {
    mcpServers: { keyflap: { type: 'http', url: 'http://127.0.0.1:8765/mcp', headersHelper: 'h' } },
  };
  const files = (over = {}) => ({
    userSettings: undefined,
    projectSettings: undefined,
    localSettings: settings,
    userState: undefined,
    projectMcp: mcp,
    ...over,
  });
  const opts = { project: '/p', mcpPort: 8765, denyDir: '/home/u/.keyflap', home: '/home/u' };

  it('recognizes a complete setup', () => {
    expect(inspectClaude(files(), opts)).toEqual({
      mcp: { where: '.mcp.json', auth: 'headersHelper' },
      hookAgents: ['0b9d6c1e-2f4a-4c3b-9e8d-7a6b5c4d3e2f'],
      hookViaPnpm: false,
      denyRead: true,
      denyWrite: true,
      permissionDeny: true,
      sandboxEnabled: true,
      failIfUnavailable: true,
      allowUnsandboxedCommands: false,
      unreadable: [],
    });
  });

  it('a deny on a parent directory covers the data dir; a later layer can re-allow unsandboxed', () => {
    const parent = {
      sandbox: {
        enabled: true,
        failIfUnavailable: true,
        allowUnsandboxedCommands: false,
        filesystem: { denyRead: ['~/**'], denyWrite: ['~/**'] },
      },
      permissions: { deny: ['Read(~/**)', 'Edit(~/**)'] },
    };
    const i = inspectClaude(files({ localSettings: undefined, userSettings: parent }), opts);
    expect(i).toMatchObject({ denyRead: true, denyWrite: true, permissionDeny: true });
    const worse = inspectClaude(
      files({
        projectSettings: { sandbox: { allowUnsandboxedCommands: true } },
        localSettings: undefined,
        userSettings: settings,
      }),
      opts,
    );
    expect(worse.allowUnsandboxedCommands).toBe(true);
  });

  it('finds the MCP entry in ~/.claude.json (project or user) and the wrong port not at all', () => {
    const state = { projects: { '/p': mcp } };
    expect(inspectClaude(files({ projectMcp: undefined, userState: state }), opts).mcp).toEqual({
      where: '~/.claude.json (this project)',
      auth: 'headersHelper',
    });
    expect(inspectClaude(files(), { ...opts, mcpPort: 9999 }).mcp).toBeNull();
  });

  it('flags hooks run through a package manager', () => {
    const viaPnpm = mergeSettings(undefined, {
      ...CFG,
      hookCommand: 'pnpm keyflap hook claude-code --agent 0b9d6c1e-2f4a-4c3b-9e8d-7a6b5c4d3e2f',
    }).doc;
    expect(inspectClaude(files({ localSettings: viaPnpm }), opts).hookViaPnpm).toBe(true);
  });
});

describe('Tailscale', () => {
  it('reads the MagicDNS name and whether HTTPS certificates are on', () => {
    expect(
      parseTailscaleStatus(
        JSON.stringify({
          BackendState: 'Running',
          Self: { DNSName: 'Broker.tail1.ts.net.' },
          CertDomains: ['broker.tail1.ts.net'],
        }),
      ),
    ).toEqual({ running: true, dnsName: 'broker.tail1.ts.net', httpsEnabled: true, problem: null });
    expect(
      parseTailscaleStatus(
        JSON.stringify({ BackendState: 'Running', Self: { DNSName: 'b.tail1.ts.net.' } }),
      ).problem,
    ).toMatch(/HTTPS certificates are not enabled/);
    expect(parseTailscaleStatus(JSON.stringify({ BackendState: 'NeedsLogin' })).problem).toMatch(
      /not logged in/,
    );
    expect(parseTailscaleStatus('garbage').running).toBe(false);
  });

  it('knows whether serve already forwards the approver port', () => {
    const served = {
      Web: { 'b.ts.net:8766': { Handlers: { '/': { Proxy: 'http://127.0.0.1:8766' } } } },
    };
    expect(serveState(JSON.stringify(served), 'b.ts.net')).toBe('served');
    const other = {
      Web: { 'b.ts.net:8766': { Handlers: { '/': { Proxy: 'http://127.0.0.1:3000' } } } },
    };
    expect(serveState(JSON.stringify(other), 'b.ts.net')).toBe('conflict');
    expect(serveState('{}', 'b.ts.net')).toBe('free');
    expect(
      serveState(JSON.stringify({ TCP: { '8766': { TCPForward: '127.0.0.1:22' } } }), 'b.ts.net'),
    ).toBe('conflict');
  });
});

describe('daemon command line from the setup choices', () => {
  it('only adds the flags that differ from the defaults', () => {
    const o = { dataDir: '/h/.keyflap', defaultDataDir: '/h/.keyflap', defaultMcpPort: 8765 };
    expect(daemonCommand(emptyState(8765), o)).toEqual(['keyflap', 'daemon', '--unprotected']);
    const s = {
      ...emptyState(9000),
      headed: true,
      approver: {
        kind: 'phone' as const,
        origin: 'https://p.example:8443',
        listen: { host: '0.0.0.0', port: 8443 },
        tlsCert: '/c.pem',
        tlsKey: '/k.pem',
        via: 'own-tls' as const,
      },
      passwordSource: { kind: 'proton-pass' as const, vault: 'Agent', bin: null },
    };
    expect(daemonCommand(s, { ...o, dataDir: '/other' })).toEqual([
      'keyflap',
      'daemon',
      '--unprotected',
      '--data-dir',
      '/other',
      '--mcp-port',
      '9000',
      '--headed',
      '--approver',
      'phone',
      '--approver-origin',
      'https://p.example:8443',
      '--approver-listen',
      '0.0.0.0:8443',
      '--tls-cert',
      '/c.pem',
      '--tls-key',
      '/k.pem',
      '--password-source',
      'proton-pass',
      '--proton-pass-vault',
      'Agent',
    ]);
  });
});

describe('args: setup, doctor, mcp-headers', () => {
  it('parses them', () => {
    expect(parseCli(['setup', '--unprotected', '--data-dir', '/d', '--mcp-port', '9000'])).toEqual({
      kind: 'setup',
      dataDir: '/d',
      mcpPort: 9000,
      unprotected: true,
    });
    expect(parseCli(['setup'])).toMatchObject({ kind: 'setup', unprotected: false });
    expect(parseCli(['doctor', '--json', '--project', '/p', '--data-dir', '/d'])).toEqual({
      kind: 'doctor',
      dataDir: '/d',
      json: true,
      project: '/p',
    });
    expect(parseCli(['mcp-headers', '--agent', 'a', '--service'])).toMatchObject({
      kind: 'mcp-headers',
      agentId: 'a',
      service: true,
    });
    expect(() => parseCli(['mcp-headers'])).toThrow(/--agent/);
    expect(() =>
      parseCli(['mcp-headers', '--agent', 'a', '--service', '--data-dir', '/d']),
    ).toThrow(/exclusive/);
    expect(() => parseCli(['setup', '--mcp-port', '0'])).toThrow(/out of range/);
  });
});
