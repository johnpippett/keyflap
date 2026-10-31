import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { encodeQr } from '@aab/approver';
import { loadOrCreateHostToken } from '@aab/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseCli, UsageError } from '../src/args.ts';
import { hermesTerminalBackend, hostChecks } from '../src/doctor-hosts.ts';
import { HERMES_PLUGIN_DIR } from '../src/host-config.ts';
import { mergeCodexHooks } from '../src/setup/hosts.ts';
import { emptyState } from '../src/setup/state.ts';
import { agentStep, type SetupContext } from '../src/setup/steps.ts';
import { plainUi } from '../src/setup/ui.ts';
import { runCli, tmpDir } from './helpers.ts';
import { AGENT_ID, AGENT_TOKEN, FakeBackend, FakeSystem, ScriptedPrompter } from './setup-fakes.ts';

const TOKEN_RE = /aab_agent_[A-Za-z0-9_-]{43}/g;

describe('keyflap agent add --host', () => {
  let dir: string;
  let hostToken: string;
  beforeAll(() => {
    dir = tmpDir();
    hostToken = loadOrCreateHostToken(join(dir, 'host-token'));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('hermes: token for .env, Docker backend required, plugin config with this agent', async () => {
    const r = await runCli([
      'agent',
      'add',
      'hermes',
      '--host',
      'hermes',
      '--owner',
      'telegram:42',
      '--data-dir',
      dir,
    ]);
    expect(r.code).toBe(0);
    const tokens = [...new Set(r.stdout.match(TOKEN_RE))];
    expect(tokens).toHaveLength(1);
    expect(r.stdout).toContain(`KEYFLAP_AGENT_TOKEN=${tokens[0]}`);
    expect(r.stdout).toMatch(/^ {2}backend: docker/m);
    expect(r.stdout).toContain('docker_forward_env: []');
    expect(r.stdout).toContain('WARNING: terminal.backend MUST be docker');
    // biome-ignore lint/suspicious/noTemplateCurlyInString: literal Hermes env reference
    expect(r.stdout).toContain('Authorization: "Bearer ${KEYFLAP_AGENT_TOKEN}"');
    expect(r.stdout).toContain(HERMES_PLUGIN_DIR);
    const cfg = JSON.parse(
      (/<<'EOF'\n([\s\S]*?)\nEOF/.exec(r.stdout) as RegExpExecArray)[1] as string,
    );
    expect(cfg).toMatchObject({ owners: ['telegram:42'], dataDir: dir, service: false });
    expect(cfg.command.at(-1)).toMatch(/packages\/cli\/src\/main\.ts$/);
    expect(r.stdout).toContain('never `hermes chat` (CLI) turns');
    expect(r.stdout).not.toContain(hostToken);
  });

  it('codex: bearer_token_env_var, a profile denying the data dir, the hook, /hooks trust', async () => {
    const r = await runCli(['agent', 'add', 'codex', '--host', 'codex', '--data-dir', dir]);
    expect(r.code).toBe(0);
    expect([...new Set(r.stdout.match(TOKEN_RE))]).toHaveLength(1);
    expect(r.stdout).toMatch(/^default_permissions = "keyflap-protected"$/m);
    expect(r.stdout).toContain(`${JSON.stringify(dir)} = "deny"`);
    expect(r.stdout).toContain('sandbox_approval = false');
    expect(r.stdout).toContain('bearer_token_env_var = "KEYFLAP_AGENT_TOKEN"');
    expect(r.stdout).toMatch(/hook codex --agent [0-9a-f-]{36} --data-dir /);
    expect(r.stdout).toContain('"UserPromptSubmit"');
    expect(r.stdout).toContain('/hooks');
    expect(r.stdout).not.toContain(hostToken);
    const toml = r.stdout.slice(r.stdout.indexOf('default_permissions'));
    expect(toml.indexOf('approval_policy')).toBeLessThan(toml.indexOf('['));
  });

  it('argument checks', () => {
    expect(parseCli(['agent', 'add', 'x', '--host', 'codex'])).toMatchObject({ host: 'codex' });
    expect(() => parseCli(['agent', 'add', 'x', '--host', 'cursor'])).toThrow(UsageError);
    expect(() => parseCli(['agent', 'add', 'x', '--owner', 'telegram:1'])).toThrow(UsageError);
    expect(() =>
      parseCli(['agent', 'add', 'x', '--host', 'hermes', '--owner', 'webhook:1']),
    ).toThrow(UsageError);
    expect(parseCli(['setup', '--unprotected', '--host', 'hermes'])).toMatchObject({
      host: 'hermes',
    });
    expect(parseCli(['hook', 'hermes', '--agent', 'a', '--owner', 'matrix:@j:x.org'])).toEqual({
      kind: 'hook-hermes',
      dataDir: expect.any(String),
      agentId: 'a',
      service: false,
      owners: [{ platform: 'matrix', userId: '@j:x.org' }],
      profile: null,
    });
    expect(() => parseCli(['hook', 'hermes', '--agent', 'a'])).toThrow(/--owner/);
    expect(parseCli(['hook', 'codex', '--agent', 'a', '--service'])).toMatchObject({
      kind: 'hook-codex',
      service: true,
    });
  });
});

function ctx(sys: FakeSystem, prompt: ScriptedPrompter, over: Partial<SetupContext> = {}) {
  let out = '';
  const write = (t: string) => {
    out += t;
  };
  const c: SetupContext = {
    sys,
    prompt,
    out: write,
    ui: plainUi(write, prompt),
    backend: new FakeBackend(sys),
    state: emptyState(8765),
    dataDir: '/home/u/.keyflap',
    defaults: { dataDir: '/home/u/.keyflap', mcpPort: 8765 },
    paths: null,
    qr: (url) => ({ code: encodeQr(url), printed: '' }),
    pairingTimeoutMs: 1,
    chromium: () => ({ path: '/c', present: true }),
    doctor: async () => ({ mode: 'dev', ok: true, checks: [] }),
    startDaemon: null,
    interruptible: (fn) => fn(new AbortController().signal),
    ...over,
  };
  return Object.assign(c, { output: () => out });
}

function withPluginSource(sys: FakeSystem): FakeSystem {
  sys.dir(HERMES_PLUGIN_DIR, 0o755);
  for (const f of ['__init__.py', 'plugin.yaml']) {
    sys.file(join(HERMES_PLUGIN_DIR, f), readFileSync(join(HERMES_PLUGIN_DIR, f), 'utf8'));
  }
  return sys;
}

describe('keyflap setup --host hermes', () => {
  const answers = (apply: string) =>
    new ScriptedPrompter([
      { q: /^Set up an agent/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Write the Hermes Agent config/, a: '' },
      { q: /^Your chat id/, a: 'telegram:42, discord:7' },
      { q: /^Apply these changes\? \[y\/N\]$/, a: apply },
    ]);

  it('previews the plugin files, writes nothing on no', async () => {
    const sys = withPluginSource(new FakeSystem());
    const c = ctx(sys, answers(''), { host: 'hermes' });
    expect(await agentStep(c)).toBe('skipped');
    expect(c.output()).toContain('/home/u/.hermes/plugins/keyflap-intent/config.json: new file');
    expect(c.output()).toContain('Nothing written.');
    expect(sys.exists('/home/u/.hermes/plugins/keyflap-intent/config.json')).toBe(false);
  });

  it('writes the plugin and its config, shows config.yaml and the .env command, never the token', async () => {
    const sys = withPluginSource(new FakeSystem());
    const c = ctx(sys, answers('y'), { host: 'hermes' });
    expect(await agentStep(c)).toBe('done');
    const cfg = JSON.parse(
      sys.text('/home/u/.hermes/plugins/keyflap-intent/config.json') as string,
    );
    expect(cfg).toMatchObject({ agent: AGENT_ID, owners: ['telegram:42', 'discord:7'] });
    expect(sys.text('/home/u/.hermes/plugins/keyflap-intent/__init__.py')).toBe(
      readFileSync(join(HERMES_PLUGIN_DIR, '__init__.py'), 'utf8'),
    );
    expect(c.output()).toContain('backend: docker');
    expect(c.output()).toContain(
      `"$(cat /home/u/.keyflap/agents/${AGENT_ID}.token)" >> /home/u/.hermes/.env`,
    );
    expect(c.output()).not.toContain(AGENT_TOKEN);
    for (const [path, text] of sys.allText()) {
      if (!path.endsWith('.token')) expect(text, path).not.toContain(AGENT_TOKEN);
    }
    expect(c.state.agentHosts).toEqual([
      { host: 'hermes', agentId: AGENT_ID, dir: '/home/u/.hermes' },
    ]);
  });

  it('Claude Code, Codex and Hermes installed: all three are set up in turn, each with its own agent', async () => {
    const sys = withPluginSource(new FakeSystem()).dir('/home/u/.codex', 0o700);
    sys.dir('/home/u/.claude', 0o700).dir('/home/u/.hermes', 0o700);
    const p = new ScriptedPrompter([
      { q: /^Set up an agent for Claude Code\?/, a: 'n' },
      { q: /^Set up an agent for Codex\?/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Write the Codex config/, a: '' },
      { q: /^Apply these changes\?/, a: 'y' },
      { q: /^Set up an agent for Hermes Agent\?/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Write the Hermes Agent config/, a: '' },
      { q: /^Your chat id/, a: 'telegram:42' },
      { q: /^Apply these changes\? \[y\/N\]$/, a: 'y' },
    ]);
    const c = ctx(sys, p);
    expect(await agentStep(c)).toBe('done');
    expect(p.remaining).toBe(0);
    const ids = (c.state.agentHosts ?? []).map((h) => h.agentId);
    expect(c.state.agentHosts?.map((h) => h.host)).toEqual(['codex', 'hermes']);
    expect(new Set(ids).size).toBe(2);
  });
});

describe('keyflap setup --host codex', () => {
  it('merges the hook into hooks.json (keeps others, replaces an earlier keyflap hook)', async () => {
    const sys = new FakeSystem().dir('/home/u/.codex', 0o700);
    const other = { type: 'command', command: '/usr/bin/lint', timeout: 5 };
    sys.file(
      '/home/u/.codex/hooks.json',
      JSON.stringify({
        hooks: {
          Stop: [{ hooks: [other] }],
          UserPromptSubmit: [
            { hooks: [other] },
            { hooks: [{ type: 'command', command: 'keyflap hook codex --agent old' }] },
          ],
        },
      }),
    );
    const p = new ScriptedPrompter([
      { q: /^Set up an agent/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Write the Codex config/, a: '' },
      { q: /^Apply these changes\? \[y\/N\]$/, a: 'y' },
    ]);
    const c = ctx(sys, p, { host: 'codex' });
    expect(await agentStep(c)).toBe('done');
    const h = JSON.parse(sys.text('/home/u/.codex/hooks.json') as string);
    expect(h.hooks.Stop).toEqual([{ hooks: [other] }]);
    expect(h.hooks.UserPromptSubmit).toHaveLength(2);
    expect(h.hooks.UserPromptSubmit[1].hooks[0].command).toMatch(
      new RegExp(`main\\.ts hook codex --agent ${AGENT_ID}( --data-dir /home/u/\\.keyflap)?$`),
    );
    expect(c.output()).toContain('replaces the earlier keyflap hook');
    expect(c.output()).toContain('"/home/u/.keyflap" = "deny"');
    expect(c.output()).toContain(
      `export KEYFLAP_AGENT_TOKEN="$(cat /home/u/.keyflap/agents/${AGENT_ID}.token)"`,
    );
    expect(c.output()).not.toContain(AGENT_TOKEN);
    expect(sys.exists('/home/u/.codex/config.toml')).toBe(false);
    expect([...sys.nodes.keys()].filter((k) => k.includes('.keyflap-backup-'))).toEqual([
      '/home/u/.codex/hooks.json.keyflap-backup-20261022T090000Z',
    ]);
  });

  it('mergeCodexHooks on an empty file', () => {
    expect(mergeCodexHooks(undefined, 'x hook codex --agent a')).toEqual({
      doc: {
        hooks: {
          UserPromptSubmit: [
            { hooks: [{ type: 'command', command: 'x hook codex --agent a', timeout: 15 }] },
          ],
        },
      },
      notes: [],
    });
  });
});

describe('doctor: Hermes and Codex checks', () => {
  const agents = [{ id: AGENT_ID, name: 'h', revoked: false }];
  const hermes = (yaml: string) =>
    new FakeSystem()
      .dir('/home/u/.hermes', 0o700)
      .file('/home/u/.hermes/plugins/keyflap-intent/__init__.py', '')
      .file(
        '/home/u/.hermes/plugins/keyflap-intent/config.json',
        JSON.stringify({ agent: AGENT_ID, owners: ['telegram:1'] }),
      )
      .file('/home/u/.hermes/config.yaml', yaml);
  const run = (sys: FakeSystem, a = agents) =>
    Object.fromEntries(
      hostChecks({
        sys,
        read: (p) => sys.readUserFile(p, { uid: 1000, gid: 1000 }),
        home: '/home/u',
        denyDir: '/home/u/.keyflap',
        agents: a,
      }).map((c) => [c.id, c.status]),
    );

  it('nothing configured: no checks', () => {
    expect(run(new FakeSystem())).toEqual({});
  });

  it('Hermes: the local terminal backend fails loudly; docker passes', () => {
    const ok = 'plugins:\n  enabled:\n    - keyflap-intent\nterminal:\n  backend: docker # yes\n';
    expect(run(hermes(ok))).toEqual({
      'hermes-plugin': 'ok',
      'hermes-backend': 'ok',
      'hermes-enabled': 'ok',
    });
    expect(run(hermes('terminal:\n  backend: local\n'))['hermes-backend']).toBe('fail');
    expect(run(hermes('model: x\n'))['hermes-backend']).toBe('fail');
    expect(run(hermes(ok), [])['hermes-plugin']).toBe('fail');
    expect(hermesTerminalBackend('terminal:\n  cwd: .\n  backend: "modal"\nother: 1\n')).toBe(
      'modal',
    );
  });

  it('Codex: the hook passes only with a profile that denies the data dir', () => {
    const sys = new FakeSystem()
      .file(
        '/home/u/.codex/hooks.json',
        JSON.stringify(mergeCodexHooks(undefined, `/n /m.ts hook codex --agent ${AGENT_ID}`).doc),
      )
      .file('/home/u/.codex/config.toml', 'model = "x"\n');
    expect(run(sys)).toEqual({ 'codex-hook': 'ok', 'codex-deny': 'fail' });
    sys.file(
      '/home/u/.codex/config.toml',
      'default_permissions = "keyflap-protected"\n[permissions.keyflap-protected.filesystem]\n"~/.keyflap" = "deny"\n',
    );
    expect(run(sys)).toEqual({ 'codex-hook': 'ok', 'codex-deny': 'ok' });
  });
});
