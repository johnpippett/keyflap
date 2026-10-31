import { encodeQr } from '@aab/approver';
import { describe, expect, it } from 'vitest';
import type { DoctorReport } from '../src/doctor.ts';
import { DARWIN_SERVICE_PATHS, SERVICE_PATHS } from '../src/service/paths.ts';
import { daemonCommand, emptyState, loadState, type SetupState } from '../src/setup/state.ts';
import {
  agentStep,
  approverStep,
  credentialsStep,
  finishStep,
  firstCredentialChoice,
  pairStep,
  preflight,
  type SetupContext,
  setUpHosts,
  walkthrough,
} from '../src/setup/steps.ts';
import { plainUi } from '../src/setup/ui.ts';
import { AGENT_ID, AGENT_TOKEN, FakeBackend, FakeSystem, ScriptedPrompter } from './setup-fakes.ts';
import {
  MAC_SIGNER_UID,
  machine,
  OP_TOKEN,
  PASS_BIN,
  PROTON_TOKEN,
  SIGNER_UID,
} from './source-machine.ts';

const TS_STATUS = JSON.stringify({
  BackendState: 'Running',
  Self: { DNSName: 'broker.tail1234.ts.net.' },
  CertDomains: ['broker.tail1234.ts.net'],
});

function ctx(
  sys: FakeSystem,
  backend: FakeBackend,
  prompt: ScriptedPrompter,
  over: Partial<SetupContext> = {},
): SetupContext & { output: () => string } {
  let out = '';
  const write = (t: string) => {
    out += t;
  };
  const c: SetupContext = {
    sys,
    prompt,
    out: write,
    ui: plainUi(write, prompt),
    backend,
    state: emptyState(8765),
    dataDir: '/home/u/.keyflap',
    defaults: { dataDir: '/home/u/.keyflap', mcpPort: 8765 },
    paths: null,
    qr: (url) => ({ code: encodeQr(url), printed: `[QR ${url.length}]` }),
    pairingTimeoutMs: 600_000,
    chromium: () => ({ path: '/c/chrome', present: true }),
    doctor: async (): Promise<DoctorReport> => ({ mode: 'dev', ok: true, checks: [] }),
    startDaemon: null,
    interruptible: (fn) => fn(new AbortController().signal),
    ...over,
  };
  return Object.assign(c, { output: () => out });
}

function tailscale(sys: FakeSystem, serve = '{}') {
  sys.bins.set('tailscale', '/usr/bin/tailscale');
  sys.exec_ = (cmd, args) => {
    if (cmd === 'tailscale' && args[0] === 'status')
      return { code: 0, stdout: TS_STATUS, stderr: '' };
    if (cmd === 'tailscale' && args.join(' ') === 'serve status --json') {
      return { code: 0, stdout: serve, stderr: '' };
    }
    if (cmd === 'tailscale' && args[0] === 'serve') return { code: 0, stdout: '', stderr: '' };
    return { code: 1, stdout: '', stderr: 'nope' };
  };
}

describe('setup step 2: approver origin', () => {
  it('detects Tailscale, shows the serve command, runs it only after y, derives the origin', async () => {
    const sys = new FakeSystem();
    tailscale(sys);
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '1' },
      { q: /^Run it\? \[Y\/n\]$/, a: 'y' },
      { q: /Use https:\/\/broker\.tail1234\.ts\.net:8766 as the approver origin/, a: '' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await approverStep(c);
    expect(c.output()).toContain('$ tailscale serve --bg --https=8766 http://127.0.0.1:8766');
    const serve = sys.execs.filter((e) => e.args[0] === 'serve' && e.args[1] === '--bg');
    expect(serve).toHaveLength(1);
    expect(serve[0]?.args).toEqual(['serve', '--bg', '--https=8766', 'http://127.0.0.1:8766']);
    expect(c.state.approver).toMatchObject({
      kind: 'phone',
      origin: 'https://broker.tail1234.ts.net:8766',
      via: 'tailscale',
      listen: { host: '127.0.0.1', port: 8766 },
    });
    expect(loadState(sys, '/home/u/.keyflap', 8765, { uid: 1000, gid: 1000 }).approver).toEqual(
      c.state.approver,
    );
  });

  it('runs nothing when the answer is no', async () => {
    const sys = new FakeSystem();
    tailscale(sys);
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '' },
      { q: /^Run it\?/, a: 'n' },
      { q: /as the approver origin/, a: 'y' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await approverStep(c);
    expect(sys.execs.some((e) => e.args[0] === 'serve' && e.args[1] === '--bg')).toBe(false);
    expect(c.output()).toContain('Not run.');
    expect(c.state.approver).toMatchObject({ origin: 'https://broker.tail1234.ts.net:8766' });
  });

  it('runs the serve command when Enter is pressed at the prompt, and says the phone can reach the origin', async () => {
    const sys = new FakeSystem();
    tailscale(sys);
    sys.http_ = () => ({ status: 200 });
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '' },
      { q: /^Run it\? \[Y\/n\]$/, a: '' },
      { q: /as the approver origin/, a: 'y' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await approverStep(c);
    expect(sys.execs.filter((e) => e.args[0] === 'serve' && e.args[1] === '--bg')).toHaveLength(1);
    expect(c.output()).toContain('✓ Your phone can now reach https://broker.tail1234.ts.net:8766');
    expect(c.output()).not.toContain('Not run.');
  });

  it('does not claim the phone can reach the origin while it does not answer yet', async () => {
    const sys = new FakeSystem();
    sys.uid = 0;
    sys.dir('/', 0o755, 0).dir('/usr', 0o755, 0).dir('/usr/bin', 0o755, 0);
    sys.file('/usr/bin/tailscale', '', 0o755, 0);
    sys.dir('/etc/keyflap', 0o755, 0);
    sys.file(
      SERVICE_PATHS.approverConfig,
      JSON.stringify({ origin: 'https://broker.tail1234.ts.net:8766' }),
    );
    sys.bins.set('tailscale', '/usr/bin/tailscale');
    sys.exec_ = (_cmd, args) =>
      args[0] === 'status'
        ? { code: 0, stdout: TS_STATUS, stderr: '' }
        : { code: 0, stdout: '{}', stderr: '' };
    sys.http_ = () => ({ status: null, error: 'ECONNREFUSED' });
    const b = new FakeBackend(sys);
    b.kind = 'service';
    const p = new ScriptedPrompter([{ q: /^Run it\? \[Y\/n\]$/, a: '' }]);
    const c = ctx(sys, b, p, { paths: SERVICE_PATHS });
    await approverStep(c);
    expect(sys.execs.filter((e) => e.args[1] === '--bg')).toHaveLength(1);
    expect(c.output()).not.toContain('Your phone can now reach');
    expect(c.output()).toContain('does not answer yet (ECONNREFUSED)');
  });

  it('prints the failure and no confirmation when tailscale serve fails', async () => {
    const sys = new FakeSystem();
    tailscale(sys);
    const base = sys.exec_;
    sys.exec_ = (cmd, args, opts) =>
      args[0] === 'serve' && args[1] === '--bg'
        ? { code: 1, stdout: '', stderr: 'serve config denied' }
        : base(cmd, args, opts);
    sys.http_ = () => ({ status: 200 });
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '' },
      { q: /^Run it\?/, a: '' },
      { q: /as the approver origin/, a: 'y' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await approverStep(c);
    expect(c.output()).toContain('failed (exit 1): serve config denied');
    expect(c.output()).not.toContain('Your phone can now reach');
  });

  it('does not offer tailscale serve when it already forwards the port', async () => {
    const sys = new FakeSystem();
    tailscale(
      sys,
      JSON.stringify({
        TCP: { '8766': { HTTPS: true } },
        Web: {
          'broker.tail1234.ts.net:8766': { Handlers: { '/': { Proxy: 'http://127.0.0.1:8766' } } },
        },
      }),
    );
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '1' },
      { q: /as the approver origin/, a: 'y' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await approverStep(c);
    expect(c.output()).toContain('already forwards');
    expect(p.remaining).toBe(0);
  });

  it('falls back to a typed origin (validated) and the own-certificate listener', async () => {
    const sys = new FakeSystem();
    sys.file('/certs/c.pem', 'CERT').file('/certs/k.pem', 'KEY', 0o600);
    sys.dir('/certs');
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: 'phone' },
      { q: /^Approver origin/, a: 'http://phone.example.net:8766' },
      { q: /^Approver origin/, a: 'https://phone.example.net:8766/path' },
      { q: /^Approver origin/, a: 'https://phone.example.net:8766' },
      { q: /serve TLS itself/, a: 'y' },
      { q: /^Certificate file/, a: '/certs/c.pem' },
      { q: /^Key file/, a: '/certs/k.pem' },
      { q: /^Listen address$/, a: '' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await approverStep(c);
    expect(c.output()).toContain('Tailscale: not installed');
    expect(c.output()).toContain('must be https://');
    expect(c.output()).toContain('bare origin');
    expect(c.state.approver).toEqual({
      kind: 'phone',
      origin: 'https://phone.example.net:8766',
      listen: { host: '0.0.0.0', port: 8766 },
      tlsCert: '/certs/c.pem',
      tlsKey: '/certs/k.pem',
      via: 'own-tls',
    });
  });

  it('is idempotent: a re-run keeps the recorded origin without asking more', async () => {
    const sys = new FakeSystem();
    const p = new ScriptedPrompter([{ q: /^Keep it\? \[Y\/n\]$/, a: '' }]);
    const c = ctx(sys, new FakeBackend(sys), p);
    c.state.approver = {
      kind: 'phone',
      origin: 'https://x.example:8766',
      listen: { host: '127.0.0.1', port: 8766 },
      tlsCert: null,
      tlsKey: null,
      via: 'proxy',
    };
    expect(await approverStep(c)).toBe('skipped');
    expect(p.remaining).toBe(0);
    expect(sys.execs).toEqual([]);
  });

  it('service mode: shows the install-time origin and checks it answers', async () => {
    const sys = new FakeSystem();
    sys.dir('/etc/keyflap', 0o755);
    sys.file(
      SERVICE_PATHS.approverConfig,
      JSON.stringify({ origin: 'https://b.tail1.ts.net:8766' }),
    );
    sys.http_ = (url) =>
      url === 'https://b.tail1.ts.net:8766/' ? { status: 200 } : { status: null };
    const b = new FakeBackend(sys);
    b.kind = 'service';
    const c = ctx(sys, b, new ScriptedPrompter([]), { paths: SERVICE_PATHS });
    await approverStep(c);
    expect(c.output()).toContain('set at install time): https://b.tail1.ts.net:8766');
    expect(c.output()).toContain('valid certificate');
  });
});

describe('setup step 3: pairing', () => {
  const phoneState = (): SetupState => ({
    ...emptyState(8765),
    approver: {
      kind: 'phone',
      origin: 'https://broker.tail1234.ts.net:8766',
      listen: { host: '127.0.0.1', port: 8766 },
      tlsCert: null,
      tlsKey: null,
      via: 'tailscale',
    },
  });

  it('shows the one-time link and its QR code, checks the origin, waits until paired', async () => {
    const sys = new FakeSystem();
    sys.http_ = () => ({ status: 200 });
    const b = new FakeBackend(sys);
    const c = ctx(sys, b, new ScriptedPrompter([{ q: /^Pair a phone now\?/, a: '' }]));
    c.state = phoneState();
    expect(await pairStep(c)).toBe('done');
    const out = c.output();
    expect(out).toContain('https://broker.tail1234.ts.net:8766/pair#CODE');
    expect(out).toContain('[QR ');
    expect(out).toContain('never paste it into an agent session');
    expect(out).toContain('answers from this machine');
    expect(out).toContain('Phone paired');
    expect(b.pairCalls[0]).toMatchObject({ origin: 'https://broker.tail1234.ts.net:8766' });
  });

  it('times out with a clear next step', async () => {
    const sys = new FakeSystem();
    const b = new FakeBackend(sys);
    b.pairResult = 'timeout';
    const c = ctx(sys, b, new ScriptedPrompter([{ q: /^Pair a phone now\?/, a: 'y' }]));
    c.state = phoneState();
    expect(await pairStep(c)).toBe('skipped');
    expect(c.output()).toContain('Run keyflap setup again for a new link');
  });

  it('service mode: the next step says sudo keyflap setup', async () => {
    const sys = new FakeSystem();
    sys.dir('/etc/keyflap', 0o755);
    sys.file(
      SERVICE_PATHS.approverConfig,
      JSON.stringify({ origin: 'https://b.tail1.ts.net:8766' }),
    );
    const b = new FakeBackend(sys);
    b.kind = 'service';
    b.pairResult = 'timeout';
    const c = ctx(sys, b, new ScriptedPrompter([{ q: /^Pair a phone now\?/, a: 'y' }]), {
      paths: SERVICE_PATHS,
    });
    c.state = phoneState();
    expect(await pairStep(c)).toBe('skipped');
    expect(c.output()).toContain('Run sudo keyflap setup again for a new link');
  });

  it('dev: asks to stop a running daemon first; "skip" skips pairing', async () => {
    const sys = new FakeSystem();
    const b = new FakeBackend(sys);
    b.running = true;
    const c = ctx(sys, b, new ScriptedPrompter([{ q: /Stop it .* or type skip/, a: 'skip' }]));
    c.state = phoneState();
    expect(await pairStep(c)).toBe('skipped');
    expect(b.pairCalls).toEqual([]);
  });

  it('already paired: only pairs another phone on request', async () => {
    const sys = new FakeSystem();
    const b = new FakeBackend(sys);
    b.paired = 1;
    const c = ctx(sys, b, new ScriptedPrompter([{ q: /^Pair another phone/, a: '' }]));
    c.state = phoneState();
    expect(await pairStep(c)).toBe('skipped');
    expect(c.output()).toContain('1 phone(s) paired');
    expect(b.pairCalls).toEqual([]);
  });

  it('terminal approver: nothing to pair', async () => {
    const sys = new FakeSystem();
    const c = ctx(sys, new FakeBackend(sys), new ScriptedPrompter([]));
    c.state.approver = { kind: 'terminal' };
    expect(await pairStep(c)).toBe('skipped');
  });
});

describe('setup step 4: agent and Claude Code config', () => {
  const answers = (apply: string) =>
    new ScriptedPrompter([
      { q: /^Set up an agent/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Write the Claude Code config/, a: '' },
      { q: /^Choice$/, a: '1' },
      { q: /^Project directory$/, a: '' },
      { q: /^Apply these changes\? \[y\/N\]$/, a: apply },
    ]);

  it('previews every change, writes nothing on no', async () => {
    const sys = new FakeSystem();
    const c = ctx(sys, new FakeBackend(sys), answers(''));
    expect(await agentStep(c)).toBe('skipped');
    expect(c.output()).toContain('/home/u/proj/.mcp.json: new file');
    expect(c.output()).toContain('/home/u/proj/.claude/settings.local.json: new file');
    expect(c.output()).toContain('Nothing written.');
    expect(sys.exists('/home/u/proj/.mcp.json')).toBe(false);
    expect(sys.exists('/home/u/proj/.claude/settings.local.json')).toBe(false);
  });

  it('merges into existing settings without clobbering them, after a backup', async () => {
    const sys = new FakeSystem();
    sys.dir('/home/u/proj/.claude', 0o755);
    const existing = {
      model: 'opus',
      hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'lint' }] }] },
      permissions: { allow: ['Bash(ls:*)'], deny: ['Read(./.env)'] },
      sandbox: { enabled: true, allowUnsandboxedCommands: true },
    };
    sys.file('/home/u/proj/.claude/settings.local.json', JSON.stringify(existing), 0o600);
    sys.file(
      '/home/u/proj/.mcp.json',
      JSON.stringify({ mcpServers: { other: { type: 'stdio', command: 'x' } } }),
    );
    const c = ctx(sys, new FakeBackend(sys), answers('y'));
    expect(await agentStep(c)).toBe('done');
    const s = JSON.parse(sys.text('/home/u/proj/.claude/settings.local.json') as string);
    expect(s.model).toBe('opus');
    expect(s.hooks.PreToolUse).toEqual(existing.hooks.PreToolUse);
    expect(s.permissions.allow).toEqual(['Bash(ls:*)']);
    expect(s.permissions.deny).toEqual([
      'Read(./.env)',
      'Read(~/.keyflap/**)',
      'Edit(~/.keyflap/**)',
    ]);
    expect(s.sandbox.allowUnsandboxedCommands).toBe(false);
    expect(c.output()).toContain('sets sandbox.allowUnsandboxedCommands to false (was true)');
    expect(sys.stat('/home/u/proj/.claude/settings.local.json')?.mode).toBe(0o600);
    const m = JSON.parse(sys.text('/home/u/proj/.mcp.json') as string);
    expect(Object.keys(m.mcpServers)).toEqual(['other', 'keyflap']);
    const backups = [...sys.nodes.keys()].filter((k) => k.includes('.keyflap-backup-'));
    expect(backups.sort()).toEqual([
      '/home/u/proj/.claude/settings.local.json.keyflap-backup-20261022T090000Z',
      '/home/u/proj/.mcp.json.keyflap-backup-20261022T090000Z',
    ]);
    expect(sys.text(backups.find((b) => b.includes('settings')) as string)).toBe(
      JSON.stringify(existing),
    );
    expect(c.state.claudeCode).toEqual([
      { agentId: AGENT_ID, scope: 'project', project: '/home/u/proj' },
    ]);
  });

  it('a re-run with the same agent changes nothing', async () => {
    const sys = new FakeSystem();
    const b = new FakeBackend(sys);
    await agentStep(ctx(sys, b, answers('y')));
    const before = sys.text('/home/u/proj/.claude/settings.local.json');
    const p = new ScriptedPrompter([
      { q: /^Set up an agent/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Use the existing agent "claude-code"\?/, a: '' },
      { q: /^Write the Claude Code config/, a: '' },
      { q: /^Choice$/, a: '' },
      { q: /^Project directory$/, a: '' },
      { q: /^Apply these changes\?/, a: 'y' },
    ]);
    const c = ctx(sys, b, p);
    await agentStep(c);
    expect(c.output()).toContain('settings.local.json: already up to date');
    expect(sys.text('/home/u/proj/.claude/settings.local.json')).toBe(before);
    expect([...sys.nodes.keys()].filter((k) => k.includes('backup'))).toEqual([]);
  });

  it('refuses an existing agent whose token it does not have, and asks again', async () => {
    const sys = new FakeSystem();
    const b = new FakeBackend(sys);
    b.agents = [
      { id: 'aaaaaaaa-0000-4000-8000-000000000000', name: 'claude-code', revoked: false },
    ];
    const p = new ScriptedPrompter([
      { q: /^Set up an agent/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Agent name/, a: '-' },
    ]);
    const c = ctx(sys, b, p);
    expect(await agentStep(c)).toBe('skipped');
    expect(c.output()).toContain('its token was shown only once');
  });

  it('uses `claude mcp add-json` when the CLI supports it; the token is not in its argv', async () => {
    const sys = new FakeSystem();
    sys.bins.set('claude', '/usr/local/bin/claude');
    sys.exec_ = (_cmd, args) => {
      if (args.join(' ') === 'mcp add-json --help')
        return { code: 0, stdout: '-s, --scope <scope>', stderr: '' };
      if (args.join(' ') === 'mcp get keyflap') return { code: 1, stdout: '', stderr: 'not found' };
      if (args[0] === 'mcp' && args[1] === 'add-json')
        return { code: 0, stdout: 'Added', stderr: '' };
      return { code: 1, stdout: '', stderr: '' };
    };
    const c = ctx(sys, new FakeBackend(sys), answers('y'));
    expect(await agentStep(c)).toBe('done');
    const add = sys.execs.find((e) => e.args[1] === 'add-json' && e.args[2] === 'keyflap');
    expect(add?.args.slice(-2)).toEqual(['-s', 'local']);
    expect(add?.opts.cwd).toBe('/home/u/proj');
    expect(JSON.parse(add?.args[3] as string)).toEqual({
      type: 'http',
      url: 'http://127.0.0.1:8765/mcp',
      headersHelper: `/usr/bin/node /repo/packages/cli/src/main.ts mcp-headers --agent ${AGENT_ID}`,
    });
    expect(sys.exists('/home/u/proj/.mcp.json')).toBe(false);
  });

  it('refuses to edit a settings file it cannot parse (JSON with comments)', async () => {
    const sys = new FakeSystem();
    sys.dir('/home/u/proj/.claude', 0o755);
    sys.file('/home/u/proj/.claude/settings.local.json', '{ // mine\n}');
    const p = new ScriptedPrompter([
      { q: /^Set up an agent/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Write the Claude Code config/, a: '' },
      { q: /^Choice$/, a: '1' },
      { q: /^Project directory$/, a: '' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    expect(await agentStep(c)).toBe('skipped');
    expect(c.output()).toContain('not plain JSON');
    expect(sys.text('/home/u/proj/.claude/settings.local.json')).toBe('{ // mine\n}');
  });

  it('service mode: the files belong to the broker user, the hook and helper are the installed wrapper', async () => {
    const sys = new FakeSystem();
    sys.uid = 0;
    const b = new FakeBackend(sys);
    b.kind = 'service';
    b.denyDir = '/var/lib/keyflap/hook';
    b.hookCommand = (id) => `/usr/local/bin/keyflap hook claude-code --agent ${id} --service`;
    const c = ctx(sys, b, answers('y'));
    await agentStep(c);
    const st = sys.stat('/home/u/proj/.claude/settings.local.json');
    expect(st?.uid).toBe(1000);
    expect(sys.stat('/home/u/proj/.claude')?.uid).toBe(1000);
    const s = JSON.parse(sys.text('/home/u/proj/.claude/settings.local.json') as string);
    expect(s.sandbox.filesystem.denyRead).toEqual(['/var/lib/keyflap/hook/**']);
    expect(s.permissions.deny).toEqual([
      'Read(//var/lib/keyflap/hook/**)',
      'Edit(//var/lib/keyflap/hook/**)',
    ]);
    expect(s.hooks.UserPromptSubmit[0].hooks[0].command).toContain('--service');
  });
});

describe('invariant 4: setup wires the intent hook and keeps the host token from the model', () => {
  it('writes the hook, and denies the data dir to sandboxed commands and file tools', async () => {
    const sys = new FakeSystem();
    const p = new ScriptedPrompter([
      { q: /^Set up an agent/, a: '' },
      { q: /^Agent name/, a: 'my agent' },
      { q: /^Write the Claude Code config/, a: 'y' },
      { q: /^Choice$/, a: '2' },
      { q: /^Apply these changes\?/, a: 'y' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await agentStep(c);
    const s = JSON.parse(sys.text('/home/u/.claude/settings.json') as string);
    expect(s.hooks.UserPromptSubmit).toEqual([
      {
        hooks: [
          {
            type: 'command',
            command: `/usr/bin/node /repo/packages/cli/src/main.ts hook claude-code --agent ${AGENT_ID}`,
          },
        ],
      },
    ]);
    expect(s.hooks.UserPromptSubmit[0].hooks[0].command).not.toMatch(/\b(pnpm|npm|npx)\b/);
    expect(s.sandbox).toEqual({
      enabled: true,
      failIfUnavailable: true,
      allowUnsandboxedCommands: false,
      filesystem: { denyRead: ['~/.keyflap/**'], denyWrite: ['~/.keyflap/**'] },
    });
    expect(s.permissions.deny).toEqual(['Read(~/.keyflap/**)', 'Edit(~/.keyflap/**)']);
    const state = JSON.parse(sys.text('/home/u/.claude.json') as string);
    expect(state.mcpServers.keyflap.headersHelper).toContain('mcp-headers');
  });
});

describe('invariant 1: secrets typed into setup reach only their destination', () => {
  it('the agent token is never printed and lands only in its own 0600 file', async () => {
    const sys = new FakeSystem();
    const p = new ScriptedPrompter([
      { q: /^Set up an agent/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Write the Claude Code config/, a: 'y' },
      { q: /^Choice$/, a: '1' },
      { q: /^Project directory$/, a: '' },
      { q: /^Apply these changes\?/, a: 'y' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await agentStep(c);
    expect(c.output()).not.toContain(AGENT_TOKEN);
    const holders = sys.allText().filter(([, t]) => t.includes(AGENT_TOKEN));
    expect(holders.map(([p]) => p)).toEqual([`/home/u/.keyflap/agents/${AGENT_ID}.token`]);
    expect(sys.stat(`/home/u/.keyflap/agents/${AGENT_ID}.token`)?.mode).toBe(0o600);
    for (const e of sys.execs) expect(e.args.join(' ')).not.toContain(AGENT_TOKEN);
  });

  it('a password and TOTP seed are read as secrets and go only to the backend', async () => {
    const sys = new FakeSystem();
    const b = new FakeBackend(sys);
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '1' },
      { q: /^Site/, a: 'rp.localhost' },
      { q: /^Username/, a: 'alice' },
      { q: /one-time code \(TOTP\)\?/, a: 'y' },
      { q: /^Password \(not shown\)$/, a: 'hunter2-pw', secret: true },
      { q: /^TOTP secret or otpauth/, a: 'JBSWY3DPEHPK3PXP', secret: true },
      { q: /^Choice$/, a: 'skip' },
    ]);
    const c = ctx(sys, b, p);
    await credentialsStep(c);
    expect(b.passwords).toEqual([
      { site: 'rp.localhost', username: 'alice', password: 'hunter2-pw', totp: 'JBSWY3DPEHPK3PXP' },
    ]);
    expect(c.output()).toContain('Added a password + TOTP for rp.localhost (username alice)');
    expect(c.output()).not.toContain('hunter2-pw');
    expect(c.output()).not.toContain('JBSWY3DPEHPK3PXP');
    expect(sys.allText().some(([, t]) => t.includes('hunter2-pw'))).toBe(false);
  });

  it('the Proton Pass token goes to pass-cli login in its environment, never argv', async () => {
    const sys = new FakeSystem();
    sys.bins.set('pass-cli', '/usr/bin/pass-cli');
    let loggedIn = false;
    sys.exec_ = (_cmd, args, opts) => {
      if (args[0] === 'vault') {
        return loggedIn
          ? {
              code: 0,
              stdout: JSON.stringify({ vaults: [{ name: 'Agent' }, { name: 'Personal' }] }),
              stderr: '',
            }
          : { code: 1, stdout: '', stderr: 'requires a logged in session' };
      }
      if (args[0] === 'login') {
        loggedIn = opts.env?.PROTON_PASS_PERSONAL_ACCESS_TOKEN === 'pst_secret::key';
        return { code: loggedIn ? 0 : 1, stdout: '', stderr: '' };
      }
      return { code: 1, stdout: '', stderr: '' };
    };
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '2' },
      { q: /^Log in now\?/, a: 'y' },
      { q: /^Personal access token/, a: 'pst_secret::key', secret: true },
      { q: /^Vault to use/, a: 'Agent' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await credentialsStep(c);
    for (const e of sys.execs) expect([e.cmd, ...e.args].join(' ')).not.toContain('pst_secret');
    expect(c.output()).not.toContain('pst_secret');
    expect(c.state.passwordSource).toEqual({ kind: 'proton-pass', vault: 'Agent', bin: null });
    expect(sys.allText().some(([, t]) => t.includes('pst_secret'))).toBe(false);
    expect(p.remaining).toBe(0);
    expect(c.output().match(/Add (a|another) credential\?/g)).toHaveLength(1);
  });
});

describe('setup step 5: 1Password', () => {
  const TOKEN = 'ops_eyJzaWduSW5BZGRyZXNzIjoic2VjcmV0In0';
  function opSys(okToken = TOKEN) {
    const sys = new FakeSystem();
    sys.bins.set('op', '/usr/bin/op');
    sys.exec_ = (_cmd, args, opts) =>
      args[0] === 'vault' && opts.env?.OP_SERVICE_ACCOUNT_TOKEN === okToken
        ? {
            code: 0,
            stdout: JSON.stringify([
              { id: 'a'.repeat(26), name: 'Agent' },
              { id: 'b'.repeat(26), name: 'Private' },
            ]),
            stderr: '',
          }
        : { code: 1, stdout: '', stderr: '[ERROR] invalid token' };
    return sys;
  }

  it("checks the service account token in op's environment, never argv, and never saves it", async () => {
    const saved = process.env.OP_SERVICE_ACCOUNT_TOKEN;
    delete process.env.OP_SERVICE_ACCOUNT_TOKEN;
    try {
      const sys = opSys();
      const p = new ScriptedPrompter([
        { q: /^Choice$/, a: '3' },
        { q: /^Service account token/, a: TOKEN, secret: true },
        { q: /^Vault to use/, a: 'Agent' },
      ]);
      const c = ctx(sys, new FakeBackend(sys), p);
      const secretEnv: Record<string, string> = {};
      c.secretEnv = secretEnv;
      await credentialsStep(c);
      expect(sys.execs).toHaveLength(1);
      const e = sys.execs[0] as (typeof sys.execs)[number];
      expect([e.cmd, ...e.args]).toEqual(['/usr/bin/op', 'vault', 'list', '--format=json']);
      expect(e.opts).toMatchObject({
        cleanEnv: true,
        env: { OP_CACHE: 'false', OP_BIOMETRIC_UNLOCK_ENABLED: 'false' },
      });
      expect(c.state.passwordSource).toEqual({ kind: '1password', vault: 'Agent', bin: null });
      expect(c.output()).not.toContain(TOKEN);
      expect(sys.allText().some(([, t]) => t.includes(TOKEN))).toBe(false);
      expect(secretEnv).toEqual({ OP_SERVICE_ACCOUNT_TOKEN: TOKEN });
    } finally {
      if (saved !== undefined) process.env.OP_SERVICE_ACCOUNT_TOKEN = saved;
    }
  });

  it('a token op refuses sets nothing up', async () => {
    const sys = opSys('ops_the-right-one');
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '3' },
      { q: /^Service account token/, a: TOKEN, secret: true },
      { q: /^Choice$/, a: 'skip' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await credentialsStep(c);
    expect(c.state.passwordSource).toBeNull();
    expect(c.output()).toContain('op could not list vaults with that token');
    expect(p.remaining).toBe(0);
  });

  it('one source at a time: switching from Proton Pass asks first', async () => {
    const sys = opSys();
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '3' },
      { q: /^Switch to 1Password\?/, a: 'n' },
      { q: /^Choice$/, a: 'skip' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    c.state.passwordSource = { kind: 'proton-pass', vault: 'Agent', bin: null };
    await credentialsStep(c);
    expect(c.state.passwordSource).toEqual({ kind: 'proton-pass', vault: 'Agent', bin: null });
    expect(sys.execs).toEqual([]);
  });

  it('the daemon command line carries the source, never the token', () => {
    const s = emptyState(8765);
    s.passwordSource = { kind: '1password', vault: 'Agent', bin: '/opt/op/op' };
    const cmd = daemonCommand(s, { dataDir: '/d', defaultDataDir: '/d', defaultMcpPort: 8765 });
    expect(cmd.slice(3)).toEqual([
      '--password-source',
      '1password',
      '--1password-vault',
      'Agent',
      '--op-bin',
      '/opt/op/op',
    ]);
  });
});

describe('setup step 5 (service mode): password managers connect on the spot', () => {
  function serviceCtx(
    platform: 'linux' | 'darwin',
    start: Parameters<typeof machine>[1],
    script: ConstructorParameters<typeof ScriptedPrompter>[0],
  ) {
    const mach = machine(platform, start);
    const b = new FakeBackend(mach.sys);
    b.kind = 'service';
    const p = new ScriptedPrompter(script);
    return { mach, p, c: ctx(mach.sys, b, p, { paths: mach.paths }) };
  }

  it('Proton Pass: finds the root-only pass-cli, logs in as the signer, connects, restarts', async () => {
    const { mach, p, c } = serviceCtx('linux', undefined, [
      { q: /^Choice$/, a: '2' },
      { q: /^Proton Pass personal access token/, a: PROTON_TOKEN, secret: true },
      { q: /^Vault to use/, a: 'Agent' },
      { q: /^Connect Proton Pass \(vault Agent\)\?/, a: 'y' },
    ]);
    expect(await credentialsStep(c)).toBe('done');
    expect(p.remaining).toBe(0);
    expect(mach.config('core').passwordSource).toEqual({ kind: 'proton-pass' });
    expect(mach.calls.find((e) => e.cmd === PASS_BIN)?.opts.uid).toBe(SIGNER_UID);
    expect(mach.commands()).toContainEqual([
      'systemctl',
      'restart',
      'keyflap-signer',
      'keyflap-core',
    ]);
    expect(c.output()).not.toMatch(/install\.sh/);
    expect(c.output()).not.toContain(PROTON_TOKEN);
  });

  it('Proton Pass on macOS: logs in as _keyflap-signer and kickstarts both services', async () => {
    const { mach, c } = serviceCtx('darwin', undefined, [
      { q: /^Choice$/, a: '2' },
      { q: /^Proton Pass personal access token/, a: PROTON_TOKEN, secret: true },
      { q: /^Vault to use/, a: '' },
      { q: /^Connect Proton Pass \(every vault\)\?/, a: 'y' },
    ]);
    await credentialsStep(c);
    expect(mach.calls.find((e) => e.cmd === PASS_BIN && e.args[0] === 'login')?.opts.uid).toBe(
      MAC_SIGNER_UID,
    );
    expect(mach.commands().filter((e) => e[0] === 'launchctl' && e[1] === 'kickstart')).toEqual([
      ['launchctl', 'kickstart', '-k', 'system/com.keyflap.signer'],
      ['launchctl', 'kickstart', '-k', 'system/com.keyflap.core'],
    ]);
    expect(c.output()).not.toMatch(/systemctl|install\.sh/);
  });

  it('after a 1Password install, setup says it is connected and does not ask for the token again', async () => {
    const { mach, p, c } = serviceCtx('linux', { source: '1password', vault: 'Agent' }, [
      { q: /^Choice$/, a: '3' },
      { q: /^Change it\?/, a: '' },
      { q: /^Choice$/, a: 'skip' },
    ]);
    const before = mach.snapshot();
    await credentialsStep(c);
    expect(p.asked.some((q) => q.includes('token'))).toBe(false);
    expect(c.output()).toContain('1Password is connected, vault Agent.');
    expect(mach.snapshot()).toBe(before);
  });

  it('1Password: asks for the token without echo, checks it as the signer, seals it', async () => {
    const { mach, c } = serviceCtx('linux', undefined, [
      { q: /^Choice$/, a: '3' },
      { q: /^1Password service account token/, a: OP_TOKEN, secret: true },
      { q: /^Vault to use/, a: 'Agent' },
      { q: /^Connect 1Password \(vault Agent\)\?/, a: 'y' },
    ]);
    expect(await credentialsStep(c)).toBe('done');
    expect(mach.config('core').passwordSource).toEqual({ kind: '1password' });
    expect(mach.sys.exists(mach.paths.opToken)).toBe(true);
    expect(c.output()).not.toContain(OP_TOKEN);
    expect(mach.allArgv()).not.toContain(OP_TOKEN);
  });

  it('a pass-cli the signer would not run is refused with the fix, not "re-run install.sh"', async () => {
    const { mach, c } = serviceCtx('linux', undefined, [
      { q: /^Choice$/, a: '2' },
      { q: /^Choice$/, a: 'skip' },
    ]);
    mach.sys.tools.set(PASS_BIN, {
      ok: false,
      problem: 'untrusted',
      detail: `${PASS_BIN} is writable by group 1000, who could replace it`,
      fix: 'sudo chmod go-w /opt/keyflap/tools/pass-cli',
    });
    const before = mach.snapshot();
    await credentialsStep(c);
    expect(mach.calls.filter((e) => e.cmd === PASS_BIN)).toEqual([]);
    expect(c.output()).toContain('writable by group 1000');
    expect(c.output()).toContain('fix: sudo chmod go-w /opt/keyflap/tools/pass-cli');
    expect(c.output()).not.toMatch(/install\.sh/);
    expect(mach.snapshot()).toBe(before);
  });

  it('with 1Password installed, choosing Proton Pass connects it instead of saying "re-run install.sh"', async () => {
    const { mach, p, c } = serviceCtx('linux', { source: '1password', vault: 'Agent' }, [
      { q: /^Choice$/, a: '2' },
      { q: /^Replace 1Password\?/, a: 'y' },
      { q: /^Proton Pass personal access token/, a: PROTON_TOKEN, secret: true },
      { q: /^Vault to use/, a: 'Agent' },
    ]);
    expect(await credentialsStep(c)).toBe('done');
    expect(p.remaining).toBe(0);
    expect(c.output()).not.toMatch(/install\.sh|No pass-cli/);
    expect(mach.config('core').passwordSource).toEqual({ kind: 'proton-pass' });
    expect(mach.sys.exists(mach.paths.opToken)).toBe(false);
  });

  it('and answering no to the replacement leaves 1Password connected', async () => {
    const { mach, c } = serviceCtx('linux', { source: '1password', vault: 'Agent' }, [
      { q: /^Choice$/, a: '2' },
      { q: /^Replace 1Password\?/, a: '' },
      { q: /^Choice$/, a: 'skip' },
    ]);
    const before = mach.snapshot();
    await credentialsStep(c);
    expect(mach.snapshot()).toBe(before);
    expect(c.output()).toContain('Nothing changed.');
  });
});

describe('setup steps 1 and 6', () => {
  it('preflight (service): stops when a unit is not active', async () => {
    const sys = new FakeSystem();
    sys.exec_ = (_c, args) => ({
      code: 0,
      stdout: args[1] === 'keyflap-core.service' ? 'failed\n' : 'active\n',
      stderr: '',
    });
    const b = new FakeBackend(sys);
    b.kind = 'service';
    const c = ctx(sys, b, new ScriptedPrompter([]), { paths: SERVICE_PATHS });
    await expect(preflight(c)).rejects.toThrow(/keyflap-core not active/);
  });

  it('preflight (service, macOS): reads launchctl, names the label and the log file', async () => {
    const sys = new FakeSystem();
    sys.platform = 'darwin';
    sys.exec_ = (_c, args) =>
      args[1] === 'system/com.keyflap.core'
        ? { code: 113, stdout: '', stderr: '' }
        : { code: 0, stdout: 'system/x = {\n\tstate = running\n}\n', stderr: '' };
    const b = new FakeBackend(sys);
    b.kind = 'service';
    const c = ctx(sys, b, new ScriptedPrompter([]), { paths: DARWIN_SERVICE_PATHS });
    await expect(preflight(c)).rejects.toThrow(
      'com.keyflap.core not active: sudo launchctl print system/com.keyflap.core (and sudo tail -n 50 /Library/Keyflap/log/core/core.log)',
    );
    expect(sys.execs.map((e) => e.cmd)).toEqual(['launchctl', 'launchctl', 'launchctl']);
  });

  it('preflight (dev, macOS): warns when the core LaunchDaemon is installed, without systemctl', async () => {
    const sys = new FakeSystem();
    sys.platform = 'darwin';
    sys.file('/Library/LaunchDaemons/com.keyflap.core.plist', '<plist/>', 0o644, 0);
    const b = new FakeBackend(sys);
    const c = ctx(sys, b, new ScriptedPrompter([]), { dataDir: '/home/u/dev-data' });
    await preflight(c);
    expect(sys.execs).toEqual([]);
    expect(c.output()).toContain('You probably want `sudo keyflap setup`');
  });

  it('preflight (dev): creates the data dir 0700 and warns when service mode is installed', async () => {
    const sys = new FakeSystem();
    sys.exec_ = () => ({ code: 0, stdout: 'keyflap-core.service enabled enabled\n', stderr: '' });
    const b = new FakeBackend(sys);
    const c = ctx(sys, b, new ScriptedPrompter([]), { dataDir: '/home/u/dev-data' });
    await preflight(c);
    expect(sys.stat('/home/u/dev-data')?.mode).toBe(0o700);
    expect(c.output()).toContain('You probably want `sudo keyflap setup`');
  });

  it('finish (dev): records --headed, prints the daemon command, runs doctor', async () => {
    const sys = new FakeSystem();
    let doctorRan = false;
    const c = ctx(sys, new FakeBackend(sys), new ScriptedPrompter([{ q: /--headed/, a: 'y' }]), {
      doctor: async () => {
        doctorRan = true;
        return { mode: 'dev', ok: true, checks: [] };
      },
    });
    c.state.approver = {
      kind: 'phone',
      origin: 'https://b.tail1.ts.net:8766',
      listen: { host: '127.0.0.1', port: 8766 },
      tlsCert: null,
      tlsKey: null,
      via: 'tailscale',
    };
    await finishStep(c);
    expect(c.output()).toContain(
      'keyflap daemon --unprotected --headed --approver phone --approver-origin https://b.tail1.ts.net:8766',
    );
    expect(doctorRan).toBe(true);
    expect(c.output()).toContain('http://rp.localhost:3000/password/login');
    expect(c.state.headed).toBe(true);
  });
});

describe('closing tips', () => {
  it('service mode suggests a real sign-in; only dev mode points at the test RP', () => {
    const svc = walkthrough('service');
    expect(svc).toContain('> Sign in to <site>');
    expect(svc).not.toMatch(/test-rp|rp\.localhost|checkout|correct horse/);
    const dev = walkthrough('dev');
    expect(dev).toContain('pnpm test-rp');
    expect(dev).toContain('http://rp.localhost:3000/password/login');
  });

  it('names the admin command as sudo keyflap on every platform', () => {
    expect(walkthrough('service')).toContain('stored with sudo keyflap password add <site>');
  });
});

describe('service backend (sudo keyflap setup)', () => {
  it('talks to the admin sockets and stores the token as the broker user, 0600', async () => {
    const { serviceBackend } = await import('../src/setup/backend.ts');
    const sys = new FakeSystem();
    sys.uid = 0;
    sys.dir('/var/lib/keyflap/hook', 0o700, 1000);
    sys.file('/etc/passwd', 'root:x:0:0::/root:/bin/sh\nu:x:1000:1000::/home/u:/bin/bash\n');
    const calls: string[] = [];
    let approvers = 0;
    let addressState: Record<string, unknown> = { kind: 'ok', checkedAt: 1 };
    const admin = async <T>(socket: string, op: string) => {
      calls.push(`${socket} ${op}`);
      const r: Record<string, unknown> = {
        'agent.add': { id: AGENT_ID, name: 'claude-code', token: AGENT_TOKEN },
        'approver.pair': { url: 'https://b.ts.net:8766/pair#X', origin: 'https://b.ts.net:8766' },
        'approver.address.clear': { state: addressState },
        status:
          socket === SERVICE_PATHS.signerAdminSocket
            ? { approvers: approvers++ }
            : { mcpUrl: 'http://127.0.0.1:9100/mcp' },
      };
      return r[op] as T;
    };
    const b = await serviceBackend({ sys, paths: SERVICE_PATHS, admin });
    expect(b.user).toMatchObject({ uid: 1000, name: 'u', home: '/home/u' });
    expect(await b.mcpPort()).toBe(9100);
    const a = await b.createAgent('claude-code');
    const path = b.storeAgentToken(a.id, a.token);
    expect(path).toBe(`/var/lib/keyflap/hook/agent-${AGENT_ID}.token`);
    expect(sys.stat(path)).toMatchObject({ uid: 1000, mode: 0o600 });
    expect(b.hookCommand(AGENT_ID)).toBe(
      `/usr/local/bin/keyflap hook claude-code --agent ${AGENT_ID} --service`,
    );
    expect(b.headersCommand(AGENT_ID)).toBe(
      `/usr/local/bin/keyflap mcp-headers --agent ${AGENT_ID} --service`,
    );
    let shown = '';
    const r = await b.pair({
      origin: '',
      listen: { host: '127.0.0.1', port: 8766 },
      tls: null,
      timeoutMs: 10_000,
      signal: new AbortController().signal,
      onOpen: async (url) => {
        shown = url;
      },
    });
    expect(r).toBe('paired');
    expect(shown).toBe('https://b.ts.net:8766/pair#X');
    const cleared = calls.indexOf(`${SERVICE_PATHS.signerAdminSocket} approver.address.clear`);
    expect(cleared).toBeGreaterThanOrEqual(0);
    expect(cleared).toBeLessThan(calls.indexOf(`${SERVICE_PATHS.adminSocket} approver.pair`));

    addressState = {
      kind: 'latched',
      at: Date.UTC(2026, 9, 30),
      seen: 'b.ts.net:8766 is on Funnel',
    };
    sys.file(
      '/etc/keyflap/signer.json',
      JSON.stringify({
        approverAddress: { origin: 'https://b.ts.net:8766', target: 'http://127.0.0.1:8766' },
      }),
      0o644,
      0,
    );
    const before = calls.length;
    await expect(
      b.pair({
        origin: '',
        listen: { host: '127.0.0.1', port: 8766 },
        tls: null,
        timeoutMs: 10_000,
        signal: new AbortController().signal,
        onOpen: async () => {},
      }),
    ).rejects.toThrow(
      /the approval address is off: it was changed at 2026-10-30T00:00:00\.000Z \(b\.ts\.net:8766 is on Funnel\), so phones were signed out to be safe\.\n {2}Approvals are off until it is fixed at this computer\.\n {2}fix: sudo tailscale serve reset \(it clears every serve setting on this computer\), then sudo tailscale serve --bg --https=8766 http:\/\/127\.0\.0\.1:8766, then sudo keyflap approver pair/,
    );
    expect(calls.slice(before)).not.toContain(`${SERVICE_PATHS.adminSocket} approver.pair`);
  });
});

describe('setup step 4: every installed agent host', () => {
  const claude = (apply = 'y') => [
    { q: /^Set up an agent for Claude Code\?/, a: '' },
    { q: /^Agent name/, a: '' },
    { q: /^Write the Claude Code config/, a: '' },
    { q: /^Choice$/, a: '2' },
    { q: /^Apply these changes\?/, a: apply },
  ];
  const codex = (apply = 'y') => [
    { q: /^Set up an agent for Codex\?/, a: '' },
    { q: /^Agent name/, a: '' },
    { q: /^Write the Codex config/, a: '' },
    { q: /^Apply these changes\?/, a: apply },
  ];
  const both = () => new FakeSystem().dir('/home/u/.claude', 0o700).dir('/home/u/.codex', 0o700);

  it('Claude Code and Codex: each gets its own agent, its own preview and its own files', async () => {
    const sys = both();
    const b = new FakeBackend(sys);
    const p = new ScriptedPrompter([...claude(), ...codex()]);
    const c = ctx(sys, b, p);
    expect(await agentStep(c)).toBe('done');
    expect(p.remaining).toBe(0);
    expect(c.output()).not.toContain('Which agent host');
    const [claudeAgent, codexAgent] = b.agents;
    expect(b.agents.map((a) => a.name)).toEqual(['claude-code', 'codex']);
    expect(claudeAgent?.id).not.toBe(codexAgent?.id);
    expect(sys.text('/home/u/.claude/settings.json')).toContain(`--agent ${claudeAgent?.id}`);
    expect(sys.text('/home/u/.claude/settings.json')).not.toContain(codexAgent?.id as string);
    expect(sys.text('/home/u/.codex/hooks.json')).toContain(`hook codex --agent ${codexAgent?.id}`);
    expect(sys.text('/home/u/.codex/hooks.json')).not.toContain(claudeAgent?.id as string);
    expect(c.output()).toContain('/home/u/.claude/settings.json: new file');
    expect(c.output()).toContain('/home/u/.codex/hooks.json: new file');
    expect(c.state.claudeCode).toEqual([
      { agentId: claudeAgent?.id, scope: 'user', project: null },
    ]);
    expect(c.state.agentHosts).toEqual([
      { host: 'codex', agentId: codexAgent?.id, dir: '/home/u/.codex' },
    ]);
    expect(c.output()).toContain('"/home/u/.keyflap" = "deny"');
    expect(c.output()).toContain('then run /hooks in Codex and trust the keyflap hook');
    for (const [path, text] of sys.allText()) {
      if (!path.endsWith('.token')) expect(text, path).not.toMatch(/aab_agent_/);
    }
    expect(c.output()).not.toMatch(/aab_agent_/);
  });

  it('Claude Code is offered even when only Codex is installed', async () => {
    const sys = new FakeSystem().dir('/home/u/.codex', 0o700);
    const p = new ScriptedPrompter([
      { q: /^Set up an agent for Claude Code\?/, a: 'n' },
      ...codex(),
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    expect(await agentStep(c)).toBe('done');
    expect(c.state.claudeCode).toEqual([]);
    expect(c.state.agentHosts?.map((h) => h.host)).toEqual(['codex']);
    expect(p.remaining).toBe(0);
  });

  it('a host declined at its preview is skipped alone; the other is still set up', async () => {
    const sys = both();
    const p = new ScriptedPrompter([...claude('y'), ...codex('n')]);
    const c = ctx(sys, new FakeBackend(sys), p);
    expect(await agentStep(c)).toBe('done');
    expect(sys.exists('/home/u/.claude/settings.json')).toBe(true);
    expect(sys.exists('/home/u/.codex/hooks.json')).toBe(false);
    expect(c.state.claudeCode).toHaveLength(1);
    expect(c.state.agentHosts ?? []).toEqual([]);
  });

  it('every host skipped: the step is skipped and nothing is recorded', async () => {
    const sys = both();
    const p = new ScriptedPrompter([
      { q: /^Set up an agent for Claude Code\?/, a: 'n' },
      { q: /^Set up an agent for Codex\?/, a: 'n' },
    ]);
    const b = new FakeBackend(sys);
    const c = ctx(sys, b, p);
    expect(await agentStep(c)).toBe('skipped');
    expect(b.agents).toEqual([]);
    expect(c.state.claudeCode).toEqual([]);
  });

  it('--host sets up only that host, whatever else is installed', async () => {
    const sys = both();
    const p = new ScriptedPrompter(codex());
    const c = ctx(sys, new FakeBackend(sys), p, { host: 'codex' });
    expect(await agentStep(c)).toBe('done');
    expect(sys.exists('/home/u/.claude/settings.json')).toBe(false);
    expect(c.state.claudeCode).toEqual([]);
    expect(p.remaining).toBe(0);
  });

  it('a host may not take the agent another host uses', async () => {
    const sys = both();
    const b = new FakeBackend(sys);
    const p = new ScriptedPrompter([
      ...claude(),
      { q: /^Set up an agent for Codex\?/, a: '' },
      { q: /^Agent name/, a: 'claude-code' },
      { q: /^Agent name/, a: '' },
      { q: /^Write the Codex config/, a: '' },
      { q: /^Apply these changes\?/, a: 'y' },
    ]);
    const c = ctx(sys, b, p);
    await agentStep(c);
    expect(c.output()).toContain('"claude-code" already serves another host');
    expect(b.agents.map((a) => a.name)).toEqual(['claude-code', 'codex']);
    expect(p.remaining).toBe(0);
  });

  it('a re-run recognises both hosts: same agents reused, nothing duplicated or rewritten', async () => {
    const sys = both();
    const b = new FakeBackend(sys);
    const first = ctx(sys, b, new ScriptedPrompter([...claude(), ...codex()]));
    await agentStep(first);
    const hooks = sys.text('/home/u/.codex/hooks.json');
    const state = loadState(sys, b.stateDir, 8765, b.fileOwner);
    expect(state.agentHosts).toHaveLength(1);
    const reuse = (host: string) => ({
      q: new RegExp(`^Use the existing agent "${host}"\\?`),
      a: '',
    });
    const p = new ScriptedPrompter([
      { q: /^Set up an agent for Claude Code\?/, a: '' },
      { q: /^Agent name/, a: '' },
      reuse('claude-code'),
      { q: /^Write the Claude Code config/, a: '' },
      { q: /^Choice$/, a: '2' },
      { q: /^Apply these changes\?/, a: 'y' },
      { q: /^Set up an agent for Codex\?/, a: '' },
      { q: /^Agent name/, a: '' },
      reuse('codex'),
      { q: /^Write the Codex config/, a: '' },
      { q: /^Apply these changes\?/, a: 'y' },
    ]);
    const c = ctx(sys, b, p, { state });
    expect(await agentStep(c)).toBe('done');
    expect(p.remaining).toBe(0);
    expect(b.agents).toHaveLength(2);
    expect(c.output()).toContain('settings.json: already up to date');
    expect(c.output()).toContain('hooks.json: already up to date');
    expect(sys.text('/home/u/.codex/hooks.json')).toBe(hooks);
    expect([...sys.nodes.keys()].filter((k) => k.includes('backup'))).toEqual([]);
    expect(c.state.claudeCode).toHaveLength(1);
    expect(c.state.agentHosts).toHaveLength(1);
  });

  it('finish lists every host that was set up', async () => {
    const sys = new FakeSystem();
    const c = ctx(sys, new FakeBackend(sys), new ScriptedPrompter([{ q: /--headed/, a: '' }]));
    c.state.claudeCode = [
      { agentId: AGENT_ID, scope: 'user', project: null },
      { agentId: AGENT_ID, scope: 'project', project: '/home/u/proj' },
    ];
    c.state.agentHosts = [
      { host: 'codex', agentId: 'c', dir: '/home/u/.codex' },
      { host: 'hermes', agentId: 'h', dir: '/home/u/.hermes' },
    ];
    await finishStep(c);
    expect(setUpHosts(c.state, '/home/u')).toEqual([
      'Claude Code, all projects (terminal and desktop app)',
      'Claude Code, ~/proj',
      'Codex',
      'Hermes Agent',
    ]);
    for (const line of setUpHosts(c.state, '/home/u')) expect(c.output()).toContain(`✓ ${line}`);
  });
});

describe('agent-led setup: setup pre-selects what it detects', () => {
  it('run from the home directory, the Claude Code config defaults to all projects; still asks before writing', async () => {
    const sys = new FakeSystem();
    sys.cwd = '/home/u';
    const p = new ScriptedPrompter([
      { q: /^Set up an agent/, a: '' },
      { q: /^Agent name/, a: '' },
      { q: /^Write the Claude Code config/, a: '' },
      { q: /^Choice$/, a: '' },
      { q: /^Apply these changes\? \[y\/N\]$/, a: '' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    expect(await agentStep(c)).toBe('skipped');
    expect(c.output()).toContain(
      '2) All your projects (~/.claude.json and ~/.claude/settings.json)  (default)',
    );
    expect(c.output()).toContain('/home/u/.claude/settings.json: new file');
    expect(c.output()).toContain('Nothing written.');
    expect(sys.exists('/home/u/.claude/settings.json')).toBe(false);
  });

  it('service mode runs only a root-owned tailscale, never one found on PATH', async () => {
    const sys = new FakeSystem();
    sys.uid = 0;
    sys.bins.set('tailscale', '/home/u/bin/tailscale');
    sys.file('/home/u/bin/tailscale', '', 0o755, 1000);
    sys.dir('/', 0o755, 0).dir('/usr', 0o755, 0).dir('/usr/bin', 0o755, 0);
    sys.file('/usr/bin/tailscale', '', 0o755, 0);
    sys.dir('/etc/keyflap', 0o755, 0);
    sys.file(
      SERVICE_PATHS.approverConfig,
      JSON.stringify({ origin: 'https://b.tail1.ts.net:8766' }),
    );
    sys.exec_ = (_cmd, args) =>
      args[0] === 'status'
        ? {
            code: 0,
            stdout: JSON.stringify({
              BackendState: 'Running',
              Self: { DNSName: 'b.tail1.ts.net.' },
              CertDomains: ['b.tail1.ts.net'],
            }),
            stderr: '',
          }
        : { code: 0, stdout: '{}', stderr: '' };
    const b = new FakeBackend(sys);
    b.kind = 'service';
    const p = new ScriptedPrompter([{ q: /^Run it\? \[Y\/n\]$/, a: 'n' }]);
    const c = ctx(sys, b, p, { paths: SERVICE_PATHS });
    await approverStep(c);
    expect(sys.execs.map((e) => e.cmd)).toEqual(['/usr/bin/tailscale', '/usr/bin/tailscale']);
    expect(c.output()).toContain(
      '$ /usr/bin/tailscale serve --bg --https=8766 http://127.0.0.1:8766',
    );
  });

  it('service mode runs a tailscale someone other than root can change only as the user (the macOS app)', async () => {
    const sys = new FakeSystem();
    sys.uid = 0;
    sys.platform = 'darwin';
    const app = '/Applications/Tailscale.app/Contents/MacOS/Tailscale';
    sys.dir('/', 0o755, 0).dir('/Applications', 0o775, 0);
    sys.file(app, '', 0o755, 0);
    sys.dir('/Library/Keyflap/etc', 0o755, 0);
    sys.file(
      DARWIN_SERVICE_PATHS.approverConfig,
      JSON.stringify({ origin: 'https://b.tail1.ts.net:8766' }),
    );
    sys.exec_ = () => ({ code: 1, stdout: '', stderr: '' });
    const b = new FakeBackend(sys);
    b.kind = 'service';
    const c = ctx(sys, b, new ScriptedPrompter([]), { paths: DARWIN_SERVICE_PATHS });
    await approverStep(c);
    expect(sys.execs.map((e) => [e.cmd, e.opts.uid])).toEqual([[app, 1000]]);
  });

  it('dev mode on macOS finds the Tailscale app CLI when tailscale is not on PATH', async () => {
    const sys = new FakeSystem();
    sys.platform = 'darwin';
    const app = '/Applications/Tailscale.app/Contents/MacOS/Tailscale';
    sys.file(app, '', 0o755, 0);
    sys.exec_ = () => ({ code: 1, stdout: '', stderr: '' });
    const p = new ScriptedPrompter([
      { q: /^Choice$/, a: '1' },
      { q: /^Approver origin/, a: 'https://b.example:8766' },
      { q: /^Does the approver serve TLS itself/, a: '' },
      { q: /^Listen address/, a: '' },
    ]);
    const c = ctx(sys, new FakeBackend(sys), p);
    await approverStep(c);
    expect(sys.execs[0]?.cmd).toBe(app);
  });
});

describe('agent-led setup: importing an Apple Passwords export', () => {
  const CSV = [
    'Title,URL,Username,Password,Notes,OTPAuth',
    'GitHub,https://github.com/login,alice,gh-secret-pw,,',
    'Example,https://app.example.com/,bob,ex-secret-pw,,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP',
    '',
  ].join('\n');

  function serviceCtx(answers: { q: RegExp; a: string; secret?: boolean }[]) {
    const sys = new FakeSystem();
    sys.uid = 0;
    sys.dir('/home/u/Downloads', 0o700, 1000);
    sys.file('/home/u/Downloads/Passwords 2.csv', CSV, 0o600, 1000);
    sys.dir('/etc/keyflap', 0o755, 0);
    sys.file(SERVICE_PATHS.coreConfig, JSON.stringify({ passwordSource: null }), 0o644, 0);
    const b = new FakeBackend(sys);
    b.kind = 'service';
    const p = new ScriptedPrompter(answers);
    return { sys, b, p, c: ctx(sys, b, p, { paths: SERVICE_PATHS }) };
  }

  it('is the default in service mode with no password source, reads the file as the user, stores what you pick', async () => {
    const { sys, b, p, c } = serviceCtx([
      { q: /^Choice$/, a: '' },
      { q: /^Export file/, a: '~/Downloads/Passwords\\ 2.csv ' },
      { q: /^Sites your agents need/, a: 'github.com' },
      { q: /^Store 1 login in Keyflap\? \[y\/N\]$/, a: 'y' },
      { q: /^Choice$/, a: '' },
    ]);
    await credentialsStep(c);
    expect(c.output()).toContain('4) Import an export: Apple Passwords');
    expect(c.output()).toMatch(/Apple Passwords export, 2 usable logins/);
    expect(c.output()).toMatch(/github\.com\s+alice\s+no/);
    expect(c.output()).toMatch(/example\.com\s+bob\s+yes/);
    expect(b.passwords).toEqual([
      { site: 'https://github.com/login', username: 'alice', password: 'gh-secret-pw', totp: null },
    ]);
    expect(sys.userAccess).toContainEqual({
      op: 'read',
      path: '/home/u/Downloads/Passwords 2.csv',
      owner: { uid: 1000, gid: 1000 },
    });
    expect(c.output()).toContain('still holds every password in plaintext. Delete it');
    expect(c.output()).not.toContain('secret-pw');
    expect(c.output()).not.toContain('JBSWY3DPEHPK3PXP');
    expect(p.remaining).toBe(0);
  });

  it('stores nothing unless you say yes', async () => {
    const { b, c } = serviceCtx([
      { q: /^Choice$/, a: '4' },
      { q: /^Export file/, a: "'/home/u/Downloads/Passwords 2.csv'" },
      { q: /^Sites your agents need/, a: '' },
      { q: /^Store 2 logins in Keyflap\? \[y\/N\]$/, a: '' },
      { q: /^Choice$/, a: 'skip' },
    ]);
    await credentialsStep(c);
    expect(b.passwords).toEqual([]);
    expect(c.output()).toContain('Nothing stored.');
  });

  it('a configured password source is the default instead', async () => {
    const sys = new FakeSystem();
    sys.dir('/etc/keyflap', 0o755, 0);
    sys.file(SERVICE_PATHS.coreConfig, JSON.stringify({ passwordSource: { kind: '1password' } }));
    const b = new FakeBackend(sys);
    b.kind = 'service';
    const c = ctx(sys, b, new ScriptedPrompter([]), { paths: SERVICE_PATHS });
    expect(firstCredentialChoice(c, 0)).toBe('1password');
    sys.file(SERVICE_PATHS.coreConfig, JSON.stringify({ passwordSource: null }));
    expect(firstCredentialChoice(c, 0)).toBe('import');
    expect(firstCredentialChoice(c, 3)).toBe('skip');
    b.kind = 'dev';
    expect(firstCredentialChoice(c, 0)).toBe('skip');
  });
});
