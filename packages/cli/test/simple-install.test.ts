import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { encodeQr } from '@aab/approver';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DaemonStartError, getPassphrase } from '../src/daemon.ts';
import { type DevDoctorContext, formatReport, runChecks } from '../src/doctor.ts';
import {
  createKeyFile,
  KEY_FILE_BYTES,
  KeyFileError,
  keyFilePath,
  readKeyFile,
  unlockFromKeyFile,
} from '../src/key-file.ts';
import { emptyState, type SetupState } from '../src/setup/state.ts';
import {
  approverStep,
  credentialsStep,
  finishStep,
  type SetupContext,
  waitForDaemonStopped,
} from '../src/setup/steps.ts';
import { plainUi } from '../src/setup/ui.ts';
import {
  FULL_INSTALL_COMMAND,
  launchAgentPlist,
  PROTECTS_LESS,
  SIMPLE_INSTALL_COMMAND,
  SIMPLE_LABEL,
  simpleInstall,
  simpleStopHint,
} from '../src/simple-install.ts';
import { status } from '../src/status.ts';
import { FakeBackend, FakeSystem, ScriptedPrompter } from './setup-fakes.ts';

const INSTALL = join(import.meta.dirname, '..', '..', 'install');
const HOME = '/Users/u';
const SIMPLE = simpleInstall(HOME);

let dir = '';
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'kf-simple-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('the key file that unlocks the simple install', () => {
  it('is created 0600 with 32 random bytes, and unlocks the same store every time', () => {
    const data = join(dir, 'data');
    const first = createKeyFile(data);
    const st = statSync(keyFilePath(data));
    expect(st.mode & 0o777).toBe(0o600);
    expect(st.size).toBe(KEY_FILE_BYTES);
    expect(statSync(data).mode & 0o777).toBe(0o700);
    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(unlockFromKeyFile(data, { create: true })).toBe(first);
    expect(unlockFromKeyFile(data, { create: false })).toBe(first);
    expect(readFileSync(keyFilePath(data)).toString('base64url')).toBe(first);
  });

  it('is never made next to a key store that a passphrase unlocks', () => {
    mkdirSync(join(dir, 'signer'), { recursive: true });
    writeFileSync(join(dir, 'signer', 'keys.enc.json'), '{}');
    expect(() => createKeyFile(dir)).toThrow(/made with a passphrase/);
    expect(() => unlockFromKeyFile(dir, { create: true })).toThrow(KeyFileError);
  });

  it('without a key file and outside the simple install, nothing is made', () => {
    expect(unlockFromKeyFile(dir, { create: false })).toBeNull();
    expect(() => statSync(keyFilePath(dir))).toThrow();
  });

  it('refuses a key file anyone else can read, a link, a wrong size, or one of another uid', () => {
    const path = keyFilePath(dir);
    writeFileSync(path, Buffer.alloc(KEY_FILE_BYTES, 1), { mode: 0o600 });
    chmodSync(path, 0o640);
    expect(() => readKeyFile(path)).toThrow(/must be 0600/);
    chmodSync(path, 0o600);
    expect(() => readKeyFile(path, (process.getuid?.() ?? 0) + 1)).toThrow(/not to you/);
    writeFileSync(path, Buffer.alloc(KEY_FILE_BYTES - 1, 1));
    expect(() => readKeyFile(path)).toThrow(/exactly 32 bytes/);
    const link = join(dir, 'link.key');
    symlinkSync(path, link);
    expect(() => readKeyFile(link)).toThrow(/symbolic link/);
  });

  it('the daemon unlocks from it without a terminal, and refuses a passphrase as well', async () => {
    const first = createKeyFile(dir);
    const saved = process.env.KEYFLAP_PASSPHRASE;
    try {
      delete process.env.KEYFLAP_PASSPHRASE;
      expect(await getPassphrase(dir)).toBe(first);
      process.env.KEYFLAP_PASSPHRASE = 'typed';
      await expect(getPassphrase(dir)).rejects.toThrow(DaemonStartError);
      expect(process.env.KEYFLAP_PASSPHRASE).toBeUndefined();
    } finally {
      if (saved === undefined) delete process.env.KEYFLAP_PASSPHRASE;
      else process.env.KEYFLAP_PASSPHRASE = saved;
    }
  });
});

describe('the LaunchAgent', () => {
  const args = [
    'daemon',
    '--unprotected',
    '--approver',
    'phone',
    '--approver-origin',
    'https://mac.tail1.ts.net:8766',
  ];

  it('runs the installed Node on the installed CLI with the daemon arguments, and holds no secret', () => {
    const xml = launchAgentPlist(SIMPLE, args);
    const strings = [...xml.matchAll(/<string>([^<]*)<\/string>/g)].map((m) => m[1]);
    const program = xml.slice(xml.indexOf('<array>'), xml.indexOf('</array>'));
    expect([...program.matchAll(/<string>([^<]*)<\/string>/g)].map((m) => m[1])).toEqual([
      `${HOME}/Library/Application Support/Keyflap/node/bin/node`,
      '--disable-warning=ExperimentalWarning',
      `${HOME}/Library/Application Support/Keyflap/app/packages/cli/src/main.ts`,
      ...args,
    ]);
    expect(strings[0]).toBe(SIMPLE_LABEL);
    expect(xml).toContain('<key>RunAtLoad</key>\n  <true/>');
    expect(xml).toContain('<key>SuccessfulExit</key>\n    <false/>');
    expect(xml).toContain(`<string>${HOME}/Library/Logs/Keyflap/daemon.log</string>`);
    expect(xml).toContain(
      `<key>PLAYWRIGHT_BROWSERS_PATH</key>\n    <string>${SIMPLE.browsers}</string>`,
    );
    expect(xml).not.toMatch(/PASSPHRASE|OP_SERVICE_ACCOUNT_TOKEN|unlock\.key|--key/);
  });

  it('the daemon log says how to stop the background job and remove it, not Ctrl-C', () => {
    const hint = simpleStopHint(501, HOME);
    expect(hint).toContain(`launchctl bootout gui/501/${SIMPLE_LABEL}`);
    expect(hint).toContain(`"${SIMPLE.uninstaller}"`);
    expect(hint).not.toMatch(/Ctrl-C/);
  });

  it('escapes XML in paths and refuses control characters', () => {
    const odd = simpleInstall('/Users/a&b<c');
    expect(launchAgentPlist(odd, args)).toContain('/Users/a&amp;b&lt;c/Library/');
    expect(() => launchAgentPlist(SIMPLE, ['daemon', 'x\ny'])).toThrow(/control character/);
  });
});

describe('the "protects less" label', () => {
  it('is word for word the same in the installers the person runs first', () => {
    for (const f of ['bootstrap/install-keyflap.sh.in', 'macos/install-simple.sh']) {
      expect(readFileSync(join(INSTALL, f), 'utf8'), f).toContain(PROTECTS_LESS);
    }
  });

  it('and the agent install guide quotes it and both commands word for word', () => {
    const guide = readFileSync(join(INSTALL, '..', '..', 'docs', 'INSTALL_FOR_AGENTS.md'), 'utf8');
    expect(guide).toContain(PROTECTS_LESS);
    expect(guide).toContain(SIMPLE_INSTALL_COMMAND);
    expect(guide).toContain(FULL_INSTALL_COMMAND);
  });

  it('heads keyflap status for a data dir the key file unlocks', () => {
    let text = '';
    const r = status({ dataDir: dir, json: false, simple: true }, (t) => {
      text += t;
    });
    expect(text.split('\n')[0]).toBe(PROTECTS_LESS);
    expect(r.install).toBe('simple');
    let plain = '';
    expect(status({ dataDir: dir, json: false }, (t) => (plain += t)).install).toBe('dev');
    expect(plain).not.toContain(PROTECTS_LESS);
  });

  it('is a doctor warning with the full install as the fix, next to the LaunchAgent check', async () => {
    const sys = new FakeSystem();
    sys.platform = 'darwin';
    sys.dir(SIMPLE.dataDir, 0o700);
    sys.exec_ = (cmd, a) =>
      cmd === '/bin/launchctl' && a[0] === 'print'
        ? { code: 1, stdout: '', stderr: 'Could not find service' }
        : { code: 1, stdout: '', stderr: '' };
    const ctx: DevDoctorContext = {
      mode: 'dev',
      sys,
      project: HOME,
      home: HOME,
      owner: { uid: 1000, gid: 1000 },
      dataDir: SIMPLE.dataDir,
      state: null,
      simple: SIMPLE,
      daemonCommand: `launchctl kickstart -k gui/1000/${SIMPLE_LABEL}`,
      chromium: async () => ({ ok: true }),
      nodeVersion: '22.23.4',
      local: {
        agents: () => [],
        audit: () => ({ intact: true, entries: 0, brokenAt: null }),
        passwords: () => 0,
      },
    };
    const r = await runChecks(ctx);
    expect(r.mode).toBe('simple');
    expect(r.checks.find((c) => c.id === 'protection')).toEqual({
      id: 'protection',
      status: 'warn',
      detail: PROTECTS_LESS,
      fix: `'${SIMPLE.uninstaller}', then the full install: ${FULL_INSTALL_COMMAND}`,
    });
    expect(r.checks.find((c) => c.id === 'background')?.status).toBe('fail');
    expect(r.checks.find((c) => c.id === 'daemon')?.fix).toBe(ctx.daemonCommand);
    expect(r.checks.find((c) => c.id === 'headed')?.status).toBe('ok');
    expect(r.checks.some((c) => c.id === 'hook-code')).toBe(false);
    const text = formatReport(r);
    expect(text.split('\n')[0]).toBe('keyflap doctor (simple install)');
    expect(text).toContain(PROTECTS_LESS);
  });
});

function simpleCtx(sys: FakeSystem, backend: FakeBackend, prompt: ScriptedPrompter) {
  let out = '';
  const write = (t: string) => {
    out += t;
  };
  const state: SetupState = {
    ...emptyState(8765),
    approver: {
      kind: 'phone',
      origin: 'https://mac.tail1.ts.net:8766',
      listen: { host: '127.0.0.1', port: 8766 },
      tlsCert: null,
      tlsKey: null,
      via: 'tailscale',
    },
  };
  const c: SetupContext = {
    sys,
    prompt,
    out: write,
    ui: plainUi(write, prompt),
    backend,
    state,
    dataDir: SIMPLE.dataDir,
    defaults: { dataDir: SIMPLE.dataDir, mcpPort: 8765 },
    paths: null,
    simple: SIMPLE,
    qr: (url) => ({ code: encodeQr(url), printed: '[QR]' }),
    pairingTimeoutMs: 600_000,
    chromium: () => ({ path: '/c', present: true }),
    doctor: async () => ({ mode: 'simple', ok: true, checks: [] }),
    startDaemon: null,
    interruptible: (fn) => fn(new AbortController().signal),
  };
  return Object.assign(c, { output: () => out });
}

function launchctl(sys: FakeSystem, loaded: { now: boolean }) {
  sys.exec_ = (cmd, a) => {
    if (cmd !== '/bin/launchctl') return { code: 1, stdout: '', stderr: '' };
    if (a[0] === 'print') return { code: loaded.now ? 0 : 113, stdout: '', stderr: '' };
    if (a[0] === 'bootout') loaded.now = false;
    if (a[0] === 'bootstrap') loaded.now = true;
    return { code: 0, stdout: '', stderr: '' };
  };
}

describe('setup in the simple install', () => {
  function sysAt() {
    const sys = new FakeSystem();
    sys.platform = 'darwin';
    sys.dir(HOME, 0o755).dir(`${HOME}/Library`, 0o700);
    return sys;
  }

  it('finish writes the LaunchAgent from the setup answers and starts it in the login session', async () => {
    const sys = sysAt();
    const loaded = { now: false };
    launchctl(sys, loaded);
    const backend = new FakeBackend(sys);
    backend.running = true;
    const c = simpleCtx(
      sys,
      backend,
      new ScriptedPrompter([{ q: /in the background now/, a: '' }]),
    );
    expect(await finishStep(c)).toBe('done');
    const plist = sys.text(SIMPLE.plist) as string;
    expect(plist).toContain(
      '<string>--approver-origin</string>\n    <string>https://mac.tail1.ts.net:8766</string>',
    );
    expect(plist).not.toContain('--headed');
    expect(sys.stat(SIMPLE.plist)?.mode).toBe(0o644);
    expect(sys.execs.map((e) => e.args.join(' '))).toContain(`bootstrap gui/1000 ${SIMPLE.plist}`);
    expect(loaded.now).toBe(true);
    expect(c.output()).toContain(PROTECTS_LESS);
    expect(c.output()).toContain(`'${SIMPLE.uninstaller}'`);
    expect(c.output()).toContain(FULL_INSTALL_COMMAND);
    expect(c.state.headed).toBe(false);
  });

  it('stops the background broker, after asking, before a step that needs the key store', async () => {
    const sys = sysAt();
    const loaded = { now: true };
    launchctl(sys, loaded);
    const c = simpleCtx(
      sys,
      new FakeBackend(sys),
      new ScriptedPrompter([{ q: /^Stop it now\? Setup starts it again at the end/, a: '' }]),
    );
    expect(await waitForDaemonStopped(c, 'pairing')).toBe(true);
    expect(sys.execs.map((e) => e.args[0])).toContain('bootout');
    expect(loaded.now).toBe(false);
  });

  it('asks only for the phone approver (no terminal approver: there is no terminal)', async () => {
    const sys = sysAt();
    const c = simpleCtx(
      sys,
      new FakeBackend(sys),
      new ScriptedPrompter([
        { q: /^Approver origin/, a: 'https://mac.example.com:8766' },
        { q: /serve TLS itself/, a: 'n' },
        { q: /^Listen address/, a: '' },
      ]),
    );
    c.state.approver = null;
    await approverStep(c);
    expect((c.state as SetupState).approver).toMatchObject({ kind: 'phone', via: 'proxy' });
    expect(c.output()).not.toContain('Where do you approve sign-ins?');
  });

  it('declines 1Password: its token would sit where an agent running as you can read it', async () => {
    const sys = sysAt();
    const c = simpleCtx(
      sys,
      new FakeBackend(sys),
      new ScriptedPrompter([
        { q: /^Choice/, a: '3' },
        { q: /^Choice/, a: '5' },
      ]),
    );
    await credentialsStep(c);
    expect(c.output()).toContain('1Password needs the full install');
    expect(c.state.passwordSource).toBeNull();
  });
});
