import { homedir } from 'node:os';
import { join } from 'node:path';
import type { TermStyle } from '@aab/approver';
import { type DoctorContext, type DoctorReport, formatReport, runChecks } from '../doctor.ts';
import { styleMarks } from '../format.ts';
import { hasKeyFile, unlockFromKeyFile } from '../key-file.ts';
import { SERVICE_PATHS, type ServicePaths } from '../service/paths.ts';
import { isSimpleMode, launchAgentTarget, simpleInstall, simpleNotice } from '../simple-install.ts';
import { type AdminCall, type Backend, devBackend, serviceBackend } from './backend.ts';
import { confirm, PromptAborted, type Prompter, TtyPrompter } from './prompt.ts';
import { STEP_NAMES } from './screen.ts';
import { daemonCommand, loadState, type SetupState, STATE_FILE } from './state.ts';
import { commandLine, type SetupContext, STEPS } from './steps.ts';
import { realSystem, type System } from './system.ts';
import { type TtyIn, type TtyOut, ttyKeys, ttyScreen } from './tty-screen.ts';
import { plainUi, ScreenUi, SetupLog, type SetupUi, useScreen } from './ui.ts';
import { lookupUser } from './users.ts';

export class SetupError extends Error {}

const PAIRING_TIMEOUT_MS = 10 * 60_000;

async function adminCaller(): Promise<AdminCall> {
  const { adminCall, AdminCallError } = await import('@aab/signer/admin-wire');
  return async <T>(socket: string, op: string, params?: Record<string, unknown>) => {
    try {
      return await adminCall<T>(socket, op, params ?? {});
    } catch (err) {
      if (err instanceof AdminCallError && err.code === 'permission') {
        throw new SetupError(`${socket} is root-only: run this with sudo`);
      }
      throw err;
    }
  };
}

export interface DoctorOptions {
  dataDir: string;
  project: string | null;
  service: boolean;
  sys?: System;
  paths?: ServicePaths;
  admin?: AdminCall;
  home?: string;
}

export async function doctorContext(o: DoctorOptions): Promise<DoctorContext> {
  const sys = o.sys ?? realSystem();
  const { chromiumLaunchable } = await import('@aab/core');
  const project = o.project ?? sys.cwd;
  if (o.service) {
    const paths = o.paths ?? SERVICE_PATHS;
    const ownerUid = sys.stat(paths.hookDir)?.uid;
    const user = ownerUid !== undefined ? await lookupUser(sys, { uid: ownerUid }) : null;
    const sudoUid = sys.env.SUDO_UID ? Number(sys.env.SUDO_UID) : Number.NaN;
    const home =
      user?.home ??
      (Number.isInteger(sudoUid) ? (await lookupUser(sys, { uid: sudoUid }))?.home : undefined) ??
      homedir();
    return {
      mode: 'service',
      sys,
      project,
      home,
      owner: user ? { uid: user.uid, gid: user.gid } : null,
      paths,
      admin: o.admin ?? (await adminCaller()),
      chromium: () => chromiumLaunchable(),
      nodeVersion: process.versions.node,
    };
  }
  const { defaultDataDir, DEFAULT_MCP_PORT } = await import('../args.ts');
  const hasState = sys.exists(join(o.dataDir, STATE_FILE));
  const owner = { uid: sys.uid, gid: sys.gid };
  const state = hasState ? loadState(sys, o.dataDir, DEFAULT_MCP_PORT, owner) : null;
  const home = o.home ?? homedir();
  const simple = hasKeyFile(o.dataDir) || isSimpleMode(sys.env) ? simpleInstall(home) : null;
  const cmd = simple
    ? ['launchctl', 'kickstart', '-k', launchAgentTarget(sys.uid)]
    : state
      ? daemonCommand(state, {
          dataDir: o.dataDir,
          defaultDataDir: defaultDataDir(),
          defaultMcpPort: DEFAULT_MCP_PORT,
        })
      : [
          'keyflap',
          'daemon',
          '--unprotected',
          ...(o.dataDir !== defaultDataDir() ? ['--data-dir', o.dataDir] : []),
        ];
  return {
    mode: 'dev',
    sys,
    project,
    home,
    owner,
    dataDir: o.dataDir,
    state,
    simple,
    daemonCommand: commandLine(cmd),
    chromium: () => chromiumLaunchable(),
    nodeVersion: process.versions.node,
    local: {
      agents: () => {
        if (!sys.exists(join(o.dataDir, 'broker.sqlite'))) return [];
        return listAgentsSync(o.dataDir);
      },
      audit: () => {
        if (!sys.exists(join(o.dataDir, 'broker.sqlite')))
          return { intact: true, entries: 0, brokenAt: null };
        return auditSync(o.dataDir);
      },
      passwords: () =>
        sys.exists(join(o.dataDir, 'broker.sqlite')) ? passwordsSync(o.dataDir) : 0,
    },
  };
}

let coreMod: typeof import('@aab/core') | null = null;
async function core() {
  coreMod ??= await import('@aab/core');
  return coreMod;
}
function withDb<T>(
  dataDir: string,
  fn: (db: ReturnType<typeof import('@aab/core').openDb>) => T,
): T {
  const c = coreMod as typeof import('@aab/core');
  const db = c.openDb(join(dataDir, 'broker.sqlite'));
  try {
    return fn(db);
  } finally {
    db.close();
  }
}
function listAgentsSync(dataDir: string) {
  const c = coreMod as typeof import('@aab/core');
  return withDb(dataDir, (db) =>
    new c.AgentRegistry(db)
      .list()
      .map((a) => ({ id: a.id, name: a.name, revoked: a.revokedAt !== null })),
  );
}
function auditSync(dataDir: string) {
  const c = coreMod as typeof import('@aab/core');
  return withDb(dataDir, (db) => {
    const audit = new c.AuditLog(db);
    const brokenAt = audit.verify();
    return { intact: brokenAt === null, entries: audit.all().length, brokenAt };
  });
}
function passwordsSync(dataDir: string): number {
  const c = coreMod as typeof import('@aab/core');
  return withDb(dataDir, (db) => new c.CredentialRepo(db).allPasswords().length);
}

export async function runDoctor(
  o: DoctorOptions & { json: boolean },
  out: (t: string) => void,
): Promise<DoctorReport> {
  await core();
  const report = await runChecks(await doctorContext(o));
  const { styleFor } = await import('@aab/approver');
  out(
    o.json
      ? `${JSON.stringify(report, null, 2)}\n`
      : formatReport(report, styleFor(process.stdout)),
  );
  return report;
}

export interface SetupOptions {
  dataDir: string;
  mcpPort: number;
  service: boolean;
  simple: boolean;
  host?: import('../args.ts').AgentHost | null;
  home?: string;
  quiet?: boolean;
}

export type PassphraseAsk = (o: { isNew: boolean; retry: boolean }) => Promise<string>;

export function passphraseAsker(
  prompt: Prompter,
  out: (t: string) => void,
  dataDir: string,
  simple: boolean,
): PassphraseAsk {
  let fromEnv = process.env.KEYFLAP_PASSPHRASE;
  delete process.env.KEYFLAP_PASSPHRASE;
  delete process.env.AAB_PASSPHRASE;
  return async ({ isNew, retry }: { isNew: boolean; retry: boolean }): Promise<string> => {
    const fromKeyFile = unlockFromKeyFile(dataDir, { create: simple });
    if (fromKeyFile !== null) return fromKeyFile;
    if (fromEnv !== undefined && !retry) {
      const v = fromEnv;
      fromEnv = undefined;
      if (v.length > 0) return v;
    }
    if (retry) out('  Wrong passphrase.\n');
    for (;;) {
      const first = await prompt.secret(
        isNew ? 'New key-store passphrase' : 'Key-store passphrase',
      );
      if (first.length === 0) continue;
      if (!isNew) return first;
      const again = await prompt.secret('Repeat passphrase');
      if (again === first) return first;
      out('  The passphrases do not match.\n');
    }
  };
}

export function modeName(o: { service: boolean; simple: boolean }): string {
  return o.service ? 'service mode' : o.simple ? 'simple install' : 'dev mode';
}

export function terminalUi(o: {
  stdin: TtyIn;
  stdout: TtyOut;
  env: NodeJS.ProcessEnv;
  style: TermStyle;
  mode: string;
  started: string;
}): SetupUi {
  const fallback = new TtyPrompter(o.stdin, o.stdout);
  const out = (t: string) => {
    o.stdout.write(styleMarks(t, o.style));
  };
  if (!useScreen(o, o.env)) return plainUi(out, fallback, o.style);
  return new ScreenUi({
    screen: ttyScreen(o.stdout, o.stdin),
    keys: ttyKeys(o.stdin),
    style: o.style,
    mode: o.mode,
    log: new SetupLog(o.started),
    afterLeave: (t) => {
      o.stdout.write(t);
    },
    fallbackPrompt: fallback,
  });
}

export const SETUP_LOG = 'setup.log';

export async function runSetupFlow(ctx: SetupContext, o: { mode: string }): Promise<void> {
  const { ui } = ctx;
  try {
    const logPath = join(ctx.backend.stateDir, SETUP_LOG);
    ui.logTo(logPath, (text) => ctx.sys.writeUserFile(logPath, text, 0o600, ctx.backend.fileOwner));
    ui.brief(
      [
        'Six short steps. Each one can be skipped, and nothing changes without asking.',
        '',
        ...STEP_NAMES.map((name, i) => `  ${i + 1}  ${name}`),
      ].join('\n'),
      `\n${ctx.style && ctx.style.level !== 0 ? ctx.style.header('setup') : 'Keyflap setup'} (${o.mode}). Every step can be skipped, and re-running\n` +
        'it picks up what is already done. Nothing is changed without asking.\n',
    );
    for (const step of STEPS) {
      try {
        const r = await step(ctx);
        if (r === 'daemon-running') return;
      } catch (err) {
        if (err instanceof PromptAborted) throw err;
        ctx.out(`  ✗ ${(err as Error).message}\n`);
        if (step === STEPS[0]) throw new SetupError('preflight failed');
        if (!(await confirm(ctx.prompt, 'Continue with the next step?', true))) return;
      }
    }
    await ui.finish();
  } finally {
    ui.leave();
  }
}

export async function runSetup(o: SetupOptions): Promise<void> {
  const { styleFor } = await import('@aab/approver');
  const style = styleFor(process.stdout);
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new SetupError(
      'keyflap setup is interactive and needs a terminal (stdin and stdout). For scripts, use the\n' +
        '  individual commands instead: keyflap agent add, keyflap password add, keyflap daemon --pair,\n' +
        '  keyflap doctor (docs/integrations/setup.md).',
    );
  }
  const sys = realSystem();
  const mode = modeName(o);
  const ui = terminalUi({
    stdin: process.stdin,
    stdout: process.stdout,
    env: process.env,
    style,
    mode,
    started: new Date(sys.now()).toISOString(),
  });
  await runSetupFlow(await setupContext(o, { sys, ui, style }), { mode });
}

export async function setupContext(
  o: SetupOptions,
  io: { sys: System; ui: SetupUi; style: TermStyle; passphrase?: PassphraseAsk },
): Promise<SetupContext> {
  const { sys, ui, style } = io;
  const home = o.home ?? homedir();
  const { out, prompt } = ui;
  const { defaultDataDir, DEFAULT_MCP_PORT } = await import('../args.ts');
  const { encodeQr, renderQrTerminal } = await import('@aab/approver');
  const { chromiumExecutable } = await import('@aab/core');
  await core();
  let backend: Backend;
  let passphrase: string | null = null;
  if (o.service) {
    if (sys.uid !== 0) {
      throw new SetupError(
        'service mode: run it with sudo (sudo keyflap setup); the admin sockets are root-only',
      );
    }
    backend = await serviceBackend({ sys, paths: SERVICE_PATHS, admin: await adminCaller() });
  } else {
    if (o.simple && sys.platform !== 'darwin') {
      throw new SetupError('the simple install is for macOS only');
    }
    if (!o.quiet && o.simple) {
      out(`${simpleNotice()}\n`);
    } else if (!o.quiet) {
      const { unprotectedBanner } = await import('../daemon.ts');
      out(`${unprotectedBanner(style)}\n`);
    }
    const ask = io.passphrase ?? passphraseAsker(prompt, out, o.dataDir, o.simple);
    backend = await devBackend({
      sys,
      dataDir: o.dataDir,
      mcpPort: o.mcpPort,
      home,
      passphrase: async (p) => {
        passphrase = await ask(p);
        return passphrase;
      },
    });
  }
  const state: SetupState = loadState(sys, backend.stateDir, o.mcpPort, backend.fileOwner);
  if (!o.service) state.mcpPort = o.mcpPort;
  const secretEnv: Record<string, string> = {};
  return {
    sys,
    prompt,
    out,
    ui,
    style,
    backend,
    state,
    dataDir: o.dataDir,
    defaults: { dataDir: defaultDataDir(), mcpPort: DEFAULT_MCP_PORT },
    paths: o.service ? SERVICE_PATHS : null,
    simple: o.simple ? simpleInstall(home) : null,
    host: o.host ?? null,
    qr: (url) => {
      const code = encodeQr(url);
      return { code, printed: renderQrTerminal(code, process.stdout) };
    },
    pairingTimeoutMs: Number(process.env.KEYFLAP_SETUP_PAIRING_TIMEOUT_MS) || PAIRING_TIMEOUT_MS,
    chromium: chromiumExecutable,
    doctor: async () =>
      runChecks(
        await doctorContext({
          dataDir: o.dataDir,
          project: state.claudeCode.at(-1)?.project ?? null,
          service: o.service,
          sys,
          home,
        }),
      ),
    secretEnv,
    startDaemon:
      o.service || o.simple
        ? null
        : async (s) => {
            ui.leave();
            const { runDaemon, stopOnSignals } = await import('../daemon.ts');
            Object.assign(process.env, secretEnv);
            for (const k of Object.keys(secretEnv)) delete secretEnv[k];
            const a = s.approver;
            const daemon = runDaemon({
              dataDir: o.dataDir,
              mcpPort: s.mcpPort,
              headed: s.headed === true,
              unprotected: true,
              phone:
                a?.kind === 'phone'
                  ? {
                      origin: a.origin,
                      listen: a.listen,
                      tlsCert: a.tlsCert,
                      tlsKey: a.tlsKey,
                      pair: false,
                      apns: null,
                    }
                  : null,
              passwordSource: s.passwordSource
                ? {
                    kind: s.passwordSource.kind,
                    vault: s.passwordSource.vault,
                    bin: s.passwordSource.bin,
                  }
                : null,
              ...(passphrase !== null ? { passphrase } : {}),
            });
            stopOnSignals(daemon);
            await daemon;
          },
    interruptible: async (fn) => {
      const ac = new AbortController();
      const onInt = () => ac.abort();
      process.on('SIGINT', onInt);
      try {
        return await fn(ac.signal);
      } finally {
        process.off('SIGINT', onInt);
      }
    },
  };
}
