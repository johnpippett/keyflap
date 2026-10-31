import { dirname } from 'node:path';
import { OP_TOKEN_CREDENTIAL, parseServiceConfig } from '@aab/signer/service';
import { OP_TOOL, PASS_CLI_TOOL, type ToolSpec, toolCandidates, toolDir } from '@aab/sources';
import type { System } from '../setup/system.ts';
import { lookupUser, type UserInfo } from '../setup/users.ts';
import { onePasswordServiceEnv, parseCoreConfig, protonPassServiceEnv } from './config.ts';
import type { ServiceManager } from './manager.ts';
import type { ServicePaths } from './paths.ts';

export type SourceKind = 'proton-pass' | '1password';

export class PasswordSourceError extends Error {
  readonly fix: string | null;
  constructor(message: string, fix: string | null = null) {
    super(message);
    this.fix = fix;
  }
}

export interface SourceDef {
  kind: SourceKind;
  name: string;
  key: 'protonPass' | 'onePassword';
  spec: ToolSpec;
  serviceEnv: (paths: ServicePaths) => Record<string, string>;
  keepsLogins: string;
}

export const SOURCES: Record<SourceKind, SourceDef> = {
  'proton-pass': {
    kind: 'proton-pass',
    name: 'Proton Pass',
    key: 'protonPass',
    spec: PASS_CLI_TOOL,
    serviceEnv: protonPassServiceEnv,
    keepsLogins: 'They stay in Proton Pass, and Keyflap signs out of it.',
  },
  '1password': {
    kind: '1password',
    name: '1Password',
    key: 'onePassword',
    spec: OP_TOOL,
    serviceEnv: onePasswordServiceEnv,
    keepsLogins: 'They stay in 1Password, and Keyflap deletes its copy of the token.',
  },
};

export const SOURCE_KINDS = Object.keys(SOURCES) as SourceKind[];

export function isSourceKind(v: unknown): v is SourceKind {
  return typeof v === 'string' && Object.hasOwn(SOURCES, v);
}

export interface SourceHost {
  sys: System;
  paths: ServicePaths;
  m: ServiceManager;
}

export interface Connected {
  kind: SourceKind;
  bin: string | null;
  sha256: string | null;
  vault: string | null;
}

export interface Plan {
  kind: SourceKind;
  bin: string;
  sha256: string;
  vault: string | null;
  token: string | null;
}

export interface ToolRun {
  bin: string;
  env: Record<string, string>;
  cleanEnv: boolean;
  uid?: number;
  gid?: number;
}

type Out = (text: string) => void;
type Json = Record<string, unknown>;

const NO_NETWORK_CONF = 'no-network.conf';
const ONE_PASSWORD_CONF = '1password.conf';
const NO_NETWORK = '[Service]\nRestrictAddressFamilies=\nRestrictAddressFamilies=AF_UNIX\n';
const RESTART_WAIT_MS = 10_000;
const TOKEN_SEAL_MS = 30_000;
const VAULT_LIST_MS = 60_000;
const LOGIN_MS = 120_000;

function parseObject(text: string | null, what: string): Json {
  if (text === null) throw new PasswordSourceError(`${what} cannot be read: is Keyflap installed?`);
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new PasswordSourceError(`${what} is not JSON`);
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new PasswordSourceError(`${what} is not an object`);
  }
  return raw as Json;
}

export function oneLine(text: string): string {
  return text.trim().split('\n').slice(0, 3).join(' / ');
}

export function connectedSource(sys: System, paths: ServicePaths): Connected | null {
  let signer: Json = {};
  let core: Json = {};
  try {
    signer = parseObject(sys.readFile(paths.signerConfig), paths.signerConfig);
    core = parseObject(sys.readFile(paths.coreConfig), paths.coreConfig);
  } catch {}
  const sources = (signer.sources ?? {}) as Record<string, Json | undefined>;
  for (const def of Object.values(SOURCES)) {
    const s = sources[def.key];
    if (s && typeof s.bin === 'string') {
      return {
        kind: def.kind,
        bin: s.bin,
        sha256: typeof s.sha256 === 'string' ? s.sha256 : null,
        vault: typeof s.vault === 'string' ? s.vault : null,
      };
    }
  }
  const kind = (core.passwordSource as { kind?: unknown } | null | undefined)?.kind;
  return isSourceKind(kind) ? { kind, bin: null, sha256: null, vault: null } : null;
}

export function findTool(
  sys: System,
  def: SourceDef,
  given?: string,
): { bin: string; sha256: string } {
  const candidates = given === undefined ? toolCandidates(def.spec) : [given];
  let refused: { detail: string; fix: string } | null = null;
  for (const bin of candidates) {
    if (!sys.exists(bin)) continue;
    const r = sys.checkTool(bin, def.spec);
    if (r.ok) return { bin: r.path, sha256: r.sha256 };
    refused ??= r;
  }
  if (refused) throw new PasswordSourceError(refused.detail, refused.fix);
  const where =
    given === undefined
      ? `${toolDir(def.spec)}/, /usr/local/bin or /usr/bin`
      : `${given} (it does not exist)`;
  const asked = sys.checkTool(candidates[0] as string, def.spec);
  throw new PasswordSourceError(
    `${def.spec.command} is not installed where Keyflap trusts it: ${where}`,
    asked.ok ? null : asked.fix,
  );
}

export async function signerAccount(sys: System, m: ServiceManager): Promise<UserInfo> {
  const user = await lookupUser(sys, { name: m.user('signer') });
  if (!user) {
    throw new PasswordSourceError(`No ${m.user('signer')} user: is Keyflap installed?`);
  }
  return user;
}

const SAFE_PATH = '/usr/bin:/bin';

export function toolRun(
  def: SourceDef,
  paths: ServicePaths,
  bin: string,
  signer: UserInfo,
  token?: string,
): ToolRun {
  const env: Record<string, string> = {
    ...def.serviceEnv(paths),
    PATH: def.kind === '1password' ? `${SAFE_PATH}:/usr/local/bin` : SAFE_PATH,
    ...(token === undefined
      ? {}
      : {
          OP_SERVICE_ACCOUNT_TOKEN: token,
          OP_CACHE: 'false',
          OP_BIOMETRIC_UNLOCK_ENABLED: 'false',
        }),
  };
  return { bin, env, cleanEnv: true, uid: signer.uid, gid: signer.gid };
}

function runOptions(run: ToolRun, timeoutMs: number) {
  return {
    env: run.env,
    cleanEnv: run.cleanEnv,
    timeoutMs,
    ...(run.uid !== undefined ? { uid: run.uid, gid: run.gid } : {}),
  };
}

export async function protonVaults(sys: System, run: ToolRun): Promise<string[] | null> {
  const r = await sys.exec(
    run.bin,
    ['vault', 'list', '--output', 'json'],
    runOptions(run, VAULT_LIST_MS),
  );
  if (r.code !== 0) return null;
  try {
    const v = (JSON.parse(r.stdout) as { vaults?: { name?: unknown }[] }).vaults ?? [];
    return v.map((x) => String(x.name ?? '')).filter(Boolean);
  } catch {
    return null;
  }
}

export async function protonLogin(sys: System, run: ToolRun, token: string): Promise<boolean> {
  const r = await sys.exec(run.bin, ['login'], {
    ...runOptions(run, LOGIN_MS),
    env: { ...run.env, PROTON_PASS_PERSONAL_ACCESS_TOKEN: token },
  });
  return r.code === 0;
}

export async function opVaults(sys: System, run: ToolRun): Promise<string[] | null> {
  const r = await sys.exec(
    run.bin,
    ['vault', 'list', '--format=json'],
    runOptions(run, VAULT_LIST_MS),
  );
  if (r.code !== 0) return null;
  try {
    const v = JSON.parse(r.stdout) as { name?: unknown }[];
    return Array.isArray(v) ? v.map((x) => String(x?.name ?? '')).filter(Boolean) : null;
  } catch {
    return null;
  }
}

interface TokenStore {
  put(h: SourceHost, token: string, signer: UserInfo): Promise<void>;
  remove(h: SourceHost): void;
}

const SEALED_TOKENS: TokenStore = {
  async put({ sys, paths }, token) {
    sys.mkdirRoot(dirname(paths.opToken), 0o700);
    const tmp = `${paths.opToken}.tmp`;
    sys.removeRootFile(tmp);
    const r = await sys.exec(
      'systemd-creds',
      ['encrypt', '--with-key=auto', `--name=${OP_TOKEN_CREDENTIAL}`, '-', tmp],
      { input: token, timeoutMs: TOKEN_SEAL_MS },
    );
    if (r.code !== 0) {
      sys.removeRootFile(tmp);
      const why = oneLine((r.stderr || r.error || '').replaceAll(token, '…'));
      throw new PasswordSourceError(`systemd-creds could not seal the token: ${why}`);
    }
    sys.promoteRootFile(tmp, paths.opToken, 0o600);
  },
  remove: ({ sys, paths }) => sys.removeRootFile(paths.opToken),
};

const OWNED_TOKEN_FILES: TokenStore = {
  async put({ sys, paths }, token, signer) {
    sys.writeRootFile(paths.opToken, token, {
      mode: 0o400,
      owner: { uid: signer.uid, gid: signer.gid },
    });
  },
  remove: ({ sys, paths }) => sys.removeRootFile(paths.opToken),
};

const TOKEN_STORES: Record<ServiceManager['kind'], TokenStore> = {
  systemd: SEALED_TOKENS,
  launchd: OWNED_TOKEN_FILES,
};

export function onePasswordDropIn(paths: ServicePaths): string {
  return `[Service]\nLoadCredentialEncrypted=${OP_TOKEN_CREDENTIAL}:${paths.opToken}\n`;
}

function syncDropIns(h: SourceHost, kind: SourceKind | null): void {
  const dir = h.m.signerDropIns;
  if (dir === null) return;
  const wanted: Record<string, string | null> = {
    [NO_NETWORK_CONF]: kind === null ? NO_NETWORK : null,
    [ONE_PASSWORD_CONF]: kind === '1password' ? onePasswordDropIn(h.paths) : null,
  };
  if (Object.values(wanted).some((v) => v !== null)) h.sys.mkdirRoot(dir, 0o755);
  for (const [name, text] of Object.entries(wanted)) {
    if (text === null) h.sys.removeRootFile(`${dir}/${name}`);
    else h.sys.writeRootFile(`${dir}/${name}`, text, { mode: 0o644 });
  }
}

async function runAll(h: SourceHost, argvs: string[][], what: string): Promise<void> {
  for (const argv of argvs) {
    const r = await h.sys.exec(argv[0] as string, argv.slice(1), { timeoutMs: 60_000 });
    if (r.code !== 0) {
      throw new PasswordSourceError(
        `${what} failed (${argv.join(' ')}): ${oneLine(r.stderr || r.stdout || r.error || `exit ${r.code}`)}`,
      );
    }
  }
}

async function restartAndWait(h: SourceHost): Promise<void> {
  const { sys, m } = h;
  await runAll(h, m.restartCommands(['signer', 'core']), 'The restart');
  const deadline = sys.now() + RESTART_WAIT_MS;
  for (;;) {
    const down: string[] = [];
    for (const n of ['signer', 'core'] as const) {
      if (!(await m.active(sys, n)).active) down.push(n);
    }
    if (down.length === 0) return;
    if (sys.now() >= deadline) {
      throw new PasswordSourceError(
        `The ${down.join(' and ')} did not come back`,
        m.logsCommand(down[0] as 'signer' | 'core'),
      );
    }
    await sys.sleep(1_000);
  }
}

export function assertRoot(sys: System): void {
  if (sys.uid !== 0) throw new PasswordSourceError('Run this as root: sudo keyflap …');
}

interface ConfigTexts {
  signer: string;
  core: string;
}

function renderConfigs(h: SourceHost, signer: Json, core: Json): ConfigTexts {
  const texts = {
    signer: `${JSON.stringify(signer, null, 2)}\n`,
    core: `${JSON.stringify(core, null, 2)}\n`,
  };
  try {
    parseServiceConfig(texts.signer);
    parseCoreConfig(texts.core, h.sys.platform);
  } catch (err) {
    throw new PasswordSourceError(`The new settings are not valid: ${(err as Error).message}`);
  }
  return texts;
}

function writeConfigs(h: SourceHost, texts: ConfigTexts): void {
  h.sys.writeRootFile(h.paths.coreConfig, texts.core, { mode: 0o644 });
  h.sys.writeRootFile(h.paths.signerConfig, texts.signer, { mode: 0o644 });
}

export async function protonSignOut(
  h: SourceHost,
  bin: string | null,
  pin: string | null,
  out: Out,
): Promise<boolean> {
  const reason = await (async (): Promise<string | null> => {
    if (bin === null) return 'no pass-cli is recorded';
    const check = h.sys.checkTool(bin, PASS_CLI_TOOL, pin ?? undefined);
    if (!check.ok) {
      return check.problem === 'changed' ? 'pass-cli changed since it was trusted' : check.detail;
    }
    const signer = await lookupUser(h.sys, { name: h.m.user('signer') });
    if (!signer) return `there is no ${h.m.user('signer')} user`;
    const run = toolRun(SOURCES['proton-pass'], h.paths, check.path, signer);
    try {
      const r = await h.sys.exec(run.bin, ['logout'], runOptions(run, VAULT_LIST_MS));
      return r.code === 0 ? null : 'pass-cli logout failed';
    } catch {
      return 'pass-cli logout could not run';
    }
  })();
  if (reason !== null) {
    out(`! Keyflap is still signed in to Proton Pass (${reason}). Only the signer can use it.\n`);
  }
  return reason === null;
}

export async function applyConnect(h: SourceHost, plan: Plan, out: Out): Promise<void> {
  const { sys, paths, m } = h;
  assertRoot(sys);
  const def = SOURCES[plan.kind];
  if (plan.vault !== null && (plan.vault.length === 0 || plan.vault.length > 200)) {
    throw new PasswordSourceError('A vault name is 1 to 200 characters');
  }
  if (def.kind === '1password' && (plan.token ?? '') === '') {
    throw new PasswordSourceError('1Password needs its service account token');
  }
  const before = connectedSource(sys, paths);
  const signer = await signerAccount(sys, m);
  const signerCfg = parseObject(sys.readFile(paths.signerConfig), paths.signerConfig);
  const coreCfg = parseObject(sys.readFile(paths.coreConfig), paths.coreConfig);
  signerCfg.sources = {
    [def.key]: {
      bin: plan.bin,
      env: def.serviceEnv(paths),
      sha256: plan.sha256,
      ...(plan.vault !== null ? { vault: plan.vault } : {}),
    },
  };
  coreCfg.passwordSource = { kind: plan.kind };
  const texts = renderConfigs(h, signerCfg, coreCfg);
  const store = TOKEN_STORES[m.kind];
  if (def.kind === '1password') await store.put(h, plan.token as string, signer);
  writeConfigs(h, texts);
  syncDropIns(h, plan.kind);
  if (def.kind !== '1password') store.remove(h);
  await runAll(h, m.reloadCommands, 'Reloading the services');
  await restartAndWait(h);
  if (before?.kind === 'proton-pass' && plan.kind !== 'proton-pass') {
    await protonSignOut(h, before.bin, before.sha256, out);
  }
}

export async function applyDisconnect(h: SourceHost, out: Out): Promise<Connected | null> {
  const { sys, paths, m } = h;
  assertRoot(sys);
  const before = connectedSource(sys, paths);
  const store = TOKEN_STORES[m.kind];
  syncDropIns(h, null);
  if (before !== null) {
    const signerCfg = parseObject(sys.readFile(paths.signerConfig), paths.signerConfig);
    const coreCfg = parseObject(sys.readFile(paths.coreConfig), paths.coreConfig);
    delete signerCfg.sources;
    coreCfg.passwordSource = null;
    writeConfigs(h, renderConfigs(h, signerCfg, coreCfg));
  }
  store.remove(h);
  await runAll(h, m.reloadCommands, 'Reloading the services');
  if (before === null) return null;
  await restartAndWait(h);
  if (before.kind === 'proton-pass') await protonSignOut(h, before.bin, before.sha256, out);
  return before;
}
