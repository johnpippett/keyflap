import type { ServeReader } from '@aab/signer/approver-address';
import { parseServiceConfig, type SignerServiceConfig } from '@aab/signer/service';
import { isTailnetOrigin, listenTarget } from '../approver-address.ts';
import { approverOrigin, listenAddress, UsageError } from '../args.ts';
import { SERVICE_PATHS, type ServicePaths } from './paths.ts';

export interface CoreServiceConfig {
  dataDir: string;
  signerSocket: string;
  intentSocket: string;
  adminSocket: string;
  mcp: { host: '127.0.0.1'; port: number };
  approver: {
    origin: string;
    listen: { host: string; port: number };
    tls: boolean;
    front?: { socket: string };
    apns?: ApnsServiceConfig;
  };
  highRisk: string[];
  passwordSource: { kind: 'proton-pass' | '1password' } | null;
  browser: (
    | { mode: 'headless'; channel?: 'chromium' }
    | { mode: 'xvfb'; xvfbBin: string; display: number }
  ) & {
    persist: boolean;
  };
}

export interface ApnsServiceConfig {
  keyId: string;
  teamId: string;
  bundleId: string;
  sandbox: boolean;
  generic: boolean;
}

export interface ApproverFrontConfig {
  origin: string;
  listen: { host: string; port: number };
  tls: boolean;
  upstream: string;
}

export class ConfigError extends Error {}

const APNS_ID_RE = /^[A-Z0-9]{10}$/;
const BUNDLE_ID_RE = /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;

function parseApns(v: unknown): ApnsServiceConfig {
  const a = obj(v, 'approver.apns');
  only(a, ['keyId', 'teamId', 'bundleId', 'sandbox', 'generic'], 'approver.apns');
  if (typeof a.keyId !== 'string' || !APNS_ID_RE.test(a.keyId)) {
    throw new ConfigError('approver.apns.keyId must be 10 characters A-Z0-9');
  }
  if (typeof a.teamId !== 'string' || !APNS_ID_RE.test(a.teamId)) {
    throw new ConfigError('approver.apns.teamId must be 10 characters A-Z0-9');
  }
  if (typeof a.bundleId !== 'string' || !BUNDLE_ID_RE.test(a.bundleId)) {
    throw new ConfigError('approver.apns.bundleId must look like com.example.App');
  }
  if (typeof a.sandbox !== 'boolean' || typeof a.generic !== 'boolean') {
    throw new ConfigError('approver.apns.sandbox and .generic must be true or false');
  }
  return {
    keyId: a.keyId,
    teamId: a.teamId,
    bundleId: a.bundleId,
    sandbox: a.sandbox,
    generic: a.generic,
  };
}

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

function obj(v: unknown, what: string): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new ConfigError(`${what} must be an object`);
  }
  return v as Record<string, unknown>;
}

function only(o: Record<string, unknown>, keys: string[], what: string): void {
  const stray = Object.keys(o).find((k) => !keys.includes(k));
  if (stray) throw new ConfigError(`${what}: unknown key "${stray}"`);
}

function absPath(v: unknown, what: string): string {
  if (typeof v !== 'string' || !v.startsWith('/') || v.includes('\0')) {
    throw new ConfigError(`${what} must be an absolute path`);
  }
  return v;
}

function portNumber(v: unknown, what: string): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > 65535) {
    throw new ConfigError(`${what} must be a port number`);
  }
  return v;
}

function wrap<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof UsageError) throw new ConfigError(err.message);
    throw err;
  }
}

const XVFB_LINUX_ONLY = 'is Linux-only: a macOS service has no display, so it runs headless';

export function parseCoreConfig(
  text: string,
  platform: string = process.platform,
): CoreServiceConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new ConfigError('core config is not JSON');
  }
  const c = obj(raw, 'core config');
  only(
    c,
    [
      'dataDir',
      'signerSocket',
      'intentSocket',
      'adminSocket',
      'mcp',
      'approver',
      'highRisk',
      'passwordSource',
      'browser',
    ],
    'core config',
  );
  let browser: CoreServiceConfig['browser'] = { mode: 'headless', persist: true };
  if (c.browser !== undefined) {
    const b = obj(c.browser, 'browser');
    if (b.persist !== undefined && typeof b.persist !== 'boolean') {
      throw new ConfigError('browser.persist must be true or false');
    }
    const persist = b.persist !== false;
    if (b.mode === 'xvfb') {
      if (platform === 'darwin') throw new ConfigError(`browser.mode xvfb ${XVFB_LINUX_ONLY}`);
      only(b, ['mode', 'xvfbBin', 'display', 'persist'], 'browser');
      const display = b.display;
      if (
        typeof display !== 'number' ||
        !Number.isInteger(display) ||
        display < 1 ||
        display > 999
      ) {
        throw new ConfigError('browser.display must be a display number (1..999)');
      }
      browser = { mode: 'xvfb', xvfbBin: absPath(b.xvfbBin, 'browser.xvfbBin'), display, persist };
    } else if (b.mode === 'headless') {
      only(b, ['mode', 'channel', 'persist'], 'browser');
      if (b.channel !== undefined && b.channel !== 'chromium') {
        throw new ConfigError(
          'browser.channel must be chromium (the full browser in new headless mode) or absent',
        );
      }
      browser = {
        mode: 'headless',
        ...(b.channel === 'chromium' ? { channel: 'chromium' } : {}),
        persist,
      };
    } else {
      throw new ConfigError('browser.mode must be headless or xvfb');
    }
  }
  const mcp = obj(c.mcp, 'mcp');
  only(mcp, ['host', 'port'], 'mcp');
  if (mcp.host !== '127.0.0.1') throw new ConfigError('mcp.host must be 127.0.0.1');
  if (c.approver === undefined || c.approver === null) {
    throw new ConfigError(
      'approver is required: service mode only runs with a phone approver (docs/ISOLATION_PLAN.md D5)',
    );
  }
  const ap = obj(c.approver, 'approver');
  only(ap, ['origin', 'listen', 'tls', 'front', 'apns'], 'approver');
  let front: { socket: string } | undefined;
  if (ap.front !== undefined) {
    const f = obj(ap.front, 'approver.front');
    only(f, ['socket'], 'approver.front');
    front = { socket: absPath(f.socket, 'approver.front.socket') };
    if (ap.tls !== false) {
      throw new ConfigError('approver.tls must be false with approver.front (the front has TLS)');
    }
  }
  const listen = obj(ap.listen, 'approver.listen');
  only(listen, ['host', 'port'], 'approver.listen');
  if (typeof listen.host !== 'string' || listen.host.length === 0) {
    throw new ConfigError('approver.listen.host must be a host');
  }
  if (typeof ap.tls !== 'boolean') throw new ConfigError('approver.tls must be true or false');
  const origin = wrap(() => approverOrigin(typeof ap.origin === 'string' ? ap.origin : undefined));
  const hr = c.highRisk ?? [];
  if (!Array.isArray(hr) || hr.some((d) => typeof d !== 'string' || !DOMAIN_RE.test(d))) {
    throw new ConfigError('highRisk must be a list of lower-case domains');
  }
  let passwordSource: CoreServiceConfig['passwordSource'] = null;
  if (c.passwordSource !== undefined && c.passwordSource !== null) {
    const ps = obj(c.passwordSource, 'passwordSource');
    only(ps, ['kind'], 'passwordSource');
    if (ps.kind !== 'proton-pass' && ps.kind !== '1password') {
      throw new ConfigError('passwordSource.kind must be proton-pass or 1password');
    }
    passwordSource = { kind: ps.kind };
  }
  return {
    dataDir: absPath(c.dataDir, 'dataDir'),
    signerSocket: absPath(c.signerSocket, 'signerSocket'),
    intentSocket: absPath(c.intentSocket, 'intentSocket'),
    adminSocket: absPath(c.adminSocket, 'adminSocket'),
    mcp: { host: '127.0.0.1', port: portNumber(mcp.port, 'mcp.port') },
    approver: {
      origin,
      listen: { host: listen.host, port: portNumber(listen.port, 'approver.listen.port') },
      tls: ap.tls,
      ...(front ? { front } : {}),
      ...(ap.apns !== undefined ? { apns: parseApns(ap.apns) } : {}),
    },
    highRisk: hr as string[],
    passwordSource,
    browser,
  };
}

export function parseApproverFrontConfig(text: string): ApproverFrontConfig {
  let c: Record<string, unknown>;
  try {
    c = obj(JSON.parse(text), 'approver config');
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    throw new ConfigError('approver config is not valid JSON');
  }
  only(c, ['origin', 'listen', 'tls', 'upstream'], 'approver config');
  const listen = obj(c.listen, 'listen');
  only(listen, ['host', 'port'], 'listen');
  if (typeof listen.host !== 'string' || listen.host.length === 0) {
    throw new ConfigError('listen.host must be a host');
  }
  if (typeof c.tls !== 'boolean') throw new ConfigError('tls must be true or false');
  return {
    origin: wrap(() => approverOrigin(typeof c.origin === 'string' ? c.origin : undefined)),
    listen: { host: listen.host, port: portNumber(listen.port, 'listen.port') },
    tls: c.tls,
    upstream: absPath(c.upstream, 'upstream'),
  };
}

export interface InstallOptions {
  approverOrigin: string;
  approverListen?: string;
  tls: boolean;
  mcpPort?: number;
  highRisk: string[];
  protonPassBin?: string;
  protonPassSha256?: string;
  protonPassVault?: string;
  onePasswordBin?: string;
  onePasswordSha256?: string;
  onePasswordVault?: string;
  tailscaleBin?: string;
  tailscaleLocalApi?: string;
  xvfbBin?: string;
  ephemeralBrowser?: boolean;
  xvfbDisplay?: number;
  apns?: ApnsServiceConfig;
}

export function protonPassServiceEnv(paths: ServicePaths = SERVICE_PATHS): Record<string, string> {
  return {
    HOME: paths.signerData,
    PROTON_PASS_SESSION_DIR: `${paths.signerData}/proton-pass`,
    PROTON_PASS_KEY_PROVIDER: 'fs',
  };
}

export function onePasswordServiceEnv(paths: ServicePaths = SERVICE_PATHS): Record<string, string> {
  return { HOME: paths.signerData };
}

export function buildServiceConfigs(
  o: InstallOptions,
  paths: ServicePaths = SERVICE_PATHS,
  platform: string = process.platform,
): { core: CoreServiceConfig; signer: SignerServiceConfig; approver: ApproverFrontConfig } {
  if (o.xvfbBin && platform === 'darwin') throw new ConfigError(`--xvfb ${XVFB_LINUX_ONLY}`);
  const highRisk = o.highRisk.map((d) => {
    const n = d.trim().toLowerCase();
    if (!DOMAIN_RE.test(n)) throw new ConfigError(`--high-risk must be a domain, got "${d}"`);
    return n;
  });
  if (o.protonPassVault !== undefined && !o.protonPassBin) {
    throw new ConfigError('--proton-pass-vault needs --password-source proton-pass');
  }
  if (
    o.protonPassVault !== undefined &&
    (o.protonPassVault.length === 0 || o.protonPassVault.length > 200)
  ) {
    throw new ConfigError('--proton-pass-vault must be a vault name');
  }
  if (o.onePasswordVault !== undefined && !o.onePasswordBin) {
    throw new ConfigError('--1password-vault needs --password-source 1password');
  }
  if (
    o.onePasswordVault !== undefined &&
    (o.onePasswordVault.length === 0 || o.onePasswordVault.length > 200)
  ) {
    throw new ConfigError('--1password-vault must be a vault name');
  }
  if (o.protonPassBin && o.onePasswordBin) {
    throw new ConfigError('one password source at a time: proton-pass or 1password');
  }
  const origin = wrap(() => approverOrigin(o.approverOrigin));
  const listen = wrap(() => listenAddress(o.approverListen));
  const core: CoreServiceConfig = {
    dataDir: paths.coreData,
    signerSocket: paths.signerSocket,
    intentSocket: paths.intentSocket,
    adminSocket: paths.adminSocket,
    mcp: { host: '127.0.0.1', port: o.mcpPort ?? 8765 },
    approver: {
      origin,
      listen,
      tls: false,
      front: { socket: paths.approverApiSocket },
      ...(o.apns ? { apns: o.apns } : {}),
    },
    highRisk,
    passwordSource: o.protonPassBin
      ? { kind: 'proton-pass' }
      : o.onePasswordBin
        ? { kind: '1password' }
        : null,
    browser: o.xvfbBin
      ? {
          mode: 'xvfb',
          xvfbBin: absPath(o.xvfbBin, '--xvfb'),
          display: o.xvfbDisplay ?? 99,
          persist: o.ephemeralBrowser !== true,
        }
      : {
          mode: 'headless',
          ...(platform === 'darwin' ? { channel: 'chromium' } : {}),
          persist: o.ephemeralBrowser !== true,
        },
  };
  parseCoreConfig(JSON.stringify(core), platform);
  if (o.tailscaleBin !== undefined && o.tailscaleLocalApi !== undefined) {
    throw new ConfigError('--tailscale-bin and --tailscale-localapi: one or the other');
  }
  const reader: ServeReader | undefined = o.tailscaleBin
    ? { via: 'cli', bin: absPath(o.tailscaleBin, '--tailscale-bin') }
    : o.tailscaleLocalApi
      ? { via: 'localapi', dir: absPath(o.tailscaleLocalApi, '--tailscale-localapi') }
      : undefined;
  const watched = isTailnetOrigin(origin) || reader !== undefined;
  const signer: SignerServiceConfig = {
    storePath: `${paths.signerData}/keys.enc.json`,
    highRiskDomains: highRisk,
    ...(watched
      ? {
          approverAddress: {
            origin,
            target: listenTarget(listen),
            ...(reader ? { tailscale: reader } : {}),
          },
        }
      : {}),
    ...(o.protonPassBin
      ? {
          sources: {
            protonPass: {
              bin: absPath(o.protonPassBin, '--proton-pass-bin'),
              env: protonPassServiceEnv(paths),
              ...(o.protonPassSha256 !== undefined ? { sha256: o.protonPassSha256 } : {}),
              ...(o.protonPassVault !== undefined ? { vault: o.protonPassVault } : {}),
            },
          },
        }
      : {}),
    ...(o.onePasswordBin
      ? {
          sources: {
            onePassword: {
              bin: absPath(o.onePasswordBin, '--op-bin'),
              env: onePasswordServiceEnv(paths),
              ...(o.onePasswordSha256 !== undefined ? { sha256: o.onePasswordSha256 } : {}),
              ...(o.onePasswordVault !== undefined ? { vault: o.onePasswordVault } : {}),
            },
          },
        }
      : {}),
  };
  parseServiceConfig(JSON.stringify(signer));
  const approver: ApproverFrontConfig = {
    origin,
    listen,
    tls: o.tls,
    upstream: paths.approverApiSocket,
  };
  parseApproverFrontConfig(JSON.stringify(approver));
  return { core, signer, approver };
}
