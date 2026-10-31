import { execFile } from 'node:child_process';
import { ToolLauncher, type ToolSpec, type ToolTrust } from '@aab/sources';
import {
  LOCALAPI_DETAIL,
  type LocalApiRead,
  readLocalApiServeConfig,
  readLocalApiStatus,
} from './tailscale-localapi.ts';

export const TAILSCALE_TOOL: ToolSpec = {
  command: 'tailscale',
  installHint: "from tailscale.com/download or your distribution's package",
  reinstallFlag: '--tailscale-bin',
};

export interface PollMs {
  idle: number;
  fast: number;
  timeout: number;
  grace?: number;
}

export const DEFAULT_POLL_MS: Readonly<Required<PollMs>> = {
  idle: 2_000,
  fast: 250,
  timeout: 5_000,
  grace: 30_000,
};

export type ServeReader =
  | { via: 'cli'; bin: string; env?: Record<string, string> }
  | { via: 'localapi'; dir: string };

export interface ApproverAddress {
  origin: string;
  target: string;
  tailscale?: ServeReader;
  pollMs?: PollMs;
}

export type ServeVerdict =
  | { kind: 'ok' }
  | { kind: 'offline' }
  | { kind: 'mismatch'; seen: string }
  | { kind: 'unreadable'; detail: string };

export type ServeConfigVerdict = Exclude<ServeVerdict, { kind: 'offline' }> | { kind: 'empty' };

export const GRACE_WINDOW_MS = 10 * 60_000;

export interface AddressTrip {
  at: number;
  seen: string;
}

export type AddressState =
  | { kind: 'unwatched' }
  | { kind: 'ok'; checkedAt: number; graceSince?: number }
  | { kind: 'paused'; since: number; detail: string; graceSince?: number; graceUntil?: number }
  | { kind: 'latched'; at: number; seen: string; latest?: AddressReading };

export interface AddressReading {
  checkedAt: number;
  verdict: ServeVerdict;
}

export type WatchedAddressState = Exclude<AddressState, { kind: 'unwatched' }>;

export type AddressPhase = 'unwatched' | 'ok' | 'holding' | 'paused' | 'latched';

export function addressPhase(state: AddressState, now: number): AddressPhase {
  if (state.kind !== 'paused') return state.kind;
  return state.graceUntil !== undefined && now < state.graceUntil ? 'holding' : 'paused';
}

export interface ExpectedServe {
  host: string;
  port: number;
  target: string;
}

export function parseApproverAddress(
  v: unknown,
  o: { where: string; pollMs: 'allow' | 'refuse' },
): ApproverAddress {
  const bad = (msg: string): never => {
    throw new Error(`${o.where}: ${msg}`);
  };
  if (typeof v !== 'object' || v === null || Array.isArray(v)) bad('must be an object');
  const a = v as Record<string, unknown>;
  const stray = Object.keys(a).find(
    (k) => !['origin', 'target', 'tailscale', 'pollMs'].includes(k),
  );
  if (stray) bad(`unknown key "${stray}"`);
  const origin = a.origin;
  if (typeof origin !== 'string' || !originHostPort(origin)) {
    bad('origin must be an https or http URL with a host and nothing else');
  }
  const target = a.target;
  if (typeof target !== 'string' || !isHttpHostPort(target)) {
    bad('target must be http://host:port');
  }
  const out: ApproverAddress = { origin: origin as string, target: target as string };
  if (a.tailscale !== undefined) out.tailscale = parseServeReader(a.tailscale, bad);
  const p = a.pollMs;
  if (p !== undefined) {
    if (o.pollMs === 'refuse') bad('pollMs is for dev mode and tests only');
    if (typeof p !== 'object' || p === null || Array.isArray(p)) bad('pollMs must be an object');
    const m = p as Record<string, unknown>;
    const ms = (k: string): number => {
      const n = m[k];
      if (typeof n !== 'number' || !Number.isInteger(n) || n < 1 || n > 3_600_000) {
        bad(`pollMs.${k} must be a whole number of milliseconds`);
      }
      return n as number;
    };
    out.pollMs = {
      idle: ms('idle'),
      fast: ms('fast'),
      timeout: ms('timeout'),
      ...(m.grace !== undefined ? { grace: ms('grace') } : {}),
    };
  }
  return out;
}

function parseServeReader(v: unknown, bad: (msg: string) => never): ServeReader {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) bad('tailscale must be an object');
  const c = v as Record<string, unknown>;
  const allowed =
    c.via === 'cli'
      ? ['via', 'bin', 'env']
      : c.via === 'localapi'
        ? ['via', 'dir']
        : bad('tailscale.via must be "cli" or "localapi"');
  const stray = Object.keys(c).find((k) => !allowed.includes(k));
  if (stray) bad(`unknown key "tailscale.${stray}"`);
  if (c.via === 'localapi') {
    if (typeof c.dir !== 'string' || !c.dir.startsWith('/')) {
      bad('tailscale.dir must be an absolute path');
    }
    return { via: 'localapi', dir: c.dir as string };
  }
  if (typeof c.bin !== 'string' || !c.bin.startsWith('/')) {
    bad('tailscale.bin must be an absolute path');
  }
  if (
    c.env !== undefined &&
    (typeof c.env !== 'object' ||
      c.env === null ||
      Array.isArray(c.env) ||
      Object.values(c.env).some((x) => typeof x !== 'string'))
  ) {
    bad('tailscale.env must map names to strings');
  }
  return {
    via: 'cli',
    bin: c.bin as string,
    ...(c.env !== undefined ? { env: c.env as Record<string, string> } : {}),
  };
}

function isHttpHostPort(target: string): boolean {
  try {
    const t = new URL(target);
    return t.protocol === 'http:' && t.origin === target && t.port !== '' && t.hostname !== '';
  } catch {
    return false;
  }
}

function originHostPort(origin: string): { host: string; port: number } | null {
  let u: URL;
  try {
    u = new URL(origin);
  } catch {
    return null;
  }
  if (u.origin !== origin || !u.hostname) return null;
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  const port = u.port !== '' ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
  return { host: u.hostname, port };
}

export function expectedServe(address: ApproverAddress): ExpectedServe {
  const hp = originHostPort(address.origin);
  if (!hp) throw new Error('approver address origin is not a URL');
  return { host: hp.host, port: hp.port, target: address.target };
}

function stripSlash(s: string): string {
  return s.endsWith('/') ? s.slice(0, -1) : s;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function portOf(hostPort: string): string {
  const i = hostPort.lastIndexOf(':');
  return i < 0 ? '' : hostPort.slice(i + 1);
}

function usesPort(cfg: Record<string, unknown>, port: string): boolean {
  const web = cfg.Web;
  if (isRecord(web) && Object.keys(web).some((k) => portOf(k) === port)) return true;
  const tcp = cfg.TCP;
  return isRecord(tcp) && Object.hasOwn(tcp, port);
}

function foregroundUses(cfg: Record<string, unknown>, port: string): boolean {
  const fg = cfg.Foreground;
  return (
    isRecord(fg) &&
    Object.values(fg).some((session) => isRecord(session) && usesPort(session, port))
  );
}

function nothingServedAt(cfg: Record<string, unknown>, key: string, port: string): boolean {
  const funnel = cfg.AllowFunnel;
  return (
    !usesPort(cfg, port) &&
    !foregroundUses(cfg, port) &&
    !(isRecord(funnel) && Object.hasOwn(funnel, key))
  );
}

const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

export function plainText(s: string, max: number): string {
  const chars = [...s.replace(UNSAFE_TEXT, '')];
  return chars.length > max ? `${chars.slice(0, max).join('')}…` : chars.join('');
}

export const SERVE_WRITER_SEEN = {
  tooLarge: 'the serve setting is over 1 MiB',
  notJson: 'the serve setting is not JSON',
  notConfig: 'the serve setting is not a serve config',
} as const;

const QUOTED_MAX = 80;
const quoted = (s: string) => JSON.stringify(plainText(s, QUOTED_MAX));

export function compareServeConfig(json: string, expected: ExpectedServe): ServeConfigVerdict {
  let cfg: unknown;
  try {
    cfg = JSON.parse(json);
  } catch {
    return { kind: 'mismatch', seen: SERVE_WRITER_SEEN.notJson };
  }
  if (cfg === null) cfg = {};
  if (!isRecord(cfg)) return { kind: 'mismatch', seen: SERVE_WRITER_SEEN.notConfig };
  const key = `${expected.host}:${expected.port}`;
  const port = String(expected.port);
  const mismatch = (seen: string): ServeConfigVerdict => ({ kind: 'mismatch', seen });
  if (nothingServedAt(cfg, key, port)) return { kind: 'empty' };

  const funnel = cfg.AllowFunnel;
  if (isRecord(funnel) && funnel[key] === true) return mismatch(`${key} is on Funnel`);
  if (foregroundUses(cfg, port)) return mismatch(`a foreground serve session uses ${port}`);

  const web = isRecord(cfg.Web) ? cfg.Web : {};
  const entry = web[key];
  if (!isRecord(entry)) return mismatch(`${port} is in use, but not for ${key}`);
  const entryKeys = Object.keys(entry);
  if (entryKeys.length !== 1 || entryKeys[0] !== 'Handlers' || !isRecord(entry.Handlers)) {
    return mismatch(`${key} has an unexpected setting`);
  }
  const handlers = entry.Handlers;
  const paths = Object.keys(handlers);
  const other = paths.find((p) => p !== '/');
  if (other !== undefined) return mismatch(`${key} also handles ${quoted(other)}`);
  const root = handlers['/'];
  if (!isRecord(root)) return mismatch(`nothing is served at ${key}/`);
  const rootKeys = Object.keys(root);
  if (rootKeys.length !== 1 || rootKeys[0] !== 'Proxy' || typeof root.Proxy !== 'string') {
    return mismatch(`${key} / is not a plain proxy`);
  }
  if (stripSlash(root.Proxy) !== stripSlash(expected.target)) {
    return mismatch(`${key} proxies to ${quoted(root.Proxy)}`);
  }

  const tcp = isRecord(cfg.TCP) ? cfg.TCP : {};
  const tcpEntry = tcp[port];
  if (!isRecord(tcpEntry)) return mismatch(`TCP ${port} is not served`);
  const tcpKeys = Object.keys(tcpEntry);
  if (tcpKeys.length !== 1 || tcpKeys[0] !== 'HTTPS' || tcpEntry.HTTPS !== true) {
    return mismatch(`TCP ${port} is forwarded`);
  }

  const alias = Object.keys(web).find((k) => k !== key && portOf(k) === port);
  if (alias !== undefined) return mismatch(`${quoted(alias)} is also served on ${port}`);
  return { kind: 'ok' };
}

export type TailnetPresence = 'on' | 'off' | Unreadable;

export function tailnetPresence(json: string): TailnetPresence {
  let st: unknown;
  try {
    st = JSON.parse(json);
  } catch {
    return unreadable(UNREADABLE_DETAIL.statusUnreadable);
  }
  if (
    !isRecord(st) ||
    typeof st.BackendState !== 'string' ||
    !isRecord(st.Self) ||
    typeof st.Self.InNetworkMap !== 'boolean'
  ) {
    return unreadable(UNREADABLE_DETAIL.statusUnreadable);
  }
  const ips = st.TailscaleIPs;
  const noAddresses = ips === null || ips === undefined || (Array.isArray(ips) && ips.length === 0);
  const off = st.BackendState !== 'Running' && st.Self.InNetworkMap === false && noAddresses;
  return off ? 'off' : 'on';
}

export const UNREADABLE_DETAIL = {
  notChecked: 'not checked yet',
  noCli: 'no tailscale CLI configured',
  notTrusted: 'tailscale is not trusted',
  cannotRun: 'tailscale cannot be run',
  statusUnreadable: "Tailscale's status cannot be read",
  ...LOCALAPI_DETAIL,
} as const;

export const PAUSE_DETAIL = {
  offline: 'Tailscale is not connected',
} as const;

export const RESTART_DETAILS: ReadonlySet<string> = new Set([
  PAUSE_DETAIL.offline,
  UNREADABLE_DETAIL.notRunning,
  UNREADABLE_DETAIL.tokenUnreadable,
  UNREADABLE_DETAIL.tokenRefused,
]);

function pauseDetail(verdict: Extract<ServeVerdict, { kind: 'offline' | 'unreadable' }>): string {
  return verdict.kind === 'offline' ? PAUSE_DETAIL.offline : verdict.detail;
}

function recentGrace(state: WatchedAddressState, now: number): number | undefined {
  const since = state.kind === 'latched' ? undefined : state.graceSince;
  return since !== undefined && now - since < GRACE_WINDOW_MS ? since : undefined;
}

function pausedFor(
  state: WatchedAddressState,
  detail: string,
  now: number,
  graceMs: number,
): WatchedAddressState {
  const restart = RESTART_DETAILS.has(detail);
  if (state.kind === 'paused') {
    const graceUntil = restart ? state.graceUntil : undefined;
    return {
      kind: 'paused',
      since: state.since,
      detail,
      ...(state.graceSince !== undefined ? { graceSince: state.graceSince } : {}),
      ...(graceUntil !== undefined ? { graceUntil } : {}),
    };
  }
  const graceSince = recentGrace(state, now) ?? (restart ? now : undefined);
  const graceUntil = restart && graceSince !== undefined ? graceSince + graceMs : undefined;
  return {
    kind: 'paused',
    since: now,
    detail,
    ...(graceSince !== undefined ? { graceSince } : {}),
    ...(graceUntil !== undefined && graceUntil > now ? { graceUntil } : {}),
  };
}

export function nextAddressState(
  state: WatchedAddressState,
  verdict: ServeVerdict,
  now: number,
  graceMs: number = DEFAULT_POLL_MS.grace,
): WatchedAddressState {
  if (state.kind === 'latched') {
    return { kind: 'latched', at: state.at, seen: state.seen, latest: { checkedAt: now, verdict } };
  }
  switch (verdict.kind) {
    case 'ok': {
      const graceSince = recentGrace(state, now);
      return { kind: 'ok', checkedAt: now, ...(graceSince !== undefined ? { graceSince } : {}) };
    }
    case 'mismatch':
      return { kind: 'latched', at: now, seen: verdict.seen };
    case 'offline':
    case 'unreadable':
      return pausedFor(state, pauseDetail(verdict), now, graceMs);
  }
}

export interface AddressTripStore {
  get(): AddressTrip | undefined;
  set(trip: AddressTrip): void;
  clear(): void;
}

export interface ApproverAddressWatchOptions {
  address: ApproverAddress;
  trust: ToolTrust;
  trip: AddressTripStore;
  onTripped: (seen: string) => void;
  log: Log;
  now?: () => number;
}

const MAX_OUTPUT = 1024 * 1024;

type Unreadable = Extract<ServeVerdict, { kind: 'unreadable' }>;
type TailscaleQuery = () => Promise<string | Unreadable>;
interface TailscaleRead {
  serve: TailscaleQuery;
  status: TailscaleQuery;
}
type Log = (event: string, fields: Record<string, unknown>) => void;

const unreadable = (detail: string): Unreadable => ({ kind: 'unreadable', detail });

const CLI_ARGS = {
  serve: ['serve', 'status', '--json'],
  status: ['status', '--json', '--peers=false'],
} as const;

function cliRead(
  reader: Extract<ServeReader, { via: 'cli' }>,
  trust: ToolTrust,
  timeoutMs: number,
  log: Log,
): TailscaleRead {
  let refusal = '';
  const launcher = new ToolLauncher(TAILSCALE_TOOL, reader.bin, trust, (e) => {
    refusal = e.detail;
    log('approver_address_tool_refused', e);
  });
  const env = { ...(reader.env ?? {}) };
  const query =
    (args: readonly string[]): TailscaleQuery =>
    async () => {
      let bin: string;
      try {
        bin = launcher.path();
      } catch {
        return unreadable(`${UNREADABLE_DETAIL.notTrusted}: ${refusal}`);
      }
      return runTailscale(bin, args, env, timeoutMs);
    };
  return { serve: query(CLI_ARGS.serve), status: query(CLI_ARGS.status) };
}

function fromLocalApi(r: LocalApiRead): string | Unreadable {
  switch (r.kind) {
    case 'body':
      return r.body;
    case 'untrusted':
      return unreadable(`${UNREADABLE_DETAIL.notTrusted}: ${r.detail}`);
    case 'failed':
      return unreadable(r.detail);
  }
}

function localApiRead(dir: string, trust: ToolTrust, timeoutMs: number): TailscaleRead {
  const o = { checkOwners: trust.mode === 'system', timeoutMs, maxBytes: MAX_OUTPUT };
  return {
    serve: async () => fromLocalApi(await readLocalApiServeConfig(dir, o)),
    status: async () => fromLocalApi(await readLocalApiStatus(dir, o)),
  };
}

function serveRead(
  reader: ServeReader | undefined,
  trust: ToolTrust,
  timeoutMs: number,
  log: Log,
): TailscaleRead | null {
  if (reader === undefined) return null;
  return reader.via === 'cli'
    ? cliRead(reader, trust, timeoutMs, log)
    : localApiRead(reader.dir, trust, timeoutMs);
}

export class ApproverAddressWatch {
  private readonly expected: ExpectedServe;
  private readonly poll: Required<PollMs>;
  private readonly read: TailscaleRead | null;
  private readonly trip: AddressTripStore;
  private readonly onTripped: (seen: string) => void;
  private readonly log: Log;
  private readonly now: () => number;
  private current: WatchedAddressState;
  private reading: Promise<ServeVerdict> | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private pendingUntil = 0;
  private stopped = false;

  constructor(opts: ApproverAddressWatchOptions) {
    this.expected = expectedServe(opts.address);
    this.poll = { ...DEFAULT_POLL_MS, ...opts.address.pollMs };
    this.trip = opts.trip;
    this.onTripped = opts.onTripped;
    this.log = opts.log;
    this.now = opts.now ?? Date.now;
    this.read = serveRead(opts.address.tailscale, opts.trust, this.poll.timeout, this.log);
    const persisted = this.trip.get();
    this.current = persisted
      ? { kind: 'latched', at: persisted.at, seen: persisted.seen }
      : { kind: 'paused', since: this.now(), detail: UNREADABLE_DETAIL.notChecked };
  }

  state(): AddressState {
    return this.current;
  }

  async start(): Promise<void> {
    this.apply(await this.readVerdict());
    this.schedule();
  }

  report(pending: boolean): void {
    if (!pending) return;
    const first = this.now() >= this.pendingUntil;
    this.pendingUntil = this.now() + 3 * this.poll.fast + this.poll.idle;
    if (first && this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
      this.schedule();
    }
  }

  async clear(): Promise<AddressState> {
    const verdict = await this.readVerdict();
    if (this.current.kind !== 'latched') {
      this.apply(verdict);
      return this.current;
    }
    if (verdict.kind === 'ok') {
      this.trip.clear();
      this.current = { kind: 'ok', checkedAt: this.now() };
      this.log('approver_address_cleared', { origin: this.originKey() });
      return this.current;
    }
    this.apply(verdict);
    this.log('approver_address_clear_refused', {
      origin: this.originKey(),
      ...(verdict.kind === 'mismatch' ? { seen: verdict.seen } : { detail: pauseDetail(verdict) }),
    });
    return this.current;
  }

  stop(): void {
    this.stopped = true;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }

  private originKey(): string {
    return `${this.expected.host}:${this.expected.port}`;
  }

  private schedule(): void {
    if (this.stopped || this.timer !== null || this.read === null) return;
    const fast = this.current.kind !== 'latched' && this.now() < this.pendingUntil;
    const delay = fast ? this.poll.fast : this.poll.idle;
    this.timer = setTimeout(() => {
      this.timer = null;
      this.readVerdict()
        .then((v) => this.apply(v))
        .finally(() => this.schedule());
    }, delay);
    this.timer.unref();
  }

  private apply(verdict: ServeVerdict): void {
    const prev = this.current;
    const next = nextAddressState(prev, verdict, this.now(), this.poll.grace);
    this.current = next;
    if (next.kind === 'latched' && prev.kind !== 'latched') {
      this.trip.set({ at: next.at, seen: next.seen });
      this.onTripped(next.seen);
      return;
    }
    if (next.kind === 'paused' && (prev.kind !== 'paused' || prev.detail !== next.detail)) {
      this.log('approver_address_unreadable', { origin: this.originKey(), detail: next.detail });
    }
    if (next.kind === 'ok' && prev.kind === 'paused') {
      this.log('approver_address_readable', { origin: this.originKey() });
    }
  }

  private readVerdict(): Promise<ServeVerdict> {
    if (this.reading) return this.reading;
    this.reading = this.readOnce().finally(() => {
      this.reading = null;
    });
    return this.reading;
  }

  private async readOnce(): Promise<ServeVerdict> {
    if (this.read === null) return unreadable(UNREADABLE_DETAIL.noCli);
    const status = await this.read.status();
    const presence = typeof status === 'string' ? tailnetPresence(status) : status;
    const out = await this.read.serve();
    const config = typeof out === 'string' ? compareServeConfig(out, this.expected) : out;
    switch (config.kind) {
      case 'empty':
        if (typeof presence !== 'string') return presence;
        return presence === 'off'
          ? { kind: 'offline' }
          : { kind: 'mismatch', seen: `nothing is served at ${this.originKey()}` };
      case 'unreadable':
        return config.detail === UNREADABLE_DETAIL.tooLarge
          ? { kind: 'mismatch', seen: SERVE_WRITER_SEEN.tooLarge }
          : config;
      default:
        return config;
    }
  }
}

const TAILSCALED_UNREACHABLE = /failed to connect to local tailscale/i;

function runTailscale(
  bin: string,
  args: readonly string[],
  env: Record<string, string>,
  timeoutMs: number,
): Promise<string | Unreadable> {
  return new Promise((resolve) => {
    execFile(
      bin,
      [...args],
      {
        env: { PATH: process.env.PATH ?? '', ...env },
        timeout: timeoutMs,
        killSignal: 'SIGKILL',
        maxBuffer: MAX_OUTPUT,
        windowsHide: true,
      },
      (err, stdout, stderr) => {
        if (!err) return resolve(stdout);
        const e = err as NodeJS.ErrnoException & { killed?: boolean; code?: unknown };
        const unreadable = (detail: string) => resolve({ kind: 'unreadable', detail });
        if (e.code === 'ENOENT' || e.code === 'EACCES')
          return unreadable(UNREADABLE_DETAIL.cannotRun);
        if (e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
          return unreadable(UNREADABLE_DETAIL.tooLarge);
        }
        if (e.killed) return unreadable('tailscale timed out');
        if (typeof e.code === 'number' && TAILSCALED_UNREACHABLE.test(stderr)) {
          return unreadable(UNREADABLE_DETAIL.notRunning);
        }
        unreadable(typeof e.code === 'number' ? `tailscale exited ${e.code}` : 'tailscale failed');
      },
    ).stdin?.end();
  });
}
