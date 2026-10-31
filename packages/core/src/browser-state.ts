import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { join } from 'node:path';
import { isHighRisk, isHighRiskOrigin } from '@aab/signer/risk';
import type { ClearRequest, PersistOptins, SessionClock, SessionStateRepo } from './db.ts';
import { canonicalOrigin, normalizeHost, registrableDomain } from './origin.ts';
import type { PolicyStore } from './policy.ts';
import { scrubString } from './scrub.ts';

export const STATE_AAD_PREFIX = 'aab-browser-state-v1\n';
export const MAX_STATE_BYTES = 16 * 1024 * 1024;
const MAX_FILE_BYTES = Math.ceil((MAX_STATE_BYTES * 4) / 3) + 64 * 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SUFFIX = '.state';

export interface SavedCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None';
}

export interface SavedOrigin {
  origin: string;
  localStorage: { name: string; value: string }[];
  indexedDB?: unknown[];
}

export interface SavedState {
  cookies: SavedCookie[];
  origins: SavedOrigin[];
}

export interface StatePlain {
  v: 1;
  savedAt: number;
  state: SavedState;
  visited: string[];
}

export type DiscardReason =
  | 'undecryptable'
  | 'malformed'
  | 'too_large'
  | 'not_regular_file'
  | 'bad_owner'
  | 'unreadable';

export type LoadResult =
  | { kind: 'none' }
  | { kind: 'ok'; plain: StatePlain }
  | { kind: 'discarded'; reason: DiscardReason };

export const isAgentId = (id: unknown): id is string => typeof id === 'string' && UUID_RE.test(id);

const aad = (agentId: string) => Buffer.from(STATE_AAD_PREFIX + agentId, 'utf8');

export interface StateFile {
  v: 1;
  iv: string;
  tag: string;
  ct: string;
}

export function encryptState(key: Buffer, agentId: string, plaintext: Buffer): StateFile {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad(agentId));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    v: 1,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ct.toString('base64'),
  };
}

export function decryptState(key: Buffer, agentId: string, file: unknown): Buffer | null {
  if (typeof file !== 'object' || file === null || Array.isArray(file)) return null;
  const f = file as Record<string, unknown>;
  const keys = Object.keys(f).sort().join(',');
  if (keys !== 'ct,iv,tag,v' || f.v !== 1) return null;
  if (typeof f.iv !== 'string' || typeof f.tag !== 'string' || typeof f.ct !== 'string') {
    return null;
  }
  try {
    const iv = Buffer.from(f.iv, 'base64');
    const tag = Buffer.from(f.tag, 'base64');
    if (iv.length !== 12 || tag.length !== 16) return null;
    const d = createDecipheriv('aes-256-gcm', key, iv);
    d.setAAD(aad(agentId));
    d.setAuthTag(tag);
    return Buffer.concat([d.update(Buffer.from(f.ct, 'base64')), d.final()]);
  } catch {
    return null;
  }
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const SAME_SITE = new Set(['Strict', 'Lax', 'None']);

function validCookie(c: unknown): c is SavedCookie {
  return (
    isObj(c) &&
    typeof c.name === 'string' &&
    typeof c.value === 'string' &&
    typeof c.domain === 'string' &&
    c.domain.length > 0 &&
    typeof c.path === 'string' &&
    typeof c.expires === 'number' &&
    typeof c.httpOnly === 'boolean' &&
    typeof c.secure === 'boolean' &&
    typeof c.sameSite === 'string' &&
    SAME_SITE.has(c.sameSite)
  );
}

function validOrigin(o: unknown): o is SavedOrigin {
  if (!isObj(o) || typeof o.origin !== 'string' || !Array.isArray(o.localStorage)) return false;
  if (o.indexedDB !== undefined && !Array.isArray(o.indexedDB)) return false;
  try {
    const u = new URL(o.origin);
    if ((u.protocol !== 'http:' && u.protocol !== 'https:') || u.origin !== o.origin) return false;
  } catch {
    return false;
  }
  return o.localStorage.every(
    (e) => isObj(e) && typeof e.name === 'string' && typeof e.value === 'string',
  );
}

export function validState(s: unknown): s is SavedState {
  return (
    isObj(s) &&
    Array.isArray(s.cookies) &&
    Array.isArray(s.origins) &&
    s.cookies.every(validCookie) &&
    s.origins.every(validOrigin)
  );
}

function parsePlain(buf: Buffer): StatePlain | null {
  let v: unknown;
  try {
    v = JSON.parse(buf.toString('utf8'));
  } catch {
    return null;
  }
  if (!isObj(v) || v.v !== 1 || typeof v.savedAt !== 'number') return null;
  if (!validState(v.state)) return null;
  if (!Array.isArray(v.visited) || !v.visited.every((o) => typeof o === 'string')) return null;
  return { v: 1, savedAt: v.savedAt, state: v.state, visited: v.visited as string[] };
}

export class BrowserStateStore {
  readonly dir: string;
  private readonly key: Buffer;
  private readonly maxBytes: number;

  constructor(opts: { dir: string; key: Buffer; maxBytes?: number }) {
    if (opts.key.length !== 32) throw new Error('browser state key must be 32 bytes');
    this.dir = opts.dir;
    this.key = opts.key;
    this.maxBytes = opts.maxBytes ?? MAX_STATE_BYTES;
    this.ensureDir();
  }

  private ensureDir(): void {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const st = lstatSync(this.dir);
    if (!st.isDirectory() || st.isSymbolicLink())
      throw new Error('browser-state is not a directory');
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
      throw new Error('browser-state is owned by another user');
    }
    if ((st.mode & 0o777) !== 0o700) chmodSync(this.dir, 0o700);
  }

  pathFor(agentId: string): string {
    if (!isAgentId(agentId)) throw new Error('bad agent id');
    return join(this.dir, `${agentId}${SUFFIX}`);
  }

  load(agentId: string): LoadResult {
    const path = this.pathFor(agentId);
    let fd: number;
    try {
      fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') return { kind: 'none' };
      if (code === 'ELOOP') return { kind: 'discarded', reason: 'not_regular_file' };
      return { kind: 'discarded', reason: 'unreadable' };
    }
    let raw: Buffer;
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) return { kind: 'discarded', reason: 'not_regular_file' };
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
        return { kind: 'discarded', reason: 'bad_owner' };
      }
      if (st.size > MAX_FILE_BYTES) return { kind: 'discarded', reason: 'too_large' };
      raw = Buffer.alloc(st.size);
      let off = 0;
      while (off < st.size) {
        const n = readSync(fd, raw, off, st.size - off, off);
        if (n === 0) break;
        off += n;
      }
      raw = raw.subarray(0, off);
    } catch {
      return { kind: 'discarded', reason: 'unreadable' };
    } finally {
      closeSync(fd);
    }
    let file: unknown;
    try {
      file = JSON.parse(raw.toString('utf8'));
    } catch {
      return { kind: 'discarded', reason: 'malformed' };
    }
    const plaintext = decryptState(this.key, agentId, file);
    if (!plaintext) return { kind: 'discarded', reason: 'undecryptable' };
    if (plaintext.length > this.maxBytes) return { kind: 'discarded', reason: 'too_large' };
    const plain = parsePlain(plaintext);
    if (!plain) return { kind: 'discarded', reason: 'malformed' };
    return { kind: 'ok', plain };
  }

  write(agentId: string, plain: StatePlain): void {
    const path = this.pathFor(agentId);
    const plaintext = Buffer.from(JSON.stringify(plain), 'utf8');
    if (plaintext.length > this.maxBytes) throw new Error('too_large');
    const body = Buffer.from(JSON.stringify(encryptState(this.key, agentId, plaintext)), 'utf8');
    const tmp = `${path}.tmp-${randomBytes(6).toString('hex')}`;
    const fd = openSync(
      tmp,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      let off = 0;
      while (off < body.length) off += writeSync(fd, body, off, body.length - off);
      fsyncSync(fd);
    } catch (err) {
      closeSync(fd);
      try {
        unlinkSync(tmp);
      } catch {}
      throw err;
    }
    closeSync(fd);
    renameSync(tmp, path);
    try {
      const dfd = openSync(this.dir, constants.O_RDONLY);
      try {
        fsyncSync(dfd);
      } finally {
        closeSync(dfd);
      }
    } catch {}
  }

  delete(agentId: string): boolean {
    try {
      unlinkSync(this.pathFor(agentId));
      return true;
    } catch {
      return false;
    }
  }

  agentIds(): string[] {
    const out: string[] = [];
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return [];
    }
    for (const n of names) {
      if (n.includes(`${SUFFIX}.tmp-`)) {
        try {
          unlinkSync(join(this.dir, n));
        } catch {}
        continue;
      }
      if (!n.endsWith(SUFFIX)) continue;
      const id = n.slice(0, -SUFFIX.length);
      if (isAgentId(id)) out.push(id);
    }
    return out;
  }
}

export function siteOfHost(host: string): string {
  const h = normalizeHost(host) ?? host.toLowerCase().replace(/^\./, '');
  return registrableDomain(h) ?? h;
}

const cookieHost = (c: SavedCookie) => c.domain.toLowerCase().replace(/^\./, '');
const originHost = (o: string): string | null => {
  try {
    return new URL(o).hostname;
  } catch {
    return null;
  }
};

export type DropReason = 'deny' | 'highRisk' | 'ttl' | 'cleared';

export interface SiteDrop {
  reason: DropReason;
  ttlMs?: number;
  origin?: string;
}

export interface SiteCount {
  site: string;
  cookies: number;
  origins: number;
}

export interface FilterReport {
  sites: string[];
  cookies: number;
  origins: number;
  dropped: {
    deny: SiteCount[];
    highRisk: SiteCount[];
    ttl: (SiteCount & { ttlMs: number; origin: string })[];
    cleared: SiteCount[];
    secret: { cookies: number; origins: number };
  };
}

export interface FilterContext {
  secrets: readonly string[];
  verdict(site: string, knownOrigins: readonly string[]): SiteDrop | null;
}

export function holdsSecret(text: string, secrets: readonly string[]): boolean {
  if (secrets.length === 0 || text.length === 0) return false;
  return scrubString(text, secrets) !== text;
}

function allStrings(v: unknown, out: string[], depth = 0): void {
  if (depth > 64) {
    out.push(JSON.stringify(v) ?? '');
    return;
  }
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) for (const x of v) allStrings(x, out, depth + 1);
  else if (isObj(v)) {
    for (const [k, x] of Object.entries(v)) {
      out.push(k);
      allStrings(x, out, depth + 1);
    }
  }
}

function originHoldsSecret(o: SavedOrigin, secrets: readonly string[]): boolean {
  if (secrets.length === 0) return false;
  const strings: string[] = [];
  allStrings(o.localStorage, strings);
  if (o.indexedDB) allStrings(o.indexedDB, strings);
  if (holdsSecret(strings.join('\n'), secrets)) return true;
  return holdsSecret(JSON.stringify([o.localStorage, o.indexedDB ?? null]), secrets);
}

export function filterState(
  state: SavedState,
  visited: readonly string[],
  ctx: FilterContext,
): { state: SavedState; report: FilterReport } {
  const report: FilterReport = {
    sites: [],
    cookies: 0,
    origins: 0,
    dropped: { deny: [], highRisk: [], ttl: [], cleared: [], secret: { cookies: 0, origins: 0 } },
  };
  const cookies = state.cookies.filter((c) => {
    const bad = holdsSecret(c.name, ctx.secrets) || holdsSecret(c.value, ctx.secrets);
    if (bad) report.dropped.secret.cookies++;
    return !bad;
  });
  const origins: SavedOrigin[] = [];
  for (const o of state.origins) {
    if (originHoldsSecret(o, ctx.secrets)) {
      report.dropped.secret.origins++;
      continue;
    }
    origins.push(o);
  }

  const bySite = new Map<
    string,
    { cookies: SavedCookie[]; origins: SavedOrigin[]; known: Set<string> }
  >();
  const entry = (site: string) => {
    let e = bySite.get(site);
    if (!e) {
      e = { cookies: [], origins: [], known: new Set([`https://${site}`]) };
      bySite.set(site, e);
    }
    return e;
  };
  for (const c of cookies) {
    const host = cookieHost(c);
    const e = entry(siteOfHost(host));
    e.cookies.push(c);
    e.known.add(`https://${host}`);
  }
  for (const o of origins) {
    const host = originHost(o.origin);
    if (!host) continue;
    const e = entry(siteOfHost(host));
    e.origins.push(o);
    e.known.add(o.origin);
  }
  for (const v of visited) {
    const host = originHost(v);
    if (!host) continue;
    const e = bySite.get(siteOfHost(host));
    if (e) e.known.add(v);
  }

  const out: SavedState = { cookies: [], origins: [] };
  for (const [site, e] of [...bySite].sort(([a], [b]) => (a < b ? -1 : 1))) {
    let drop: SiteDrop | null;
    try {
      drop = ctx.verdict(site, [...e.known]);
    } catch {
      drop = { reason: 'deny' };
    }
    const count = { site, cookies: e.cookies.length, origins: e.origins.length };
    if (drop) {
      if (drop.reason === 'ttl') {
        report.dropped.ttl.push({
          ...count,
          ttlMs: drop.ttlMs ?? 0,
          origin: drop.origin ?? `https://${site}`,
        });
      } else {
        report.dropped[drop.reason].push(count);
      }
      continue;
    }
    if (e.cookies.length === 0 && e.origins.length === 0) continue;
    report.sites.push(site);
    out.cookies.push(...e.cookies);
    out.origins.push(...e.origins);
  }
  report.cookies = out.cookies.length;
  report.origins = out.origins.length;
  return { state: out, report };
}

export function dropSite(
  state: SavedState,
  site: string,
): { state: SavedState; cookies: number; origins: number } {
  const on = (host: string | null) => host !== null && siteOfHost(host) === site;
  const cookies = state.cookies.filter((c) => !on(cookieHost(c)));
  const origins = state.origins.filter((o) => !on(originHost(o.origin)));
  return {
    state: { cookies, origins },
    cookies: state.cookies.length - cookies.length,
    origins: state.origins.length - origins.length,
  };
}

export function trimPlain(
  plain: StatePlain,
  maxBytes = MAX_STATE_BYTES,
): { plain: StatePlain; trimmed: number } {
  const size = (p: StatePlain) => Buffer.byteLength(JSON.stringify(p), 'utf8');
  if (size(plain) <= maxBytes) return { plain, trimmed: 0 };
  const origins = plain.state.origins.map((o) => ({ ...o }));
  const next: StatePlain = { ...plain, state: { cookies: plain.state.cookies, origins } };
  const touched = new Set<string>();
  const bytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v ?? null), 'utf8');
  for (const field of ['indexedDB', 'localStorage'] as const) {
    const order = [...origins].sort((a, b) => bytes(b[field]) - bytes(a[field]));
    for (const o of order) {
      if (size(next) <= maxBytes) break;
      if (field === 'indexedDB') {
        if (!o.indexedDB || o.indexedDB.length === 0) continue;
        delete o.indexedDB;
      } else {
        if (o.localStorage.length === 0) continue;
        o.localStorage = [];
      }
      touched.add(o.origin);
    }
  }
  next.state.origins = origins.filter(
    (o) => o.localStorage.length > 0 || (o.indexedDB?.length ?? 0) > 0,
  );
  if (size(next) > maxBytes) throw new Error('too_large');
  return { plain: next, trimmed: touched.size };
}

const onSite = (host: string, site: string) => siteOfHost(host) === site;

export interface PersistenceOptions {
  store: BrowserStateStore;
  repo: SessionStateRepo;
  optins: Pick<PersistOptins, 'has'>;
  policy: Pick<PolicyStore, 'resolve'>;
  highRiskDomains?: readonly string[];
  isActive: (agentId: string) => boolean;
  audit: (event: string, fields: Record<string, unknown>) => void;
  now?: () => number;
}

export interface Restored {
  state: SavedState | null;
  finish(ok: boolean): void;
}

export interface SaveResult {
  written: boolean;
  report: FilterReport | null;
  trimmed: number;
}

export class SessionPersistence {
  readonly store: BrowserStateStore;
  readonly repo: SessionStateRepo;
  private readonly optins: Pick<PersistOptins, 'has'>;
  private readonly policy: Pick<PolicyStore, 'resolve'>;
  private readonly highRisk: readonly string[];
  private readonly isActive: (agentId: string) => boolean;
  private readonly audit: (event: string, fields: Record<string, unknown>) => void;
  private readonly now: () => number;

  constructor(o: PersistenceOptions) {
    this.store = o.store;
    this.repo = o.repo;
    this.optins = o.optins;
    this.policy = o.policy;
    this.highRisk = o.highRiskDomains ?? [];
    this.isActive = o.isActive;
    this.audit = o.audit;
    this.now = o.now ?? Date.now;
  }

  verdictFor(
    agentId: string,
    clearedSites: ReadonlySet<string> = new Set(),
  ): FilterContext['verdict'] {
    const clocks = this.repo.clocks(agentId);
    const now = this.now();
    return (site, knownOrigins) => {
      if (clearedSites.has(site)) return { reason: 'cleared' };
      const siteClocks = clocks.filter((c) => onSite(c.host, site));
      const origins = new Set([
        ...knownOrigins,
        ...siteClocks.map((c) => c.origin),
        `https://${site}`,
      ]);
      let ttl: number | null = null;
      let highRisk = false;
      for (const seen of origins) {
        const c = canonicalOrigin(seen);
        if (!c) continue;
        const { origin, host } = c;
        const pol = this.policy.resolve(agentId, { origin, host });
        if (pol.mode === 'deny') return { reason: 'deny' };
        if (
          pol.mode === 'ask-strong' ||
          isHighRisk(host, this.highRisk) ||
          isHighRiskOrigin(origin, this.highRisk)
        )
          highRisk = true;
        if (pol.sessionTtlMs !== null)
          ttl = ttl === null ? pol.sessionTtlMs : Math.min(ttl, pol.sessionTtlMs);
      }
      if (highRisk && !this.optins.has(agentId, site)) return { reason: 'highRisk' };
      if (ttl !== null) {
        const live = siteClocks.some((c) => c.startedAt + ttl > now);
        if (!live) {
          return { reason: 'ttl', ttlMs: ttl, origin: siteClocks[0]?.origin ?? `https://${site}` };
        }
      }
      return null;
    };
  }

  private indexRows(state: SavedState, savedAt: number) {
    const rows = new Map<
      string,
      { site: string; cookies: number; origins: number; savedAt: number }
    >();
    const row = (site: string) => {
      let r = rows.get(site);
      if (!r) {
        r = { site, cookies: 0, origins: 0, savedAt };
        rows.set(site, r);
      }
      return r;
    };
    for (const c of state.cookies) row(siteOfHost(cookieHost(c))).cookies++;
    for (const o of state.origins) {
      const h = originHost(o.origin);
      if (h) row(siteOfHost(h)).origins++;
    }
    return [...rows.values()];
  }

  private applyQueued(agentId: string, requests: ClearRequest[], dropped: SiteCount[]): void {
    for (const r of requests) {
      const hit = r.site === null ? dropped : dropped.filter((d) => d.site === r.site);
      this.audit('session.cleared', {
        agentId,
        ...(r.site !== null ? { site: r.site } : {}),
        cookies: hit.reduce((n, d) => n + d.cookies, 0),
        pages: 0,
        via: 'admin',
      });
      this.repo.deleteClearRequest(r.id);
    }
  }

  restore(agentId: string): Restored {
    const none: Restored = { state: null, finish: () => {} };
    if (!this.isActive(agentId)) return none;
    const loaded = this.store.load(agentId);
    if (loaded.kind === 'none') return none;
    if (loaded.kind === 'discarded') {
      this.store.delete(agentId);
      this.repo.deleteIndex(agentId);
      this.audit('browser_state.discarded', { agentId, reason: loaded.reason });
      return none;
    }
    const plain = loaded.plain;
    const requests = this.repo.clearRequests(agentId);
    if (requests.some((r) => r.site === null)) {
      const all = this.indexRows(plain.state, plain.savedAt).map((r) => ({
        site: r.site,
        cookies: r.cookies,
        origins: r.origins,
      }));
      this.store.delete(agentId);
      this.repo.deleteIndex(agentId);
      this.repo.deleteClocks(agentId);
      this.applyQueued(agentId, requests, all);
      return none;
    }
    const cleared = new Set(requests.map((r) => r.site as string));
    const { state, report } = filterState(plain.state, plain.visited, {
      secrets: [],
      verdict: this.verdictFor(agentId, cleared),
    });
    const d = report.dropped;
    const anyDropped =
      d.deny.length + d.highRisk.length + d.ttl.length + d.cleared.length > 0 ||
      d.secret.cookies + d.secret.origins > 0;
    for (const t of d.ttl) {
      this.audit('session.cleared', {
        agentId,
        origin: t.origin,
        ttlMs: t.ttlMs,
        cookies: t.cookies,
        pages: 0,
        via: 'restore',
      });
      for (const c of this.repo.clocks(agentId)) {
        if (onSite(c.host, t.site)) this.repo.deleteClock(agentId, c.origin);
      }
    }
    this.applyQueued(agentId, requests, d.cleared);
    if (anyDropped) {
      try {
        if (state.cookies.length === 0 && state.origins.length === 0) this.store.delete(agentId);
        else this.store.write(agentId, { ...plain, state });
      } catch {
        this.store.delete(agentId);
      }
    }
    this.repo.setIndex(agentId, this.indexRows(state, plain.savedAt));
    const empty = state.cookies.length === 0 && state.origins.length === 0;
    return {
      state: empty ? null : state,
      finish: (ok) => {
        if (!ok && !empty) {
          this.store.delete(agentId);
          this.repo.deleteIndex(agentId);
          this.audit('browser_state.discarded', { agentId, reason: 'restore_failed' });
          return;
        }
        this.audit('browser_state.restored', {
          agentId,
          sites: report.sites,
          cookies: report.cookies,
          origins: report.origins,
          dropped: {
            ttl: d.ttl.map(({ site, cookies, origins }) => ({ site, cookies, origins })),
            deny: d.deny,
            highRisk: d.highRisk,
            cleared: d.cleared,
            secret: d.secret,
          },
        });
      },
    };
  }

  save(
    agentId: string,
    collected: { state: SavedState; visited: readonly string[] },
    secrets: readonly string[],
  ): SaveResult {
    if (!this.isActive(agentId)) return { written: false, report: null, trimmed: 0 };
    const cleared = new Set(
      this.repo
        .clearRequests(agentId)
        .map((r) => r.site)
        .filter((s): s is string => s !== null),
    );
    const { state, report } = filterState(collected.state, collected.visited, {
      secrets,
      verdict: this.verdictFor(agentId, cleared),
    });
    const keptSites = new Set(report.sites);
    const visited = [...new Set(collected.visited)].filter((o) => {
      const h = originHost(o);
      return h !== null && keptSites.has(siteOfHost(h));
    });
    const savedAt = this.now();
    let plain: StatePlain = { v: 1, savedAt, state, visited };
    const t = trimPlain(plain);
    plain = t.plain;
    if (plain.state.cookies.length === 0 && plain.state.origins.length === 0) {
      this.store.delete(agentId);
    } else {
      this.store.write(agentId, plain);
    }
    if (!this.isActive(agentId)) {
      this.discardFiles(agentId);
      return { written: false, report, trimmed: t.trimmed };
    }
    this.repo.setIndex(agentId, this.indexRows(plain.state, savedAt));
    if (t.trimmed > 0) this.audit('browser_state.trimmed', { agentId, origins: t.trimmed });
    if (report.dropped.secret.cookies + report.dropped.secret.origins > 0) {
      this.audit('browser_state.filtered', { agentId, secret: report.dropped.secret });
    }
    return { written: true, report, trimmed: t.trimmed };
  }

  rewriteDropSite(agentId: string, site: string): { cookies: number; origins: number } {
    const loaded = this.store.load(agentId);
    if (loaded.kind === 'none') return { cookies: 0, origins: 0 };
    if (loaded.kind === 'discarded') {
      this.store.delete(agentId);
      this.repo.deleteIndex(agentId);
      this.audit('browser_state.discarded', { agentId, reason: loaded.reason });
      return { cookies: 0, origins: 0 };
    }
    const r = dropSite(loaded.plain.state, site);
    if (r.cookies + r.origins > 0) {
      if (r.state.cookies.length === 0 && r.state.origins.length === 0) this.store.delete(agentId);
      else this.store.write(agentId, { ...loaded.plain, state: r.state });
    }
    this.repo.setIndex(agentId, this.indexRows(r.state, loaded.plain.savedAt));
    return { cookies: r.cookies, origins: r.origins };
  }

  refilter(agentId: string): FilterReport | null {
    const loaded = this.store.load(agentId);
    if (loaded.kind !== 'ok') return null;
    const { state, report } = filterState(loaded.plain.state, loaded.plain.visited, {
      secrets: [],
      verdict: this.verdictFor(agentId),
    });
    if (
      state.cookies.length === loaded.plain.state.cookies.length &&
      state.origins.length === loaded.plain.state.origins.length
    ) {
      return report;
    }
    if (state.cookies.length === 0 && state.origins.length === 0) this.store.delete(agentId);
    else this.store.write(agentId, { ...loaded.plain, state });
    this.repo.setIndex(agentId, this.indexRows(state, loaded.plain.savedAt));
    return report;
  }

  savedCookies(agentId: string): number {
    const loaded = this.store.load(agentId);
    return loaded.kind === 'ok' ? loaded.plain.state.cookies.length : 0;
  }

  discardFiles(agentId: string): boolean {
    const had = isAgentId(agentId) ? this.store.delete(agentId) : false;
    this.repo.deleteClocks(agentId);
    this.repo.deleteIndex(agentId);
    return had;
  }

  cleanupInactive(): void {
    for (const id of this.store.agentIds()) {
      if (this.isActive(id)) continue;
      this.discardFiles(id);
      this.audit('browser_state.deleted', { agentId: id, reason: 'agent_inactive' });
    }
    const rowAgents = new Set([
      ...this.repo.clocks().map((c) => c.agentId),
      ...this.repo.index().map((r) => r.agentId),
    ]);
    for (const id of rowAgents) if (!this.isActive(id)) this.repo.forgetAgent(id);
  }
}

export function cookieHash(cookies: readonly SavedCookie[]): string {
  return createHash('sha256').update(JSON.stringify(cookies)).digest('base64url');
}

export type { SessionClock };
