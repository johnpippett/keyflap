import { isIP } from 'node:net';
import type { DatabaseSync } from 'node:sqlite';
import { MAX_GRANT_MS } from '@aab/signer/approval';
import { isLocalhost, registrableDomain } from './origin.ts';

export type PolicyMode = 'deny' | 'ask' | 'ask-strong' | 'allow-for';
export type RuleMode = PolicyMode | 'none';
export const RULE_MODES: readonly RuleMode[] = ['deny', 'ask', 'ask-strong', 'allow-for', 'none'];

export const ALL_AGENTS = '*';

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const ALLOW_FOR_MIN_MS = SECOND;
export const ALLOW_FOR_MAX_MS = MAX_GRANT_MS;
export const SESSION_TTL_MIN_MS = SECOND;
export const SESSION_TTL_MAX_MS = 30 * DAY;

export class PolicyError extends Error {}

export interface PolicyRule {
  pattern: string;
  agentId: string;
  mode: RuleMode;
  allowForMs: number | null;
  sessionTtlMs: number | null;
  updatedAt: number;
}

export interface EffectivePolicy {
  mode: PolicyMode;
  allowForMs: number | null;
  sessionTtlMs: number | null;
  matched: { pattern: string; agentId: string }[];
}

export const DEFAULT_POLICY: EffectivePolicy = {
  mode: 'ask',
  allowForMs: null,
  sessionTtlMs: null,
  matched: [],
};

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function validHost(h: string): boolean {
  return (
    h.length > 0 &&
    h.length <= 253 &&
    isIP(h.replace(/^\[|\]$/g, '')) === 0 &&
    h.split('.').every((l) => LABEL.test(l))
  );
}

export function normalizePattern(input: string): string {
  if (typeof input !== 'string') throw new PolicyError('site must be a string');
  const raw = input.trim();
  if (raw.length === 0 || raw.length > 300) throw new PolicyError('site must not be empty');
  if (raw.includes('*')) throw new PolicyError('wildcards are not supported; use a domain');
  if (/\s/.test(raw)) throw new PolicyError(`not a valid site: "${raw}"`);
  if (raw.includes('://')) {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new PolicyError(`not a valid origin: "${raw}"`);
    }
    const host = url.hostname;
    const httpOk = url.protocol === 'http:' && isLocalhost(host);
    if (url.protocol !== 'https:' && !httpOk) {
      throw new PolicyError('an origin must be https:// (http:// only on localhost)');
    }
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/') {
      throw new PolicyError('an origin is scheme://host[:port], nothing after it');
    }
    if (!validHost(host)) throw new PolicyError(`not a valid origin: "${raw}"`);
    return url.origin;
  }
  if (/[/?#@:\\]/.test(raw)) {
    throw new PolicyError(
      `not a valid domain: "${raw}" (for one origin, give https://host[:port])`,
    );
  }
  let host: string;
  try {
    host = new URL(`https://${raw.replace(/\.$/, '')}/`).hostname;
  } catch {
    throw new PolicyError(`not a valid domain: "${raw}"`);
  }
  if (!validHost(host)) throw new PolicyError(`not a valid domain: "${raw}"`);
  if (registrableDomain(host) === null) {
    throw new PolicyError(
      `"${host}" is a public suffix or has no registrable domain; name a site such as example.com`,
    );
  }
  return host;
}

export const isOriginPattern = (p: string) => p.includes('://');

export function patternMatches(pattern: string, target: { origin: string; host: string }): boolean {
  if (isOriginPattern(pattern)) return pattern === target.origin;
  return target.host === pattern || target.host.endsWith(`.${pattern}`);
}

const STRICTNESS: Record<PolicyMode, number> = {
  'allow-for': 0,
  ask: 1,
  'ask-strong': 2,
  deny: 3,
};

export function resolvePolicy(
  rules: readonly PolicyRule[],
  agentId: string,
  target: { origin: string; host: string },
): EffectivePolicy {
  const hits = rules.filter(
    (r) => (r.agentId === agentId || r.agentId === ALL_AGENTS) && patternMatches(r.pattern, target),
  );
  if (hits.length === 0) return { ...DEFAULT_POLICY, matched: [] };
  let mode: PolicyMode | null = null;
  let allowForMs: number | null = null;
  let sessionTtlMs: number | null = null;
  for (const r of hits) {
    if (r.sessionTtlMs !== null && (sessionTtlMs === null || r.sessionTtlMs < sessionTtlMs)) {
      sessionTtlMs = r.sessionTtlMs;
    }
    if (r.mode === 'none') continue;
    if (r.mode === 'allow-for' && (r.allowForMs === null || r.allowForMs <= 0)) {
      if (mode === null || STRICTNESS.ask > STRICTNESS[mode]) mode = 'ask';
      continue;
    }
    if (mode === null || STRICTNESS[r.mode] > STRICTNESS[mode]) {
      mode = r.mode;
      allowForMs = r.mode === 'allow-for' ? r.allowForMs : null;
    } else if (mode === 'allow-for' && r.mode === 'allow-for') {
      allowForMs = Math.min(allowForMs ?? Number.POSITIVE_INFINITY, r.allowForMs as number);
    }
  }
  const finalMode = mode ?? 'ask';
  return {
    mode: finalMode,
    allowForMs: finalMode === 'allow-for' ? allowForMs : null,
    sessionTtlMs,
    matched: hits.map((r) => ({ pattern: r.pattern, agentId: r.agentId })),
  };
}

export function parseDuration(input: string): number {
  const s = typeof input === 'string' ? input.trim().toLowerCase() : '';
  if (!/^(\d{1,6}[smhd])+$/.test(s)) {
    throw new PolicyError(`not a duration: "${input}" (use e.g. 30m, 2h, 1h30m, 7d)`);
  }
  const unit: Record<string, number> = { s: SECOND, m: MINUTE, h: HOUR, d: DAY };
  let total = 0;
  for (const m of s.matchAll(/(\d+)([smhd])/g)) {
    total += Number(m[1]) * (unit[m[2] as string] as number);
  }
  return total;
}

function checkRange(ms: number, min: number, max: number, what: string): void {
  if (!Number.isInteger(ms) || ms < min || ms > max) {
    throw new PolicyError(`${what} must be between ${min / SECOND}s and ${max / HOUR}h`);
  }
}

interface Row {
  origin_pattern: string;
  agent_id: string;
  mode: string;
  allow_for_ms: number | null;
  session_ttl: number | null;
  updated_at: number;
}

const toRule = (r: Row): PolicyRule | null => {
  if (!RULE_MODES.includes(r.mode as RuleMode)) return null;
  return {
    pattern: r.origin_pattern,
    agentId: r.agent_id,
    mode: r.mode as RuleMode,
    allowForMs: r.allow_for_ms === null ? null : Number(r.allow_for_ms),
    sessionTtlMs: r.session_ttl === null ? null : Number(r.session_ttl),
    updatedAt: Number(r.updated_at),
  };
};

export interface RuleUpdate {
  mode?: PolicyMode;
  allowForMs?: number;
  sessionTtlMs?: number | null;
}

export class PolicyStore {
  private readonly db: DatabaseSync;
  private readonly now: () => number;

  constructor(db: DatabaseSync, opts: { now?: () => number } = {}) {
    this.db = db;
    this.now = opts.now ?? Date.now;
  }

  list(agentId?: string): PolicyRule[] {
    const rows = (agentId === undefined
      ? this.db
          .prepare(
            `SELECT origin_pattern, agent_id, mode, allow_for_ms, session_ttl, updated_at
               FROM policies ORDER BY origin_pattern, agent_id`,
          )
          .all()
      : this.db
          .prepare(
            `SELECT origin_pattern, agent_id, mode, allow_for_ms, session_ttl, updated_at
               FROM policies WHERE agent_id = ? ORDER BY origin_pattern`,
          )
          .all(agentId)) as unknown as Row[];
    return rows.map(toRule).filter((r): r is PolicyRule => r !== null);
  }

  private allForResolve(): PolicyRule[] {
    const rows = this.db
      .prepare(
        'SELECT origin_pattern, agent_id, mode, allow_for_ms, session_ttl, updated_at FROM policies',
      )
      .all() as unknown as Row[];
    return rows.map(
      (r) =>
        toRule(r) ?? {
          pattern: r.origin_pattern,
          agentId: r.agent_id,
          mode: 'deny',
          allowForMs: null,
          sessionTtlMs: null,
          updatedAt: Number(r.updated_at),
        },
    );
  }

  resolve(agentId: string, target: { origin: string; host: string }): EffectivePolicy {
    return resolvePolicy(this.allForResolve(), agentId, target);
  }

  get(pattern: string, agentId: string): PolicyRule | null {
    return this.list().find((r) => r.pattern === pattern && r.agentId === agentId) ?? null;
  }

  set(patternInput: string, agentId: string, u: RuleUpdate): PolicyRule | null {
    const pattern = normalizePattern(patternInput);
    if (typeof agentId !== 'string' || agentId.length === 0 || agentId.length > 128) {
      throw new PolicyError('bad agent id');
    }
    if (u.mode !== undefined && !RULE_MODES.includes(u.mode)) {
      throw new PolicyError(`unknown mode "${u.mode}"`);
    }
    if (u.mode === 'allow-for') {
      if (u.allowForMs === undefined) throw new PolicyError('allow-for needs a duration');
      checkRange(u.allowForMs, ALLOW_FOR_MIN_MS, ALLOW_FOR_MAX_MS, 'allow-for');
    } else if (u.allowForMs !== undefined) {
      throw new PolicyError('a duration goes only with allow-for');
    }
    if (u.sessionTtlMs !== undefined && u.sessionTtlMs !== null) {
      checkRange(u.sessionTtlMs, SESSION_TTL_MIN_MS, SESSION_TTL_MAX_MS, 'session TTL');
    }
    const old = this.get(pattern, agentId);
    const mode: RuleMode = u.mode ?? old?.mode ?? 'none';
    const allowForMs = mode === 'allow-for' ? (u.allowForMs ?? old?.allowForMs ?? null) : null;
    const sessionTtlMs =
      u.sessionTtlMs === undefined ? (old?.sessionTtlMs ?? null) : u.sessionTtlMs;
    if (mode === 'none' && sessionTtlMs === null) {
      this.remove(pattern, agentId);
      return null;
    }
    const updatedAt = this.now();
    this.db
      .prepare(
        `INSERT INTO policies (origin_pattern, agent_id, mode, allow_for_ms, session_ttl, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (origin_pattern, agent_id) DO UPDATE SET mode = excluded.mode,
           allow_for_ms = excluded.allow_for_ms, session_ttl = excluded.session_ttl,
           updated_at = excluded.updated_at`,
      )
      .run(pattern, agentId, mode, allowForMs, sessionTtlMs, updatedAt);
    return { pattern, agentId, mode, allowForMs, sessionTtlMs, updatedAt };
  }

  remove(patternInput: string, agentId: string): boolean {
    const pattern = normalizePattern(patternInput);
    const r = this.db
      .prepare('DELETE FROM policies WHERE origin_pattern = ? AND agent_id = ?')
      .run(pattern, agentId);
    return Number(r.changes) > 0;
  }
}
