import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import {
  AgentRegistry,
  ALL_AGENTS,
  AuditLog,
  openDb,
  type PolicyMode,
  type PolicyRule,
  PolicyStore,
} from '@aab/core';
import { formatDuration } from './format.ts';

type Out = (text: string) => void;

export class PolicyCliError extends Error {}

export function withDb<T>(target: string | DatabaseSync, fn: (db: DatabaseSync) => T): T {
  if (typeof target !== 'string') return fn(target);
  const dataDir = target;
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const db = openDb(join(dataDir, 'broker.sqlite'));
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

export function appendAudit(audit: AuditLog, type: string, payload: Record<string, unknown>) {
  let lastErr: unknown;
  for (let i = 0; i < 5; i++) {
    try {
      audit.append(type, payload);
      return;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

function agentScope(db: DatabaseSync, agent: string | null): string {
  if (agent === null) return ALL_AGENTS;
  if (!new AgentRegistry(db).byId(agent)) {
    throw new PolicyCliError(`no active agent with id ${agent} (see keyflap agent list)`);
  }
  return agent;
}

function describeRule(r: PolicyRule): string {
  const mode =
    r.mode === 'allow-for'
      ? `allow-for ${formatDuration(r.allowForMs ?? 0)}`
      : r.mode === 'none'
        ? 'no mode of its own'
        : r.mode;
  const ttl = r.sessionTtlMs === null ? '' : `, session TTL ${formatDuration(r.sessionTtlMs)}`;
  return `${mode}${ttl}`;
}

export function policySet(
  opts: {
    dataDir: string;
    db?: DatabaseSync;
    site: string;
    agent: string | null;
    mode: PolicyMode | null;
    allowForMs: number | null;
    sessionTtlMs: number | null | undefined;
  },
  out: Out,
): PolicyRule | null {
  return withDb(opts.db ?? opts.dataDir, (db) => {
    const agentId = agentScope(db, opts.agent);
    const rule = new PolicyStore(db).set(opts.site, agentId, {
      ...(opts.mode !== null ? { mode: opts.mode } : {}),
      ...(opts.allowForMs !== null ? { allowForMs: opts.allowForMs } : {}),
      ...(opts.sessionTtlMs !== undefined ? { sessionTtlMs: opts.sessionTtlMs } : {}),
    });
    const who = agentId === ALL_AGENTS ? 'all agents' : `agent ${agentId}`;
    if (rule === null) {
      appendAudit(new AuditLog(db), 'policy.removed', { pattern: opts.site, agentId });
      out(`Removed the rule for ${opts.site} (${who}): it set nothing.\n`);
      return null;
    }
    appendAudit(new AuditLog(db), 'policy.set', {
      pattern: rule.pattern,
      agentId,
      mode: rule.mode,
      ...(rule.allowForMs !== null ? { allowForMs: rule.allowForMs } : {}),
      ...(rule.sessionTtlMs !== null ? { sessionTtlMs: rule.sessionTtlMs } : {}),
    });
    out(`${rule.pattern} (${who}): ${describeRule(rule)}. Applies from the next request.\n`);
    return rule;
  });
}

export function policyRemove(
  opts: { dataDir: string; db?: DatabaseSync; site: string; agent: string | null },
  out: Out,
): boolean {
  return withDb(opts.db ?? opts.dataDir, (db) => {
    const agentId = opts.agent ?? ALL_AGENTS;
    const removed = new PolicyStore(db).remove(opts.site, agentId);
    if (!removed) {
      throw new PolicyCliError(
        `no rule for ${opts.site} (${agentId === ALL_AGENTS ? 'all agents' : `agent ${agentId}`})`,
      );
    }
    appendAudit(new AuditLog(db), 'policy.removed', { pattern: opts.site, agentId });
    out(`Removed the rule for ${opts.site}.\n`);
    return true;
  });
}

export interface PolicyListing {
  site: string;
  agentId: string;
  agentName: string | null;
  mode: PolicyRule['mode'];
  allowForMs: number | null;
  sessionTtlMs: number | null;
  updatedAt: number;
}

export function listPolicies(db: DatabaseSync, agent: string | null): PolicyListing[] {
  const names = new Map(new AgentRegistry(db).list().map((a) => [a.id, a.name]));
  return new PolicyStore(db)
    .list()
    .filter((r) => agent === null || r.agentId === agent || r.agentId === ALL_AGENTS)
    .map((r) => ({
      site: r.pattern,
      agentId: r.agentId,
      agentName: r.agentId === ALL_AGENTS ? null : (names.get(r.agentId) ?? null),
      mode: r.mode,
      allowForMs: r.allowForMs,
      sessionTtlMs: r.sessionTtlMs,
      updatedAt: r.updatedAt,
    }));
}

export function policyTable(rows: PolicyListing[]): string {
  const table = [
    ['SITE', 'AGENT', 'MODE', 'SESSION TTL'],
    ...rows.map((r) => [
      r.site,
      r.agentId === ALL_AGENTS ? '* (all)' : `${r.agentName ?? '(revoked)'} ${r.agentId}`,
      r.mode === 'allow-for'
        ? `allow-for ${formatDuration(r.allowForMs ?? 0)}`
        : r.mode === 'none'
          ? '-'
          : r.mode,
      r.sessionTtlMs === null ? '-' : formatDuration(r.sessionTtlMs),
    ]),
  ];
  const widths = [0, 1, 2].map((i) => Math.max(...table.map((r) => (r[i] as string).length)));
  return `${table
    .map((r) =>
      r
        .map((c, i) => (i < 3 ? c.padEnd(widths[i] as number) : c))
        .join('  ')
        .trimEnd(),
    )
    .join('\n')}\n`;
}

export function policyList(
  opts: { dataDir: string; db?: DatabaseSync; agent: string | null; json: boolean },
  out: Out,
): PolicyListing[] {
  const rows = withDb(opts.db ?? opts.dataDir, (db) => listPolicies(db, opts.agent));
  if (opts.json) out(`${JSON.stringify(rows, null, 2)}\n`);
  else if (rows.length === 0) {
    out('No policy rules: every site asks (high-risk sites ask with user verification).\n');
  } else out(policyTable(rows));
  return rows;
}
