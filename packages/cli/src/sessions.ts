import type { DatabaseSync } from 'node:sqlite';
import {
  AgentRegistry,
  ALL_AGENTS_OPTIN,
  AuditLog,
  normalizePattern,
  PersistOptins,
  PolicyStore,
  SessionStateRepo,
  siteOfHost,
} from '@aab/core';
import { isHighRisk } from '@aab/signer/risk';
import { appendAudit, withDb } from './policy.ts';

type Out = (text: string) => void;

export class SessionsCliError extends Error {}

export function normalizeSite(input: string): string {
  let pattern: string;
  try {
    pattern = normalizePattern(input);
  } catch (err) {
    throw new SessionsCliError(err instanceof Error ? err.message : 'not a valid site');
  }
  const host = pattern.includes('://') ? new URL(pattern).hostname : pattern;
  return siteOfHost(host);
}

function requireAgent(db: DatabaseSync, agent: string): void {
  if (!new AgentRegistry(db).byId(agent)) {
    throw new SessionsCliError(`no active agent with id ${agent} (see keyflap agent list)`);
  }
}

export interface SessionListing {
  agentId: string;
  agentName: string;
  site: string;
  cookies: number;
  origins: number;
  savedAt: number;
  ttlDeadline: number | null;
}

export interface SessionsReport {
  sessions: SessionListing[];
  kept: { agentId: string; site: string; createdAt: number; via: string }[];
  pendingClears: number;
}

export function collectSessions(db: DatabaseSync, agent: string | null): SessionsReport {
  const repo = new SessionStateRepo(db);
  const policy = new PolicyStore(db);
  const names = new Map(new AgentRegistry(db).list().map((a) => [a.id, a.name]));
  const rows = repo.index(agent ?? undefined);
  const clocks = repo.clocks(agent ?? undefined);
  const sessions = rows.map((r) => {
    let deadline: number | null = null;
    for (const c of clocks) {
      if (c.agentId !== r.agentId || siteOfHost(c.host) !== r.site) continue;
      const ttl = policy.resolve(c.agentId, { origin: c.origin, host: c.host }).sessionTtlMs;
      if (ttl === null) continue;
      const d = c.startedAt + ttl;
      deadline = deadline === null ? d : Math.max(deadline, d);
    }
    return {
      agentId: r.agentId,
      agentName: names.get(r.agentId) ?? '?',
      site: r.site,
      cookies: r.cookies,
      origins: r.origins,
      savedAt: r.savedAt,
      ttlDeadline: deadline,
    };
  });
  const kept = new PersistOptins(db)
    .list(agent ?? undefined)
    .map((o) => ({ agentId: o.agentId, site: o.site, createdAt: o.createdAt, via: o.via }));
  return { sessions, kept, pendingClears: repo.clearRequests().length };
}

const iso = (ms: number | null) => (ms === null ? '-' : new Date(ms).toISOString());

export function formatSessions(report: SessionsReport, json: boolean): string {
  if (json) return `${JSON.stringify(report, null, 2)}\n`;
  let text = '';
  if (report.sessions.length === 0) {
    text += 'No saved browser sessions.\n';
  } else {
    const rows = [
      ['AGENT', 'SITE', 'COOKIES', 'ORIGINS', 'SAVED', 'TTL ENDS'],
      ...report.sessions.map((s) => [
        `${s.agentName} (${s.agentId.slice(0, 8)})`,
        s.site,
        String(s.cookies),
        String(s.origins),
        iso(s.savedAt),
        iso(s.ttlDeadline),
      ]),
    ];
    const widths =
      rows[0]?.map((_, i) => Math.max(...rows.map((r) => (r[i] as string).length))) ?? [];
    text += `${rows
      .map((r) =>
        r
          .map((c, i) => c.padEnd(widths[i] as number))
          .join('  ')
          .trimEnd(),
      )
      .join('\n')}\n`;
  }
  if (report.kept.length > 0) {
    text += '\nHigh-risk sites kept signed in (keyflap sessions unkeep <site> to stop):\n';
    for (const k of report.kept) {
      text += `  ${k.site}  ${k.agentId === ALL_AGENTS_OPTIN ? 'all agents' : k.agentId}  (${k.via}, ${iso(k.createdAt)})\n`;
    }
  }
  if (report.pendingClears > 0) {
    text += `\n${report.pendingClears} clear request(s) queued for the daemon.\n`;
  }
  return text;
}

export function sessionsList(
  opts: { dataDir: string; db?: DatabaseSync; agent: string | null; json: boolean },
  out: Out,
): SessionsReport {
  const report = withDb(opts.db ?? opts.dataDir, (db) => collectSessions(db, opts.agent));
  out(formatSessions(report, opts.json));
  return report;
}

export function sessionsClear(
  opts: { dataDir: string; agent: string | null; all: boolean; site: string | null },
  out: Out,
): { queued: number } {
  const site = opts.site === null ? null : normalizeSite(opts.site);
  const queued = withDb(opts.dataDir, (db) => {
    const registry = new AgentRegistry(db);
    let agents: string[];
    if (opts.all) {
      agents = registry
        .list()
        .filter((a) => a.revokedAt === null)
        .map((a) => a.id);
    } else {
      requireAgent(db, opts.agent as string);
      agents = [opts.agent as string];
    }
    const repo = new SessionStateRepo(db);
    for (const id of agents) repo.queueClear({ agentId: id, site, via: 'cli', now: Date.now() });
    appendAudit(new AuditLog(db), 'session.clear_requested', {
      agentId: opts.all ? '*' : opts.agent,
      ...(site !== null ? { site } : {}),
      via: 'cli',
    });
    return agents.length;
  });
  out(
    `Queued: ${site ?? 'every site'} for ${opts.all ? `all agents (${queued})` : `agent ${opts.agent}`}. ` +
      'A running daemon applies it within 30 s; otherwise the next start applies it before ' +
      'anything is restored.\n',
  );
  return { queued };
}

export function sessionsKeep(
  opts: {
    dataDir: string;
    db?: DatabaseSync;
    site: string;
    agent: string | null;
    via?: 'cli' | 'admin';
  },
  out: Out,
): { site: string; added: boolean } {
  const site = normalizeSite(opts.site);
  const added = withDb(opts.db ?? opts.dataDir, (db) => {
    if (opts.agent !== null) requireAgent(db, opts.agent);
    const audit = new AuditLog(db);
    const optins = new PersistOptins(db, { audit: (e, f) => appendAudit(audit, e, f) });
    return optins.add(opts.agent ?? ALL_AGENTS_OPTIN, site, opts.via ?? 'cli');
  });
  const who = opts.agent === null ? 'every agent' : `agent ${opts.agent}`;
  out(
    `${added ? 'Keeping' : 'Already keeping'} ${site} signed in across restarts for ${who}.` +
      (isHighRisk(site)
        ? ''
        : ` (${site} is not on the built-in high-risk list; non-high-risk sites are kept anyway.)`) +
      '\n',
  );
  return { site, added };
}

export function sessionsUnkeep(
  opts: {
    dataDir: string;
    db?: DatabaseSync;
    site: string;
    agent: string | null;
    via?: 'cli' | 'admin';
  },
  out: Out,
): { site: string; removed: boolean } {
  const site = normalizeSite(opts.site);
  const removed = withDb(opts.db ?? opts.dataDir, (db) => {
    const audit = new AuditLog(db);
    const optins = new PersistOptins(db, { audit: (e, f) => appendAudit(audit, e, f) });
    return optins.remove(opts.agent ?? ALL_AGENTS_OPTIN, site, opts.via ?? 'cli');
  });
  out(
    removed
      ? `No longer keeping ${site}. It leaves the saved state on the daemon's next save or sweep (at most 30 s).\n`
      : `${site} was not kept${opts.agent === null ? ' for all agents' : ` for agent ${opts.agent}`}.\n`,
  );
  return { site, removed };
}
