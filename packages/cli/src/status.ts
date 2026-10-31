import type { DatabaseSync } from 'node:sqlite';
import { plainStyle, type TermStyle } from '@aab/approver';
import {
  AgentRegistry,
  AuditLog,
  type AuditRow,
  CredentialRepo,
  SessionStateRepo,
} from '@aab/core';
import { listPolicies, type PolicyListing, policyTable, withDb } from './policy.ts';
import { PROTECTS_LESS } from './simple-install.ts';

type Out = (text: string) => void;

export interface AuditEntry {
  seq: number;
  ts: number;
  event: string;
  payload: Record<string, unknown>;
}

const toEntry = (r: AuditRow): AuditEntry => ({
  seq: r.seq,
  ts: r.ts,
  event: r.event_type,
  payload: JSON.parse(r.payload_json) as Record<string, unknown>,
});

function lastEntries(audit: AuditLog, limit: number): AuditEntry[] {
  return audit.all().slice(-limit).map(toEntry);
}

const line = (e: AuditEntry, st: TermStyle = plainStyle) =>
  `${st.dim(String(e.seq).padStart(6))}  ${st.dim(new Date(e.ts).toISOString())}  ${e.event}  ${st.dim(JSON.stringify(e.payload))}\n`;

export interface StatusReport {
  install: 'simple' | 'dev';
  protectsLess: string | null;
  agents: { id: string; name: string }[];
  revokedAgents: number;
  credentials: { passkeys: number; passwords: number; bySource: Record<string, number> };
  policies: PolicyListing[];
  savedSessions: { agents: number; sites: number };
  audit: { entries: number; intact: boolean; brokenAt: number | null; last: AuditEntry[] };
}

export function status(
  opts: { dataDir: string; db?: DatabaseSync; json: boolean; simple?: boolean; style?: TermStyle },
  out: Out,
): StatusReport {
  const st = opts.style ?? plainStyle;
  const report = withDb(opts.db ?? opts.dataDir, (db): StatusReport => {
    const all = new AgentRegistry(db).list();
    const creds = new CredentialRepo(db);
    const passwords = creds.allPasswords();
    const bySource: Record<string, number> = {};
    for (const p of passwords) bySource[p.source] = (bySource[p.source] ?? 0) + 1;
    const audit = new AuditLog(db);
    const brokenAt = audit.verify();
    return {
      install: opts.simple ? 'simple' : 'dev',
      protectsLess: opts.simple ? PROTECTS_LESS : null,
      agents: all.filter((a) => a.revokedAt === null).map((a) => ({ id: a.id, name: a.name })),
      revokedAgents: all.filter((a) => a.revokedAt !== null).length,
      credentials: {
        passkeys: creds.allPasskeyRpIds().length,
        passwords: passwords.length,
        bySource,
      },
      policies: listPolicies(db, null),
      savedSessions: (() => {
        const rows = new SessionStateRepo(db).index();
        return { agents: new Set(rows.map((r) => r.agentId)).size, sites: rows.length };
      })(),
      audit: {
        entries: audit.all().length,
        intact: brokenAt === null,
        brokenAt,
        last: lastEntries(audit, 10),
      },
    };
  });
  if (opts.json) {
    out(`${JSON.stringify(report, null, 2)}\n`);
    return report;
  }
  const a = report.agents;
  const sources = Object.entries(report.credentials.bySource)
    .map(([k, n]) => `${n} ${k === 'signer' ? 'native' : k}`)
    .join(', ');
  const label = (l: string) => st.dim(l);
  out(
    [
      ...(st.level === 0 ? [] : [st.header('status'), '']),
      ...(report.protectsLess ? [st.bold(report.protectsLess), ''] : []),
      `${label('Data dir:   ')} ${opts.dataDir}`,
      `${label('Agents:     ')} ${a.length} active${a.length > 0 ? ` (${a.map((x) => x.name).join(', ')})` : ''}` +
        (report.revokedAgents > 0 ? `, ${report.revokedAgents} revoked` : ''),
      `${label('Credentials:')} ${report.credentials.passkeys} passkeys, ${report.credentials.passwords} password items` +
        (sources ? ` (${sources})` : ''),
      `${label('Policies:   ')} ${report.policies.length === 0 ? 'none (every site asks)' : `${report.policies.length} rules`}`,
      `${label('Saved sessions:')} ${report.savedSessions.agents} agents, ${report.savedSessions.sites} sites`,
      `${label('Audit log:  ')} ${report.audit.entries} entries, ${
        report.audit.intact
          ? st.ok('hash chain intact')
          : st.bad(`HASH CHAIN BROKEN at seq ${report.audit.brokenAt}`)
      }`,
      '',
    ].join('\n'),
  );
  if (report.policies.length > 0) out(`${policyTable(report.policies)}\n`);
  if (report.audit.last.length > 0) {
    out(`${st.head('LAST AUDIT ENTRIES')}\n`);
    for (const e of report.audit.last) out(line(e, st));
  }
  return report;
}

export function auditVerify(
  opts: { dataDir: string; db?: DatabaseSync; style?: TermStyle },
  out: Out,
): boolean {
  const st = opts.style ?? plainStyle;
  const { entries, brokenAt } = withDb(opts.db ?? opts.dataDir, (db) => {
    const audit = new AuditLog(db);
    return { entries: audit.all().length, brokenAt: audit.verify() };
  });
  if (brokenAt === null) {
    out(`${st.ok('Audit hash chain intact')} (${entries} entries).\n`);
    return true;
  }
  out(`${st.bad(`Audit hash chain BROKEN at seq ${brokenAt}`)} (${entries} entries).\n`);
  return false;
}

export function auditTail(
  opts: { dataDir: string; db?: DatabaseSync; limit: number; json: boolean },
  out: Out,
): AuditEntry[] {
  const entries = withDb(opts.db ?? opts.dataDir, (db) =>
    lastEntries(new AuditLog(db), opts.limit),
  );
  if (opts.json) out(`${JSON.stringify(entries, null, 2)}\n`);
  else for (const e of entries) out(line(e));
  return entries;
}
