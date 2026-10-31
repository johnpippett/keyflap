import type { DatabaseSync } from 'node:sqlite';
import type { PolicyMode } from '@aab/core';
import { AdminError, type AdminOps } from '@aab/signer/admin-wire';
import { policyList, policyRemove, policySet } from '../policy.ts';
import { sessionsList } from '../sessions.ts';
import { auditTail, auditVerify, status } from '../status.ts';

const MODES = new Set(['deny', 'ask', 'ask-strong', 'allow-for']);

function optStr(p: Record<string, unknown>, k: string): string | null {
  const v = p[k];
  if (v === undefined || v === null) return null;
  if (typeof v !== 'string' || v.length === 0 || v.length > 2048) throw new AdminError(`bad ${k}`);
  return v;
}

function optMs(p: Record<string, unknown>, k: string): number | null {
  const v = p[k];
  if (v === undefined || v === null) return null;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) throw new AdminError(`bad ${k}`);
  return v;
}

function printed<T>(fn: (out: (t: string) => void) => T): { text: string; result: T } {
  let text = '';
  try {
    const result = fn((t) => {
      text += t;
    });
    return { text, result };
  } catch (err) {
    throw new AdminError(err instanceof Error ? err.message : 'failed');
  }
}

export function registerCliAdminOps(ops: AdminOps, db: DatabaseSync, dataDir: string): void {
  ops.register('policy.set', (p) => {
    const site = optStr(p, 'site');
    if (site === null) throw new AdminError('missing site');
    const mode = optStr(p, 'mode');
    if (mode !== null && !MODES.has(mode)) throw new AdminError('bad mode');
    const ttl = p.sessionTtlMs === undefined ? undefined : optMs(p, 'sessionTtlMs');
    const { text } = printed((out) =>
      policySet(
        {
          dataDir,
          db,
          site,
          agent: optStr(p, 'agent'),
          mode: mode as PolicyMode | null,
          allowForMs: optMs(p, 'allowForMs'),
          sessionTtlMs: ttl,
        },
        out,
      ),
    );
    return { text };
  });
  ops.register('policy.list', (p) => ({
    text: printed((out) =>
      policyList({ dataDir, db, agent: optStr(p, 'agent'), json: p.json === true }, out),
    ).text,
  }));
  ops.register('policy.remove', (p) => {
    const site = optStr(p, 'site');
    if (site === null) throw new AdminError('missing site');
    return {
      text: printed((out) => policyRemove({ dataDir, db, site, agent: optStr(p, 'agent') }, out))
        .text,
    };
  });
  ops.register('sessions.list', (p) => ({
    text: printed((out) =>
      sessionsList({ dataDir, db, agent: optStr(p, 'agent'), json: p.json === true }, out),
    ).text,
  }));
  ops.register('status.report', (p) => ({
    text: printed((out) => status({ dataDir, db, json: p.json === true }, out)).text,
  }));
  ops.register('audit.verify', () => {
    const r = printed((out) => auditVerify({ dataDir, db }, out));
    return { text: r.text, intact: r.result };
  });
  ops.register('audit.tail', (p) => {
    const limit = p.limit;
    if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > 100_000) {
      throw new AdminError('bad limit');
    }
    return {
      text: printed((out) => auditTail({ dataDir, db, limit, json: p.json === true }, out)).text,
    };
  });
}
