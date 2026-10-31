import type { DatabaseSync } from 'node:sqlite';
import type { ListSourceItemsResult } from '@aab/signer/protocol';
import type { AuditLog } from './audit.ts';
import { CredentialRepo, type PasswordRow } from './db.ts';
import { hasUnsafeText } from './display-text.ts';
import { registrableDomain } from './origin.ts';

export interface SourceSyncOptions {
  source: string;
  signer: { listSourceItems(source: string): Promise<ListSourceItemsResult> };
  db: DatabaseSync;
  audit: AuditLog;
  now?: () => number;
  minIntervalMs?: number;
}

export interface SyncResult {
  items: number;
  added: number;
  removed: number;
  updated: number;
}

interface Wanted {
  id: string;
  ref: string;
  domain: string;
  username: string | null;
  hasTotp: boolean;
}

const MIN_INTERVAL_MS = 30_000;

export function dropUnconfiguredSourceRows(
  db: DatabaseSync,
  audit: AuditLog,
  configured: string | null,
): number {
  const repo = new CredentialRepo(db);
  const stale = repo.allPasswords().filter((r) => r.source !== 'signer' && r.source !== configured);
  if (stale.length === 0) return 0;
  db.exec('BEGIN IMMEDIATE');
  try {
    for (const r of stale) repo.deletePassword(r.id);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  for (const r of stale) {
    audit.append('credential.removed', {
      credentialId: r.id,
      type: 'password',
      source: r.source,
      reason: 'source_not_configured',
    });
  }
  return stale.length;
}

export class SourceSync {
  readonly source: string;
  private readonly signer: SourceSyncOptions['signer'];
  private readonly repo: CredentialRepo;
  private readonly db: DatabaseSync;
  private readonly audit: AuditLog;
  private readonly now: () => number;
  private readonly minIntervalMs: number;
  private inFlight: Promise<SyncResult> | null = null;
  private lastAttempt = Number.NEGATIVE_INFINITY;
  private lastError: string | null = null;

  constructor(opts: SourceSyncOptions) {
    this.source = opts.source;
    this.signer = opts.signer;
    this.db = opts.db;
    this.repo = new CredentialRepo(opts.db);
    this.audit = opts.audit;
    this.now = opts.now ?? Date.now;
    this.minIntervalMs = opts.minIntervalMs ?? MIN_INTERVAL_MS;
  }

  refresh(): Promise<SyncResult> {
    this.inFlight ??= this.run().finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  async refreshIfStale(): Promise<void> {
    if (!this.inFlight && this.now() - this.lastAttempt < this.minIntervalMs) return;
    await this.refresh().catch(() => {});
  }

  private async run(): Promise<SyncResult> {
    this.lastAttempt = this.now();
    let items: ListSourceItemsResult['items'];
    try {
      ({ items } = await this.signer.listSourceItems(this.source));
      if (!Array.isArray(items)) throw new Error('bad_response');
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'source_failed';
      if (reason !== this.lastError) {
        this.audit.append('source.sync_failed', { source: this.source, reason });
      }
      this.lastError = reason;
      throw err;
    }
    if (this.lastError !== null) this.audit.append('source.sync_ok', { source: this.source });
    this.lastError = null;
    return this.apply(items);
  }

  private apply(items: ListSourceItemsResult['items']): SyncResult {
    const wanted = new Map<string, Wanted>();
    for (const it of items) {
      if (typeof it?.ref !== 'string' || !it.ref.startsWith(`${this.source}:`)) continue;
      if (it.ref.length > 600 || !Array.isArray(it.hosts)) continue;
      const username = cleanUsername(it.username);
      for (const host of it.hosts) {
        if (typeof host !== 'string') continue;
        const domain = registrableDomain(host);
        if (!domain) continue;
        const id = `${it.ref}@${domain}`;
        wanted.set(id, { id, ref: it.ref, domain, username, hasTotp: it.hasTotp === true });
      }
    }
    const existing = new Map<string, PasswordRow>(
      this.repo.sourcePasswords(this.source).map((r) => [r.id, r]),
    );
    const result: SyncResult = { items: items.length, added: 0, removed: 0, updated: 0 };
    const events: [string, Record<string, unknown>][] = [];
    const now = this.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const [id] of existing) {
        if (wanted.has(id)) continue;
        this.repo.deletePassword(id);
        events.push([
          'credential.removed',
          { credentialId: id, type: 'password', source: this.source },
        ]);
        result.removed++;
      }
      for (const w of wanted.values()) {
        const row = existing.get(w.id);
        if (!row) {
          this.repo.insertSourcePassword({ ...w, source: this.source, now });
          events.push([
            'credential.added',
            {
              credentialId: w.id,
              type: 'password',
              domain: w.domain,
              totp: w.hasTotp,
              source: this.source,
            },
          ]);
          result.added++;
        } else if (row.username !== w.username || (row.has_totp === 1) !== w.hasTotp) {
          this.repo.updateSourcePassword(w.id, { username: w.username, hasTotp: w.hasTotp });
          events.push([
            'credential.updated',
            { credentialId: w.id, type: 'password', totp: w.hasTotp, source: this.source },
          ]);
          result.updated++;
        }
      }
      this.db.exec('COMMIT');
    } catch (err) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      throw err;
    }
    for (const [e, f] of events) this.audit.append(e, f);
    return result;
  }
}

function cleanUsername(u: unknown): string | null {
  if (typeof u !== 'string' || u.length === 0 || u.length > 256) return null;
  return hasUnsafeText(u) ? null : u;
}
