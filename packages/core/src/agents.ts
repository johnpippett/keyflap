import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { AgentIdentity } from './broker.ts';
import { hasUnsafeText } from './display-text.ts';

export const AGENT_TOKEN_PREFIX = 'aab_agent_';
const TOKEN_RE = /^aab_agent_[A-Za-z0-9_-]{43}$/;
const MAX_NAME = 64;

export interface NewAgent extends AgentIdentity {
  token: string;
}

export interface AgentListing extends AgentIdentity {
  createdAt: number;
  revokedAt: number | null;
}

const tokenHash = (token: string) => createHash('sha256').update(token).digest('hex');

export class AgentRegistry {
  private readonly db: DatabaseSync;
  private readonly now: () => number;
  private readonly revokeListeners = new Set<(id: string) => void>();

  constructor(db: DatabaseSync, opts: { now?: () => number } = {}) {
    this.db = db;
    this.now = opts.now ?? Date.now;
  }

  add(name: string): NewAgent {
    if (
      typeof name !== 'string' ||
      name.length === 0 ||
      name.length > MAX_NAME ||
      name.trim() !== name ||
      hasUnsafeText(name)
    ) {
      throw new Error(`agent name must be 1..${MAX_NAME} printable characters, no outer spaces`);
    }
    const clash = this.db
      .prepare(
        'SELECT 1 FROM agents WHERE name = ? AND revoked_at IS NULL AND token_hash IS NOT NULL',
      )
      .get(name);
    if (clash) throw new Error(`an active agent named "${name}" already exists`);
    const id = randomUUID();
    const token = AGENT_TOKEN_PREFIX + randomBytes(32).toString('base64url');
    this.db
      .prepare('INSERT INTO agents (id, name, created_at, token_hash) VALUES (?, ?, ?, ?)')
      .run(id, name, this.now(), tokenHash(token));
    return { id, name, token };
  }

  byToken(token: unknown): AgentIdentity | null {
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) return null;
    const row = this.db
      .prepare('SELECT id, name FROM agents WHERE token_hash = ? AND revoked_at IS NULL')
      .get(tokenHash(token)) as { id: string; name: string } | undefined;
    return row ? { id: row.id, name: row.name } : null;
  }

  byId(id: unknown): AgentIdentity | null {
    if (typeof id !== 'string' || id.length === 0 || id.length > 128) return null;
    const row = this.db
      .prepare(
        'SELECT id, name FROM agents WHERE id = ? AND revoked_at IS NULL AND token_hash IS NOT NULL',
      )
      .get(id) as { id: string; name: string } | undefined;
    return row ? { id: row.id, name: row.name } : null;
  }

  list(): AgentListing[] {
    const rows = this.db
      .prepare(
        'SELECT id, name, created_at, revoked_at FROM agents WHERE token_hash IS NOT NULL ORDER BY created_at, rowid',
      )
      .all() as { id: string; name: string; created_at: number; revoked_at: number | null }[];
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      createdAt: r.created_at,
      revokedAt: r.revoked_at,
    }));
  }

  revoke(id: string): boolean {
    const res = this.db
      .prepare('UPDATE agents SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
      .run(this.now(), id);
    const changed = Number(res.changes) > 0;
    if (changed) {
      for (const l of this.revokeListeners) {
        try {
          l(id);
        } catch {}
      }
    }
    return changed;
  }

  noticeRevoked(id: string): boolean {
    if (this.byId(id) !== null) return false;
    for (const l of this.revokeListeners) {
      try {
        l(id);
      } catch {}
    }
    return true;
  }

  onRevoke(listener: (id: string) => void): () => void {
    this.revokeListeners.add(listener);
    return () => this.revokeListeners.delete(listener);
  }
}
