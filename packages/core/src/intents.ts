import { createHash, randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

export const DEFAULT_INTENT_TTL_MS = 10 * 60_000;

export interface Intent {
  id: string;
  agentId: string;
  text: string;
  createdAt: number;
  expiresAt: number;
}

export class IntentStore {
  private readonly db: DatabaseSync;
  private readonly now: () => number;
  private readonly ttlMs: number;

  constructor(db: DatabaseSync, opts: { now?: () => number; ttlMs?: number } = {}) {
    this.db = db;
    this.now = opts.now ?? Date.now;
    this.ttlMs = opts.ttlMs ?? DEFAULT_INTENT_TTL_MS;
  }

  record(agentId: string, text: string): Intent {
    const createdAt = this.now();
    const intent: Intent = {
      id: randomUUID(),
      agentId,
      text,
      createdAt,
      expiresAt: createdAt + this.ttlMs,
    };
    this.db
      .prepare(
        'INSERT INTO intents (id, agent_id, text, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
      )
      .run(intent.id, agentId, text, createdAt, intent.expiresAt);
    return intent;
  }

  latestLive(agentId: string): Intent | undefined {
    const row = this.db
      .prepare(
        `SELECT id, agent_id, text, created_at, expires_at FROM intents
         WHERE agent_id = ? AND expires_at > ? ORDER BY created_at DESC, rowid DESC LIMIT 1`,
      )
      .get(agentId, this.now()) as
      | { id: string; agent_id: string; text: string; created_at: number; expires_at: number }
      | undefined;
    if (!row) return undefined;
    return {
      id: row.id,
      agentId: row.agent_id,
      text: row.text,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
    };
  }
}

export function intentHash(i: Intent): string {
  return createHash('sha256')
    .update(JSON.stringify([i.id, i.agentId, i.createdAt, i.text]))
    .digest('base64url');
}
