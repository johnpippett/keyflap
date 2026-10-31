import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

const GENESIS = '0'.repeat(64);

export interface AuditRow {
  seq: number;
  prev_hash: string;
  hash: string;
  ts: number;
  event_type: string;
  payload_json: string;
}

function entryHash(prev: string, seq: number, ts: number, type: string, payload: string): string {
  return createHash('sha256').update(`${prev}\n${seq}\n${ts}\n${type}\n${payload}`).digest('hex');
}

export class AuditLog {
  private readonly db: DatabaseSync;
  private readonly now: () => number;

  constructor(db: DatabaseSync, now: () => number = Date.now) {
    this.db = db;
    this.now = now;
  }

  append(eventType: string, payload: Record<string, unknown>): AuditRow {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.appendLocked(eventType, payload);
      this.db.exec('COMMIT');
      return row;
    } catch (err) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      throw err;
    }
  }

  private appendLocked(eventType: string, payload: Record<string, unknown>): AuditRow {
    const last = this.db.prepare('SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1').get() as
      | { seq: number; hash: string }
      | undefined;
    const seq = (last?.seq ?? 0) + 1;
    const prev = last?.hash ?? GENESIS;
    const ts = this.now();
    const payloadJson = JSON.stringify(payload);
    const hash = entryHash(prev, seq, ts, eventType, payloadJson);
    this.db
      .prepare(
        'INSERT INTO audit (seq, prev_hash, hash, ts, event_type, payload_json) VALUES (?, ?, ?, ?, ?, ?)',
      )
      .run(seq, prev, hash, ts, eventType, payloadJson);
    return { seq, prev_hash: prev, hash, ts, event_type: eventType, payload_json: payloadJson };
  }

  all(): AuditRow[] {
    return this.db.prepare('SELECT * FROM audit ORDER BY seq').all() as unknown as AuditRow[];
  }

  verify(): number | null {
    let prev = GENESIS;
    let expectedSeq = 1;
    for (const r of this.all()) {
      if (r.seq !== expectedSeq || r.prev_hash !== prev) return r.seq;
      if (entryHash(prev, r.seq, r.ts, r.event_type, r.payload_json) !== r.hash) return r.seq;
      prev = r.hash;
      expectedSeq++;
    }
    return null;
  }
}
