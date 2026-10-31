import { chmodSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  public_key TEXT,
  created_at INTEGER NOT NULL,
  token_hash TEXT,                   -- SHA-256 hex of the agent's bearer token (M2)
  revoked_at INTEGER                 -- set by revoke; revoked agents never resolve (M2)
);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,               -- passkeys: the public WebAuthn credential id (b64url)
  type TEXT NOT NULL CHECK (type IN ('passkey','password','totp')),
  rp_id TEXT,
  registrable_domain TEXT,
  user_handle TEXT,
  username TEXT,                     -- passkeys: site-supplied; passwords: user-supplied (CLI) or the source item's. Never in prompts
  public_key TEXT,
  signer_ref TEXT NOT NULL,          -- native: signer item id; external: the source ref (proton-pass:...)
  source TEXT NOT NULL,              -- 'signer' (native) or an external source kind ('proton-pass')
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS credentials_rp ON credentials (rp_id);
CREATE TABLE IF NOT EXISTS policies (
  origin_pattern TEXT NOT NULL,      -- an origin, or a domain covering its subdomains (M5)
  agent_id TEXT NOT NULL,            -- an agent id, or '*' for all agents
  mode TEXT NOT NULL,                -- deny | ask | ask-strong | allow-for | none (TTL only)
  allow_for_ms INTEGER,              -- allow-for window (M5)
  session_ttl INTEGER,               -- ms (M5)
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (origin_pattern, agent_id)
);
CREATE TABLE IF NOT EXISTS intents (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS intents_agent ON intents (agent_id, created_at);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  verified_origin TEXT,
  credential_id TEXT,
  intent_id TEXT,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  decided_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  ts INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
-- Persistent browser state (SESSIONS_PLAN section 2). Identifiers and counts only, never
-- cookie names or values.
CREATE TABLE IF NOT EXISTS session_clocks (  -- M5 session-TTL clocks, now persisted
  agent_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  host TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, origin)
);
CREATE TABLE IF NOT EXISTS browser_sessions (  -- index of saved state, for keyflap sessions list
  agent_id TEXT NOT NULL,
  site TEXT NOT NULL,                -- registrable domain (or host)
  cookies INTEGER NOT NULL,
  origins INTEGER NOT NULL,          -- origins with saved localStorage / IndexedDB
  saved_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, site)
);
CREATE TABLE IF NOT EXISTS session_clear_requests (  -- clears queued by the dev-mode CLI
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL,            -- an agent id (--all is queued once per agent)
  site TEXT,                         -- a site, or NULL for all of the agent's sites
  requested_at INTEGER NOT NULL,
  via TEXT NOT NULL
);
-- Owner opt-ins to keep a high-risk site's session across restarts ("Keep me signed in").
-- Written only by the owner (CLI, admin socket; later the owner's signed approval), never
-- by any MCP tool input.
CREATE TABLE IF NOT EXISTS persist_optins (
  agent_id TEXT NOT NULL,            -- an agent id, or '*' for every agent
  site TEXT NOT NULL,                -- registrable domain
  created_at INTEGER NOT NULL,
  via TEXT NOT NULL,                 -- cli | admin | approval
  PRIMARY KEY (agent_id, site)
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
-- INSERT OR REPLACE deletes the conflicting row without firing DELETE triggers.
CREATE TRIGGER IF NOT EXISTS audit_no_replace BEFORE INSERT ON audit
  WHEN EXISTS (SELECT 1 FROM audit WHERE seq = NEW.seq)
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
`;

export interface PasskeyRow {
  id: string;
  rp_id: string;
  user_handle: string;
  username: string | null;
  public_key: string;
  signer_ref: string;
  created_at: number;
}

export interface PasswordRow {
  id: string;
  registrable_domain: string;
  username: string | null;
  has_totp: number;
  signer_ref: string;
  source: string;
  created_at: number;
}

const PASSWORD_COLS = 'id, registrable_domain, username, has_totp, signer_ref, source, created_at';

export function openDb(path: string): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA busy_timeout = 2000; PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  migrate(db);
  if (path !== ':memory:') chmodSync(path, 0o600);
  return db;
}

const ADDED_COLUMNS: { table: string; column: string; decl: string }[] = [
  { table: 'agents', column: 'token_hash', decl: 'TEXT' },
  { table: 'agents', column: 'revoked_at', decl: 'INTEGER' },
  { table: 'credentials', column: 'has_totp', decl: 'INTEGER NOT NULL DEFAULT 0' },
  { table: 'policies', column: 'allow_for_ms', decl: 'INTEGER' },
];

function migrate(db: DatabaseSync): void {
  for (const { table, column, decl } of ADDED_COLUMNS) {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
    if (!cols.some((c) => c.name === column)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
    }
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS agents_token_hash ON agents (token_hash)');
}

export class CredentialRepo {
  private readonly db: DatabaseSync;
  constructor(db: DatabaseSync) {
    this.db = db;
  }

  passkeysForRp(rpId: string): PasskeyRow[] {
    return this.db
      .prepare(
        `SELECT id, rp_id, user_handle, username, public_key, signer_ref, created_at
         FROM credentials WHERE type = 'passkey' AND rp_id = ? ORDER BY created_at DESC`,
      )
      .all(rpId) as unknown as PasskeyRow[];
  }

  allPasskeyRpIds(): { id: string; rp_id: string }[] {
    return this.db
      .prepare(`SELECT id, rp_id FROM credentials WHERE type = 'passkey' ORDER BY created_at DESC`)
      .all() as unknown as { id: string; rp_id: string }[];
  }

  passwordsForDomain(domain: string): PasswordRow[] {
    return this.db
      .prepare(
        `SELECT ${PASSWORD_COLS}
         FROM credentials WHERE type = 'password' AND registrable_domain = ?
         ORDER BY created_at DESC`,
      )
      .all(domain) as unknown as PasswordRow[];
  }

  allPasswords(): PasswordRow[] {
    return this.db
      .prepare(
        `SELECT ${PASSWORD_COLS}
         FROM credentials WHERE type = 'password' ORDER BY registrable_domain, created_at`,
      )
      .all() as unknown as PasswordRow[];
  }

  sourcePasswords(source: string): PasswordRow[] {
    return this.db
      .prepare(
        `SELECT ${PASSWORD_COLS}
         FROM credentials WHERE type = 'password' AND source = ? ORDER BY id`,
      )
      .all(source) as unknown as PasswordRow[];
  }

  insertSourcePassword(row: {
    id: string;
    ref: string;
    source: string;
    domain: string;
    username: string | null;
    hasTotp: boolean;
    now: number;
  }): void {
    this.db
      .prepare(
        `INSERT INTO credentials (id, type, rp_id, registrable_domain, user_handle, username,
           public_key, signer_ref, source, created_at, has_totp)
         VALUES (?, 'password', NULL, ?, NULL, ?, NULL, ?, ?, ?, ?)`,
      )
      .run(row.id, row.domain, row.username, row.ref, row.source, row.now, row.hasTotp ? 1 : 0);
  }

  updateSourcePassword(id: string, f: { username: string | null; hasTotp: boolean }): void {
    this.db
      .prepare(
        `UPDATE credentials SET username = ?, has_totp = ? WHERE type = 'password' AND id = ?`,
      )
      .run(f.username, f.hasTotp ? 1 : 0, id);
  }

  insertPassword(row: {
    itemId: string;
    domain: string;
    username: string | null;
    hasTotp: boolean;
    now: number;
  }): void {
    this.db
      .prepare(
        `INSERT INTO credentials (id, type, rp_id, registrable_domain, user_handle, username,
           public_key, signer_ref, source, created_at, has_totp)
         VALUES (?, 'password', NULL, ?, NULL, ?, NULL, ?, 'signer', ?, ?)`,
      )
      .run(row.itemId, row.domain, row.username, row.itemId, row.now, row.hasTotp ? 1 : 0);
  }

  deletePassword(id: string): boolean {
    const r = this.db.prepare(`DELETE FROM credentials WHERE type = 'password' AND id = ?`).run(id);
    return Number(r.changes) > 0;
  }

  insertPasskey(row: {
    id: string;
    rpId: string;
    registrableDomain: string | null;
    userHandle: string;
    username: string | null;
    publicKey: string;
    now: number;
  }): void {
    this.db
      .prepare(
        `INSERT INTO credentials (id, type, rp_id, registrable_domain, user_handle, username,
           public_key, signer_ref, source, created_at)
         VALUES (?, 'passkey', ?, ?, ?, ?, ?, ?, 'signer', ?)`,
      )
      .run(
        row.id,
        row.rpId,
        row.registrableDomain,
        row.userHandle,
        row.username,
        row.publicKey,
        row.id,
        row.now,
      );
  }
}

export class RequestRepo {
  private readonly db: DatabaseSync;
  constructor(db: DatabaseSync) {
    this.db = db;
  }

  insert(r: {
    id: string;
    agentId: string;
    verifiedOrigin: string | null;
    kind: string;
    now: number;
  }): void {
    this.db
      .prepare(
        `INSERT INTO requests (id, agent_id, verified_origin, kind, status, created_at)
         VALUES (?, ?, ?, ?, 'pending', ?)`,
      )
      .run(r.id, r.agentId, r.verifiedOrigin, r.kind, r.now);
  }

  update(
    id: string,
    fields: { status: string; credentialId?: string | null; intentId?: string | null; now: number },
  ): void {
    this.db
      .prepare(
        `UPDATE requests SET status = ?, credential_id = COALESCE(?, credential_id),
           intent_id = COALESCE(?, intent_id), decided_at = ? WHERE id = ?`,
      )
      .run(fields.status, fields.credentialId ?? null, fields.intentId ?? null, fields.now, id);
  }

  get(id: string): Record<string, unknown> | undefined {
    return this.db.prepare('SELECT * FROM requests WHERE id = ?').get(id) as
      | Record<string, unknown>
      | undefined;
  }
}

export interface SessionClock {
  agentId: string;
  origin: string;
  host: string;
  startedAt: number;
}

export interface BrowserSessionRow {
  agentId: string;
  site: string;
  cookies: number;
  origins: number;
  savedAt: number;
}

export interface ClearRequest {
  id: number;
  agentId: string;
  site: string | null;
  requestedAt: number;
  via: string;
}

export class SessionStateRepo {
  private readonly db: DatabaseSync;
  constructor(db: DatabaseSync) {
    this.db = db;
  }

  upsertClock(c: SessionClock): void {
    this.db
      .prepare(
        `INSERT INTO session_clocks (agent_id, origin, host, started_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (agent_id, origin) DO UPDATE SET host = excluded.host, started_at = excluded.started_at`,
      )
      .run(c.agentId, c.origin, c.host, c.startedAt);
  }

  clocks(agentId?: string): SessionClock[] {
    const rows = (
      agentId === undefined
        ? this.db.prepare('SELECT * FROM session_clocks ORDER BY agent_id, origin').all()
        : this.db
            .prepare('SELECT * FROM session_clocks WHERE agent_id = ? ORDER BY origin')
            .all(agentId)
    ) as { agent_id: string; origin: string; host: string; started_at: number }[];
    return rows.map((r) => ({
      agentId: r.agent_id,
      origin: r.origin,
      host: r.host,
      startedAt: r.started_at,
    }));
  }

  deleteClock(agentId: string, origin: string): void {
    this.db
      .prepare('DELETE FROM session_clocks WHERE agent_id = ? AND origin = ?')
      .run(agentId, origin);
  }

  deleteClocks(agentId: string): void {
    this.db.prepare('DELETE FROM session_clocks WHERE agent_id = ?').run(agentId);
  }

  setIndex(agentId: string, rows: Omit<BrowserSessionRow, 'agentId'>[]): void {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('DELETE FROM browser_sessions WHERE agent_id = ?').run(agentId);
      const ins = this.db.prepare(
        'INSERT INTO browser_sessions (agent_id, site, cookies, origins, saved_at) VALUES (?, ?, ?, ?, ?)',
      );
      for (const r of rows) ins.run(agentId, r.site, r.cookies, r.origins, r.savedAt);
      this.db.exec('COMMIT');
    } catch (err) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      throw err;
    }
  }

  index(agentId?: string): BrowserSessionRow[] {
    const rows = (
      agentId === undefined
        ? this.db.prepare('SELECT * FROM browser_sessions ORDER BY agent_id, site').all()
        : this.db
            .prepare('SELECT * FROM browser_sessions WHERE agent_id = ? ORDER BY site')
            .all(agentId)
    ) as { agent_id: string; site: string; cookies: number; origins: number; saved_at: number }[];
    return rows.map((r) => ({
      agentId: r.agent_id,
      site: r.site,
      cookies: r.cookies,
      origins: r.origins,
      savedAt: r.saved_at,
    }));
  }

  deleteIndex(agentId: string): void {
    this.db.prepare('DELETE FROM browser_sessions WHERE agent_id = ?').run(agentId);
  }

  queueClear(r: { agentId: string; site: string | null; via: string; now: number }): number {
    const res = this.db
      .prepare(
        'INSERT INTO session_clear_requests (agent_id, site, requested_at, via) VALUES (?, ?, ?, ?)',
      )
      .run(r.agentId, r.site, r.now, r.via);
    return Number(res.lastInsertRowid);
  }

  clearRequests(agentId?: string): ClearRequest[] {
    const rows = (
      agentId === undefined
        ? this.db.prepare('SELECT * FROM session_clear_requests ORDER BY id').all()
        : this.db
            .prepare('SELECT * FROM session_clear_requests WHERE agent_id = ? ORDER BY id')
            .all(agentId)
    ) as { id: number; agent_id: string; site: string | null; requested_at: number; via: string }[];
    return rows.map((r) => ({
      id: r.id,
      agentId: r.agent_id,
      site: r.site,
      requestedAt: r.requested_at,
      via: r.via,
    }));
  }

  deleteClearRequest(id: number): void {
    this.db.prepare('DELETE FROM session_clear_requests WHERE id = ?').run(id);
  }

  forgetAgent(agentId: string): void {
    this.deleteClocks(agentId);
    this.deleteIndex(agentId);
    this.db.prepare('DELETE FROM session_clear_requests WHERE agent_id = ?').run(agentId);
  }
}

export type OptinVia = 'cli' | 'admin' | 'approval';
export const ALL_AGENTS_OPTIN = '*';

export interface PersistOptin {
  agentId: string;
  site: string;
  createdAt: number;
  via: OptinVia;
}

export class PersistOptins {
  private readonly db: DatabaseSync;
  private readonly audit: (event: string, fields: Record<string, unknown>) => void;
  private readonly now: () => number;

  constructor(
    db: DatabaseSync,
    opts: {
      audit?: (event: string, fields: Record<string, unknown>) => void;
      now?: () => number;
    } = {},
  ) {
    this.db = db;
    this.audit = opts.audit ?? (() => {});
    this.now = opts.now ?? Date.now;
  }

  add(agentId: string, site: string, via: OptinVia): boolean {
    const res = this.db
      .prepare(
        `INSERT INTO persist_optins (agent_id, site, created_at, via) VALUES (?, ?, ?, ?)
         ON CONFLICT (agent_id, site) DO NOTHING`,
      )
      .run(agentId, site, this.now(), via);
    const added = Number(res.changes) > 0;
    if (added) this.audit('session.keep_set', { agentId, site, via });
    return added;
  }

  remove(agentId: string, site: string, via: OptinVia): boolean {
    const res = this.db
      .prepare('DELETE FROM persist_optins WHERE agent_id = ? AND site = ?')
      .run(agentId, site);
    const removed = Number(res.changes) > 0;
    if (removed) this.audit('session.keep_removed', { agentId, site, via });
    return removed;
  }

  has(agentId: string, site: string): boolean {
    return (
      this.db
        .prepare(
          `SELECT 1 FROM persist_optins WHERE site = ? AND (agent_id = ? OR agent_id = '${ALL_AGENTS_OPTIN}')`,
        )
        .get(site, agentId) !== undefined
    );
  }

  list(agentId?: string): PersistOptin[] {
    const rows = (
      agentId === undefined
        ? this.db.prepare('SELECT * FROM persist_optins ORDER BY site, agent_id').all()
        : this.db
            .prepare(
              `SELECT * FROM persist_optins WHERE agent_id = ? OR agent_id = '${ALL_AGENTS_OPTIN}' ORDER BY site`,
            )
            .all(agentId)
    ) as { agent_id: string; site: string; created_at: number; via: OptinVia }[];
    return rows.map((r) => ({
      agentId: r.agent_id,
      site: r.site,
      createdAt: r.created_at,
      via: r.via,
    }));
  }

  forgetAgent(agentId: string): void {
    this.db.prepare('DELETE FROM persist_optins WHERE agent_id = ?').run(agentId);
  }
}
