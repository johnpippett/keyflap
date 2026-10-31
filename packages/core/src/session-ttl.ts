import type { Broker, LoginEvent } from './broker.ts';
import { siteOfHost } from './browser-state.ts';
import type { PersistOptin, SessionClock, SessionStateRepo } from './db.ts';
import { canonicalOrigin } from './origin.ts';
import type { AgentSession, AgentSessions } from './sessions.ts';

export const DEFAULT_SESSION_SWEEP_MS = 30_000;

const MAX_FAILURES = 3;

export class SessionTtl {
  private readonly broker: Broker;
  private readonly sessions: AgentSessions;
  private readonly repo: SessionStateRepo;
  private readonly isActive: (agentId: string) => boolean;
  private readonly optins: (() => PersistOptin[]) | null;
  private readonly now: () => number;
  private readonly timer: ReturnType<typeof setInterval>;
  private readonly unsubscribe: () => void;
  private readonly failures = new Map<string, number>();
  private lastOptins: Set<string> | null = null;
  private sweeping: Promise<void> | null = null;

  constructor(opts: {
    broker: Broker;
    sessions: AgentSessions;
    repo: SessionStateRepo;
    isActive: (agentId: string) => boolean;
    optins?: () => PersistOptin[];
    sweepMs?: number;
    now?: () => number;
  }) {
    this.broker = opts.broker;
    this.sessions = opts.sessions;
    this.repo = opts.repo;
    this.isActive = opts.isActive;
    this.optins = opts.optins ?? null;
    this.now = opts.now ?? Date.now;
    this.unsubscribe = this.broker.onLogin((e) => this.record(e));
    for (const c of this.repo.clocks()) {
      if (!this.isActive(c.agentId)) this.repo.deleteClock(c.agentId, c.origin);
    }
    this.timer = setInterval(() => void this.sweep(), opts.sweepMs ?? DEFAULT_SESSION_SWEEP_MS);
    this.timer.unref();
  }

  record(e: LoginEvent): void {
    try {
      this.repo.upsertClock({
        agentId: e.agentId,
        origin: e.origin,
        host: e.host,
        startedAt: this.now(),
      });
      this.failures.delete(`${e.agentId}\n${e.origin}`);
    } catch {}
  }

  tracked(): { agentId: string; origin: string; at: number }[] {
    return this.repo
      .clocks()
      .map((c) => ({ agentId: c.agentId, origin: c.origin, at: c.startedAt }));
  }

  sweep(): Promise<void> {
    this.sweeping ??= this.sweepOnce().finally(() => {
      this.sweeping = null;
    });
    return this.sweeping;
  }

  private audit(event: string, fields: Record<string, unknown>): void {
    try {
      this.broker.audit.append(event, fields);
    } catch {}
  }

  private siteTtl(
    agentId: string,
    site: string,
    siteClocks: readonly SessionClock[],
    session: AgentSession | undefined,
  ): number | null {
    const origins = new Set([
      ...siteClocks.map((c) => c.origin),
      ...(session ? session.originsOnSite(site) : []),
      `https://${site}`,
    ]);
    let ttl: number | null = null;
    for (const seen of origins) {
      const at = canonicalOrigin(seen);
      if (!at) continue;
      const t = this.broker.policy.resolve(agentId, at).sessionTtlMs;
      if (t !== null && (ttl === null || t < ttl)) ttl = t;
    }
    return ttl;
  }

  private async sweepOnce(): Promise<void> {
    await this.sessions.applyQueuedClears(this.isActive).catch(() => {});
    await this.enforceOptins().catch(() => {});
    let clocks: ReturnType<SessionStateRepo['clocks']>;
    try {
      clocks = this.repo.clocks();
    } catch {
      return;
    }
    const decided = new Set<string>();
    for (const c of clocks) {
      const key = `${c.agentId}\n${c.origin}`;
      try {
        if (!this.isActive(c.agentId)) {
          this.repo.deleteClock(c.agentId, c.origin);
          continue;
        }
        const site = siteOfHost(c.host);
        const siteKey = `${c.agentId}\n${site}`;
        if (decided.has(siteKey)) continue;
        decided.add(siteKey);
        const session = this.sessions.peek(c.agentId);
        const siteClocks = clocks.filter(
          (x) => x.agentId === c.agentId && siteOfHost(x.host) === site,
        );
        const ttl = this.siteTtl(c.agentId, site, siteClocks, session);
        if (ttl === null) continue;
        const now = this.now();
        if (siteClocks.some((x) => now < x.startedAt + ttl)) continue;
        for (const x of siteClocks) this.repo.deleteClock(x.agentId, x.origin);
        if (session) {
          const r = await session.clearSite(c.origin);
          this.audit('session.cleared', {
            agentId: c.agentId,
            origin: c.origin,
            ttlMs: ttl,
            cookies: r.cookies,
            pages: r.pages,
            via: 'ttl',
          });
          session.markDirty();
          await this.sessions.save(c.agentId, 'full');
        } else if (this.sessions.persistence) {
          const r = this.sessions.persistence.rewriteDropSite(c.agentId, site);
          this.audit('session.cleared', {
            agentId: c.agentId,
            origin: c.origin,
            ttlMs: ttl,
            cookies: r.cookies,
            pages: 0,
            via: 'ttl',
          });
        }
        this.failures.delete(key);
      } catch {
        const failures = (this.failures.get(key) ?? 0) + 1;
        this.failures.set(key, failures);
        if (
          failures < MAX_FAILURES &&
          !this.repo.clocks(c.agentId).some((x) => x.origin === c.origin)
        ) {
          this.repo.upsertClock(c);
        }
        this.audit('session.clear_failed', { agentId: c.agentId, origin: c.origin, failures });
      }
    }
  }

  private async enforceOptins(): Promise<void> {
    if (!this.optins || !this.sessions.persistence) return;
    const now = new Set(this.optins().map((o) => `${o.agentId}\n${o.site}`));
    const before = this.lastOptins;
    this.lastOptins = now;
    if (!before) return;
    const removed = [...before].filter((k) => !now.has(k));
    if (removed.length === 0) return;
    const agents = new Set<string>();
    for (const k of removed) {
      const agentId = k.split('\n')[0] as string;
      if (agentId === '*') {
        for (const r of this.sessions.persistence.repo.index()) agents.add(r.agentId);
      } else {
        agents.add(agentId);
      }
    }
    for (const id of agents) await this.sessions.refilter(id);
  }

  close(): void {
    clearInterval(this.timer);
    this.unsubscribe();
  }
}
