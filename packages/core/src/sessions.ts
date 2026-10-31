import type { ManagedBrowser, StorageState } from '@aab/shim';
import type { BrowserContext, Page } from 'playwright';
import type { AgentIdentity, Broker, CeremonyEvent } from './broker.ts';
import {
  cookieHash,
  type SavedOrigin,
  type SavedState,
  type SessionPersistence,
  siteOfHost,
} from './browser-state.ts';
import { ChallengeWatch, detectHumanCheck, type HumanCheck } from './challenge.ts';

export const DEFAULT_SAVE_MS = 60_000;
export const DEFAULT_FULL_SAVE_MS = 10 * 60_000;
const SHUTDOWN_SAVE_PER_AGENT_MS = 5_000;
const SHUTDOWN_SAVE_TOTAL_MS = 10_000;
const SAVE_COLLECT_MS = 15_000;

const withTimeout = <T>(p: Promise<T>, ms: number, what: string): Promise<T> =>
  new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(what)), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      },
    );
  });

export type CeremonyKind = 'create' | 'get';
export type CeremonyOutcome = 'success' | 'denied' | 'timeout';

export const RECENT_CEREMONY_MS = 60_000;
const MAX_RECENT = 32;
const MAX_SEEN_ORIGINS = 1_000;

interface Inflight {
  id: string;
  page: object | null;
  kind: CeremonyKind;
  claimed: boolean;
  done: Promise<boolean>;
  resolve(ok: boolean): void;
}
interface Ended {
  page: object | null;
  kind: CeremonyKind;
  ok: boolean;
  endedAt: number;
  claimed: boolean;
}
interface Waiter {
  page: Page;
  kind: CeremonyKind;
  attach(c: Inflight): void;
}

export class AgentSession {
  readonly agent: AgentIdentity;
  readonly context: BrowserContext;
  private readonly pages: Page[] = [];
  private readonly inflight = new Map<string, Inflight>();
  private readonly ended: Ended[] = [];
  private readonly waiters = new Set<Waiter>();
  private readonly now: () => number;
  private readonly unsubscribe: () => void;
  private readonly filledSecrets = new Set<string>();
  dirtyGen = 0;
  savedGen = 0;
  lastFullAt = 0;
  lastCookieHash: string | null = null;
  lastFullOrigins: SavedOrigin[] = [];
  private readonly seenOrigins = new Set<string>();
  private internalOpen: Page[] | null = null;
  private readonly watches = new WeakMap<Page, ChallengeWatch>();
  private readonly challengeHosts: readonly string[];

  constructor(
    agent: AgentIdentity,
    context: BrowserContext,
    broker: Broker,
    now: () => number,
    opts: { challengeHosts?: readonly string[] } = {},
  ) {
    this.agent = agent;
    this.context = context;
    this.now = now;
    this.challengeHosts = opts.challengeHosts ?? [];
    for (const p of context.pages()) this.track(p);
    context.on('page', (p) => this.track(p));
    this.unsubscribe = broker.onCeremony((e) => {
      if (e.agentId === agent.id) this.onCeremony(e);
    });
    context.on('close', () => this.unsubscribe());
  }

  private track(page: Page): void {
    if (this.internalOpen) {
      this.internalOpen.push(page);
      return;
    }
    if (page.isClosed() || this.pages.includes(page)) return;
    this.pages.push(page);
    this.noteOrigin(page.url());
    page.on('framenavigated', (f) => this.noteOrigin(f.url()));
    const watch = new ChallengeWatch(page, { extraHosts: this.challengeHosts });
    this.watches.set(page, watch);
    page.once('close', () => {
      const i = this.pages.indexOf(page);
      if (i >= 0) this.pages.splice(i, 1);
      watch.dispose();
    });
  }

  humanCheck(page: Page): Promise<HumanCheck | null> {
    return detectHumanCheck(page, this.watches.get(page) ?? null).catch(() => null);
  }

  currentPage(): Page | null {
    for (let i = this.pages.length - 1; i >= 0; i--) {
      const p = this.pages[i] as Page;
      if (!p.isClosed()) return p;
    }
    return null;
  }

  markDirty(): void {
    this.dirtyGen++;
  }

  isDirty(): boolean {
    return this.dirtyGen !== this.savedGen;
  }

  noteOrigin(url: string): void {
    try {
      const u = new URL(url);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      if (this.seenOrigins.size >= MAX_SEEN_ORIGINS && !this.seenOrigins.has(u.origin)) {
        this.seenOrigins.delete(this.seenOrigins.values().next().value as string);
      }
      this.seenOrigins.add(u.origin);
    } catch {}
  }

  originsOnSite(site: string): string[] {
    const out = new Set<string>();
    const add = (o: string) => {
      try {
        const u = new URL(o);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
        if (siteOfHost(u.hostname) === site) out.add(u.origin);
      } catch {}
    };
    for (const o of this.seenOrigins) add(o);
    for (const o of this.lastFullOrigins) add(o.origin);
    for (const o of this.visitedOrigins()) add(o);
    return [...out];
  }

  visitedOrigins(): string[] {
    const out = new Set<string>();
    for (const p of this.pages) {
      try {
        const u = new URL(p.url());
        if (u.protocol === 'http:' || u.protocol === 'https:') out.add(u.origin);
      } catch {}
    }
    return [...out];
  }

  async collect(kind: 'full' | 'cheap'): Promise<SavedState> {
    if (kind === 'full') {
      const st = (await this.context.storageState({ indexedDB: true })) as SavedState;
      return { cookies: st.cookies, origins: st.origins };
    }
    return {
      cookies: (await this.context.cookies()) as SavedState['cookies'],
      origins: this.lastFullOrigins,
    };
  }

  rememberSecret(value: string): void {
    this.filledSecrets.add(value);
  }

  secrets(): string[] {
    return [...this.filledSecrets];
  }

  hasCeremony(kind: CeremonyKind, page: Page): boolean {
    for (const c of this.inflight.values()) if (c.page === page && c.kind === kind) return true;
    const cutoff = this.now() - RECENT_CEREMONY_MS;
    return this.ended.some(
      (r) => r.page === page && r.kind === kind && !r.claimed && r.endedAt >= cutoff,
    );
  }

  async newPage(): Promise<Page> {
    const page = await this.context.newPage();
    this.track(page);
    return page;
  }

  private onCeremony(e: CeremonyEvent): void {
    if (e.phase === 'start') {
      let resolve!: (ok: boolean) => void;
      const done = new Promise<boolean>((r) => {
        resolve = r;
      });
      const c: Inflight = { id: e.id, page: e.page, kind: e.kind, claimed: false, done, resolve };
      this.inflight.set(e.id, c);
      for (const w of [...this.waiters]) {
        if (w.page === e.page && w.kind === e.kind) w.attach(c);
      }
      return;
    }
    const c = this.inflight.get(e.id);
    if (!c) return;
    this.inflight.delete(e.id);
    c.resolve(e.ok);
    this.ended.push({
      page: c.page,
      kind: c.kind,
      ok: e.ok,
      endedAt: this.now(),
      claimed: c.claimed,
    });
    if (this.ended.length > MAX_RECENT) this.ended.splice(0, this.ended.length - MAX_RECENT);
  }

  waitForCeremony(kind: CeremonyKind, page: Page, timeoutMs: number): Promise<CeremonyOutcome> {
    const toOutcome = (ok: boolean): CeremonyOutcome => (ok ? 'success' : 'denied');
    const current = [...this.inflight.values()].filter((c) => c.page === page && c.kind === kind);
    const live = current.at(-1);
    if (!live) {
      const cutoff = this.now() - RECENT_CEREMONY_MS;
      for (let i = this.ended.length - 1; i >= 0; i--) {
        const r = this.ended[i] as Ended;
        if (r.page === page && r.kind === kind && !r.claimed && r.endedAt >= cutoff) {
          r.claimed = true;
          return Promise.resolve(toOutcome(r.ok));
        }
      }
    }
    return new Promise<CeremonyOutcome>((resolve) => {
      let settled = false;
      const finish = (o: CeremonyOutcome) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.waiters.delete(waiter);
        page.off('close', onClose);
        resolve(o);
      };
      const onClose = () => finish('timeout');
      const waiter: Waiter = {
        page,
        kind,
        attach: (c) => {
          c.claimed = true;
          this.waiters.delete(waiter);
          void c.done.then((ok) => finish(toOutcome(ok)));
        },
      };
      const timer = setTimeout(() => finish('timeout'), timeoutMs);
      page.once('close', onClose);
      if (live) waiter.attach(live);
      else this.waiters.add(waiter);
    });
  }

  private async internalPage(): Promise<Page> {
    while (this.internalOpen) await new Promise((r) => setTimeout(r, 10));
    const seen: Page[] = [];
    this.internalOpen = seen;
    let page: Page;
    try {
      page = await this.context.newPage();
    } finally {
      this.internalOpen = null;
    }
    for (const p of seen) if (p !== page) this.track(p);
    return page;
  }

  async clearSite(origin: string): Promise<{ cookies: number; pages: number }> {
    const host = new URL(origin).hostname;
    const site = siteOfHost(host);
    const onSite = (h: string) => h === site || h.endsWith(`.${site}`);
    const origins = new Set([origin, ...this.originsOnSite(site)]);
    let pages = 0;
    for (const p of [...this.pages]) {
      let u: URL | null = null;
      try {
        u = new URL(p.url());
      } catch {
        u = null;
      }
      if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:') || !onSite(u.hostname)) {
        continue;
      }
      origins.add(u.origin);
      await p.close().catch(() => {});
      pages++;
    }
    const domainRe = new RegExp(
      `^\\.?(?:[^.]+\\.)*${site.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`,
    );
    const cookies = (await this.context.cookies()).filter((c) => domainRe.test(c.domain)).length;
    await this.context.clearCookies({ domain: domainRe });
    const tmp = await this.internalPage();
    try {
      const cdp = await this.context.newCDPSession(tmp);
      for (const o of origins) {
        await cdp.send('Storage.clearDataForOrigin', { origin: o, storageTypes: 'all' });
      }
    } finally {
      await tmp.close().catch(() => {});
    }
    return { cookies, pages };
  }

  async close(): Promise<void> {
    this.unsubscribe();
    this.filledSecrets.clear();
    await this.context.close().catch(() => {});
  }
}

export interface AgentSessionsOptions {
  now?: () => number;
  challengeHosts?: readonly string[];
  persistence?: SessionPersistence | null;
  saveMs?: number;
  fullSaveMs?: number;
}

export class AgentSessions {
  private readonly browser: ManagedBrowser;
  private readonly broker: Broker;
  private readonly now: () => number;
  private readonly sessions = new Map<string, Promise<AgentSession>>();
  private readonly ready = new Map<string, AgentSession>();
  private readonly challengeHosts: readonly string[];
  readonly persistence: SessionPersistence | null;
  private readonly fullSaveMs: number;
  private readonly timer: ReturnType<typeof setInterval> | null = null;
  private readonly unsubscribeLogin: () => void = () => {};
  private readonly saving = new Map<string, Promise<void>>();
  private readonly epochs = new Map<string, number>();
  private readonly failures = new Map<string, string>();
  private closed = false;

  constructor(browser: ManagedBrowser, broker: Broker, opts: AgentSessionsOptions = {}) {
    this.browser = browser;
    this.broker = broker;
    this.now = opts.now ?? Date.now;
    this.challengeHosts = opts.challengeHosts ?? [];
    this.persistence = opts.persistence ?? null;
    this.fullSaveMs = opts.fullSaveMs ?? DEFAULT_FULL_SAVE_MS;
    if (this.persistence) {
      this.unsubscribeLogin = broker.onLogin((e) => {
        const s = this.ready.get(e.agentId);
        if (!s) return;
        s.markDirty();
        void this.save(e.agentId, 'full');
      });
      this.timer = setInterval(() => void this.tick(), opts.saveMs ?? DEFAULT_SAVE_MS);
      this.timer.unref();
    }
  }

  private safeAudit(event: string, fields: Record<string, unknown>): void {
    try {
      this.broker.audit.append(event, fields);
    } catch {}
  }

  private async tick(): Promise<void> {
    if (this.closed) return;
    for (const [id, s] of [...this.ready]) {
      if (!s.isDirty()) continue;
      const kind = this.now() - s.lastFullAt >= this.fullSaveMs ? 'full' : 'cheap';
      await this.save(id, kind).catch(() => {});
    }
  }

  save(agentId: string, kind: 'full' | 'cheap'): Promise<void> {
    const p = this.persistence;
    if (!p) return Promise.resolve();
    const prev = this.saving.get(agentId) ?? Promise.resolve();
    const run = prev.then(() => this.saveNow(p, agentId, kind)).catch(() => {});
    this.saving.set(agentId, run);
    void run.finally(() => {
      if (this.saving.get(agentId) === run) this.saving.delete(agentId);
    });
    return run;
  }

  private async saveNow(p: SessionPersistence, agentId: string, kind: 'full' | 'cheap') {
    const s = this.ready.get(agentId);
    if (!s) return;
    const epoch = this.epochs.get(agentId) ?? 0;
    const gen = s.dirtyGen;
    try {
      const state = await withTimeout(s.collect(kind), SAVE_COLLECT_MS, 'collect_timeout');
      const hash = cookieHash(state.cookies);
      if (kind === 'cheap' && hash === s.lastCookieHash) {
        s.savedGen = gen;
        return;
      }
      if ((this.epochs.get(agentId) ?? 0) !== epoch || this.ready.get(agentId) !== s) return;
      const r = p.save(agentId, { state, visited: s.visitedOrigins() }, s.secrets());
      s.lastCookieHash = hash;
      if (kind === 'full') {
        s.lastFullAt = this.now();
        s.lastFullOrigins = state.origins;
      }
      s.savedGen = gen;
      if (r.written && this.failures.has(agentId)) {
        this.failures.delete(agentId);
        this.safeAudit('browser_state.save_ok', { agentId });
      }
    } catch (err) {
      const reason = err instanceof Error && /^[a-z_]+$/.test(err.message) ? err.message : 'error';
      if (this.failures.get(agentId) !== reason) {
        this.failures.set(agentId, reason);
        this.safeAudit('browser_state.save_failed', { agentId, reason });
      }
    }
  }

  get(agent: AgentIdentity): Promise<AgentSession> {
    if (this.closed) return Promise.reject(new Error('sessions closed'));
    const existing = this.sessions.get(agent.id);
    if (existing) return existing;
    const bound: AgentIdentity = { id: agent.id, name: agent.name };
    const handler = (
      req: Parameters<Parameters<ManagedBrowser['newContext']>[0]>[0],
      source: { page?: object },
    ) => this.broker.handleWebAuthn(req, bound, { page: source.page });
    let restored: ReturnType<SessionPersistence['restore']> = { state: null, finish: () => {} };
    if (this.persistence) {
      try {
        restored = this.persistence.restore(bound.id);
      } catch {
        this.safeAudit('browser_state.discarded', { agentId: bound.id, reason: 'restore_failed' });
      }
    }
    const initial = restored.state;
    const created = (
      initial
        ? this.browser.newContext(handler, { storageState: initial as StorageState }).then(
            (ctx) => {
              restored.finish(true);
              return ctx;
            },
            () => {
              restored.finish(false);
              return this.browser.newContext(handler);
            },
          )
        : this.browser.newContext(handler).then((ctx) => {
            restored.finish(true);
            return ctx;
          })
    ).then((context) => {
      const s = new AgentSession(bound, context, this.broker, this.now, {
        challengeHosts: this.challengeHosts,
      });
      if (initial) {
        s.lastFullOrigins = initial.origins;
        s.lastCookieHash = cookieHash(initial.cookies);
        s.lastFullAt = this.now();
      }
      context.on('close', () => {
        if (this.ready.get(bound.id) === s) {
          this.ready.delete(bound.id);
          this.sessions.delete(bound.id);
        }
      });
      if (this.closed || this.sessions.get(bound.id) !== created) {
        void s.close();
        throw new Error('session closed while starting');
      }
      this.ready.set(bound.id, s);
      return s;
    });
    created.catch(() => {
      if (this.sessions.get(bound.id) === created) this.sessions.delete(bound.id);
    });
    this.sessions.set(bound.id, created);
    return created;
  }

  agentIds(): string[] {
    return [...this.sessions.keys()];
  }

  peek(agentId: string): AgentSession | undefined {
    return this.ready.get(agentId);
  }

  async close(agentId: string): Promise<void> {
    const p = this.sessions.get(agentId);
    this.sessions.delete(agentId);
    this.ready.delete(agentId);
    if (p) await p.then((s) => s.close()).catch(() => {});
  }

  async discard(
    agentId: string,
    reason: 'revoked' | 'cleared',
  ): Promise<{ cookies: number; pages: number }> {
    this.epochs.set(agentId, (this.epochs.get(agentId) ?? 0) + 1);
    const s = this.ready.get(agentId);
    let cookies = 0;
    let pages = 0;
    if (s) {
      cookies = (await s.context.cookies().catch(() => [])).length;
      pages = s.context.pages().length;
    } else if (this.persistence) {
      cookies = this.persistence.savedCookies(agentId);
    }
    await this.close(agentId);
    await (this.saving.get(agentId) ?? Promise.resolve());
    if (this.persistence) {
      const had = this.persistence.discardFiles(agentId);
      if (reason === 'revoked' && had) {
        this.safeAudit('browser_state.deleted', { agentId, reason: 'revoked' });
      }
    }
    return { cookies, pages };
  }

  async clearSite(
    agentId: string,
    site: string,
    via: 'admin',
  ): Promise<{ cookies: number; pages: number }> {
    const s = this.ready.get(agentId);
    let r: { cookies: number; pages: number };
    if (s) {
      r = await s.clearSite(`https://${site}`);
      s.markDirty();
      await this.save(agentId, 'full');
    } else if (this.persistence) {
      r = { cookies: this.persistence.rewriteDropSite(agentId, site).cookies, pages: 0 };
    } else {
      r = { cookies: 0, pages: 0 };
    }
    if (this.persistence) {
      for (const c of this.persistence.repo.clocks(agentId)) {
        if (siteOfHost(c.host) === site) this.persistence.repo.deleteClock(agentId, c.origin);
      }
    }
    this.safeAudit('session.cleared', { agentId, site, cookies: r.cookies, pages: r.pages, via });
    return r;
  }

  async refilter(agentId: string): Promise<void> {
    const s = this.ready.get(agentId);
    if (s) {
      s.markDirty();
      await this.save(agentId, 'full');
    } else {
      this.persistence?.refilter(agentId);
    }
  }

  async clearAgent(agentId: string, via: 'admin'): Promise<{ cookies: number; pages: number }> {
    const r = await this.discard(agentId, 'cleared');
    this.safeAudit('session.cleared', { agentId, cookies: r.cookies, pages: r.pages, via });
    return r;
  }

  async applyQueuedClears(isActive: (agentId: string) => boolean): Promise<void> {
    const p = this.persistence;
    if (!p) return;
    for (const req of p.repo.clearRequests()) {
      try {
        p.repo.deleteClearRequest(req.id);
        if (!isActive(req.agentId)) continue;
        if (req.site === null) await this.clearAgent(req.agentId, 'admin');
        else await this.clearSite(req.agentId, req.site, 'admin');
      } catch {
        this.safeAudit('session.clear_failed', { agentId: req.agentId, via: 'admin' });
      }
    }
  }

  async closeAll(): Promise<void> {
    this.closed = true;
    if (this.timer) clearInterval(this.timer);
    this.unsubscribeLogin();
    if (this.persistence) {
      const saves = [...this.ready.entries()].map(([id, s]) => {
        s.markDirty();
        return withTimeout(this.save(id, 'full'), SHUTDOWN_SAVE_PER_AGENT_MS, 'shutdown').catch(
          () => {},
        );
      });
      await withTimeout(Promise.all(saves), SHUTDOWN_SAVE_TOTAL_MS, 'shutdown').catch(() => {});
    }
    const all = [...this.sessions.keys()];
    await Promise.all(all.map((id) => this.close(id)));
  }
}
