import { randomUUID } from 'node:crypto';
import type {
  HandoffClip,
  HandoffInput,
  HandoffInputResult,
  HandoffPort,
  HandoffStartResult,
  HandoffSurface,
  HandoffView,
} from '@aab/approver';
import type { Frame, Page } from 'playwright';
import { SENSITIVE_FIELDS_CSS } from './agent-port.ts';
import type { AgentIdentity } from './broker.ts';
import type { HumanCheck } from './challenge.ts';
import type { Intent } from './intents.ts';
import {
  checkOriginUrl,
  type OriginCheck,
  registrableDomain,
  verifiedOriginOfPage,
} from './origin.ts';

export type HandoffEnd =
  | 'done'
  | 'cancelled'
  | 'expired'
  | 'left_site'
  | 'page_closed'
  | 'revoked'
  | 'closed';

export type HandoffResult =
  | { status: 'done' | 'cancelled' | 'expired' | 'pending' | 'denied' }
  | { status: 'unsupported'; reason: 'not_available' | 'not_eligible' | 'no_human_check' };

export interface HandoffSession {
  readonly agent: AgentIdentity;
  currentPage(): Page | null;
  humanCheck(page: Page): Promise<HumanCheck | null>;
  rememberSecret(value: string): void;
  markDirty(): void;
}

export interface HandoffSignInHooks<O = unknown> {
  offer(
    agent: AgentIdentity,
    at: { origin: string; host: string },
  ): { ok: true; offer: O } | { ok: false; reason: string };
  approve(
    agent: AgentIdentity,
    offer: O,
    handoff: { id: string; signal: AbortSignal },
  ): Promise<{ ok: true; deviceId: string } | { ok: false; reason: string }>;
  ended(handoffId: string, outcome: HandoffEnd): void;
}

export interface HandoffManagerOptions {
  surface: HandoffSurface | null;
  intents: { latestLive(agentId: string): Intent | undefined | null };
  policy: { resolve(agentId: string, o: { origin: string; host: string }): { mode: string } };
  approvalPending(agentId: string): boolean;
  audit(event: string, fields: Record<string, unknown>): void;
  // biome-ignore lint/suspicious/noExplicitAny: the offer is opaque to the manager
  signIn?: HandoffSignInHooks<any>;
  onDone?(e: { agentId: string; origin: string; host: string }): void | Promise<void>;
  now?: () => number;
  ttlMs?: number;
  limits?: Partial<HandoffLimits>;
  originOf?: (page: Page) => OriginCheck;
}

export interface HandoffLimits {
  maxOpen: number;
  pushesPerAgent: number;
  pushWindowMs: number;
  cooldownMs: number;
}

export const DEFAULT_HANDOFF_TTL_MS = 5 * 60_000;
export const DEFAULT_HANDOFF_WAIT_MS = 45_000;
export const MAX_HANDOFF_WAIT_MS = 120_000;
const DEFAULT_LIMITS: HandoffLimits = {
  maxOpen: 2,
  pushesPerAgent: 3,
  pushWindowMs: 10 * 60_000,
  cooldownMs: 30_000,
};
const UNCLAIMED_MS = 60_000;
const FRAME_CACHE_MS = 250;
const SCREENSHOT_TIMEOUT_MS = 5_000;
const DETAIL_QUALITY = 85;
const clamp01 = (v: number) => Math.min(1, Math.max(0, v));
const INPUT_TIMEOUT_MS = 5_000;
export const REMEMBER_MIN = 4;

interface Inputs {
  clicks: number;
  scrolls: number;
  drags: number;
  keys: number;
  texts: number;
}

interface Handoff {
  id: string;
  agentId: string;
  agentName: string;
  session: HandoffSession;
  page: Page;
  origin: string;
  host: string;
  site: string;
  intentText: string;
  intentAt: number;
  openedAt: number;
  expiresAt: number;
  controller: string | null;
  inputs: Inputs;
  ended: HandoffEnd | null;
  done: Promise<HandoffEnd>;
  resolve(e: HandoffEnd): void;
  timer: ReturnType<typeof setTimeout>;
  detach(): void;
  frame: { at: number; img: Buffer } | null;
  capturing: Promise<Buffer | null> | null;
  detail: { at: number; key: string; img: Buffer } | null;
  detailing: { key: string; img: Promise<Buffer | null> } | null;
  queue: Promise<unknown>;
  claimed: boolean;
  endedAt: number;
  withSignIn: boolean;
  abort: AbortController | null;
}

const siteOf = (host: string): string => registrableDomain(host) ?? host;

const toResult = (e: HandoffEnd): HandoffResult => {
  switch (e) {
    case 'done':
      return { status: 'done' };
    case 'expired':
      return { status: 'expired' };
    default:
      return { status: 'cancelled' };
  }
};

const withTimeout = <T>(p: Promise<T>, ms: number): Promise<T> =>
  new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms);
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

export class HandoffManager {
  private readonly opts: HandoffManagerOptions;
  private readonly surface: HandoffSurface | null;
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly limits: HandoffLimits;
  private readonly open = new Map<string, Handoff>();
  private readonly pushes = new Map<string, number[]>();
  private readonly cooldown = new Map<string, number>();
  private readonly lastEnded = new Map<string, Handoff>();
  private readonly opening = new Map<string, Promise<unknown>>();
  private closed = false;
  private readonly originOf: (page: Page) => OriginCheck;

  constructor(opts: HandoffManagerOptions) {
    this.opts = opts;
    this.surface = opts.surface;
    this.now = opts.now ?? Date.now;
    this.ttlMs = opts.ttlMs ?? DEFAULT_HANDOFF_TTL_MS;
    this.limits = { ...DEFAULT_LIMITS, ...opts.limits };
    this.originOf = opts.originOf ?? verifiedOriginOfPage;
    this.surface?.attachHandoffs(this.port());
  }

  private pageSite(page: Page): string | null {
    if (page.isClosed()) return null;
    const o = this.originOf(page);
    return o.ok ? siteOf(o.host) : null;
  }

  private urlSite(page: Page): string | null {
    if (page.isClosed()) return null;
    const o = checkOriginUrl(page.url());
    return o.ok ? siteOf(o.host) : null;
  }

  isOpen(agentId: string): boolean {
    for (const h of this.open.values()) if (h.agentId === agentId) return true;
    return false;
  }

  private byAgent(agentId: string): Handoff | null {
    for (const h of this.open.values()) if (h.agentId === agentId) return h;
    return null;
  }

  private audit(event: string, fields: Record<string, unknown>): void {
    try {
      this.opts.audit(event, fields);
    } catch {}
  }

  private auditOrEnd(h: Handoff, event: string, fields: Record<string, unknown>): boolean {
    try {
      this.opts.audit(event, fields);
      return true;
    } catch {
      h.controller = null;
      this.end(h, 'cancelled');
      return false;
    }
  }

  async request(
    session: HandoffSession,
    timeoutMs = DEFAULT_HANDOFF_WAIT_MS,
  ): Promise<HandoffResult> {
    const agentId = session.agent.id;
    while (this.opening.has(agentId)) await this.opening.get(agentId)?.catch(() => {});
    let h = this.byAgent(agentId);
    if (!h) {
      const last = this.lastEnded.get(agentId);
      if (last?.ended && !last.claimed && this.now() - last.endedAt <= UNCLAIMED_MS) {
        last.claimed = true;
        return toResult(last.ended);
      }
      const p = this.openFor(session);
      this.opening.set(agentId, p);
      let r: Handoff | HandoffResult;
      try {
        r = await p;
      } finally {
        this.opening.delete(agentId);
      }
      if (!('id' in r)) return r;
      h = r;
    }
    return this.wait(h, timeoutMs);
  }

  private wait(h: Handoff, timeoutMs: number): Promise<HandoffResult> {
    if (h.ended) {
      h.claimed = true;
      return Promise.resolve(toResult(h.ended));
    }
    return new Promise<HandoffResult>((resolve) => {
      let settled = false;
      const t = setTimeout(() => {
        settled = true;
        resolve({ status: 'pending' });
      }, timeoutMs);
      void h.done.then((e) => {
        if (settled) return;
        settled = true;
        clearTimeout(t);
        h.claimed = true;
        resolve(toResult(e));
      });
    });
  }

  private deny(
    agentId: string,
    verifiedOrigin: string | null,
    reason: string,
    result: HandoffResult,
  ): HandoffResult {
    this.audit('handoff.denied', {
      agentId,
      ...(verifiedOrigin ? { verifiedOrigin } : {}),
      reason,
    });
    return result;
  }

  private async openFor(session: HandoffSession): Promise<Handoff | HandoffResult> {
    const agentId = session.agent.id;
    const unsupported = (reason: 'not_available' | 'not_eligible' | 'no_human_check') =>
      ({ status: 'unsupported', reason }) as const;
    const denied = { status: 'denied' } as const;
    if (this.closed || !this.surface) {
      return this.deny(agentId, null, 'not_available', unsupported('not_available'));
    }
    const page = session.currentPage();
    const o = page ? this.originOf(page) : null;
    if (!page || !o?.ok) {
      return this.deny(agentId, null, 'not_eligible', unsupported('not_eligible'));
    }
    const at = { origin: o.origin, host: o.host };
    let mode: string;
    try {
      mode = this.opts.policy.resolve(agentId, at).mode;
    } catch {
      mode = 'deny';
    }
    if (mode === 'deny') return this.deny(agentId, o.origin, 'policy_deny', denied);
    await page.waitForLoadState('load', { timeout: 2_000 }).catch(() => {});
    const check = await session.humanCheck(page).catch(() => null);
    if (!check)
      return this.deny(agentId, o.origin, 'no_human_check', unsupported('no_human_check'));
    if (this.pageSite(page) !== siteOf(o.host)) {
      return this.deny(agentId, o.origin, 'not_eligible', unsupported('not_eligible'));
    }
    const intent = this.opts.intents.latestLive(agentId);
    if (!intent) return this.deny(agentId, o.origin, 'no_live_intent', denied);
    let pending = true;
    try {
      pending = this.opts.approvalPending(agentId);
    } catch {
      pending = true;
    }
    if (pending) return this.deny(agentId, o.origin, 'approval_pending', denied);
    const now = this.now();
    if (this.open.size >= this.limits.maxOpen) {
      return this.deny(agentId, o.origin, 'too_many_open', denied);
    }
    const recent = (this.pushes.get(agentId) ?? []).filter(
      (t) => now - t < this.limits.pushWindowMs,
    );
    this.pushes.set(agentId, recent);
    if (recent.length >= this.limits.pushesPerAgent) {
      return this.deny(agentId, o.origin, 'rate_limited', denied);
    }
    const cool = this.cooldown.get(agentId);
    if (cool !== undefined && now - cool < this.limits.cooldownMs) {
      return this.deny(agentId, o.origin, 'cooldown', denied);
    }
    let available = false;
    try {
      available = this.surface.handoffAvailable();
    } catch {
      available = false;
    }
    if (!available)
      return this.deny(agentId, o.origin, 'not_available', unsupported('not_available'));

    let signIn: { ok: true; offer: unknown } | { ok: false; reason: string } = {
      ok: false,
      reason: 'unsupported',
    };
    if (this.opts.signIn) {
      try {
        signIn = this.opts.signIn.offer(session.agent, at);
      } catch {
        signIn = { ok: false, reason: 'internal_error' };
      }
    }
    const h = this.create(session, page, o, intent, now, signIn.ok);
    recent.push(now);
    const logged = this.auditOrEnd(h, 'handoff.requested', {
      handoffId: h.id,
      agentId,
      verifiedOrigin: h.origin,
      provider: check.provider,
      ...(signIn.ok
        ? { withSignIn: true }
        : this.opts.signIn
          ? { signInSkipped: signIn.reason }
          : {}),
    });
    if (!logged) return denied;
    if (signIn.ok) void this.approveSignIn(h, signIn.offer);
    else void this.surface.notifyHandoff(this.view(h));
    return h;
  }

  private async approveSignIn(h: Handoff, offer: unknown): Promise<void> {
    const hooks = this.opts.signIn;
    const ctl = new AbortController();
    h.abort = ctl;
    let r: { ok: true; deviceId: string } | { ok: false; reason: string };
    try {
      r = hooks
        ? await hooks.approve(h.session.agent, offer, { id: h.id, signal: ctl.signal })
        : { ok: false, reason: 'unsupported' };
    } catch {
      r = { ok: false, reason: 'internal_error' };
    }
    h.abort = null;
    if (h.ended) {
      this.signInEnded(h, h.ended);
      return;
    }
    if (!r.ok || typeof r.deviceId !== 'string' || r.deviceId.length === 0) {
      this.end(h, !r.ok && r.reason === 'approval_timeout' ? 'expired' : 'cancelled');
      return;
    }
    h.controller = r.deviceId;
    this.auditOrEnd(h, 'handoff.started', {
      handoffId: h.id,
      deviceId: r.deviceId,
      via: 'approval',
    });
  }

  private signInEnded(h: Handoff, outcome: HandoffEnd): void {
    if (!h.withSignIn) return;
    try {
      this.opts.signIn?.ended(h.id, outcome);
    } catch {}
  }

  private create(
    session: HandoffSession,
    page: Page,
    o: { origin: string; host: string },
    intent: Intent,
    now: number,
    withSignIn = false,
  ): Handoff {
    let resolve!: (e: HandoffEnd) => void;
    const done = new Promise<HandoffEnd>((r) => {
      resolve = r;
    });
    const site = siteOf(o.host);
    const h: Handoff = {
      id: randomUUID(),
      agentId: session.agent.id,
      agentName: session.agent.name,
      session,
      page,
      origin: o.origin,
      host: o.host,
      site,
      intentText: intent.text,
      intentAt: intent.createdAt,
      openedAt: now,
      expiresAt: now + this.ttlMs,
      controller: null,
      inputs: { clicks: 0, scrolls: 0, drags: 0, keys: 0, texts: 0 },
      ended: null,
      done,
      resolve,
      timer: setTimeout(() => this.end(h, 'expired'), this.ttlMs),
      detach: () => {},
      frame: null,
      detail: null,
      detailing: null,
      capturing: null,
      queue: Promise.resolve(),
      claimed: false,
      endedAt: 0,
      withSignIn,
      abort: null,
    };
    h.timer.unref?.();
    const onClose = () => this.end(h, 'page_closed');
    const onNav = (f: Frame) => {
      if (f === page.mainFrame() && this.urlSite(page) !== site) this.end(h, 'left_site');
    };
    page.on('close', onClose);
    page.on('framenavigated', onNav);
    h.detach = () => {
      page.off('close', onClose);
      page.off('framenavigated', onNav);
    };
    this.open.set(h.id, h);
    return h;
  }

  private view(h: Handoff): HandoffView {
    return {
      id: h.id,
      host: h.host,
      agentName: h.agentName,
      intentText: h.intentText,
      intentAt: h.intentAt,
      openedAt: h.openedAt,
      expiresAt: h.expiresAt,
      ...(h.withSignIn ? { withSignIn: true } : {}),
    };
  }

  private end(h: Handoff, outcome: HandoffEnd): void {
    if (h.ended) return;
    h.ended = outcome;
    clearTimeout(h.timer);
    h.detach();
    h.frame = null;
    h.detail = null;
    this.open.delete(h.id);
    const now = this.now();
    h.endedAt = now;
    this.lastEnded.set(h.agentId, h);
    if (outcome === 'cancelled' || outcome === 'expired') this.cooldown.set(h.agentId, now);
    this.audit('handoff.ended', {
      handoffId: h.id,
      agentId: h.agentId,
      verifiedOrigin: h.origin,
      outcome,
      durationMs: now - h.openedAt,
      inputs: { ...h.inputs },
    });
    h.abort?.abort();
    this.signInEnded(h, outcome);
    if (outcome === 'done' && this.opts.onDone) {
      try {
        void Promise.resolve(
          this.opts.onDone({ agentId: h.agentId, origin: h.origin, host: h.host }),
        ).catch(() => {});
      } catch {}
    }
    h.resolve(outcome);
  }

  endAgent(agentId: string, outcome: 'revoked' | 'closed'): void {
    const h = this.byAgent(agentId);
    if (h) this.end(h, outcome);
  }

  close(): void {
    this.closed = true;
    for (const h of [...this.open.values()]) this.end(h, 'closed');
  }

  private controlled(id: string, deviceId: string): Handoff | HandoffInputResult {
    const h = this.open.get(id);
    if (!h || h.ended) return { ok: false, reason: 'not_open' };
    if (h.controller === null || h.controller !== deviceId) {
      return { ok: false, reason: 'not_controller' };
    }
    if (this.urlSite(h.page) !== h.site) {
      this.end(h, h.page.isClosed() ? 'page_closed' : 'left_site');
      return { ok: false, reason: 'not_open' };
    }
    if (this.pageSite(h.page) !== h.site) return { ok: false, reason: 'failed' };
    return h;
  }

  port(): HandoffPort {
    return {
      list: () => [...this.open.values()].map((h) => this.view(h)),
      get: (id) => {
        const h = this.open.get(id);
        return h ? this.view(h) : null;
      },
      controller: (id) => this.open.get(id)?.controller ?? null,
      start: (id, deviceId) => this.start(id, deviceId),
      frame: (id, deviceId, clip) =>
        clip ? this.detail(id, deviceId, clip) : this.frame(id, deviceId),
      input: (id, deviceId, input) => this.input(id, deviceId, input),
      finish: (id, deviceId, outcome) => {
        const h = this.controlled(id, deviceId);
        if (!('id' in h)) return false;
        this.end(h, outcome === 'done' ? 'done' : 'cancelled');
        return true;
      },
    };
  }

  private start(id: string, deviceId: string): HandoffStartResult {
    const h = this.open.get(id);
    if (!h || h.ended) return 'not_found';
    if (h.controller !== null) return h.controller === deviceId ? 'ok' : 'taken';
    if (h.withSignIn) return 'approval_only';
    h.controller = deviceId;
    if (!this.auditOrEnd(h, 'handoff.started', { handoffId: h.id, deviceId })) return 'not_found';
    return 'ok';
  }

  private async frame(id: string, deviceId: string): Promise<Buffer | null> {
    const h = this.controlled(id, deviceId);
    if (!('id' in h)) return null;
    const now = this.now();
    if (h.frame && now - h.frame.at < FRAME_CACHE_MS) return h.frame.img;
    if (!h.capturing) {
      h.capturing = h.page
        .screenshot({ type: 'jpeg', quality: 60, scale: 'css', timeout: SCREENSHOT_TIMEOUT_MS })
        .then(
          (img) => {
            if (h.ended || this.pageSite(h.page) !== h.site) return null;
            h.frame = { at: this.now(), img };
            return img;
          },
          () => null,
        )
        .finally(() => {
          h.capturing = null;
        });
    }
    return h.capturing;
  }

  private async detail(id: string, deviceId: string, clip: HandoffClip): Promise<Buffer | null> {
    const h = this.controlled(id, deviceId);
    if (!('id' in h)) return null;
    const vp = h.page.viewportSize();
    if (!vp) return null;
    const x0 = Math.floor(clamp01(clip.x) * vp.width);
    const y0 = Math.floor(clamp01(clip.y) * vp.height);
    const x1 = Math.ceil(clamp01(clip.x + clip.w) * vp.width);
    const y1 = Math.ceil(clamp01(clip.y + clip.h) * vp.height);
    if (x1 - x0 < 1 || y1 - y0 < 1) return null;
    const rect = { x: x0, y: y0, width: x1 - x0, height: y1 - y0 };
    const key = `${rect.x},${rect.y},${rect.width},${rect.height}`;
    const now = this.now();
    if (h.detail && h.detail.key === key && now - h.detail.at < FRAME_CACHE_MS) return h.detail.img;
    if (h.detailing?.key === key) return h.detailing.img;
    const img = h.page
      .screenshot({
        type: 'jpeg',
        quality: DETAIL_QUALITY,
        scale: 'css',
        clip: rect,
        timeout: SCREENSHOT_TIMEOUT_MS,
      })
      .then(
        (img) => {
          if (h.ended || this.pageSite(h.page) !== h.site) return null;
          h.detail = { at: this.now(), key, img };
          return img;
        },
        () => null,
      )
      .finally(() => {
        if (h.detailing?.img === img) h.detailing = null;
      });
    h.detailing = { key, img };
    return img;
  }

  private input(id: string, deviceId: string, input: HandoffInput): Promise<HandoffInputResult> {
    const h = this.controlled(id, deviceId);
    if (!('id' in h)) return Promise.resolve(h);
    const run = h.queue.then(() => this.apply(h, input));
    h.queue = run.catch(() => {});
    return run;
  }

  private async apply(h: Handoff, input: HandoffInput): Promise<HandoffInputResult> {
    if (h.ended) return { ok: false, reason: 'not_open' };
    const page = h.page;
    try {
      const vp = page.viewportSize();
      const at = (p: { x: number; y: number }) => {
        if (!vp) throw new Error('no viewport');
        return { x: p.x * vp.width, y: p.y * vp.height };
      };
      switch (input.type) {
        case 'click': {
          const p = at(input);
          await withTimeout(page.mouse.click(p.x, p.y), INPUT_TIMEOUT_MS);
          h.inputs.clicks++;
          break;
        }
        case 'scroll':
          await withTimeout(page.mouse.wheel(0, input.dy), INPUT_TIMEOUT_MS);
          h.inputs.scrolls++;
          break;
        case 'drag': {
          const a = at(input.from);
          const b = at(input.to);
          await withTimeout(
            (async () => {
              await page.mouse.move(a.x, a.y);
              await page.mouse.down();
              await page.mouse.move(b.x, b.y, { steps: 12 });
              await page.mouse.up();
            })(),
            INPUT_TIMEOUT_MS,
          );
          h.inputs.drags++;
          break;
        }
        case 'key':
          await withTimeout(page.keyboard.press(input.key), INPUT_TIMEOUT_MS);
          h.inputs.keys++;
          break;
        case 'text': {
          if (await this.sensitiveFocus(page)) {
            this.audit('handoff.input_refused', { handoffId: h.id, reason: 'sensitive_field' });
            return { ok: false, reason: 'sensitive_field' };
          }
          if (input.text.length >= REMEMBER_MIN) h.session.rememberSecret(input.text);
          await withTimeout(page.keyboard.insertText(input.text), INPUT_TIMEOUT_MS);
          h.inputs.texts++;
          break;
        }
      }
      h.session.markDirty();
      h.frame = null;
      h.detail = null;
      return { ok: true };
    } catch {
      return { ok: false, reason: 'failed' };
    }
  }

  private async sensitiveFocus(page: Page): Promise<boolean> {
    try {
      for (const f of page.frames()) {
        if (f.isDetached()) continue;
        const n = await withTimeout(
          f.locator(`css=:is(${SENSITIVE_FIELDS_CSS}):focus`).count(),
          INPUT_TIMEOUT_MS,
        );
        if (n > 0) return true;
      }
      return false;
    } catch {
      return true;
    }
  }
}

export function handoffWaitMs(v: number | undefined): number {
  if (v === undefined) return DEFAULT_HANDOFF_WAIT_MS;
  if (!Number.isFinite(v)) return DEFAULT_HANDOFF_WAIT_MS;
  return Math.min(Math.max(Math.floor(v), 1_000), MAX_HANDOFF_WAIT_MS);
}
