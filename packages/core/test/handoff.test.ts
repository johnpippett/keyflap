import type { HandoffSurface, HandoffView } from '@aab/approver';
import type { Page } from 'playwright';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type HandoffEnd,
  HandoffManager,
  type HandoffSession,
  type HandoffSignInHooks,
  handoffWaitMs,
} from '../src/handoff.ts';
import type { Intent } from '../src/intents.ts';
import { checkOriginUrl } from '../src/origin.ts';

type Listener = (...a: unknown[]) => void;

class FakePage {
  href: string;
  closed = false;
  log: string[] = [];
  sensitive = false;
  shots = 0;
  failShot = false;
  readonly main = { name: 'main' };
  private readonly listeners = new Map<string, Set<Listener>>();
  constructor(href: string) {
    this.href = href;
  }
  url() {
    return this.href;
  }
  isClosed() {
    return this.closed;
  }
  on(ev: string, fn: Listener) {
    if (!this.listeners.has(ev)) this.listeners.set(ev, new Set());
    this.listeners.get(ev)?.add(fn);
    return this;
  }
  off(ev: string, fn: Listener) {
    this.listeners.get(ev)?.delete(fn);
    return this;
  }
  emit(ev: string, ...a: unknown[]) {
    for (const fn of [...(this.listeners.get(ev) ?? [])]) fn(...a);
  }
  listenerCount() {
    let n = 0;
    for (const s of this.listeners.values()) n += s.size;
    return n;
  }
  mainFrame() {
    return this.main;
  }
  async waitForLoadState() {}
  navigate(href: string) {
    this.href = href;
    this.emit('framenavigated', this.main);
  }
  close() {
    this.closed = true;
    this.emit('close');
  }
  viewportSize() {
    return { width: 1280, height: 720 };
  }
  async screenshot(o: Record<string, unknown>) {
    this.shots++;
    this.log.push(`screenshot ${JSON.stringify(o)}`);
    if (this.failShot) throw new Error('boom');
    return Buffer.from(`jpeg-${this.shots}`);
  }
  frames() {
    return [
      {
        isDetached: () => false,
        locator: (sel: string) => ({
          count: async () => {
            this.log.push(`focus-check ${sel.includes(':focus')}`);
            return this.sensitive ? 1 : 0;
          },
        }),
      },
    ];
  }
  mouse = {
    click: async (x: number, y: number) => void this.log.push(`click ${x},${y}`),
    wheel: async (dx: number, dy: number) => void this.log.push(`wheel ${dx},${dy}`),
    move: async (x: number, y: number, o?: { steps?: number }) =>
      void this.log.push(`move ${x},${y}${o?.steps ? ` steps=${o.steps}` : ''}`),
    down: async () => void this.log.push('down'),
    up: async () => void this.log.push('up'),
  };
  keyboard = {
    press: async (k: string) => void this.log.push(`press ${k}`),
    insertText: async (t: string) => void this.log.push(`insert ${t}`),
  };
}

class FakeSession implements HandoffSession {
  readonly agent: { id: string; name: string };
  page: FakePage | null;
  check: { provider: string } | null = { provider: 'test' };
  dirty = 0;
  constructor(id: string, page: FakePage | null) {
    this.agent = { id, name: `${id}-name` };
    this.page = page;
  }
  currentPage() {
    return this.page as unknown as Page | null;
  }
  async humanCheck() {
    return this.check;
  }
  rememberSecret(v: string) {
    this.page?.log.push(`remember ${v}`);
  }
  markDirty() {
    this.dirty++;
  }
}

class FakeSurface implements HandoffSurface {
  port: Parameters<HandoffSurface['attachHandoffs']>[0] | null = null;
  pushed: HandoffView[] = [];
  available = true;
  attachHandoffs(p: Parameters<HandoffSurface['attachHandoffs']>[0]) {
    this.port = p;
  }
  async notifyHandoff(v: HandoffView) {
    this.pushed.push(v);
  }
  handoffAvailable() {
    return this.available;
  }
}

interface Setup {
  m: HandoffManager;
  surface: FakeSurface;
  audit: { event: string; fields: Record<string, unknown> }[];
  intents: Map<string, Intent>;
  policy: Map<string, string>;
  pendingApproval: Set<string>;
  done: { agentId: string; origin: string; host: string }[];
  failAudit: Set<string>;
}

function setup(
  o: { surface?: FakeSurface | null; signIn?: HandoffSignInHooks<unknown> } = {},
): Setup {
  const surface = o.surface === undefined ? new FakeSurface() : o.surface;
  const audit: Setup['audit'] = [];
  const intents = new Map<string, Intent>();
  const policy = new Map<string, string>();
  const pendingApproval = new Set<string>();
  const done: Setup['done'] = [];
  const failAudit = new Set<string>();
  const m = new HandoffManager({
    surface,
    intents: { latestLive: (id) => intents.get(id) },
    policy: { resolve: (id) => ({ mode: policy.get(id) ?? 'ask' }) },
    approvalPending: (id) => pendingApproval.has(id),
    audit: (event, fields) => {
      if (failAudit.has(event)) throw new Error('audit append failed');
      audit.push({ event, fields });
    },
    onDone: (e) => void done.push(e),
    originOf: (page) => checkOriginUrl(page.url()),
    ...(o.signIn ? { signIn: o.signIn } : {}),
  });
  return {
    m,
    surface: surface as FakeSurface,
    audit,
    intents,
    policy,
    pendingApproval,
    done,
    failAudit,
  };
}

const intent = (agentId: string): Intent => ({
  id: `i-${agentId}`,
  agentId,
  text: 'sign me in to the test site',
  createdAt: Date.now(),
  expiresAt: Date.now() + 600_000,
});

const URL_RP = 'http://rp.localhost:3000/password/login';

describe('HandoffManager', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(1_700_000_000_000);
  });
  afterEach(() => vi.useRealTimers());

  async function open(s: Setup, sess: FakeSession, timeoutMs = 45_000) {
    s.intents.set(sess.agent.id, intent(sess.agent.id));
    const result = s.m.request(sess, timeoutMs);
    await vi.advanceTimersByTimeAsync(0);
    const view = s.surface.port?.list().find((v) => v.agentName === sess.agent.name);
    return { result, id: view?.id as string };
  }

  it('refuses in the plan order, auditing each reason and sending no push', async () => {
    const reasons: string[] = [];
    const reasonOf = (s: Setup) => s.audit.filter((a) => a.event === 'handoff.denied').at(-1);

    const none = setup({ surface: null });
    expect(await none.m.request(new FakeSession('a', new FakePage(URL_RP)))).toEqual({
      status: 'unsupported',
      reason: 'not_available',
    });
    reasons.push(reasonOf(none)?.fields.reason as string);

    const s = setup();
    const page = new FakePage('file:///etc/passwd');
    const sess = new FakeSession('a', null);
    expect(await s.m.request(sess)).toEqual({ status: 'unsupported', reason: 'not_eligible' });
    sess.page = page;
    expect(await s.m.request(sess)).toEqual({ status: 'unsupported', reason: 'not_eligible' });
    expect(reasonOf(s)?.fields).toEqual({ agentId: 'a', reason: 'not_eligible' });
    reasons.push(reasonOf(s)?.fields.reason as string);
    page.href = URL_RP;
    s.policy.set('a', 'deny');
    expect(await s.m.request(sess)).toEqual({ status: 'denied' });
    reasons.push(reasonOf(s)?.fields.reason as string);
    expect(reasonOf(s)?.fields.verifiedOrigin).toBe('http://rp.localhost:3000');
    s.policy.delete('a');
    sess.check = null;
    expect(await s.m.request(sess)).toEqual({ status: 'unsupported', reason: 'no_human_check' });
    reasons.push(reasonOf(s)?.fields.reason as string);
    sess.check = { provider: 'aws-waf' };
    expect(await s.m.request(sess)).toEqual({ status: 'denied' });
    reasons.push(reasonOf(s)?.fields.reason as string);
    s.intents.set('a', intent('a'));
    s.pendingApproval.add('a');
    expect(await s.m.request(sess)).toEqual({ status: 'denied' });
    reasons.push(reasonOf(s)?.fields.reason as string);
    s.pendingApproval.delete('a');
    s.surface.available = false;
    expect(await s.m.request(sess)).toEqual({ status: 'unsupported', reason: 'not_available' });
    reasons.push(reasonOf(s)?.fields.reason as string);

    expect(reasons).toEqual([
      'not_available',
      'not_eligible',
      'policy_deny',
      'no_human_check',
      'no_live_intent',
      'approval_pending',
      'not_available',
    ]);
    expect(s.surface.pushed).toEqual([]);
    expect(s.m.isOpen('a')).toBe(false);
    for (const a of s.audit) {
      expect(
        Object.keys(a.fields).every((k) => ['agentId', 'reason', 'verifiedOrigin'].includes(k)),
      ).toBe(true);
    }
  });

  it('opens with one push; a second call joins it (no new push); Done answers both', async () => {
    const s = setup();
    const page = new FakePage(URL_RP);
    const sess = new FakeSession('a', page);
    const first = await open(s, sess);
    expect(s.m.isOpen('a')).toBe(true);
    expect(s.surface.pushed).toHaveLength(1);
    expect(s.surface.pushed[0]).toMatchObject({
      host: 'rp.localhost',
      agentName: 'a-name',
      intentText: 'sign me in to the test site',
    });
    expect(Object.keys(s.surface.pushed[0] as object).sort()).toEqual(
      ['agentName', 'expiresAt', 'host', 'id', 'intentAt', 'intentText', 'openedAt'].sort(),
    );
    const second = s.m.request(sess, 45_000);
    await vi.advanceTimersByTimeAsync(0);
    expect(s.surface.pushed).toHaveLength(1);
    const port = s.surface.port as NonNullable<FakeSurface['port']>;
    expect(port.start(first.id, 'dev1')).toBe('ok');
    expect(port.finish(first.id, 'dev1', 'done')).toBe(true);
    expect(await first.result).toEqual({ status: 'done' });
    expect(await second).toEqual({ status: 'done' });
    expect(s.m.isOpen('a')).toBe(false);
    expect(s.done).toEqual([
      { agentId: 'a', origin: 'http://rp.localhost:3000', host: 'rp.localhost' },
    ]);
    const requested = s.audit.find((a) => a.event === 'handoff.requested');
    expect(requested?.fields).toEqual({
      handoffId: first.id,
      agentId: 'a',
      verifiedOrigin: 'http://rp.localhost:3000',
      provider: 'test',
    });
    const ended = s.audit.find((a) => a.event === 'handoff.ended');
    expect(ended?.fields).toMatchObject({ handoffId: first.id, outcome: 'done' });
    expect(page.listenerCount()).toBe(0);
  });

  it('invariant 10 (review L9): no open and no start without its audit entry', async () => {
    const s = setup();
    const sess = new FakeSession('a', new FakePage(URL_RP));
    s.intents.set('a', intent('a'));
    s.failAudit.add('handoff.requested');
    expect(await s.m.request(sess)).toEqual({ status: 'denied' });
    expect(s.surface.pushed).toHaveLength(0);
    expect(s.m.isOpen('a')).toBe(false);

    const t = setup();
    const h = await open(t, new FakeSession('b', new FakePage(URL_RP)));
    t.failAudit.add('handoff.started');
    const port = t.surface.port as NonNullable<FakeSurface['port']>;
    expect(port.start(h.id, 'dev1')).toBe('not_found');
    expect(port.controller(h.id)).toBeNull();
    expect(t.m.isOpen('b')).toBe(false);
    expect(await h.result).toEqual({ status: 'cancelled' });
  });

  it('a call that came back pending gets the outcome on its re-call, once', async () => {
    const s = setup();
    const sess = new FakeSession('a', new FakePage(URL_RP));
    const h = await open(s, sess, 1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await h.result).toEqual({ status: 'pending' });
    const port = s.surface.port as NonNullable<FakeSurface['port']>;
    port.start(h.id, 'dev1');
    port.finish(h.id, 'dev1', 'done');
    await vi.advanceTimersByTimeAsync(0);
    expect(await s.m.request(sess)).toEqual({ status: 'done' });
    sess.check = null;
    expect(await s.m.request(sess)).toEqual({ status: 'unsupported', reason: 'no_human_check' });
  });

  it('expires after 5 minutes', async () => {
    const s = setup();
    const sess = new FakeSession('a', new FakePage(URL_RP));
    const h = await open(s, sess, 120_000);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(await h.result).toEqual({ status: 'pending' });
    const again = s.m.request(sess, 120_000);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(await again).toEqual({ status: 'pending' });
    const last = s.m.request(sess, 120_000);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(await last).toEqual({ status: 'expired' });
    expect(s.m.isOpen('a')).toBe(false);
    expect(s.done).toEqual([]);
  });

  it('the page leaving the site, closing, or a revoke ends it (cancelled for the agent)', async () => {
    const s = setup();
    const p1 = new FakePage(URL_RP);
    const a = await open(s, new FakeSession('a', p1));
    p1.navigate('http://login.rp.localhost:3000/challenge');
    expect(s.m.isOpen('a')).toBe(true);
    p1.navigate('http://evil.localhost:3000/');
    expect(await a.result).toEqual({ status: 'cancelled' });

    const p2 = new FakePage(URL_RP);
    const b = await open(s, new FakeSession('b', p2));
    p2.close();
    expect(await b.result).toEqual({ status: 'cancelled' });

    const c = await open(s, new FakeSession('c', new FakePage(URL_RP)));
    s.m.endAgent('c', 'revoked');
    expect(await c.result).toEqual({ status: 'cancelled' });

    const outcomes = s.audit
      .filter((x) => x.event === 'handoff.ended')
      .map((x) => x.fields.outcome);
    expect(outcomes).toEqual(['left_site', 'page_closed', 'revoked']);
    expect(s.done).toEqual([]);
  });

  it('rate limits: 2 open overall, 3 pushes per agent per 10 minutes, 30 s after a cancel', async () => {
    const s = setup();
    await open(s, new FakeSession('a', new FakePage(URL_RP)));
    await open(s, new FakeSession('b', new FakePage(URL_RP)));
    const sc = new FakeSession('c', new FakePage(URL_RP));
    s.intents.set('c', intent('c'));
    expect(await s.m.request(sc)).toEqual({ status: 'denied' });
    expect(s.audit.at(-1)?.fields.reason).toBe('too_many_open');
    s.m.endAgent('a', 'closed');
    s.m.endAgent('b', 'closed');

    const port = () => s.surface.port as NonNullable<FakeSurface['port']>;
    const sd = new FakeSession('d', new FakePage(URL_RP));
    for (let i = 0; i < 3; i++) {
      const h = await open(s, sd);
      port().start(h.id, 'dev1');
      port().finish(h.id, 'dev1', 'cancelled');
      expect(await h.result).toEqual({ status: 'cancelled' });
      expect(await s.m.request(sd)).toEqual({ status: 'denied' });
      expect(s.audit.at(-1)?.fields.reason).toBe(i < 2 ? 'cooldown' : 'rate_limited');
      await vi.advanceTimersByTimeAsync(31_000);
    }
    const pushes = s.surface.pushed.length;
    expect(await s.m.request(sd)).toEqual({ status: 'denied' });
    expect(s.audit.at(-1)?.fields.reason).toBe('rate_limited');
    expect(s.surface.pushed).toHaveLength(pushes);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    const later = await open(s, sd);
    expect(later.id).toBeTruthy();
  });

  it('one device controls it: frames and input only for that device, after it started', async () => {
    const s = setup();
    const page = new FakePage(URL_RP);
    const h = await open(s, new FakeSession('a', page));
    const port = s.surface.port as NonNullable<FakeSurface['port']>;
    expect(await port.frame(h.id, 'dev1')).toBeNull();
    expect(await port.input(h.id, 'dev1', { type: 'click', x: 0.5, y: 0.5 })).toEqual({
      ok: false,
      reason: 'not_controller',
    });
    expect(port.controller(h.id)).toBeNull();
    expect(port.start(h.id, 'dev1')).toBe('ok');
    expect(port.start(h.id, 'dev2')).toBe('taken');
    expect(port.start('nope', 'dev1')).toBe('not_found');
    expect(port.controller(h.id)).toBe('dev1');
    expect(await port.frame(h.id, 'dev2')).toBeNull();
    expect(port.finish(h.id, 'dev2', 'done')).toBe(false);
    const f1 = await port.frame(h.id, 'dev1');
    expect(f1?.toString()).toBe('jpeg-1');
    expect((await port.frame(h.id, 'dev1'))?.toString()).toBe('jpeg-1');
    await vi.advanceTimersByTimeAsync(300);
    expect((await port.frame(h.id, 'dev1'))?.toString()).toBe('jpeg-2');
    expect(page.log.find((l) => l.startsWith('screenshot'))).toBe(
      'screenshot {"type":"jpeg","quality":60,"scale":"css","timeout":5000}',
    );
    expect(await port.frame(h.id, 'dev2', { x: 0.25, y: 0.5, w: 0.5, h: 0.25 })).toBeNull();
    const shotsBefore = page.shots;
    const d1 = await port.frame(h.id, 'dev1', { x: 0.25, y: 0.5, w: 0.5, h: 0.25 });
    expect(d1?.toString()).toBe(`jpeg-${shotsBefore + 1}`);
    expect(page.log.filter((l) => l.startsWith('screenshot')).at(-1)).toBe(
      'screenshot {"type":"jpeg","quality":85,"scale":"css","clip":{"x":320,"y":360,"width":640,"height":180},"timeout":5000}',
    );
    expect(await port.frame(h.id, 'dev1', { x: 0.25, y: 0.5, w: 0.5, h: 0.25 })).toBe(d1);
    await port.frame(h.id, 'dev1', { x: 0.9, y: 0.9, w: 0.5, h: 0.5 });
    expect(page.log.filter((l) => l.startsWith('screenshot')).at(-1)).toContain(
      '"clip":{"x":1152,"y":648,"width":128,"height":72}',
    );
    expect(await port.input(h.id, 'dev1', { type: 'key', key: 'Enter' })).toEqual({ ok: true });
    const n = page.shots;
    await port.frame(h.id, 'dev1', { x: 0.9, y: 0.9, w: 0.5, h: 0.5 });
    expect(page.shots).toBe(n + 1);
    page.failShot = true;
    await vi.advanceTimersByTimeAsync(300);
    expect(await port.frame(h.id, 'dev1')).toBeNull();
    expect(s.audit.filter((a) => a.event === 'handoff.started').map((a) => a.fields)).toEqual([
      { handoffId: h.id, deviceId: 'dev1' },
    ]);
  });

  it('maps coordinates onto the viewport; keys, scroll and drag; counts inputs', async () => {
    const s = setup();
    const page = new FakePage(URL_RP);
    const sess = new FakeSession('a', page);
    const h = await open(s, sess);
    const port = s.surface.port as NonNullable<FakeSurface['port']>;
    port.start(h.id, 'dev1');
    page.log = [];
    expect(await port.input(h.id, 'dev1', { type: 'click', x: 0.5, y: 0.25 })).toEqual({
      ok: true,
    });
    await port.input(h.id, 'dev1', { type: 'scroll', dy: 400 });
    await port.input(h.id, 'dev1', {
      type: 'drag',
      from: { x: 0, y: 0 },
      to: { x: 1, y: 1 },
    });
    await port.input(h.id, 'dev1', { type: 'key', key: 'Enter' });
    expect(page.log).toEqual([
      'click 640,180',
      'wheel 0,400',
      'move 0,0',
      'down',
      'move 1280,720 steps=12',
      'up',
      'press Enter',
    ]);
    expect(sess.dirty).toBe(4);
    port.finish(h.id, 'dev1', 'cancelled');
    const ended = s.audit.find((a) => a.event === 'handoff.ended');
    expect(ended?.fields.inputs).toEqual({ clicks: 1, scrolls: 1, drags: 1, keys: 1, texts: 0 });
    expect(JSON.stringify(s.audit)).not.toMatch(/"x"|"y"|"dy"|Enter|"key"/);
  });

  it('text: refused into a focused password / OTP field; else remembered before insertion', async () => {
    const s = setup();
    const page = new FakePage(URL_RP);
    const h = await open(s, new FakeSession('a', page));
    const port = s.surface.port as NonNullable<FakeSurface['port']>;
    port.start(h.id, 'dev1');
    page.log = [];
    page.sensitive = true;
    expect(await port.input(h.id, 'dev1', { type: 'text', text: 'hunter2-typed' })).toEqual({
      ok: false,
      reason: 'sensitive_field',
    });
    expect(page.log).toEqual(['focus-check true']);
    expect(s.audit.at(-1)).toEqual({
      event: 'handoff.input_refused',
      fields: { handoffId: h.id, reason: 'sensitive_field' },
    });
    page.sensitive = false;
    page.log = [];
    expect(await port.input(h.id, 'dev1', { type: 'text', text: 'Main Street 1' })).toEqual({
      ok: true,
    });
    expect(page.log).toEqual([
      'focus-check true',
      'remember Main Street 1',
      'insert Main Street 1',
    ]);
    page.log = [];
    await port.input(h.id, 'dev1', { type: 'text', text: 'abc' });
    expect(page.log).toEqual(['focus-check true', 'insert abc']);
    expect(JSON.stringify(s.audit)).not.toMatch(/hunter2|Main Street/);
  });

  it('a handoff never outlives its site for frames: a frame request after leaving ends it', async () => {
    const s = setup();
    const page = new FakePage(URL_RP);
    const h = await open(s, new FakeSession('a', page));
    const port = s.surface.port as NonNullable<FakeSurface['port']>;
    port.start(h.id, 'dev1');
    page.href = 'http://evil.localhost:3000/';
    expect(await port.frame(h.id, 'dev1')).toBeNull();
    expect(await h.result).toEqual({ status: 'cancelled' });
    expect(page.shots).toBe(0);
  });

  it('close() ends every open handoff', async () => {
    const s = setup();
    const h = await open(s, new FakeSession('a', new FakePage(URL_RP)));
    s.m.close();
    expect(await h.result).toEqual({ status: 'cancelled' });
    expect(await s.m.request(new FakeSession('b', new FakePage(URL_RP)))).toEqual({
      status: 'unsupported',
      reason: 'not_available',
    });
  });

  describe('P3b: one approval for the check and the sign-in after it', () => {
    class FakeSignIn {
      eligible: { ok: true; offer: string } | { ok: false; reason: string } = {
        ok: true,
        offer: 'offer-1',
      };
      asked: { agentId: string; offer: string; id: string; signal: AbortSignal }[] = [];
      ended: [string, HandoffEnd][] = [];
      private answer: ((
        r: { ok: true; deviceId: string } | { ok: false; reason: string },
      ) => void)[] = [];
      offer() {
        return this.eligible;
      }
      approve(agent: { id: string }, offer: string, h: { id: string; signal: AbortSignal }) {
        this.asked.push({ agentId: agent.id, offer, ...h });
        return new Promise<{ ok: true; deviceId: string } | { ok: false; reason: string }>((r) =>
          this.answer.push(r),
        );
      }
      decide(r: { ok: true; deviceId: string } | { ok: false; reason: string }) {
        this.answer.shift()?.(r);
      }
      endedFn = (id: string, outcome: HandoffEnd) => void this.ended.push([id, outcome]);
    }
    const hooks = (f: FakeSignIn): HandoffSignInHooks<unknown> => ({
      offer: () => f.offer(),
      approve: (agent, offer, h) => f.approve(agent, offer as string, h),
      ended: f.endedFn,
    });
    const viewOf = (s: Setup, agent: string) =>
      s.surface.port?.list().find((v) => v.agentName === `${agent}-name`);

    it('eligible: no handoff push and no Face ID start; the approval starts it for the approving device', async () => {
      const f = new FakeSignIn();
      const s = setup({ signIn: hooks(f) });
      const h = await open(s, new FakeSession('a', new FakePage(URL_RP)));
      const port = s.surface.port as NonNullable<FakeSurface['port']>;
      expect(s.surface.pushed).toEqual([]);
      expect(f.asked).toHaveLength(1);
      expect(f.asked[0]).toMatchObject({ agentId: 'a', offer: 'offer-1', id: h.id });
      expect(viewOf(s, 'a')?.withSignIn).toBe(true);
      expect(s.audit.find((a) => a.event === 'handoff.requested')?.fields).toMatchObject({
        withSignIn: true,
      });
      expect(port.start(h.id, 'dev1')).toBe('approval_only');
      expect(port.controller(h.id)).toBeNull();
      expect(await port.frame(h.id, 'dev1')).toBeNull();
      f.decide({ ok: true, deviceId: 'dev1' });
      await vi.advanceTimersByTimeAsync(0);
      expect(port.controller(h.id)).toBe('dev1');
      expect(s.audit.find((a) => a.event === 'handoff.started')?.fields).toEqual({
        handoffId: h.id,
        deviceId: 'dev1',
        via: 'approval',
      });
      expect(await port.frame(h.id, 'dev2')).toBeNull();
      expect(port.finish(h.id, 'dev1', 'done')).toBe(true);
      expect(await h.result).toEqual({ status: 'done' });
      expect(f.ended).toEqual([[h.id, 'done']]);
    });

    it('not eligible: the plain P3 handoff (push, Face ID start), and why is audited', async () => {
      const f = new FakeSignIn();
      f.eligible = { ok: false, reason: 'high_risk' };
      const s = setup({ signIn: hooks(f) });
      const h = await open(s, new FakeSession('a', new FakePage(URL_RP)));
      expect(s.surface.pushed).toHaveLength(1);
      expect(f.asked).toEqual([]);
      expect(viewOf(s, 'a')?.withSignIn).toBeUndefined();
      expect(s.audit.find((a) => a.event === 'handoff.requested')?.fields).toMatchObject({
        signInSkipped: 'high_risk',
      });
      const port = s.surface.port as NonNullable<FakeSurface['port']>;
      expect(port.start(h.id, 'dev1')).toBe('ok');
      port.finish(h.id, 'dev1', 'cancelled');
      expect(await h.result).toEqual({ status: 'cancelled' });
      expect(f.ended).toEqual([]);
    });

    it('a denied approval cancels it, a timed-out one expires it; the grant is dropped either way', async () => {
      for (const [reason, status] of [
        ['approval_user_denied', 'cancelled'],
        ['approval_timeout', 'expired'],
      ] as const) {
        const f = new FakeSignIn();
        const s = setup({ signIn: hooks(f) });
        const h = await open(s, new FakeSession('a', new FakePage(URL_RP)));
        f.decide({ ok: false, reason });
        expect(await h.result).toEqual({ status });
        expect(f.ended).toEqual([[h.id, status]]);
        expect(s.surface.port?.controller(h.id) ?? null).toBeNull();
      }
    });

    it('ending while the owner decides withdraws the approval and drops what it recorded', async () => {
      const f = new FakeSignIn();
      const s = setup({ signIn: hooks(f) });
      const page = new FakePage(URL_RP);
      const h = await open(s, new FakeSession('a', page));
      page.close();
      expect(await h.result).toEqual({ status: 'cancelled' });
      expect(f.asked[0]?.signal.aborted).toBe(true);
      f.decide({ ok: true, deviceId: 'dev1' });
      await vi.advanceTimersByTimeAsync(0);
      expect(f.ended).toEqual([
        [h.id, 'page_closed'],
        [h.id, 'page_closed'],
      ]);
      expect(s.audit.filter((a) => a.event === 'handoff.started')).toEqual([]);
    });

    it('cancel, expiry, leaving the site and revoke after the start drop the grant', async () => {
      const ends: HandoffEnd[] = [];
      for (const how of ['cancelled', 'expired', 'left_site', 'revoked'] as const) {
        const f = new FakeSignIn();
        const s = setup({ signIn: hooks(f) });
        const page = new FakePage(URL_RP);
        const h = await open(s, new FakeSession('a', page));
        f.decide({ ok: true, deviceId: 'dev1' });
        await vi.advanceTimersByTimeAsync(0);
        const port = s.surface.port as NonNullable<FakeSurface['port']>;
        if (how === 'cancelled') port.finish(h.id, 'dev1', 'cancelled');
        if (how === 'expired') await vi.advanceTimersByTimeAsync(5 * 60_000);
        if (how === 'left_site') page.navigate('http://evil.localhost:3000/');
        if (how === 'revoked') s.m.endAgent('a', 'revoked');
        await h.result;
        ends.push(...f.ended.map(([, e]) => e));
      }
      expect(ends).toEqual(['cancelled', 'expired', 'left_site', 'revoked']);
    });
  });

  it('wait bounds: 1 s .. 120 s, default 45 s', () => {
    expect(handoffWaitMs(undefined)).toBe(45_000);
    expect(handoffWaitMs(10)).toBe(1_000);
    expect(handoffWaitMs(10_000_000)).toBe(120_000);
    expect(handoffWaitMs(Number.NaN)).toBe(45_000);
  });
});
