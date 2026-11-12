import type { HandoffSurface, HandoffView } from '@aab/approver';
import type { Page } from 'playwright';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type HandoffEnd,
  type HandoffEvent,
  HandoffManager,
  type HandoffSession,
  type HandoffSignInHooks,
  type HandoffState,
  nextHandoffState,
} from '../src/handoff.ts';
import type { Intent } from '../src/intents.ts';
import { checkOriginUrl } from '../src/origin.ts';

type Listener = (...a: unknown[]) => void;
type Answer = { ok: true; deviceId: string } | { ok: false; reason: string };

const URL_RP = 'http://rp.localhost:3000/password/login';

class FakePage {
  href: string;
  closed = false;
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
  async screenshot() {
    return Buffer.from('jpeg');
  }
}

class FakeSession implements HandoffSession {
  readonly agent: { id: string; name: string };
  page: FakePage | null;
  constructor(id: string, page: FakePage | null) {
    this.agent = { id, name: `${id}-name` };
    this.page = page;
  }
  currentPage() {
    return this.page as unknown as Page | null;
  }
  async humanCheck() {
    return { provider: 'test' } as never;
  }
  rememberSecret() {}
  markDirty() {}
}

class FakeSurface implements HandoffSurface {
  port: Parameters<HandoffSurface['attachHandoffs']>[0] | null = null;
  pushed: HandoffView[] = [];
  attachHandoffs(p: Parameters<HandoffSurface['attachHandoffs']>[0]) {
    this.port = p;
  }
  async notifyHandoff(v: HandoffView) {
    this.pushed.push(v);
  }
  handoffAvailable() {
    return true;
  }
}

class FakeSignIn {
  eligible = true;
  asked: { id: string; signal: AbortSignal }[] = [];
  ended: [string, HandoffEnd][] = [];
  granted = new Set<string>();
  private answers: ((r: Answer) => void)[] = [];
  hooks(): HandoffSignInHooks<unknown> {
    return {
      offer: () =>
        this.eligible ? { ok: true, offer: 'offer' } : { ok: false, reason: 'high_risk' },
      approve: (_agent, _offer, h) => {
        this.asked.push(h);
        return new Promise<Answer>((resolve) =>
          this.answers.push((r) => {
            if (r.ok) this.granted.add(h.id);
            resolve(r);
          }),
        );
      },
      ended: (id, outcome) => {
        this.ended.push([id, outcome]);
        this.granted.delete(id);
      },
    };
  }
  decide(r: Answer) {
    this.answers.shift()?.(r);
  }
}

function setup(o: { signIn?: FakeSignIn; failAudit?: string } = {}) {
  const surface = new FakeSurface();
  const intents = new Map<string, Intent>();
  const audit: { event: string; fields: Record<string, unknown> }[] = [];
  const m = new HandoffManager({
    surface,
    intents: { latestLive: (id) => intents.get(id) },
    policy: { resolve: () => ({ mode: 'ask' }) },
    approvalPending: () => false,
    audit: (event, fields) => {
      if (event === o.failAudit) throw new Error('audit append failed');
      audit.push({ event, fields });
    },
    originOf: (page) => checkOriginUrl(page.url()),
    ...(o.signIn ? { signIn: o.signIn.hooks() } : {}),
  });
  const port = () => surface.port as NonNullable<FakeSurface['port']>;
  const open = async (sess: FakeSession) => {
    intents.set(sess.agent.id, {
      id: `i-${sess.agent.id}`,
      agentId: sess.agent.id,
      text: 'sign me in to the test site',
      createdAt: Date.now(),
      expiresAt: Date.now() + 600_000,
    });
    const result = m.request(sess, 45_000);
    await vi.advanceTimersByTimeAsync(0);
    const view = port()
      .list()
      .find((v) => v.agentName === sess.agent.name);
    return { result, id: view?.id as string };
  };
  return { m, surface, port, open, audit };
}

const ENDS: HandoffEnd[] = [
  'done',
  'cancelled',
  'expired',
  'left_site',
  'page_closed',
  'revoked',
  'closed',
];

describe('handoff states: every state against every event', () => {
  const abort = new AbortController();
  const states: Record<HandoffState['kind'], HandoffState> = {
    awaiting_approval: { kind: 'awaiting_approval', abort, settled: Promise.resolve() },
    waiting_for_phone: { kind: 'waiting_for_phone' },
    controlled: { kind: 'controlled', deviceId: 'dev1' },
    ended: { kind: 'ended', outcome: 'done' },
  };
  const events: Record<string, HandoffEvent> = {
    approved: { kind: 'approved', deviceId: 'dev2' },
    start: { kind: 'start', deviceId: 'dev2' },
    end: { kind: 'end', outcome: 'cancelled' },
  };
  const controlledBy2: HandoffState = { kind: 'controlled', deviceId: 'dev2' };
  const endedNow: HandoffState = { kind: 'ended', outcome: 'cancelled' };
  const table: [keyof typeof states, keyof typeof events, HandoffState][] = [
    ['awaiting_approval', 'approved', controlledBy2],
    ['awaiting_approval', 'start', states.awaiting_approval],
    ['awaiting_approval', 'end', endedNow],
    ['waiting_for_phone', 'approved', states.waiting_for_phone],
    ['waiting_for_phone', 'start', controlledBy2],
    ['waiting_for_phone', 'end', endedNow],
    ['controlled', 'approved', states.controlled],
    ['controlled', 'start', states.controlled],
    ['controlled', 'end', endedNow],
    ['ended', 'approved', states.ended],
    ['ended', 'start', states.ended],
    ['ended', 'end', states.ended],
  ];

  it('covers each state and event once', () => {
    expect(new Set(table.map(([s, e]) => `${s} ${e}`)).size).toBe(
      Object.keys(states).length * Object.keys(events).length,
    );
  });

  for (const [from, event, to] of table) {
    it(`${from} + ${event} -> ${to.kind}`, () => {
      const next = nextHandoffState(states[from], events[event] as HandoffEvent);
      expect(next).toEqual(to);
      if (next.kind === from && from !== 'ended' && to === states[from]) {
        expect(next).toBe(states[from]);
      }
    });
  }

  it('an ended state keeps its first outcome', () => {
    for (const outcome of ENDS) {
      expect(nextHandoffState(states.ended, { kind: 'end', outcome })).toBe(states.ended);
    }
  });
});

describe('handoff states: the manager', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(1_700_000_000_000);
  });
  afterEach(() => vi.useRealTimers());

  async function endBy(
    how: HandoffEnd,
    s: ReturnType<typeof setup>,
    page: FakePage,
    id: string,
    agentId: string,
  ) {
    const port = s.port();
    switch (how) {
      case 'done':
      case 'cancelled':
        port.finish(id, 'dev1', how);
        break;
      case 'expired':
        await vi.advanceTimersByTimeAsync(5 * 60_000);
        break;
      case 'left_site':
        page.navigate('http://evil.localhost:3000/');
        break;
      case 'page_closed':
        page.close();
        break;
      case 'revoked':
      case 'closed':
        s.m.endAgent(agentId, how);
        break;
    }
  }

  for (const how of ENDS) {
    it(`signIn.ended runs exactly once when a started handoff ends: ${how}`, async () => {
      const f = new FakeSignIn();
      const s = setup({ signIn: f });
      const page = new FakePage(URL_RP);
      const h = await s.open(new FakeSession('a', page));
      f.decide({ ok: true, deviceId: 'dev1' });
      await vi.advanceTimersByTimeAsync(0);
      expect(s.port().controller(h.id)).toBe('dev1');
      await endBy(how, s, page, h.id, 'a');
      await h.result;
      await vi.advanceTimersByTimeAsync(0);
      expect(f.ended).toEqual([[h.id, how]]);
      expect(f.granted.size).toBe(0);
    });
  }

  for (const how of ENDS.filter((e) => e !== 'done')) {
    it(`signIn.ended runs exactly once, after the approval settles, when it ends while the card waits: ${how}`, async () => {
      const f = new FakeSignIn();
      const s = setup({ signIn: f });
      const page = new FakePage(URL_RP);
      const h = await s.open(new FakeSession('a', page));
      if (how === 'cancelled') f.decide({ ok: false, reason: 'approval_user_denied' });
      else if (how !== 'expired') await endBy(how, s, page, h.id, 'a');
      else f.decide({ ok: false, reason: 'approval_timeout' });
      await h.result;
      if (how !== 'cancelled' && how !== 'expired') {
        expect(f.asked[0]?.signal.aborted).toBe(true);
        expect(f.ended).toEqual([]);
        f.decide({ ok: false, reason: 'approval_withdrawn' });
      }
      await vi.advanceTimersByTimeAsync(0);
      expect(f.ended).toEqual([[h.id, how]]);
    });
  }

  it('an approval that lands after the end is dropped, once', async () => {
    const f = new FakeSignIn();
    const s = setup({ signIn: f });
    const page = new FakePage(URL_RP);
    const h = await s.open(new FakeSession('a', page));
    page.close();
    expect(await h.result).toEqual({ status: 'cancelled' });
    expect(f.ended).toEqual([]);
    f.decide({ ok: true, deviceId: 'dev1' });
    await vi.advanceTimersByTimeAsync(0);
    expect(f.ended).toEqual([[h.id, 'page_closed']]);
    expect(f.granted.size).toBe(0);
    expect(s.audit.filter((a) => a.event === 'handoff.started')).toEqual([]);
    expect(s.port().controller(h.id)).toBeNull();
  });

  it('a handoff whose request cannot be audited still drops its sign-in, once', async () => {
    const f = new FakeSignIn();
    const s = setup({ signIn: f, failAudit: 'handoff.requested' });
    const sess = new FakeSession('a', new FakePage(URL_RP));
    await s.open(sess);
    await vi.advanceTimersByTimeAsync(0);
    expect(f.asked).toEqual([]);
    expect(f.ended).toHaveLength(1);
    expect(f.ended[0]?.[1]).toBe('cancelled');
  });

  it('a handoff whose approved start cannot be audited ends and drops its sign-in, once', async () => {
    const f = new FakeSignIn();
    const s = setup({ signIn: f, failAudit: 'handoff.started' });
    const h = await s.open(new FakeSession('a', new FakePage(URL_RP)));
    f.decide({ ok: true, deviceId: 'dev1' });
    await vi.advanceTimersByTimeAsync(0);
    expect(await h.result).toEqual({ status: 'cancelled' });
    expect(f.ended).toEqual([[h.id, 'cancelled']]);
    expect(f.granted.size).toBe(0);
  });

  it('a handoff without a sign-in offer never calls signIn.ended', async () => {
    for (const how of ENDS) {
      const f = new FakeSignIn();
      f.eligible = false;
      const s = setup({ signIn: f });
      const page = new FakePage(URL_RP);
      const h = await s.open(new FakeSession('a', page));
      expect(s.port().start(h.id, 'dev1')).toBe('ok');
      expect(s.port().start(h.id, 'dev2')).toBe('taken');
      await endBy(how, s, page, h.id, 'a');
      await h.result;
      await vi.advanceTimersByTimeAsync(0);
      expect(s.port().start(h.id, 'dev1')).toBe('not_found');
      expect(f.asked).toEqual([]);
      expect(f.ended).toEqual([]);
    }
  });

  it('an approval that ignores the abort and lands late still has its grant dropped, once', async () => {
    const f = new FakeSignIn();
    const s = setup({ signIn: f });
    const page = new FakePage(URL_RP);
    const h = await s.open(new FakeSession('a', page));
    s.m.endAgent('a', 'revoked');
    expect(await h.result).toEqual({ status: 'cancelled' });
    expect(f.asked[0]?.signal.aborted).toBe(true);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(f.ended).toEqual([]);
    f.decide({ ok: true, deviceId: 'dev1' });
    await vi.advanceTimersByTimeAsync(0);
    expect(f.ended).toEqual([[h.id, 'revoked']]);
    expect(f.granted.size).toBe(0);
    expect(s.audit.filter((a) => a.event === 'handoff.started')).toEqual([]);
  });

  it('an ended handoff holds no reference to its page or session', async () => {
    const s = setup();
    const page = new FakePage(URL_RP);
    const session = new FakeSession('a', page);
    const h = await s.open(session);
    expect(s.port().start(h.id, 'dev1')).toBe('ok');
    s.port().finish(h.id, 'dev1', 'done');
    expect(await h.result).toEqual({ status: 'done' });
    const seen = new Set<unknown>();
    const reaches = (v: unknown): boolean => {
      if (v === page || v === session) return true;
      if (typeof v !== 'object' || v === null || seen.has(v)) return false;
      seen.add(v);
      if (v instanceof Map) return [...v.entries()].some(([k, x]) => reaches(k) || reaches(x));
      if (v instanceof Set) return [...v].some(reaches);
      if (v === s.surface) return false;
      return Object.values(v).some(reaches);
    };
    expect(reaches(s.m)).toBe(false);
  });
});
