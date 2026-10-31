import type { HandoffPort, HandoffSurface, HandoffView } from '@aab/approver';
import type { Page } from 'playwright';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HandoffManager, type HandoffSession } from '../src/handoff.ts';
import type { Intent } from '../src/intents.ts';
import { checkOriginUrl, type OriginCheck } from '../src/origin.ts';

const URL_RP = 'http://rp.localhost:3000/password/login';
const DEVICE = 'dev1';

class FakePage {
  href = URL_RP;
  log: string[] = [];
  shots = 0;
  focusCount: () => Promise<number> = async () => 0;
  framesError: Error | null = null;
  screenshotGate: Promise<void> | null = null;
  readonly main = { name: 'main' };
  url() {
    return this.href;
  }
  isClosed() {
    return false;
  }
  on() {
    return this;
  }
  off() {
    return this;
  }
  mainFrame() {
    return this.main;
  }
  async waitForLoadState() {}
  viewportSize() {
    return { width: 1280, height: 720 };
  }
  async screenshot() {
    this.shots++;
    this.log.push('screenshot');
    await this.screenshotGate;
    return Buffer.from(`jpeg-${this.shots}`);
  }
  frames() {
    if (this.framesError) throw this.framesError;
    return [
      {
        isDetached: () => false,
        locator: () => ({ count: () => this.focusCount() }),
      },
    ];
  }
  mouse = {
    click: async (x: number, y: number) => void this.log.push(`click ${x},${y}`),
    wheel: async () => void this.log.push('wheel'),
    move: async () => void this.log.push('move'),
    down: async () => void this.log.push('down'),
    up: async () => void this.log.push('up'),
  };
  keyboard = {
    press: async (k: string) => void this.log.push(`press ${k}`),
    insertText: async (t: string) => void this.log.push(`insert ${t}`),
  };
}

class FakeSession implements HandoffSession {
  readonly agent = { id: 'a', name: 'agent-a' };
  readonly page: FakePage;
  remembered: string[] = [];
  onHumanCheck: () => void = () => {};
  constructor(page: FakePage) {
    this.page = page;
  }
  currentPage() {
    return this.page as unknown as Page;
  }
  async humanCheck() {
    this.onHumanCheck();
    return { provider: 'test' };
  }
  rememberSecret(v: string) {
    this.remembered.push(v);
  }
  markDirty() {}
}

class FakeSurface implements HandoffSurface {
  port: HandoffPort | null = null;
  attachHandoffs(p: HandoffPort) {
    this.port = p;
  }
  async notifyHandoff(_v: HandoffView) {}
  handoffAvailable() {
    return true;
  }
}

const intent: Intent = {
  id: 'i-a',
  agentId: 'a',
  text: 'sign me in',
  createdAt: Date.now(),
  expiresAt: Date.now() + 600_000,
};

describe('handoff fails closed when it cannot tell', () => {
  let page: FakePage;
  let session: FakeSession;
  let surface: FakeSurface;
  let manager: HandoffManager;
  let documentOriginKnown: boolean;
  let audit: { event: string; fields: Record<string, unknown> }[];

  const originOf = (p: Page): OriginCheck =>
    documentOriginKnown
      ? checkOriginUrl(p.url())
      : { ok: false, reason: 'document_origin_unknown' };
  const port = () => surface.port as HandoffPort;
  const open = async () => {
    const result = manager.request(session, 45_000);
    await vi.advanceTimersByTimeAsync(0);
    const id = port().list()[0]?.id as string;
    expect(port().start(id, DEVICE)).toBe('ok');
    page.log = [];
    return { id, result };
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(1_700_000_000_000);
    page = new FakePage();
    session = new FakeSession(page);
    surface = new FakeSurface();
    documentOriginKnown = true;
    audit = [];
    manager = new HandoffManager({
      surface,
      intents: { latestLive: () => intent },
      policy: { resolve: () => ({ mode: 'ask' }) },
      approvalPending: () => false,
      audit: (event, fields) => void audit.push({ event, fields }),
      originOf,
    });
  });
  afterEach(() => {
    manager.close();
    vi.useRealTimers();
  });

  describe('typing text when the focused field cannot be read', () => {
    it.each([
      [
        'the focus query throws',
        () => {
          page.focusCount = () => Promise.reject(new Error('detached'));
        },
      ],
      [
        'the focus query never answers',
        () => {
          page.focusCount = () => new Promise<number>(() => {});
        },
      ],
      [
        'the frame list cannot be read',
        () => {
          page.framesError = new Error('page is gone');
        },
      ],
    ])(
      '%s: the text is refused as a sensitive field, not remembered, not inserted',
      async (_name, break_) => {
        const { id } = await open();
        break_();
        const pending = port().input(id, DEVICE, { type: 'text', text: 'hunter2-typed' });
        await vi.advanceTimersByTimeAsync(5_001);
        expect(await pending).toEqual({ ok: false, reason: 'sensitive_field' });
        expect(page.log).toEqual([]);
        expect(session.remembered).toEqual([]);
        expect(audit.at(-1)).toEqual({
          event: 'handoff.input_refused',
          fields: { handoffId: id, reason: 'sensitive_field' },
        });
      },
    );

    it('control: a readable focus with no sensitive field takes the text, remembered first', async () => {
      const { id } = await open();
      expect(await port().input(id, DEVICE, { type: 'text', text: 'Main Street 1' })).toEqual({
        ok: true,
      });
      expect(session.remembered).toEqual(['Main Street 1']);
      expect(page.log).toEqual(['insert Main Street 1']);
    });
  });

  describe('a document whose origin is not verified on the handoff site', () => {
    it('gets no frames and no input, and the handoff stays open for when it is verified', async () => {
      const { id } = await open();
      documentOriginKnown = false;
      expect(await port().frame(id, DEVICE)).toBeNull();
      expect(await port().frame(id, DEVICE, { x: 0, y: 0, w: 0.5, h: 0.5 })).toBeNull();
      for (const input of [
        { type: 'click', x: 0.5, y: 0.5 },
        { type: 'scroll', dy: 100 },
        { type: 'key', key: 'Enter' },
        { type: 'text', text: 'Main Street 1' },
      ] as const) {
        expect(await port().input(id, DEVICE, input), input.type).toEqual({
          ok: false,
          reason: 'failed',
        });
      }
      expect(page.log).toEqual([]);
      expect(session.remembered).toEqual([]);
      expect(manager.isOpen('a')).toBe(true);

      documentOriginKnown = true;
      expect(await port().frame(id, DEVICE)).not.toBeNull();
      expect(await port().input(id, DEVICE, { type: 'key', key: 'Enter' })).toEqual({ ok: true });
      expect(page.log).toEqual(['screenshot', 'press Enter']);
    });

    it('a frame captured while the document origin became unverified is dropped, not cached', async () => {
      const { id } = await open();
      let release!: () => void;
      page.screenshotGate = new Promise<void>((r) => {
        release = r;
      });
      const inFlight = port().frame(id, DEVICE);
      await vi.advanceTimersByTimeAsync(0);
      documentOriginKnown = false;
      release();
      expect(await inFlight).toBeNull();

      documentOriginKnown = true;
      page.screenshotGate = null;
      expect(await port().frame(id, DEVICE)).toEqual(Buffer.from('jpeg-2'));
      expect(page.shots).toBe(2);
    });

    it('no handoff opens on it, whether it is unverified at the request or after the human-check read', async () => {
      const request = async () => {
        const result = manager.request(session, 1_000);
        await vi.advanceTimersByTimeAsync(1_000);
        return result;
      };
      documentOriginKnown = false;
      expect(await request()).toEqual({ status: 'unsupported', reason: 'not_eligible' });
      documentOriginKnown = true;
      session.onHumanCheck = () => {
        documentOriginKnown = false;
      };
      expect(await request()).toEqual({ status: 'unsupported', reason: 'not_eligible' });
      expect(manager.isOpen('a')).toBe(false);
      expect(audit.filter((a) => a.event === 'handoff.denied').map((a) => a.fields.reason)).toEqual(
        ['not_eligible', 'not_eligible'],
      );
      expect(audit.some((a) => a.event === 'handoff.requested')).toBe(false);
    });
  });
});
