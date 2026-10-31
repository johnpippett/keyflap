import type { CDPSession } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type HandoffHarness, startHandoffHarness } from './handoff-harness.ts';

let worldSeq = 0;
async function evalIsolated(session: CDPSession, expression: string): Promise<unknown> {
  const { frameTree } = await session.send('Page.getFrameTree');
  const { executionContextId } = await session.send('Page.createIsolatedWorld', {
    frameId: frameTree.frame.id,
    worldName: `keyflap-inv7-handoff-${worldSeq++}`,
  });
  const { result, exceptionDetails } = await session.send('Runtime.evaluate', {
    contextId: executionContextId,
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (exceptionDetails) throw new Error(exceptionDetails.text);
  return result.value;
}

const TIMEOUT = 1000;
const NATIVE_GET = `(() => {
  const t0 = performance.now();
  return Promise.race([
    navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: 'rp.localhost', timeout: ${TIMEOUT} } })
      .then((c) => ({ name: 'OK' }), (e) => ({ name: e.name })),
    new Promise((r) => setTimeout(() => r({ name: 'PENDING' }), ${TIMEOUT + 4000})),
  ]).then((r) => ({ ...r, ms: Math.round(performance.now() - t0) }));
})()`;

describe('invariant 7: a handoff attaches no CDP session to the agent page', () => {
  let h: HandoffHarness;
  const cdpCalls: string[] = [];
  let restore: () => void = () => {};

  beforeAll(async () => {
    h = await startHandoffHarness({ rp: { challenge: 'frame' } });
    const ctx = (await h.daemon.sessions.get(h.agent)).context;
    const browser = h.daemon.browser.browser;
    const origCtx = ctx.newCDPSession;
    const origBrowser = browser.newBrowserCDPSession;
    ctx.newCDPSession = function (this: unknown, ...a: Parameters<typeof origCtx>) {
      cdpCalls.push('context.newCDPSession');
      return origCtx.apply(ctx, a);
    };
    browser.newBrowserCDPSession = function (this: unknown) {
      cdpCalls.push('browser.newBrowserCDPSession');
      return origBrowser.apply(browser);
    };
    restore = () => {
      ctx.newCDPSession = origCtx;
      browser.newBrowserCDPSession = origBrowser;
    };
  });
  afterAll(async () => {
    restore();
    await h?.close();
  });

  it('a whole handoff (frames, taps, keys, text) calls newCDPSession zero times', async () => {
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const login = h.mcp.ok('auth_login');
    await h.approveOnPhone();
    expect(await login).toEqual({ status: 'challenge' });
    const handoff = h.mcp.ok('browser_handoff', { timeoutMs: 60_000 });
    await h.openLiveView();
    await h.phonePage.click('.scroll[data-dy="400"]');
    await h.phonePage.click('.scroll[data-dy="-400"]');
    await h.phonePage.click('.key[data-key="Escape"]');
    await h.phonePage.fill('#text', 'hello there');
    await h.phonePage.click('#text-form button');
    await new Promise((r) => setTimeout(r, 1000));
    await h.tapOnPhone('#challenge-solve');
    await h.page().waitForURL('**/account', { timeout: 10_000 });
    await h.phonePage.click('#done');
    expect(await handoff).toEqual({ status: 'done' });
    expect(cdpCalls).toEqual([]);
    const ended = h.auditEvents().find((e) => e.type === 'handoff.ended');
    expect(ended?.payload.inputs).toEqual({ clicks: 1, scrolls: 2, drags: 0, keys: 1, texts: 1 });
  });

  it('afterwards, native WebAuthn from that page still lands in the empty virtual environment', async () => {
    restore();
    const cdp = await h.page().context().newCDPSession(h.page());
    const o = (await evalIsolated(cdp, NATIVE_GET)) as { name: string; ms: number };
    expect(o.name).toBe('NotAllowedError');
    expect(o.ms).toBeGreaterThanOrEqual(TIMEOUT - 50);
  });

  it("the agent's raw MCP bytes hold no image content", async () => {
    const everything = await h.mcp.everything();
    expect(everything).not.toMatch(/"type":"image"|image\/jpeg|data:image|\/9j\/|"mimeType"/);
    expect(everything).not.toContain('hello there');
  });
});
