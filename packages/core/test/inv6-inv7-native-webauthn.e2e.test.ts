import { generateKeyPairSync } from 'node:crypto';
import { installNativeWebAuthnBlock, type NativeWebAuthnBlock } from '@aab/shim';
import { startTestRp, type TestRp } from '@aab/test-rp';
import {
  type Browser,
  type BrowserContext,
  type CDPSession,
  chromium,
  type Page,
} from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Harness, signUpAndRegister, startHarness } from './harness.ts';

type Outcome = { name: string; ms: number; type?: string };

let worldSeq = 0;
async function evalIsolated(session: CDPSession, expression: string): Promise<unknown> {
  const { frameTree } = await session.send('Page.getFrameTree');
  const { executionContextId } = await session.send('Page.createIsolatedWorld', {
    frameId: frameTree.frame.id,
    worldName: `keyflap-test-${worldSeq++}`,
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

function nativeCall(kind: 'create' | 'get', timeoutMs: number, rpId?: string): string {
  const rp = rpId ? `rpId: ${JSON.stringify(rpId)},` : '';
  const publicKey =
    kind === 'create'
      ? `{ challenge: crypto.getRandomValues(new Uint8Array(32)),
           rp: { ${rpId ? `id: ${JSON.stringify(rpId)},` : ''} name: 'probe' },
           user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'probe', displayName: 'probe' },
           pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: ${timeoutMs} }`
      : `{ challenge: crypto.getRandomValues(new Uint8Array(32)), ${rp} timeout: ${timeoutMs} }`;
  return `(() => {
    const t0 = performance.now();
    return Promise.race([
      navigator.credentials.${kind}({ publicKey: ${publicKey} })
        .then((c) => ({ name: 'OK', type: c && c.type }), (e) => ({ name: e.name })),
      new Promise((r) => setTimeout(() => r({ name: 'PENDING' }), ${timeoutMs + 4000})),
    ]).then((r) => ({ ...r, ms: Math.round(performance.now() - t0) }));
  })()`;
}

const TIMEOUT = 1000;
const expectNoAuthenticator = (o: Outcome) => {
  expect(o.name).toBe('NotAllowedError');
  expect(o.ms).toBeGreaterThanOrEqual(TIMEOUT - 50);
};

const HOSTILE_PAGE = `<!doctype html><body><h1>hostile</h1><script>
const pkCreate = () => ({
  challenge: crypto.getRandomValues(new Uint8Array(32)),
  rp: { name: 'hostile' },
  user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'mallory', displayName: 'mallory' },
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  timeout: 3000,
});
const pkGet = () => ({ challenge: crypto.getRandomValues(new Uint8Array(32)), timeout: 3000 });
const rapply = Reflect.apply;
const freshIframe = () => {
  const f = document.createElement('iframe');
  document.body.append(f);
  return f.contentWindow;
};
const popups = [];
const freshPopup = () => {
  const w = window.open('about:blank');
  popups.push(w);
  return w;
};
const vectors = {
  'delete own get': () => {
    delete navigator.credentials.get;
    return navigator.credentials.get({ publicKey: pkGet() });
  },
  'delete own create': () => {
    delete navigator.credentials.create;
    return navigator.credentials.create({ publicKey: pkCreate() });
  },
  'delete prototype methods': () => {
    delete CredentialsContainer.prototype.create;
    delete navigator.credentials.create;
    return navigator.credentials.create({ publicKey: pkCreate() });
  },
  'redefine to recover': () => {
    try {
      Object.defineProperty(navigator.credentials, 'get', { value: undefined });
    } catch {}
    try {
      Object.setPrototypeOf(navigator.credentials, Object.prototype);
    } catch {}
    return CredentialsContainer.prototype.get.call(navigator.credentials, { publicKey: pkGet() });
  },
  'prototype get .call': () =>
    CredentialsContainer.prototype.get.call(navigator.credentials, { publicKey: pkGet() }),
  'prototype create .call': () =>
    CredentialsContainer.prototype.create.call(navigator.credentials, { publicKey: pkCreate() }),
  'fresh iframe realm get': () =>
    freshIframe().CredentialsContainer.prototype.get.call(navigator.credentials, { publicKey: pkGet() }),
  'fresh iframe realm create': () =>
    freshIframe().CredentialsContainer.prototype.create.call(navigator.credentials, {
      publicKey: pkCreate(),
    }),
  'fresh iframe realm, after deleting there': () => {
    const w = freshIframe();
    delete w.navigator.credentials.create;
    delete w.CredentialsContainer.prototype.create;
    const create = w.navigator.credentials.create || w.CredentialsContainer.prototype.create;
    return create.call(navigator.credentials, { publicKey: pkCreate() });
  },
  'popup realm get': () =>
    freshPopup().CredentialsContainer.prototype.get.call(navigator.credentials, { publicKey: pkGet() }),
  'popup realm create': () =>
    freshPopup().CredentialsContainer.prototype.create.call(navigator.credentials, {
      publicKey: pkCreate(),
    }),
  'popup calling on itself': () => freshPopup().navigator.credentials.get({ publicKey: pkGet() }),
  'publicKey hidden by a getter, revealed on the second read': () => {
    let reads = 0;
    const options = {};
    Object.defineProperty(options, 'publicKey', { get: () => (reads++ ? pkCreate() : undefined) });
    return navigator.credentials.create(options);
  },
  'publicKey hidden by a Proxy': () => {
    let reads = 0;
    const options = new Proxy({}, {
      get: (_, k) => (k === 'publicKey' ? (reads++ ? pkGet() : undefined) : undefined),
      has: (_, k) => k === 'publicKey' && reads > 0,
    });
    return navigator.credentials.get(options);
  },
  'publicKey getter on Object.prototype': () => {
    let reads = 0;
    Object.defineProperty(Object.prototype, 'publicKey', {
      configurable: true,
      get: () => (reads++ ? pkCreate() : undefined),
    });
    try {
      return navigator.credentials.create({});
    } finally {
      delete Object.prototype.publicKey;
    }
  },
  'natives leaked through poisoned call/apply/bind': () => {
    const fp = Function.prototype;
    const saved = { call: fp.call, apply: fp.apply, bind: fp.bind, rapply: Reflect.apply };
    const leaked = new Set();
    fp.call = function (t, ...a) { leaked.add(this); return rapply(this, t, a); };
    fp.apply = function (t, a) { leaked.add(this); return rapply(this, t, a || []); };
    fp.bind = function (...a) { leaked.add(this); return rapply(saved.bind, this, a); };
    Reflect.apply = (f, t, a) => { leaked.add(f); return rapply(f, t, a); };
    try {
      navigator.credentials.get({ password: true }).catch(() => {});
      navigator.credentials.create({}).catch(() => {});
    } finally {
      Object.assign(fp, { call: saved.call, apply: saved.apply, bind: saved.bind });
      Reflect.apply = saved.rapply;
    }
    const ours = [CredentialsContainer.prototype.get, CredentialsContainer.prototype.create];
    const tries = [...leaked]
      .filter((f) => typeof f === 'function' && !ours.includes(f))
      .map((f) => settle(() => rapply(f, navigator.credentials, [{ publicKey: pkCreate() }])));
    return Promise.all(tries).then((rs) => {
      if (rs.some((r) => r.ok)) return { type: 'public-key' };
      throw new DOMException('nothing leaked', 'NotAllowedError');
    });
  },
};
const settle = (thunk) => {
  let p;
  try {
    p = Promise.resolve(thunk());
  } catch (e) {
    return Promise.resolve({ ok: false, name: 'threw ' + e.name });
  }
  return Promise.race([
    p.then((c) => ({ ok: !!c, name: c ? 'OK' : 'null' }), (e) => ({ ok: false, name: e && e.name })),
    new Promise((r) => setTimeout(() => r({ ok: false, name: 'PENDING' }), 8000)),
  ]);
};
window.vectorNames = Object.keys(vectors);
window.attempt = async (name) => {
  const r = await settle(vectors[name]);
  for (const w of popups.splice(0)) w.close();
  return r;
};
</script></body>`;

describe('invariants 6 + 7: pages cannot reach native WebAuthn around the broker', () => {
  describe('layer B: in-page bypass attempts, with an authenticator reachable natively', () => {
    let h: Harness;
    let cdp: CDPSession;
    let authenticatorId: string;
    const requests = () =>
      h.daemon.broker.audit.all().filter((r) => r.event_type === 'request').length;
    const credentials = async () =>
      (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials
        .map((c) => ({ id: c.credentialId, rpId: c.rpId, signCount: c.signCount }))
        .sort((a, b) => a.id.localeCompare(b.id));
    let baseline: Awaited<ReturnType<typeof credentials>>;

    beforeAll(async () => {
      h = await startHarness({ decide: () => false });
      const url = `http://rp.localhost:${new URL(h.rp.origin).port}/hostile`;
      await h.page.route(url, (route) =>
        route.fulfill({ contentType: 'text/html', body: HOSTILE_PAGE }),
      );
      await h.page.goto(url);

      cdp = await h.context.newCDPSession(h.page);
      await cdp.send('WebAuthn.enable');
      ({ authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'usb',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      }));
      const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      await cdp.send('WebAuthn.addCredential', {
        authenticatorId,
        credential: {
          credentialId: Buffer.from('host-authenticator-credential').toString('base64'),
          isResidentCredential: true,
          rpId: 'rp.localhost',
          privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
          userHandle: Buffer.from('victim').toString('base64'),
          signCount: 0,
        },
      });

      const get = (await evalIsolated(cdp, nativeCall('get', 3000, 'rp.localhost'))) as Outcome;
      const create = (await evalIsolated(cdp, nativeCall('create', 3000))) as Outcome;
      expect([get.name, create.name]).toEqual(['OK', 'OK']);
      baseline = await credentials();
      expect(baseline).toHaveLength(2);
    });
    afterAll(async () => h?.close());

    it('the override is locked in place on the prototype and the instance', async () => {
      const desc = await h.page.evaluate(() =>
        [CredentialsContainer.prototype, navigator.credentials].flatMap((o) =>
          ['get', 'create'].map((k) => {
            const d = Object.getOwnPropertyDescriptor(o, k);
            return { configurable: d?.configurable, writable: d?.writable };
          }),
        ),
      );
      expect(desc).toEqual(Array(4).fill({ configurable: false, writable: false }));
    });

    const brokered = [
      'delete own get',
      'delete own create',
      'delete prototype methods',
      'redefine to recover',
      'prototype get .call',
      'prototype create .call',
      'fresh iframe realm get',
      'fresh iframe realm create',
      'fresh iframe realm, after deleting there',
      'popup realm get',
      'popup realm create',
      'popup calling on itself',
    ];

    it('every vector goes through the broker or fails, and none reaches the authenticator', async () => {
      const names = await h.page.evaluate(
        () => (window as unknown as { vectorNames: string[] }).vectorNames,
      );
      expect(names.length).toBeGreaterThanOrEqual(16);
      const results: Record<string, { ok: boolean; name: string; viaBroker: boolean }> = {};
      for (const name of names) {
        await h.page.reload();
        const before = requests();
        const r = await h.page.evaluate(
          (n) =>
            (
              window as unknown as {
                attempt: (n: string) => Promise<{ ok: boolean; name: string }>;
              }
            ).attempt(n),
          name,
        );
        results[name] = { ...r, viaBroker: requests() > before };
      }
      for (const [name, r] of Object.entries(results)) {
        expect({ name, ok: r.ok }).toEqual({ name, ok: false });
        if (brokered.includes(name))
          expect({ name, viaBroker: r.viaBroker }).toEqual({ name, viaBroker: true });
      }
      expect(await credentials()).toEqual(baseline);
    });

    it('requests without publicKey still reach Chromium natively, not the broker', async () => {
      await h.page.reload();
      const before = requests();
      const expr = `navigator.credentials.get({ password: true, mediation: 'silent' })
        .then((c) => 'resolved ' + c, (e) => 'rejected ' + e.name)`;
      const viaPage = await h.page.evaluate(expr);
      const native = await evalIsolated(cdp, expr);
      expect(viaPage).toBe(native);
      expect(requests()).toBe(before);
    });
  });

  describe('layer A: native WebAuthn reaches no authenticator in any tab or frame', () => {
    let h: Harness;
    let context: BrowserContext;
    let port: string;
    const sessions: CDPSession[] = [];
    const session = async (target: Page | import('playwright').Frame) => {
      const s = await context.newCDPSession(target);
      sessions.push(s);
      return s;
    };
    const nativeIn = async (
      target: Page | import('playwright').Frame,
      kind: 'create' | 'get',
      rpId?: string,
    ) => (await evalIsolated(await session(target), nativeCall(kind, TIMEOUT, rpId))) as Outcome;

    beforeAll(async () => {
      h = await startHarness({ launchArgs: ['--site-per-process'] });
      context = h.context;
      port = new URL(h.rp.origin).port;
      await context.route(/^http:\/\/(rp|evil)\.localhost:\d+\/(x|frames)/, (route) => {
        const body = route.request().url().includes('/frames')
          ? `<iframe src="http://evil.localhost:${port}/x" allow="publickey-credentials-get *; publickey-credentials-create *"></iframe>`
          : '<h1>x</h1>';
        return route.fulfill({ contentType: 'text/html', body });
      });
    });
    afterAll(async () => h?.close());

    it('a tab: create and get, before and after a cross-site navigation', async () => {
      await h.page.goto(`http://rp.localhost:${port}/x`);
      expectNoAuthenticator(await nativeIn(h.page, 'create'));
      expectNoAuthenticator(await nativeIn(h.page, 'get', 'rp.localhost'));
      await h.page.goto(`http://evil.localhost:${port}/x`);
      expectNoAuthenticator(await nativeIn(h.page, 'get', 'evil.localhost'));
    });

    it('an out-of-process cross-site iframe', async () => {
      const page = await context.newPage();
      await page.goto(`http://rp.localhost:${port}/frames`);
      const frame = page.frames().find((f) => f.url().startsWith('http://evil.localhost'));
      if (!frame) throw new Error('iframe missing');
      await frame.waitForLoadState();
      expectNoAuthenticator(await nativeIn(frame, 'get', 'evil.localhost'));
      await page.close();
    });

    it('popups: about:blank, navigated, and noopener to another site', async () => {
      const page = await context.newPage();
      await page.goto(`http://rp.localhost:${port}/x`);
      const opened = async (open: (p: Page) => Promise<unknown>) => {
        const [popup] = await Promise.all([context.waitForEvent('page'), open(page)]);
        await popup.waitForLoadState();
        return popup;
      };
      const blank = await opened((p) => p.evaluate(() => void window.open('about:blank')));
      expectNoAuthenticator(await nativeIn(blank, 'get'));
      const navigated = await opened((p) =>
        p.evaluate((u) => void window.open(u), `http://rp.localhost:${port}/x?popup`),
      );
      expectNoAuthenticator(await nativeIn(navigated, 'create'));
      const noopener = await opened((p) =>
        p.evaluate((u) => {
          const a = document.createElement('a');
          a.href = u;
          a.target = '_blank';
          a.rel = 'noopener';
          document.body.append(a);
          a.click();
        }, `http://evil.localhost:${port}/x?noopener`),
      );
      expectNoAuthenticator(await nativeIn(noopener, 'get', 'evil.localhost'));
      await page.close();
    });

    it("another agent's context, created later, is covered too", async () => {
      const other = h.daemon.registry.add('second-agent');
      const ctx = (await h.daemon.sessions.get(other)).context;
      expect(ctx).not.toBe(context);
      const page = await ctx.newPage();
      await page.route(/\/x/, (route) =>
        route.fulfill({ contentType: 'text/html', body: '<h1>x</h1>' }),
      );
      await page.goto(`http://evil.localhost:${port}/x`);
      const s = await ctx.newCDPSession(page);
      sessions.push(s);
      expectNoAuthenticator(
        (await evalIsolated(s, nativeCall('get', TIMEOUT, 'evil.localhost'))) as Outcome,
      );
      await page.close();
    });

    it('still holds after another CDP session on the tab detaches', async () => {
      const page = await context.newPage();
      await page.goto(`http://rp.localhost:${port}/x`);
      const transient = await context.newCDPSession(page);
      await transient.send('Runtime.evaluate', { expression: '1' });
      await transient.detach();
      await page.waitForTimeout(100);
      expectNoAuthenticator(await nativeIn(page, 'create'));
      await page.close();
    });
  });

  describe('layer A on its own, before any page script runs (no page override)', () => {
    let rp: TestRp;
    let browser: Browser;
    let block: NativeWebAuthnBlock;
    let context: BrowserContext;
    let base: string;
    const PROBE = `<script>
      window.result = ${nativeCall('create', TIMEOUT)};
    </script>`;

    beforeAll(async () => {
      rp = await startTestRp({ host: 'rp.localhost' });
      base = `http://rp.localhost:${new URL(rp.origin).port}`;
      browser = await chromium.launch();
      block = installNativeWebAuthnBlock(browser);
      context = await browser.newContext();
      await block.cover(context);
      await context.route(/\/probe/, (route) =>
        route.fulfill({ contentType: 'text/html', body: PROBE }),
      );
    });
    afterAll(async () => {
      await browser?.close();
      await rp?.close();
    });

    const resultOf = (p: Page) =>
      p.evaluate(() => (window as unknown as { result: Promise<Outcome> }).result);

    it('the first script of a new tab already runs against the empty environment', async () => {
      const page = await context.newPage();
      await page.goto(`${base}/probe`);
      expectNoAuthenticator(await resultOf(page));
    });

    it('so do popups, whatever the opener does synchronously', async () => {
      const opener = await context.newPage();
      await opener.goto(`${base}/probe?opener`);
      const sync = (await opener.evaluate(`(() => {
        const w = window.open('about:blank');
        return ${nativeCall('create', TIMEOUT).replace('navigator.credentials', 'w.navigator.credentials')};
      })()`)) as Outcome;
      expectNoAuthenticator(sync);
      for (const url of [`${base}/probe?popup`, `${base.replace('rp.', 'evil.')}/probe?other`]) {
        const [popup] = await Promise.all([
          context.waitForEvent('page'),
          opener.evaluate((u) => void window.open(u), url),
        ]);
        const r = await resultOf(popup);
        expect(
          r.name === 'NotSupportedError' || (r.name === 'NotAllowedError' && r.ms >= TIMEOUT - 50),
        ).toBe(true);
      }
    });

    it('one browser-level hook covers every context, including ones created later', async () => {
      const second = await browser.newContext();
      await block.cover(second);
      await second.route(/\/probe/, (route) =>
        route.fulfill({ contentType: 'text/html', body: PROBE }),
      );
      const page = await second.newPage();
      await page.goto(`${base}/probe?second-context`);
      expectNoAuthenticator(await resultOf(page));
      await second.close();
    });

    it('refuses to install twice on one browser, or to cover a context twice', async () => {
      expect(() => installNativeWebAuthnBlock(browser)).toThrow(/already installed/);
      await expect(block.cover(context)).rejects.toThrow(/already covered/);
    });
  });

  describe('the broker path is unchanged', () => {
    let h: Harness;
    beforeAll(async () => {
      h = await startHarness();
    });
    afterAll(async () => h?.close());

    it('returns real PublicKeyCredential objects and the same capability answers', async () => {
      expect(await signUpAndRegister(h, 'nina')).toBe('passkey added');
      const r = await h.page.evaluate(async () => {
        const c = (await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rpId: 'rp.localhost',
          },
        })) as PublicKeyCredential;
        const PKC = PublicKeyCredential as unknown as Record<string, unknown>;
        return {
          credential: c instanceof PublicKeyCredential,
          response: c.response instanceof AuthenticatorAssertionResponse,
          uvpaa: await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
          conditional: await PublicKeyCredential.isConditionalMediationAvailable(),
          capabilities: await (
            PKC.getClientCapabilities as () => Promise<Record<string, boolean>>
          )(),
          signal: typeof PKC.signalUnknownCredential,
        };
      });
      expect(r).toEqual({
        credential: true,
        response: true,
        uvpaa: true,
        conditional: false,
        capabilities: expect.objectContaining({
          passkeyPlatformAuthenticator: true,
          userVerifyingPlatformAuthenticator: true,
          conditionalGet: false,
          signalUnknownCredential: false,
        }),
        signal: 'undefined',
      });
      expect(h.approver.seen.map((a) => a.display.action)).toEqual(['register', 'sign-in']);
    });

    it('insecure contexts still get no WebAuthn at all', async () => {
      await h.page.route('http://insecure.test/', (route) =>
        route.fulfill({ contentType: 'text/html', body: '<h1>plain http</h1>' }),
      );
      await h.page.goto('http://insecure.test/');
      expect(
        await h.page.evaluate(() => ({
          secure: window.isSecureContext,
          credentials: typeof navigator.credentials,
          pkc: typeof (window as unknown as Record<string, unknown>).PublicKeyCredential,
        })),
      ).toEqual({ secure: false, credentials: 'undefined', pkc: 'undefined' });
    });
  });
});
