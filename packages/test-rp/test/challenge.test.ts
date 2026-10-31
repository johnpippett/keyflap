import { afterEach, describe, expect, it } from 'vitest';
import { startTestRp, type TestRp, type TestRpOptions } from '../src/server.ts';

function client(base: string) {
  const jar = new Map<string, string>();
  return async (path: string, form?: Record<string, string>) => {
    const res = await fetch(new URL(path, base), {
      method: form ? 'POST' : 'GET',
      redirect: 'manual',
      headers: {
        cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
        ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
      },
      body: form ? new URLSearchParams(form).toString() : null,
    });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(';');
      const i = (kv ?? '').indexOf('=');
      if (i > 0) jar.set((kv as string).slice(0, i), (kv as string).slice(i + 1));
    }
    return res;
  };
}

describe('test RP challenge modes', () => {
  let rp: TestRp | undefined;
  afterEach(async () => {
    await rp?.close();
    rp = undefined;
  });
  const start = async (o: TestRpOptions) => {
    rp = await startTestRp({ users: [{ username: 'bob', password: 'pw-bob' }], ...o });
    return rp;
  };

  const cases: [NonNullable<TestRpOptions['challenge']>, number, Record<string, string>][] = [
    ['aws-waf', 405, { 'x-amzn-waf-action': 'captcha' }],
    ['cloudflare', 403, { 'cf-mitigated': 'challenge' }],
    ['frame', 200, {}],
    ['text-only', 200, {}],
  ];

  for (const [mode, status, headers] of cases) {
    it(`${mode}: the password POST answers ${status} with the challenge, then "I'm human" clears it`, async () => {
      const r = await start({ challenge: mode });
      const c = client(r.url);
      const res = await c('/password/login', { username: 'bob', password: 'pw-bob' });
      expect(res.status).toBe(status);
      for (const [k, v] of Object.entries(headers)) expect(res.headers.get(k)).toBe(v);
      if (mode !== 'aws-waf') expect(res.headers.get('x-amzn-waf-action')).toBeNull();
      if (mode !== 'cloudflare') expect(res.headers.get('cf-mitigated')).toBeNull();
      const body = await res.text();
      expect(body).toContain("Let's confirm you are human");
      expect(body).toContain("I'm human");
      if (mode === 'frame') {
        expect(body).toMatch(
          /<iframe[^>]+src="http:\/\/captcha\.localhost:\d+\/challenge\/widget"/,
        );
      } else {
        expect(body).not.toContain('<iframe');
      }
      expect(await (await c('/api/whoami')).json()).toEqual({ username: 'bob' });
      const blocked = await c('/account');
      expect(blocked.status).toBe(status);
      expect(await blocked.text()).toContain("Let's confirm you are human");

      const solve = await c('/challenge/solve', {});
      expect(solve.status).toBe(303);
      expect(solve.headers.get('location')).toBe('/account');
      expect(solve.headers.getSetCookie().some((v) => v.startsWith('rp_clearance=ok'))).toBe(true);
      const account = await c('/account');
      expect(account.status).toBe(200);
      expect(await account.text()).toContain('Signed in as bob');
    });
  }

  it('the clearance alone is not a session', async () => {
    const r = await start({ challenge: 'aws-waf' });
    const c = client(r.url);
    await c('/challenge/solve', {});
    const res = await c('/account');
    expect(res.status).toBe(303);
    expect(res.headers.get('location')).toBe('/login');
  });

  it('a wrong password is still a plain 401, without a challenge', async () => {
    const r = await start({ challenge: 'cloudflare' });
    const res = await client(r.url)('/password/login', { username: 'bob', password: 'nope' });
    expect(res.status).toBe(401);
    expect(res.headers.get('cf-mitigated')).toBeNull();
  });

  it('login-page (P3b): the sign-in page itself is behind the check until "I\'m human", which returns there', async () => {
    const r = await start({ challenge: 'aws-waf', challengeAt: 'login-page' });
    const c = client(r.url);
    const first = await c('/password/login');
    expect(first.status).toBe(405);
    expect(first.headers.get('x-amzn-waf-action')).toBe('captcha');
    const body = await first.text();
    expect(body).toContain("Let's confirm you are human");
    expect(body).toContain('name="next" value="/password/login"');
    expect(body).not.toContain('name="password"');
    expect((await c('/')).status).toBe(200);
    const solve = await c('/challenge/solve', { next: '/password/login' });
    expect(solve.status).toBe(303);
    expect(solve.headers.get('location')).toBe('/password/login');
    const form = await c('/password/login');
    expect(form.status).toBe(200);
    expect(await form.text()).toContain('name="password"');
    const login = await c('/password/login', { username: 'bob', password: 'pw-bob' });
    expect(login.status).toBe(303);
    expect(login.headers.get('location')).toBe('/account');
    expect((await c('/account')).status).toBe(200);
    const odd = await c('/challenge/solve', { next: 'https://evil.localhost/' });
    expect(odd.headers.get('location')).toBe('/account');
  });
});
