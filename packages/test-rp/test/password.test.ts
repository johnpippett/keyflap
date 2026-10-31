import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startTestRp, type TestRp } from '../src/server.ts';
import { totp } from '../src/totp.ts';

const SECRET = 'JBSWY3DPEHPK3PXP';

function client(base: string) {
  let cookie = '';
  return async (path: string, form?: Record<string, string>) => {
    const res = await fetch(new URL(path, base), {
      method: form ? 'POST' : 'GET',
      redirect: 'manual',
      headers: {
        cookie,
        ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
      },
      body: form ? new URLSearchParams(form).toString() : null,
    });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0] ?? '';
    return res;
  };
}

describe('test RP password + TOTP', () => {
  let rp: TestRp;
  beforeAll(async () => {
    rp = await startTestRp({
      users: [
        { username: 'alice', password: 'pw-alice', totpSecret: SECRET },
        { username: 'bob', password: 'pw-bob' },
      ],
    });
  });
  afterAll(() => rp.close());

  it('requires a valid TOTP code as the second step', async () => {
    const c = client(rp.url);
    const step1 = await c('/password/login', { username: 'alice', password: 'pw-alice' });
    expect(step1.headers.get('location')).toBe('/password/totp');
    expect(await (await c('/api/whoami')).json()).toEqual({ username: null });

    expect(
      (await c('/password/totp', { code: '000000' === totp(SECRET) ? '111111' : '000000' })).status,
    ).toBe(401);
    const ok = await c('/password/totp', { code: totp(SECRET) });
    expect(ok.headers.get('location')).toBe('/account');
    expect(await (await c('/api/whoami')).json()).toEqual({ username: 'alice' });
    expect(rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password+totp' });
  });

  it('identifier-first: username, then password, then TOTP', async () => {
    const c = client(rp.url);
    const id = await c('/password/login-id', { username: 'alice' });
    expect(id.headers.get('location')).toBe('/password/login-pw');
    expect(await (await c('/password/login-pw')).text()).toContain('Welcome, alice');
    expect((await c('/password/login-pw', { password: 'nope' })).status).toBe(401);
    const pw = await c('/password/login-pw', { password: 'pw-alice' });
    expect(pw.headers.get('location')).toBe('/password/totp');
    const ok = await c('/password/totp', { code: totp(SECRET) });
    expect(ok.headers.get('location')).toBe('/account');
    expect(await (await c('/api/whoami')).json()).toEqual({ username: 'alice' });
  });
});
