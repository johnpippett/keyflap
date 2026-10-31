import { afterEach, describe, expect, it } from 'vitest';
import { type Harness, signUpAndRegister, startHarness } from './harness.ts';

describe('passkey register + sign-in through the broker', () => {
  let h: Harness;
  afterEach(async () => h?.close());

  it('registers a passkey and signs in with it', async () => {
    h = await startHarness();
    expect(await signUpAndRegister(h, 'dana')).toBe('passkey added');
    expect(h.rp.users.get('dana')?.passkeys).toHaveLength(1);

    await h.page.click('#logout');
    await h.page.goto(`${h.rp.url}login`);
    await h.page.click('#passkey-login');
    await h.page.waitForURL('**/account');
    expect(await h.page.textContent('#whoami')).toBe('Signed in as dana');
    expect(h.rp.logins.at(-1)).toEqual({ username: 'dana', method: 'passkey' });

    expect(h.approver.seen.map((r) => [r.display.action, r.display.verifiedOrigin])).toEqual([
      ['register', h.rp.origin],
      ['sign-in', h.rp.origin],
    ]);
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });

  it('an Ed25519 approver cannot claim user verification', async () => {
    h = await startHarness({ rp: { userVerification: 'required' }, userVerified: true });
    expect(await signUpAndRegister(h, 'erin')).toBe('error: NotAllowedError');
    expect(h.signerLog.some((l) => l.includes('uv_requires_phone_approver'))).toBe(true);
    expect(h.rp.users.get('erin')?.passkeys).toHaveLength(0);
  });

  it('a user denial reaches the page as NotAllowedError and nothing is created', async () => {
    h = await startHarness({ decide: () => false });
    expect(await signUpAndRegister(h, 'fay')).toBe('error: NotAllowedError');
    expect(h.rp.users.get('fay')?.passkeys).toHaveLength(0);
    expect(h.daemon.broker.credentials.passkeysForRp('rp.localhost')).toHaveLength(0);
  });

  it('honors excludeCredentials with InvalidStateError', async () => {
    h = await startHarness();
    expect(await signUpAndRegister(h, 'hal')).toBe('passkey added');
    await h.page.click('#add-passkey');
    await h.page.waitForFunction(
      () => document.querySelector('#status')?.textContent !== 'working',
    );
    expect(await h.page.textContent('#status')).toBe('error: InvalidStateError');
  });
});
