import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addPasswordItem } from '../src/passwords.ts';
import { ALICE_PW, type HandoffHarness, startHandoffHarness } from './handoff-harness.ts';

const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

describe('invariant 6: phone approval of a password + TOTP fill with a counting authenticator', () => {
  let h: HandoffHarness;

  const approverCounter = async () => {
    const { approvers } = await h.daemon.signer.client.listApprovers();
    expect(approvers).toHaveLength(1);
    return approvers[0]?.signCount ?? 0;
  };

  const signIn = async () => {
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const asked = h.recording.requests.length;
    const login = h.mcp.ok<{ status: string }>('auth_login');
    const card = await h.approveOnPhone();
    expect(card).toContain('sign me in with my password and code');
    expect(await login).toEqual({ status: 'success' });
    expect(h.recording.requests.length - asked).toBe(1);
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password+totp' });
  };

  beforeAll(async () => {
    h = await startHandoffHarness({
      rp: { users: [{ username: 'alice', password: ALICE_PW, totpSecret: SEED }] },
      password: false,
    });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: ALICE_PW, totp: { secret: SEED } },
    );
  });
  afterAll(async () => h?.close());

  it('releases the password and then the TOTP code under the one assertion', async () => {
    await h.intent('sign me in with my password and code');
    await signIn();

    const released = h.auditEvents().filter((e) => e.type === 'fill.released');
    expect(released.map((e) => e.payload.field)).toEqual(['password', 'totp']);
    expect(released[0]?.payload.requestId).toBe(released[1]?.payload.requestId);
    expect(h.auditEvents().filter((e) => e.type === 'denied')).toEqual([]);
    const first = await approverCounter();
    expect(first).toBeGreaterThan(0);

    await (await h.daemon.sessions.get(h.agent)).context.clearCookies();
    await signIn();
    expect(await approverCounter()).toBeGreaterThan(first);
    const all = h.auditEvents().filter((e) => e.type === 'fill.released');
    expect(all.map((e) => e.payload.field)).toEqual(['password', 'totp', 'password', 'totp']);
    expect(all[2]?.payload.requestId).not.toBe(all[0]?.payload.requestId);
    expect(all[2]?.payload.requestId).toBe(all[3]?.payload.requestId);
    expect(h.auditEvents().filter((e) => e.type === 'denied')).toEqual([]);
    expect(h.daemon.broker.audit.verify()).toBeNull();

    expect(await h.mcp.everything()).not.toContain(ALICE_PW);
  });
});
