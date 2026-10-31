import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addPasswordItem } from '../src/passwords.ts';
import { type McpHarness, startMcpHarness } from './mcp-harness.ts';

const ALICE_PW = 'alice-Secr3t/pass word+%&?';

const page = (body: string, action = '/password/login') =>
  `<!doctype html><title>Page</title><body><form method="post" action="${action}">${body}<button>Go</button></form></body>`;
const username = '<label>Username <input name="username" autocomplete="username"></label>';
const newPassword =
  '<label>New <input name="password" type="password" autocomplete="new-password"></label>';
const currentPassword =
  '<label>Password <input name="password" type="password" autocomplete="current-password"></label>';

describe('invariant 8: the login step is never a new-password field', () => {
  let h: McpHarness;

  beforeAll(async () => {
    h = await startMcpHarness({
      agentName: 'inv8-new-password',
      rp: { users: [{ username: 'alice', password: ALICE_PW }] },
    });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: ALICE_PW },
    );
    const ctx = await h.context();
    const routes: [RegExp, string][] = [
      [/\/new-password-only$/, page(newPassword)],
      [/\/new-password-with-username$/, page(username + newPassword, '/inert')],
      [
        /\/new-password-spaced-tokens$/,
        page(newPassword.replace('new-password', 'off NEW-PASSWORD')),
      ],
      [/\/current-password$/, page(username + currentPassword)],
    ];
    routes.push([/\/inert$/, '<!doctype html><title>Inert</title><body>done</body>']);
    for (const [re, body] of routes) {
      await ctx.route(re, (r) => r.fulfill({ contentType: 'text/html', body }));
    }
    await h.intent('sign me in to the test site');
  });
  afterAll(async () => h?.close());

  it.each(['new-password-only', 'new-password-spaced-tokens'])(
    '%s: auth_login is not_eligible, no prompt, nothing released',
    async (path) => {
      const before = h.approver.seen.length;
      const auditBefore = h.auditEvents().length;
      const loginsBefore = h.rp.logins.length;
      await h.mcp.ok('browser_open', { url: `${h.rp.url}${path}` });
      expect(await h.mcp.ok('auth_login')).toEqual({
        status: 'unsupported',
        reason: 'not_eligible',
      });
      expect(h.approver.seen.length).toBe(before);
      expect(
        h
          .auditEvents()
          .slice(auditBefore)
          .filter((e) => e.type === 'fill.released'),
      ).toEqual([]);
      expect(h.rp.logins.length).toBe(loginsBefore);
    },
  );

  it('a username beside a new-password field: the password is never released', async () => {
    const auditBefore = h.auditEvents().length;
    const loginsBefore = h.rp.logins.length;
    await h.mcp.ok('browser_open', { url: `${h.rp.url}new-password-with-username` });
    await h.mcp.ok('auth_login');
    const events = h.auditEvents().slice(auditBefore);
    expect(events.filter((e) => e.type === 'fill.released')).toEqual([]);
    expect(events.filter((e) => e.type === 'fill.completed').map((e) => e.payload.fields)).toEqual([
      [],
    ]);
    expect(h.rp.logins.length).toBe(loginsBefore);
  });

  it('control: the same form with a current-password field is filled', async () => {
    const before = h.approver.seen.length;
    await h.mcp.ok('browser_open', { url: `${h.rp.url}current-password` });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    expect(h.approver.seen.length).toBe(before + 1);
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password' });
  });
});
