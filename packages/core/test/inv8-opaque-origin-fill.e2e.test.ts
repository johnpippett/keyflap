import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addPasswordItem } from '../src/passwords.ts';
import { type McpHarness, startMcpHarness } from './mcp-harness.ts';

const PW = 'alice-opaque-Secr3t-pw';

const STEALING_FORM = `<!doctype html><title>Sign in</title>
<form method="post" action="/password/login">
  <label>Username <input id="username" name="username" autocomplete="username"></label>
  <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
  <button id="password-submit" type="submit">Sign in</button>
</form>
<script>window.__stolen = '';
document.getElementById('password').addEventListener('input', (e) => {
  if (e.target.value.length > window.__stolen.length) window.__stolen = e.target.value;
});
</script>`;

const SANDBOX = { 'content-security-policy': 'sandbox allow-scripts allow-forms' };

describe('invariant 8: no fill into an opaque-origin document on the site URL', () => {
  let h: McpHarness;
  beforeAll(async () => {
    h = await startMcpHarness({
      agentName: 'opaque-agent',
      rp: { users: [{ username: 'alice', password: PW }] },
    });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: PW },
    );
  });
  afterAll(async () => h?.close());

  const stolen = () =>
    h.page().evaluate(() => (window as unknown as { __stolen?: string }).__stolen ?? '');
  const released = (since: number) =>
    h
      .auditEvents()
      .slice(since)
      .some((e) => e.type === 'fill.released');

  it('a sandboxed upload with a login form: not eligible, no prompt, nothing typed', async () => {
    const url = `${h.rp.url}uploads/login.html`;
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    await h
      .page()
      .route(url, (r) =>
        r.fulfill({ contentType: 'text/html', headers: SANDBOX, body: STEALING_FORM }),
      );
    await h.mcp.ok('browser_open', { url });
    expect(await h.page().evaluate(() => self.origin)).toBe('null');
    await h.intent('sign in to the test RP with my password');
    const before = h.approver.seen.length;
    const auditBefore = h.auditEvents().length;

    const status = (await h.mcp.ok('auth_status')) as { origin: unknown; credentials: unknown[] };
    expect(status.origin).toBeNull();
    expect(status.credentials).toEqual([]);
    expect(await h.mcp.ok('auth_login')).toMatchObject({ status: 'unsupported' });

    expect(await stolen()).toBe('');
    expect(released(auditBefore)).toBe(false);
    expect(h.approver.seen.length).toBe(before);
  });

  it('the page swaps to a sandboxed copy while the user approves: nothing released', async () => {
    const url = `${h.rp.url}password/login`;
    await h.mcp.ok('browser_open', { url });
    await h.intent('sign in to the test RP with my password');
    const page = h.page();
    await page.route(url, (r) =>
      r.fulfill({ contentType: 'text/html', headers: SANDBOX, body: STEALING_FORM }),
    );
    const before = h.approver.seen.length;
    const auditBefore = h.auditEvents().length;
    h.approver.decide = async () => {
      await page.reload();
      return true;
    };
    try {
      const r = (await h.mcp.ok('auth_login')) as { status: string };
      expect(r.status).not.toBe('success');
    } finally {
      h.approver.decide = () => true;
    }
    expect(h.approver.seen.length).toBe(before + 1);
    expect(page.url()).toBe(url);
    expect(await page.evaluate(() => self.origin)).toBe('null');
    expect(await stolen()).toBe('');
    expect(released(auditBefore)).toBe(false);
    expect(h.rp.logins.some((l) => l.username === 'alice')).toBe(false);
  });
});
