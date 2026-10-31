import type { ApprovalRequest } from '@aab/approver';
import type { AgentBrowserPort } from '@aab/mcp';
import { ToolError } from '@aab/mcp';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { type Harness, startHarness } from './harness.ts';

const portOf = (h: Harness): AgentBrowserPort => {
  const resolved = h.daemon.resolveAgent(h.agent.token);
  if (!resolved) throw new Error('agent did not resolve');
  expect(resolved.agentId).toBe(h.agent.id);
  return resolved.port;
};
const toolCalls = (h: Harness) =>
  h.daemon.broker.audit
    .all()
    .filter((r) => r.event_type === 'tool.call')
    .map((r) => JSON.parse(r.payload_json) as Record<string, unknown>);

const SECRETS_PAGE = `<!doctype html><title>secrets</title><body>
<label>Display name <input id="name" value="visible-name"></label>
<label>Password <input id="pw" type="password" value="hunter2-prefilled"></label>
<input type="PASSWORD" aria-label="Confirm" value='q"uo\\te&lt;d'>
<label>Code <input id="otp" autocomplete="one-time-code" value="246810"></label>
<label>New <input id="np" type="text" autocomplete="new-password" value="np-secret-value"></label>
<label>Short <input type="password" value="Qz"></label>
<label>Later <input id="later" type="password"></label>
<iframe srcdoc="<input type=password value=frame-secret-pw>"></iframe>
<div id="open-host"></div>
<div><template shadowrootmode="closed"><label>Closed <input type="password" value="closed-shadow-pw"></label></template></div>
<button id="dup">Go</button><button>Go</button>
<script>
document.getElementById('later').value = 'set-by-script-later';
document.getElementById('open-host').attachShadow({ mode: 'open' }).innerHTML =
  '<label>Open <input type="password" value="open-shadow-pw"></label>';
</script>
</body>`;

describe('agent browser port', () => {
  let h: Harness;
  let port: AgentBrowserPort;
  let rpPort: string;

  beforeAll(async () => {
    h = await startHarness({ daemon: { actionTimeoutMs: 1500 } });
    port = portOf(h);
    rpPort = new URL(h.rp.origin).port;
    await h.context.route(/\/secrets$/, (route) =>
      route.fulfill({ contentType: 'text/html', body: SECRETS_PAGE }),
    );
    await h.context.route('http://insecure.test/', (route) =>
      route.fulfill({ contentType: 'text/html', body: '<h1>plain http</h1>' }),
    );
  });
  afterAll(async () => h?.close());

  describe('browser_open', () => {
    it('opens http(s) pages and reports url and title', async () => {
      const info = await port.open(`${h.rp.url}login`);
      expect(info).toEqual({ url: `${h.rp.url}login`, title: 'Sign in · Test RP' });
      expect(toolCalls(h).at(-1)).toEqual({
        agentId: h.agent.id,
        tool: 'browser_open',
        ok: true,
        origin: h.rp.origin,
      });
    });

    it('navigation failures are tool errors', async () => {
      await expect(port.open('http://127.0.0.1:1/')).rejects.toThrow(/navigation failed/);
    });
  });

  describe('browser_click / browser_type', () => {
    it('not found and ambiguous targets are tool errors', async () => {
      await port.open(`http://rp.localhost:${rpPort}/secrets`);
      await expect(port.click({ text: 'There is no such thing' })).rejects.toThrow(
        /no matching element/,
      );
      await expect(port.click({ role: 'button', name: 'Go' })).rejects.toThrow(/more than one/);
      await expect(port.type({ role: 'button', name: 'Go', exact: true }, 'x')).rejects.toThrow(
        /more than one/,
      );
    });

    it('refuses to type into password and one-time-code fields', async () => {
      await port.open(`http://rp.localhost:${rpPort}/secrets`);
      for (const target of [
        { label: 'Password' },
        { css: '#pw' },
        { label: 'Confirm' },
        { label: 'Code' },
        { css: '#np' },
        { label: 'Open' },
      ]) {
        await expect(port.type(target, 'agent-typed'), JSON.stringify(target)).rejects.toThrow(
          /auth_login/,
        );
      }
      for (const target of [{ text: 'Password' }, { text: 'Code' }, { css: 'label:has(#pw)' }]) {
        await expect(port.type(target, 'agent-typed'), JSON.stringify(target)).rejects.toThrow(
          /not an editable text field/,
        );
      }
      expect(await h.page.inputValue('#otp')).toBe('246810');
      expect(await h.page.inputValue('#pw')).toBe('hunter2-prefilled');
      await port.type({ label: 'Display name' }, 'new name');
      expect(await h.page.inputValue('#name')).toBe('new name');
    });

    it('the test RP password form: username yes, password no', async () => {
      await port.open(`${h.rp.url}password/login`);
      await port.type({ label: 'Username' }, 'alice');
      await expect(port.type({ label: 'Password' }, 'correct horse')).rejects.toThrow(/auth_login/);
      expect(await h.page.inputValue('#password')).toBe('');
    });
  });

  describe('browser_snapshot', () => {
    it('redacts password and one-time-code values, prefilled or set by script', async () => {
      await port.open(`http://rp.localhost:${rpPort}/secrets`);
      const snap = await port.snapshot();
      expect(snap.url).toBe(`http://rp.localhost:${rpPort}/secrets`);
      expect(snap.title).toBe('secrets');
      expect(snap.snapshot).toContain('visible-name');
      expect(snap.snapshot).toContain('[redacted]');
      for (const secret of [
        'hunter2',
        'prefilled',
        'uo\\te',
        'q\\"uo',
        'te<d',
        '246810',
        'np-secret-value',
        'set-by-script-later',
        'frame-secret-pw',
        'open-shadow-pw',
        'closed-shadow-pw',
        ': Qz',
      ]) {
        expect(snap.snapshot, secret).not.toContain(secret);
      }
    });

    it('the audit records the call, not the content', async () => {
      const calls = toolCalls(h);
      expect(calls.at(-1)).toEqual({
        agentId: h.agent.id,
        tool: 'browser_snapshot',
        ok: true,
        origin: `http://rp.localhost:${rpPort}`,
      });
      const all = JSON.stringify(h.daemon.broker.audit.all());
      for (const s of ['visible-name', 'new name', 'agent-typed', 'alice', '/secrets']) {
        expect(all).not.toContain(s);
      }
      expect(h.daemon.broker.audit.verify()).toBeNull();
    });
  });

  describe('auth_status / auth_login / auth_enroll_passkey', () => {
    it('ineligible origins: http on a non-localhost host', async () => {
      await port.open('http://insecure.test/');
      expect(await port.authStatus()).toEqual({ origin: null, credentials: [], humanCheck: false });
      expect(await port.authLogin()).toEqual({ status: 'unsupported', reason: 'not_eligible' });
      expect(await port.authEnrollPasskey()).toEqual({
        status: 'unsupported',
        reason: 'not_eligible',
      });
    });

    it('no passkey for the origin yet: auth_login is unsupported (no_credential)', async () => {
      await port.open(`${h.rp.url}login`);
      expect(await port.authStatus()).toEqual({
        origin: h.rp.origin,
        credentials: [],
        humanCheck: false,
      });
      expect(await port.authLogin()).toEqual({ status: 'unsupported', reason: 'no_credential' });
    });

    it('timeout: nothing on the page starts a ceremony', async () => {
      await port.open(`${h.rp.url}login`);
      const t0 = Date.now();
      expect(await port.authEnrollPasskey({ timeoutMs: 800 })).toEqual({ status: 'timeout' });
      expect(Date.now() - t0).toBeGreaterThanOrEqual(700);
      await expect(port.authLogin({ timeoutMs: -1 })).rejects.toThrow(ToolError);
      await expect(port.authLogin({ timeoutMs: 'soon' as unknown as number })).rejects.toThrow(
        ToolError,
      );
    });

    it('enroll then sign in, driven only through the port', async () => {
      await port.open(`${h.rp.url}signup`);
      const signedUp = await port.type({ label: 'Username' }, 'pat', { submit: true });
      expect(signedUp.url).toBe(`${h.rp.url}account`);
      await port.click({ role: 'button', name: 'Add a passkey' });
      expect(await port.authEnrollPasskey()).toEqual({ status: 'success' });
      await expect.poll(() => h.rp.users.get('pat')?.passkeys.length).toBe(1);

      await port.click({ role: 'button', name: 'Log out' });
      await port.open(`${h.rp.url}login`);
      expect(await port.authStatus()).toEqual({
        origin: h.rp.origin,
        credentials: [{ type: 'passkey' }],
        humanCheck: false,
      });
      await port.click({ role: 'button', name: 'Sign in with a passkey' });
      expect(await port.authLogin()).toEqual({ status: 'success' });
      await h.page.waitForURL('**/account');
      expect(h.rp.logins.at(-1)).toEqual({ username: 'pat', method: 'passkey' });
      expect(h.approver.seen.map((r) => [r.display.action, r.display.agentName])).toEqual([
        ['register', 'test-agent'],
        ['sign-in', 'test-agent'],
      ]);
      expect(await port.authLogin({ timeoutMs: 300 })).toEqual({ status: 'timeout' });
    });

    it('a ceremony already in flight when auth_login is called counts', async () => {
      let release!: () => void;
      const gate = new Promise<void>((r) => {
        release = r;
      });
      const seen = h.approver.seen.length;
      const original = h.approver.request.bind(h.approver);
      h.approver.request = async (req: ApprovalRequest) => {
        await gate;
        return original(req);
      };
      try {
        await port.open(`${h.rp.url}login`);
        await port.click({ role: 'button', name: 'Sign in with a passkey' });
        const outcome = port.authLogin();
        setTimeout(release, 300);
        expect(await outcome).toEqual({ status: 'success' });
        expect(h.approver.seen.length).toBe(seen + 1);
        await h.page.waitForURL('**/account');
      } finally {
        h.approver.request = original;
      }
    });

    it('other origins never see the credential', async () => {
      await h.context.route(`http://evil.localhost:${rpPort}/`, (route) =>
        route.fulfill({ contentType: 'text/html', body: '<h1>evil</h1>' }),
      );
      expect((await port.open(`http://evil.localhost:${rpPort}/`)).url).toBe(
        `http://evil.localhost:${rpPort}/`,
      );
      expect(await port.authStatus()).toEqual({
        origin: `http://evil.localhost:${rpPort}`,
        credentials: [],
        humanCheck: false,
      });
      expect(await port.authLogin()).toEqual({ status: 'unsupported', reason: 'no_credential' });
    });

    it('every auth tool call is audited with the verified origin', async () => {
      const calls = toolCalls(h).filter((c) => String(c.tool).startsWith('auth_'));
      expect(calls.length).toBeGreaterThanOrEqual(10);
      for (const c of calls) {
        expect(Object.keys(c).sort()).toEqual(
          c.origin ? ['agentId', 'ok', 'origin', 'tool'] : ['agentId', 'ok', 'tool'],
        );
      }
    });
  });
});

describe('auth outcomes under denial', () => {
  let h: Harness;
  afterEach(async () => h?.close());

  it('denied when the approver says no', async () => {
    h = await startHarness({ decide: () => false });
    const port = portOf(h);
    await port.open(`${h.rp.url}signup`);
    await port.type({ label: 'Username' }, 'quinn', { submit: true });
    await port.click({ role: 'button', name: 'Add a passkey' });
    expect(await port.authEnrollPasskey()).toEqual({ status: 'denied' });
    expect(h.rp.users.get('quinn')?.passkeys).toHaveLength(0);
    expect(h.approver.seen).toHaveLength(1);
  });

  it('a revoked agent stops resolving, its port refuses, its context is closed', async () => {
    h = await startHarness();
    const port = portOf(h);
    await port.open(`${h.rp.url}login`);
    h.daemon.registry.revoke(h.agent.id);
    expect(h.daemon.resolveAgent(h.agent.token)).toBeNull();
    await expect(port.snapshot()).rejects.toThrow(/revoked/);
    await expect.poll(() => h.page.isClosed()).toBe(true);
  });
});
