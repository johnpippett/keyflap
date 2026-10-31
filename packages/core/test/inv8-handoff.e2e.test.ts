import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { secretForms } from '../src/scrub.ts';
import { type HandoffHarness, routeChallengePage, startHandoffHarness } from './handoff-harness.ts';

const OWNER_TEXT = 'owner-typed-ZQX42';
const PW_ATTEMPT = 'pw-attempt-ZQX77';

const PAGE = `
<h1>One more step</h1>
<label>Note <input id="note" autocomplete="off"></label>
<label>Password <input id="pw" type="password" autocomplete="current-password"></label>
<p id="echo"></p>
<script>
document.getElementById('note').addEventListener('input', (e) => {
  const v = e.target.value;
  document.getElementById('echo').textContent = 'You typed: ' + v;
  localStorage.setItem('note', v);
  document.cookie = 'note=' + encodeURIComponent(v) + '; path=/; max-age=3600';
  document.cookie = 'keep=1; path=/; max-age=3600';
});
</script>`;

describe('invariant 8: owner text in the live view is scrubbed and never saved', () => {
  let h: HandoffHarness;

  beforeAll(async () => {
    h = await startHandoffHarness({ password: false });
  });
  afterAll(async () => h?.close());

  it('text into a password field is refused; text into a text field is redacted for the agent', async () => {
    const url = await routeChallengePage(h, '/inv8-note', PAGE);
    await h.intent('get past the check on the test site');
    await h.mcp.ok('browser_open', { url });
    const handoff = h.mcp.ok('browser_handoff', { timeoutMs: 60_000 });
    await h.openLiveView();

    await h.tapOnPhone('#pw');
    await h.phonePage.fill('#text', PW_ATTEMPT);
    await h.phonePage.click('#text-form button');
    await h.phonePage.locator('#input-error').waitFor({ state: 'visible' });
    expect(await h.phonePage.textContent('#input-error')).toBe(
      "Use the broker's sign-in for passwords",
    );
    expect(await h.page().locator('#pw').inputValue()).toBe('');
    const refused = h.auditEvents().filter((e) => e.type === 'handoff.input_refused');
    expect(refused.map((e) => e.payload.reason)).toEqual(['sensitive_field']);

    await h.tapOnPhone('#note');
    await h.phonePage.fill('#text', OWNER_TEXT);
    await h.phonePage.click('#text-form button');
    await expect.poll(() => h.page().locator('#note').inputValue()).toBe(OWNER_TEXT);
    await h.phonePage.click('#done');
    expect(await handoff).toEqual({ status: 'done' });

    const snap = await h.mcp.ok<{ snapshot: string }>('browser_snapshot');
    expect(snap.snapshot).toContain('You typed: [redacted]');
    for (const f of secretForms(OWNER_TEXT)) expect(snap.snapshot).not.toContain(f);
    const everything = await h.mcp.everything();
    expect(everything).not.toContain(OWNER_TEXT);
    expect(everything).not.toContain(PW_ATTEMPT);
    const audit = JSON.stringify(h.daemon.broker.audit.all());
    expect(audit).not.toContain(OWNER_TEXT);
    expect(audit).not.toContain(PW_ATTEMPT);
  });

  it('the saved state (written at Done) holds no copy of the owner text', async () => {
    const ctx = (await h.daemon.sessions.get(h.agent)).context;
    expect((await ctx.cookies()).map((c) => c.name)).toEqual(
      expect.arrayContaining(['note', 'keep']),
    );
    await expect
      .poll(() => {
        const r = h.daemon.persistence?.store.load(h.agent.id);
        return r?.kind === 'ok' ? r.plain.state.cookies.map((c) => c.name) : null;
      })
      .toEqual(['keep']);
    const r = h.daemon.persistence?.store.load(h.agent.id);
    const plain = JSON.stringify(r);
    for (const f of secretForms(OWNER_TEXT)) expect(plain).not.toContain(f);
    expect(plain).not.toContain('note=');
    const filtered = h.auditEvents().filter((e) => e.type === 'browser_state.filtered');
    expect(filtered.length).toBeGreaterThan(0);
    expect(JSON.stringify(filtered)).not.toContain(OWNER_TEXT);
  });
});
