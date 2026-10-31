import type { ApprovalRequest, Approver } from '@aab/approver';
import { ApproverKey } from '@aab/approver';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addPasswordItem } from '../src/passwords.ts';
import { type HandoffHarness, startHandoffHarness } from './handoff-harness.ts';
import { startMcpHarness } from './mcp-harness.ts';

describe('high-risk "Keep me signed in" on the phone card', () => {
  let h: HandoffHarness;

  beforeAll(async () => {
    h = await startHandoffHarness({ daemon: { highRiskDomains: ['rp.localhost'] } });
  });
  afterAll(async () => h?.close());

  const signIn = async (keep: boolean | 'absent') => {
    const ctx = (await h.daemon.sessions.get(h.agent)).context;
    await ctx.clearCookies();
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const login = h.mcp.ok<{ status: string }>('auth_login');
    await h.phonePage.goto(`${h.approver.origin}/`);
    const card = h.phonePage.locator('#requests .card').first();
    await card.waitFor({ timeout: 15_000 });
    const box = card.locator('.keep-box');
    const offered = await card.locator('.keep').isVisible();
    const label = offered ? await card.locator('.keep').textContent() : null;
    const checked = offered ? await box.isChecked() : null;
    if (keep === true) await box.check();
    await card.locator('.approve').click();
    await card.waitFor({ state: 'detached', timeout: 15_000 });
    return { status: (await login).status, offered, label, checked };
  };

  const savedSites = () => {
    const r = h.daemon.persistence?.store.load(h.agent.id);
    return r?.kind === 'ok' ? [...new Set(r.plain.state.cookies.map((c) => c.domain))] : [];
  };

  it('offered on a high-risk card, unticked; left unticked nothing is kept or saved', async () => {
    const r = await signIn(false);
    expect(r).toMatchObject({ status: 'success', offered: true, checked: false });
    expect(r.label).toContain('Keep me signed in on rp.localhost');
    const req = h.recording.requests.at(-1) as ApprovalRequest;
    expect(req.policy.tier).toBe('ask-strong');
    expect(req.display.keepSignedInSite).toBe('rp.localhost');
    const d = h.recording.decisions.at(-1);
    expect(d?.approved && d.approval.statement.keepSignedIn).toBeUndefined();
    expect(h.daemon.optins.has(h.agent.id, 'rp.localhost')).toBe(false);
    await h.daemon.sessions.save(h.agent.id, 'full');
    expect(savedSites()).toEqual([]);
  });

  it('a statement altered to claim it after the phone signed is refused: no sign-in, no opt-in', async () => {
    h.recording.wrap = (d) =>
      d.approved
        ? {
            approved: true,
            approval: {
              ...d.approval,
              statement: { ...d.approval.statement, keepSignedIn: { site: 'rp.localhost' } },
            },
          }
        : d;
    const released = h.auditEvents().filter((e) => e.type === 'fill.released').length;
    try {
      const r = await signIn(false);
      expect(r.status).toBe('denied');
    } finally {
      h.recording.wrap = null;
    }
    expect(h.auditEvents().filter((e) => e.type === 'fill.released')).toHaveLength(released);
    const denied = h
      .auditEvents()
      .filter((e) => e.type === 'denied')
      .at(-1);
    expect(denied?.payload.kind).toBe('password.fill');
    expect(h.daemon.optins.has(h.agent.id, 'rp.localhost')).toBe(false);
    expect(h.auditEvents().some((e) => e.type === 'session.keep_set')).toBe(false);
  });

  it('ticked: the signed statement carries it, the opt-in is recorded via approval, the site is saved', async () => {
    const r = await signIn(true);
    expect(r).toMatchObject({ status: 'success', offered: true, checked: false });
    const d = h.recording.decisions.at(-1);
    expect(d?.approved).toBe(true);
    if (!d?.approved) throw new Error('not approved');
    expect(d.approval.webauthn).toBeDefined();
    expect(d.approval.statement).toMatchObject({
      strong: true,
      keepSignedIn: { site: 'rp.localhost' },
    });
    expect(h.daemon.optins.list(h.agent.id)).toMatchObject([
      { agentId: h.agent.id, site: 'rp.localhost', via: 'approval' },
    ]);
    const set = h.auditEvents().filter((e) => e.type === 'session.keep_set');
    expect(set.map((e) => e.payload)).toEqual([
      { agentId: h.agent.id, site: 'rp.localhost', via: 'approval' },
    ]);
    await expect
      .poll(async () => {
        await h.daemon.sessions.save(h.agent.id, 'full');
        return savedSites();
      })
      .toEqual(['rp.localhost']);
    const again = await signIn(false);
    expect(again).toMatchObject({ status: 'success', offered: false });
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});

describe('an approver claiming "Keep me signed in" where the broker never offered it', () => {
  it('is refused by the broker (unexpected_keep), before the signer; nothing is recorded', async () => {
    const key = ApproverKey.generate('lying-approver');
    const lying: Approver = {
      async request(req: ApprovalRequest) {
        const forged: ApprovalRequest = {
          ...req,
          display: { ...req.display, keepSignedInSite: 'rp.localhost' },
          policy: { tier: 'ask-strong' },
        };
        return {
          approved: true,
          approval: key.approve(forged, { userVerified: false, keepSignedIn: true }),
        };
      },
    };
    const m = await startMcpHarness({
      agentName: 'keep-agent',
      rp: { users: [{ username: 'alice', password: 'alice-keep-pw-1!' }] },
      daemon: { approver: lying, trustedApproverKeys: key.trustEntry() },
    });
    try {
      await addPasswordItem(
        { signer: m.daemon.signer.client, db: m.daemon.db },
        { site: 'rp.localhost', username: 'alice', password: 'alice-keep-pw-1!' },
      );
      await m.intent('sign me in to the test site');
      await m.mcp.ok('browser_open', { url: `${m.rp.url}password/login` });
      expect(await m.mcp.ok('auth_login')).toEqual({ status: 'denied' });
      const denied = m
        .auditEvents()
        .filter((e) => e.type === 'denied')
        .at(-1);
      expect(denied?.payload.reason).toBe('unexpected_keep');
      expect(m.auditEvents().some((e) => e.type === 'fill.released')).toBe(false);
      expect(m.daemon.optins.list()).toEqual([]);
      expect(m.rp.logins).toEqual([]);
    } finally {
      await m.close();
    }
  });
});
