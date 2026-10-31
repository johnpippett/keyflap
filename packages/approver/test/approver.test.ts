import { verify } from 'node:crypto';
import { PassThrough } from 'node:stream';
import { approvalSigningBytes, ed25519PublicKey } from '@aab/signer/approval';
import { describe, expect, it } from 'vitest';
import {
  type ApprovalRequest,
  ApproverKey,
  buildStatement,
  formatDuration,
  renderPrompt,
  requestProblem,
  ScriptedApprover,
  TerminalApprover,
} from '../src/index.ts';

const req = (over: Partial<ApprovalRequest['display']> = {}): ApprovalRequest => ({
  display: {
    intentText: 'log me into the test site',
    intentAt: Date.UTC(2026, 0, 1),
    verifiedOrigin: 'https://example.com',
    agentName: 'dev-agent',
    credentialType: 'passkey',
    action: 'sign-in',
    ...over,
  },
  policy: { tier: 'ask' },
  binding: {
    requestId: 'r1',
    kind: 'webauthn.get',
    rpId: 'example.com',
    credentialId: 'c1',
    intentHash: 'aA',
    clientDataHash: 'bB',
  },
});

describe('approval prompt', () => {
  it('shows the verbatim intent, verified origin, agent, and credential type', () => {
    const out = renderPrompt(req());
    expect(out).toContain('"log me into the test site"');
    expect(out).toContain('https://example.com');
    expect(out).toContain('dev-agent');
    expect(out).toContain('passkey (sign-in)');
    expect(out).not.toContain('example.com\n│ Credential: c1');
  });

  it('labels password fills', () => {
    expect(renderPrompt(req({ credentialType: 'password' }))).toContain('password (sign-in)');
    expect(renderPrompt(req({ credentialType: 'password+totp' }))).toContain(
      'password + one-time code (sign-in)',
    );
    expect(renderPrompt(req({ credentialType: 'totp' }))).toContain('one-time code (sign-in)');
  });

  it('neutralizes bidi marks as well as overrides and isolates', () => {
    const out = renderPrompt(req({ intentText: 'a\u200eb\u200fc\u061cd\u202ee\u2067f' }));
    expect(out).not.toMatch(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/);
    expect(out).toContain('a�b�c�d�e�f');
  });
});

describe('terminal approver', () => {
  const run = async (answer: string | null, timeoutMs = 2000) => {
    const key = ApproverKey.generate('t');
    const input = new PassThrough();
    const output = new PassThrough();
    const approver = new TerminalApprover({ key, input, output, timeoutMs });
    const p = approver.request(req());
    if (answer !== null) input.write(`${answer}\n`);
    return { decision: await p, key };
  };

  it('"y" produces an approval signed by the approver key, without user verification', async () => {
    const { decision, key } = await run('y');
    expect(decision.approved).toBe(true);
    if (!decision.approved) return;
    const s = decision.approval.statement;
    expect(s).toMatchObject({
      requestId: 'r1',
      verifiedOrigin: 'https://example.com',
      userVerified: false,
    });
    expect(
      verify(
        null,
        approvalSigningBytes(s),
        ed25519PublicKey(key.publicKey),
        Buffer.from(decision.approval.signature as string, 'base64url'),
      ),
    ).toBe(true);
  });

  it.each(['n', '', 'yes please', 'Y E S'])('anything but y/yes denies (%j)', async (a) => {
    expect((await run(a)).decision).toEqual({ approved: false, reason: 'user_denied' });
  });

  it('no answer times out to a denial', async () => {
    expect((await run(null, 50)).decision).toEqual({ approved: false, reason: 'timeout' });
  });
});

describe('M5: allow-for and ask-strong in the prompt and the signed statement', () => {
  const allowFor = (ms = 30 * 60_000): ApprovalRequest => {
    const r = req({ allowForMs: ms });
    return { ...r, binding: { ...r.binding, grant: { agentId: 'agent-1', durationMs: ms } } };
  };

  it('the terminal prompt shows the broker-authored allow-for line only when there is one', () => {
    expect(renderPrompt(req())).not.toContain('Allow-for');
    expect(renderPrompt(allowFor())).toContain(
      '│ Allow-for:  approving also lets this agent sign in here again without asking, for 30 minutes',
    );
    expect(renderPrompt(allowFor(90 * 60_000))).toContain('for 1 hour 30 minutes');
    expect(formatDuration(2 * 60 * 60_000)).toBe('2 hours');
    expect(formatDuration(45_000)).toBe('45 seconds');
    expect(formatDuration(60_000)).toBe('1 minute');
  });

  it('the statement carries the grant (until = issuedAt + window) and strong for ask-strong', () => {
    const s = buildStatement(allowFor(), { userVerified: false, now: 1_000 });
    expect(s.grant).toEqual({ agentId: 'agent-1', until: 1_000 + 30 * 60_000 });
    expect(s.strong).toBeUndefined();
    const strong = buildStatement(
      { ...req(), policy: { tier: 'ask-strong' } },
      { userVerified: true, now: 1_000 },
    );
    expect(strong.strong).toBe(true);
    expect(strong.grant).toBeUndefined();
    const plain = Object.keys(buildStatement(req(), { userVerified: false }));
    expect(plain).not.toContain('grant');
    expect(plain).not.toContain('strong');
  });

  it('what is shown must be what is granted, and ask-strong never grants; else deny unseen', async () => {
    const base = req();
    const shownOnly = req({ allowForMs: 60_000 });
    const grantOnly: ApprovalRequest = {
      ...base,
      binding: { ...base.binding, grant: { agentId: 'a', durationMs: 60_000 } },
    };
    const mismatch: ApprovalRequest = {
      ...allowFor(60_000),
      display: { ...allowFor(60_000).display, allowForMs: 120_000 },
    };
    const strongGrant: ApprovalRequest = { ...allowFor(), policy: { tier: 'ask-strong' } };
    for (const r of [shownOnly, grantOnly, mismatch, strongGrant]) {
      expect(requestProblem(r)).toBe('inconsistent_request');
      expect(() => buildStatement(r, { userVerified: false })).toThrow('inconsistent_request');
      const out: string[] = [];
      const output = new PassThrough();
      output.on('data', (c: Buffer) => out.push(c.toString()));
      const key = ApproverKey.generate('t');
      const t = new TerminalApprover({ key, input: new PassThrough(), output, timeoutMs: 1000 });
      expect(await t.request(r)).toEqual({ approved: false, reason: 'inconsistent_request' });
      expect(await new ScriptedApprover(key).request(r)).toEqual({
        approved: false,
        reason: 'inconsistent_request',
      });
      expect(out.join('')).toBe('');
    }
    expect(requestProblem(allowFor())).toBeNull();
  });

  it('a window of exactly 24 hours is signed, and one millisecond more is denied unseen', () => {
    const cap = 24 * 60 * 60_000;
    expect(requestProblem(allowFor(cap))).toBeNull();
    const s = buildStatement(allowFor(cap), { userVerified: false, now: 1_000 });
    expect(s.grant).toEqual({ agentId: 'agent-1', until: 1_000 + cap });
    expect(requestProblem(allowFor(cap + 1))).toBe('inconsistent_request');
    expect(() => buildStatement(allowFor(cap + 1), { userVerified: false })).toThrow(
      'inconsistent_request',
    );
  });

  it('a terminal "y" to an allow-for request signs over the grant', async () => {
    const key = ApproverKey.generate('t');
    const input = new PassThrough();
    const output = new PassThrough();
    const t = new TerminalApprover({ key, input, output, timeoutMs: 2000 });
    const p = t.request(allowFor());
    input.write('y\n');
    const d = await p;
    expect(d.approved).toBe(true);
    if (!d.approved) return;
    const s = d.approval.statement;
    expect(s.grant?.agentId).toBe('agent-1');
    expect((s.grant?.until ?? 0) - s.issuedAt).toBe(30 * 60_000);
    expect(
      verify(
        null,
        approvalSigningBytes(s),
        ed25519PublicKey(key.publicKey),
        Buffer.from(d.approval.signature as string, 'base64url'),
      ),
    ).toBe(true);
  });
});
