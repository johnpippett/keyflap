import { readFileSync } from 'node:fs';
import { createContext, runInContext } from 'node:vm';
import {
  type ApprovalStatement,
  approvalChallenge,
  approverDescriptor,
  fillScope,
  handoffSignInClientDataHash,
  nativeApproverDescriptor,
  nativeKeyId,
  sha256B64url,
} from '@aab/signer/approval';
import { describe, expect, it } from 'vitest';
import { type ApprovalRequest, buildStatement } from '../src/index.ts';
import { checkCode, handoffStartChallenge } from '../src/phone.ts';

interface Card {
  id: string;
  kind: string;
  display?: ApprovalRequest['display'];
  check?: string;
  newDevice?: string;
}
interface CheckOpts {
  keepSignedIn?: boolean;
  descriptor?: string | null;
  origin: string;
  now: number;
}
interface AabCheck {
  canonicalJson(v: unknown): string;
  sha256B64url(s: string): Promise<string>;
  approvalChallenge(s: unknown): Promise<string>;
  handoffStartChallenge(id: string, nonce: string): Promise<string>;
  checkCode(descriptor: string): Promise<string>;
  checkStatement(s: unknown, r: Card, o: CheckOpts): Promise<void>;
}

function loadPageCheck(): AabCheck {
  const src = readFileSync(new URL('../src/page/approval-check.js', import.meta.url), 'utf8');
  const ctx = createContext({ crypto: globalThis.crypto, TextEncoder, btoa, URL });
  runInContext(src, ctx);
  return (ctx as unknown as { AabCheck: AabCheck }).AabCheck;
}

const C = loadPageCheck();
const NOW = 1_760_000_000_000;
const ORIGIN = 'https://approver.example.ts.net:8766';
const HANDOFF_ID = '6f0a7c5e-1d0b-4c38-9d8e-2b1f3e4a5b6c';

function req(
  over: { display?: Partial<ApprovalRequest['display']> } & Partial<
    Omit<ApprovalRequest, 'display'>
  > = {},
): ApprovalRequest {
  const base: ApprovalRequest = {
    display: {
      intentText: 'sign me in to GitHub',
      intentAt: NOW - 5_000,
      verifiedOrigin: 'https://github.com',
      agentName: 'Claude Code',
      credentialType: 'passkey',
      action: 'sign-in',
    },
    policy: { tier: 'ask' },
    binding: {
      requestId: 'req-1',
      kind: 'webauthn.get',
      rpId: 'github.com',
      credentialId: 'cred-1',
      intentHash: 'intent-hash',
      clientDataHash: 'cd-hash',
    },
  };
  return {
    display: { ...base.display, ...over.display },
    policy: over.policy ?? base.policy,
    binding: over.binding ?? base.binding,
  };
}

const card = (r: ApprovalRequest): Card => ({
  id: r.binding.requestId,
  kind: 'credential',
  display: r.display,
});
const statementFor = (r: ApprovalRequest, keepSignedIn = false) =>
  buildStatement(r, { userVerified: true, now: NOW, keepSignedIn });
const opts = (o: Partial<CheckOpts> = {}): CheckOpts => ({ origin: ORIGIN, now: NOW, ...o });

async function refused(s: unknown, c: Card, o: CheckOpts = opts()): Promise<string> {
  try {
    await C.checkStatement(s, c, o);
  } catch (e) {
    expect((e as Error).name).toBe('Mismatch');
    return (e as Error).message;
  }
  throw new Error(`accepted: ${JSON.stringify(s)}`);
}

const fill = (credentialType: 'password' | 'totp' | 'password+totp') => {
  const fields = credentialType === 'password+totp' ? ['password', 'totp'] : [credentialType];
  return req({
    display: { credentialType, verifiedOrigin: 'https://login.bank.example' },
    binding: {
      requestId: 'req-fill',
      kind: 'fill',
      rpId: 'bank.example',
      credentialId: 'item-1',
      intentHash: 'intent-hash',
      clientDataHash: sha256B64url(fillScope(fields as ('password' | 'totp')[])),
    },
  });
};
const register = () =>
  req({
    display: { action: 'register' },
    binding: {
      requestId: 'req-reg',
      kind: 'webauthn.create',
      rpId: 'github.com',
      credentialId: null,
      intentHash: 'intent-hash',
      clientDataHash: 'cd-hash',
    },
  });
const allowFor = (ms = 30 * 60_000) =>
  req({
    display: { allowForMs: ms },
    binding: { ...req().binding, grant: { agentId: 'agent-1', durationMs: ms } },
  });
const keepOffer = () =>
  req({
    display: {
      credentialType: 'password',
      verifiedOrigin: 'https://login.bank.example',
      keepSignedInSite: 'bank.example',
    },
    policy: { tier: 'ask-strong' },
    binding: fill('password').binding,
  });
const combined = (kind: 'webauthn.get' | 'fill') => {
  const f = fill('password');
  return req({
    display: {
      ...(kind === 'fill' ? f.display : {}),
      handoffSignIn: { withinMs: 6 * 60_000 },
    },
    binding: {
      ...(kind === 'fill'
        ? f.binding
        : { ...req().binding, clientDataHash: handoffSignInClientDataHash(HANDOFF_ID) }),
      grant: { agentId: 'agent-1', durationMs: 6 * 60_000, uses: 1 },
      handoff: { id: HANDOFF_ID },
    },
  });
};

describe('invariant 5: the approver page computes what it signs', () => {
  it('its approval challenge is the signer approvalChallenge, for any statement', async () => {
    const odd = 'émoji 🙂 "quote" \\ back \u2028 line \u0000 nul \ud83d lone';
    const statements: ApprovalStatement[] = [
      statementFor(req()),
      statementFor(register()),
      statementFor(allowFor()),
      statementFor(keepOffer(), true),
      statementFor(combined('webauthn.get')),
      { ...statementFor(req()), verifiedOrigin: `https://${odd}`, intentHash: odd },
    ];
    for (const s of statements) {
      const wire = JSON.parse(JSON.stringify(s));
      expect(await C.approvalChallenge(wire)).toBe(approvalChallenge(s));
    }
  });

  it("its live-view start challenge is the server's, and never an approval's", async () => {
    const nonce = 'n'.repeat(43);
    expect(await C.handoffStartChallenge(HANDOFF_ID, nonce)).toBe(
      handoffStartChallenge(HANDOFF_ID, nonce),
    );
    expect(await C.handoffStartChallenge(HANDOFF_ID, nonce)).not.toBe(
      approvalChallenge(statementFor(req())),
    );
  });

  it('its check code is the one the new phone shows', async () => {
    const d = approverDescriptor({ credentialId: 'c', x: 'x', y: 'y', rpId: 'r', origin: 'o' });
    expect(await C.checkCode(d)).toBe(checkCode(d));
  });
});

describe('invariant 5: honest statements pass', () => {
  const cases: [string, ApprovalRequest, boolean][] = [
    ['passkey sign-in', req(), false],
    ['passkey register', register(), false],
    ['password fill', fill('password'), false],
    ['one-time code fill', fill('totp'), false],
    ['password + code fill', fill('password+totp'), false],
    ['allow-for', allowFor(), false],
    ['high-risk, keep box left unticked', keepOffer(), false],
    ['high-risk, keep box ticked', keepOffer(), true],
    ['human check + passkey sign-in (P3b)', combined('webauthn.get'), false],
    ['human check + password sign-in (P3b)', combined('fill'), false],
  ];
  for (const [name, r, keep] of cases) {
    it(name, async () => {
      const s = JSON.parse(JSON.stringify(statementFor(r, keep)));
      await expect(
        C.checkStatement(s, card(r), opts({ keepSignedIn: keep })),
      ).resolves.toBeUndefined();
    });
  }

  it('adding a phone or an iOS app key', async () => {
    const pk = { credentialId: 'new-cred', x: 'x', y: 'y', rpId: new URL(ORIGIN).hostname };
    const d1 = approverDescriptor({ ...pk, origin: ORIGIN });
    const x = Buffer.alloc(32, 1).toString('base64url');
    const y = Buffer.alloc(32, 2).toString('base64url');
    const keyId = nativeKeyId(x, y);
    const d2 = nativeApproverDescriptor({
      keyId,
      x,
      y,
      origin: ORIGIN,
      userVerification: 'biometry',
    });
    for (const [d, id, newDevice] of [
      [d1, 'new-cred', 'passkey'],
      [d2, keyId, 'ios-app'],
    ] as const) {
      const s = pairStatement(d, id);
      const c: Card = { id: 'pair-1', kind: 'pair', check: checkCode(d), newDevice };
      await expect(C.checkStatement(s, c, opts({ descriptor: d }))).resolves.toBeUndefined();
    }
  });
});

function pairStatement(descriptor: string, credentialId: string): ApprovalStatement {
  return {
    v: 1,
    requestId: 'pair-1',
    kind: 'approver.add',
    verifiedOrigin: ORIGIN,
    rpId: new URL(ORIGIN).hostname,
    credentialId,
    intentHash: sha256B64url(descriptor),
    clientDataHash: sha256B64url(descriptor),
    userVerified: true,
    issuedAt: NOW,
    expiresAt: NOW + 60_000,
  };
}

describe('invariant 5: a statement that differs from the card is refused', () => {
  it('another site, or an rpId the site is not within', async () => {
    const r = req();
    const s = statementFor(r);
    await refused({ ...s, verifiedOrigin: 'https://bank.example' }, card(r));
    await refused({ ...s, rpId: 'bank.example' }, card(r));
    await refused({ ...s, rpId: 'hub.com' }, card(r));
    await refused({ ...s, rpId: '.github.com' }, card(r));
    await refused({ ...s, rpId: 'GitHub.com' }, card(r));
    await refused(s, card(req({ display: { verifiedOrigin: 'https://gist.github.com' } })));
  });

  it('another kind of operation or credential', async () => {
    const r = req();
    const s = statementFor(r);
    await refused({ ...s, kind: 'fill' }, card(r));
    await refused({ ...s, kind: 'webauthn.create', credentialId: null }, card(r));
    await refused({ ...s, kind: 'approver.add' }, card(r));
    await refused({ ...s, credentialId: null }, card(r));
    const f = fill('password');
    const fs = statementFor(f);
    await refused(
      { ...fs, clientDataHash: sha256B64url(fillScope(['password', 'totp'])) },
      card(f),
    );
    await refused({ ...fs, kind: 'webauthn.get' }, card(f));
    const reg = register();
    await refused({ ...statementFor(reg), credentialId: 'cred-1' }, card(reg));
  });

  it('an allow-for window other than the one shown, or one not shown at all', async () => {
    const a = allowFor();
    const s = statementFor(a);
    await refused({ ...s, grant: { agentId: 'agent-1', until: NOW + 31 * 60_000 } }, card(a));
    await refused({ ...s, grant: undefined }, card(a));
    const plain = req();
    await refused(
      { ...statementFor(plain), grant: { agentId: 'agent-1', until: NOW + 60_000 } },
      card(plain),
    );
    await refused({ ...s, strong: true }, card(a));
    await refused({ ...s, grant: { ...s.grant, extra: 1 } }, card(a));
  });

  it('an allow-for window of more than 24 hours, even when the card shows it', async () => {
    const cap = 24 * 60 * 60_000;
    const windowOf = (ms: number) => ({
      ...statementFor(allowFor()),
      grant: { agentId: 'agent-1', until: NOW + ms },
    });
    await expect(
      C.checkStatement(windowOf(cap), card(allowFor(cap)), opts()),
    ).resolves.toBeUndefined();
    expect(await refused(windowOf(cap + 1), card(allowFor(cap + 1)))).toContain(
      '(allow-for window)',
    );
  });

  it('"Keep me signed in" signed without the tick, or for another site', async () => {
    const k = keepOffer();
    const ticked = statementFor(k, true);
    await refused(ticked, card(k), opts({ keepSignedIn: false }));
    await refused(
      { ...ticked, keepSignedIn: { site: 'other.example' } },
      card(k),
      opts({ keepSignedIn: true }),
    );
    await refused(statementFor(k), card(k), opts({ keepSignedIn: true }));
    const { strong: _s, ...notStrong } = ticked;
    await refused(notStrong, card(k), opts({ keepSignedIn: true }));
  });

  it('a human check + sign-in that is not the one shown (P3b)', async () => {
    const c = combined('webauthn.get');
    const s = statementFor(c);
    await refused({ ...s, handoff: undefined }, card(c));
    await refused({ ...s, handoff: { id: 'other-handoff' } }, card(c));
    await refused({ ...s, grant: { agentId: 'agent-1', until: s.grant?.until } }, card(c));
    await refused({ ...s, grant: { ...s.grant, until: NOW + 7 * 60_000 } }, card(c));
    await refused({ ...s, clientDataHash: 'a-real-sites-client-data-hash' }, card(c));
    const plain = req();
    await refused({ ...statementFor(plain), handoff: s.handoff, grant: s.grant }, card(plain));
  });

  it('terms the page does not know, wrong ids, no UV, or a stale or long-lived statement', async () => {
    const r = req();
    const s = statementFor(r);
    await refused({ ...s, scope: 'everything' }, card(r));
    await refused({ ...s, v: 2 }, card(r));
    await refused({ ...s, requestId: 'req-2' }, card(r));
    await refused({ ...s, userVerified: false }, card(r));
    await refused({ ...s, expiresAt: NOW + 6 * 60_000 }, card(r));
    await refused({ ...s, strong: true, expiresAt: NOW + 2 * 60_000 }, card(r));
    await refused({ ...s, issuedAt: NOW + 1.5 }, card(r));
    await refused(s, card(r), opts({ now: NOW + 61_000 }));
    await refused(s, card(r), opts({ now: NOW - 31_000 }));
    await refused(null, card(r));
    await refused(s, { ...card(r), kind: 'something-new' });
  });

  it("adding a phone whose key, check code or origin isn't the one shown", async () => {
    const pk = { credentialId: 'new-cred', x: 'x', y: 'y', rpId: new URL(ORIGIN).hostname };
    const d = approverDescriptor({ ...pk, origin: ORIGIN });
    const s = pairStatement(d, 'new-cred');
    const c: Card = { id: 'pair-1', kind: 'pair', check: checkCode(d), newDevice: 'passkey' };
    const other = approverDescriptor({ ...pk, credentialId: 'evil-cred', origin: ORIGIN });
    await refused(s, c, opts({ descriptor: other }));
    await refused(pairStatement(other, 'evil-cred'), c, opts({ descriptor: other }));
    await refused(s, { ...c, check: '0000-0000-0000' }, opts({ descriptor: d }));
    await refused(s, { ...c, newDevice: 'ios-app' }, opts({ descriptor: d }));
    await refused(s, c, opts({ descriptor: null }));
    const elsewhere = approverDescriptor({ ...pk, origin: 'https://evil.example' });
    await refused(
      pairStatement(elsewhere, 'new-cred'),
      { ...c, check: checkCode(elsewhere) },
      opts({ descriptor: elsewhere }),
    );
    await refused(s, card(req({ binding: { ...req().binding, requestId: 'pair-1' } })));
  });
});
