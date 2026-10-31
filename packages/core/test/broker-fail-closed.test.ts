import { type ApprovalDecision, type Approver, ApproverKey, ScriptedApprover } from '@aab/approver';
import { SignerDenied } from '@aab/signer/client';
import { beforeEach, describe, expect, it } from 'vitest';
import { Broker, type FillTarget, type SignerPort } from '../src/broker.ts';
import { openDb } from '../src/db.ts';
import { AGENT, registerAgents } from './harness.ts';

const ORIGIN = 'https://login.example.com';
const frame = { url: `${ORIGIN}/signin`, isMainFrame: true, securityOrigin: ORIGIN };
const bytes = (n: number, fill = 7) => ({ $b: Buffer.alloc(n, fill).toString('base64url') });
const credentialId = (n: number) => Buffer.alloc(16, n).toString('base64url');

class UnreachableSigner implements SignerPort {
  readonly calls: string[] = [];
  error: Error = new Error('the signer must not be reached');
  async createCredential(): Promise<never> {
    this.calls.push('createCredential');
    throw this.error;
  }
  async sign(): Promise<never> {
    this.calls.push('sign');
    throw this.error;
  }
  async releaseSecret(): Promise<never> {
    this.calls.push('releaseSecret');
    throw this.error;
  }
}

class FakeApprover implements Approver {
  readonly inner = new ScriptedApprover(ApproverKey.generate());
  fault: Error | null = null;
  get seen() {
    return this.inner.seen;
  }
  async request(...args: Parameters<Approver['request']>): Promise<ApprovalDecision> {
    if (this.fault) throw this.fault;
    return this.inner.request(args[0]);
  }
}

describe('the broker fails closed when it cannot tell', () => {
  let db: ReturnType<typeof openDb>;
  let broker: Broker;
  let signer: UnreachableSigner;
  let approver: FakeApprover;
  let performed: string[];

  const get = (options: Record<string, unknown> = {}) =>
    broker.handleWebAuthn(
      {
        kind: 'get',
        frame,
        mediation: null,
        options: { challenge: bytes(32), rpId: 'example.com', ...options },
      },
      AGENT,
    );
  const fill = () => {
    const target: FillTarget = {
      origin: { origin: ORIGIN, host: 'login.example.com' },
      first: 'password',
      async perform(ctx) {
        performed.push('perform');
        await ctx.release('password');
        return { outcome: 'success' };
      },
    };
    return broker.fill(AGENT, target);
  };
  const denials = () =>
    broker.audit
      .all()
      .filter((r) => r.event_type === 'denied')
      .map((r) => JSON.parse(r.payload_json).reason as string);
  const addPasskey = (n: number) =>
    broker.credentials.insertPasskey({
      id: credentialId(n),
      rpId: 'example.com',
      registrableDomain: 'example.com',
      userHandle: 'dQ',
      username: null,
      publicKey: 'AA',
      now: 0,
    });
  const addPassword = (itemId: string) =>
    broker.credentials.insertPassword({
      itemId,
      domain: 'example.com',
      username: 'alice',
      hasTotp: false,
      now: 0,
    });
  const expectNothingReached = () => {
    expect(approver.seen).toEqual([]);
    expect(signer.calls).toEqual([]);
    expect(performed).toEqual([]);
  };

  beforeEach(() => {
    db = openDb(':memory:');
    registerAgents(db, AGENT);
    signer = new UnreachableSigner();
    approver = new FakeApprover();
    performed = [];
    broker = new Broker({ db, signer, approver });
    broker.intents.record(AGENT.id, 'sign in to example');
    addPasskey(1);
    addPassword('pw_1');
  });

  describe('a handoff check that does not answer false', () => {
    it.each([
      [
        'throws',
        () => {
          throw new Error('handoff manager is down');
        },
      ],
      ['answers undefined', () => undefined as unknown as boolean],
      ['answers a truthy non-boolean', () => 1 as unknown as boolean],
    ])(
      '%s: a passkey sign-in and a fill are both denied handoff_open, unseen by the approver',
      async (_name, check) => {
        broker.setHandoffCheck(check);
        expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
        expect(await fill()).toBe('denied');
        expect(denials()).toEqual(['handoff_open', 'handoff_open']);
        expectNothingReached();
      },
    );

    it('control: a check that answers false lets both reach the approver', async () => {
      broker.setHandoffCheck(() => false);
      await get();
      await fill();
      expect(approver.seen).toHaveLength(2);
      expect(denials()).not.toContain('handoff_open');
    });
  });

  describe('a failure anywhere else is a denial, never a throw', () => {
    it('the approver fails: nothing is signed, released or performed', async () => {
      approver.fault = new Error('approver crashed');
      expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
      expect(await fill()).toBe('denied');
      expect(denials()).toEqual(['internal_error', 'internal_error']);
      expect(signer.calls).toEqual([]);
      expect(performed).toEqual([]);
    });

    it('the signer fails after an approval: the sign-in and the fill are denied', async () => {
      expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
      expect(await fill()).toBe('denied');
      expect(approver.seen).toHaveLength(2);
      expect(signer.calls).toEqual(['sign', 'releaseSecret']);
      expect(denials()).toEqual(['internal_error', 'internal_error']);
    });

    it('the policy store is unreadable: denied before any prompt, credential lookup or signer call', async () => {
      db.exec('DROP TABLE policies');
      expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
      expect(await fill()).toBe('denied');
      expect(denials()).toEqual(['internal_error', 'internal_error']);
      expectNothingReached();
    });
  });

  describe('which signer refusal reason is kept', () => {
    it.each([
      ['grant_used', 'signer:grant_used'],
      ['approval_expired', 'signer:approval_expired'],
      ['x <y>', 'internal_error'],
      ['Grant_Used', 'internal_error'],
      ['a'.repeat(65), 'internal_error'],
      ['', 'internal_error'],
    ])('a signer refusal "%s" is audited as %s', async (message, reason) => {
      signer.error = new SignerDenied(message);
      expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
      expect(denials()).toEqual([reason]);
    });

    it('anything that is not a signer refusal never shows its message', async () => {
      signer.error = new Error('grant_used');
      await get();
      expect(denials()).toEqual(['internal_error']);
    });
  });

  describe('several accounts for one site are ambiguous, so no prompt can be shown', () => {
    it('two passkeys for one rpId without allowCredentials: denied ambiguous_credential', async () => {
      addPasskey(2);
      expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
      expect(denials()).toEqual(['ambiguous_credential']);
      expectNothingReached();
    });

    it('allowCredentials naming exactly one of the two makes it unambiguous', async () => {
      addPasskey(2);
      await get({ allowCredentials: [{ type: 'public-key', id: { $b: credentialId(2) } }] });
      expect(denials()).not.toContain('ambiguous_credential');
      expect(approver.seen).toHaveLength(1);
      expect(approver.seen[0]?.binding.credentialId).toBe(credentialId(2));
    });

    it('two password items for one domain: the fill is denied ambiguous_credential', async () => {
      addPassword('pw_2');
      expect(await fill()).toBe('denied');
      expect(denials()).toEqual(['ambiguous_credential']);
      expectNothingReached();
    });
  });
});
