import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  type ApprovalStatement,
  approverDescriptor,
  type SignedApproval,
  sha256B64url,
} from '../src/approval.ts';
import { type ApproverMode, approverModeOf, approverModeRules } from '../src/approver-mode.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import { clientData, statement, testApprover, testPhone, tmpDir } from './helpers.ts';

type Res = { ok: true; result: Record<string, unknown> } | { ok: false; error: string };

const terminal = testApprover('terminal');

interface World {
  store: KeyStore;
  call: (req: unknown, o?: { approverAdmin?: boolean }) => Res;
  paired: ReturnType<typeof testPhone> | undefined;
}

function world(mode: ApproverMode): World {
  const path = join(tmpDir(), 'keys');
  const store = KeyStore.open(path, 'pw');
  const handler = (approverAdmin: boolean) =>
    new SignerHandler({ store, trustedApproverKeys: terminal.trusted, approverAdmin });
  const core = handler(false);
  const admin = handler(true);
  const call = (req: unknown, o: { approverAdmin?: boolean } = {}) =>
    (o.approverAdmin === true ? admin : core).handle(req as never) as Res;
  let paired: ReturnType<typeof testPhone> | undefined;
  if (mode !== 'unpaired') {
    paired = testPhone();
    expect(call({ op: 'add_approver', key: paired.key }).ok).toBe(true);
  }
  if (mode === 'phone-empty') {
    store.removeAllApprovers();
    paired = undefined;
  }
  expect(store.approverMode()).toBe(mode);
  return { store, call, paired };
}

function addStatement(p: ReturnType<typeof testPhone>): ApprovalStatement {
  return {
    ...statement({ clientDataJSON: '' }),
    kind: 'approver.add',
    verifiedOrigin: p.key.origin,
    rpId: p.key.rpId,
    credentialId: p.key.credentialId,
    clientDataHash: sha256B64url(approverDescriptor(p.key)),
    userVerified: true,
  };
}

type Event =
  | 'verify-with-ed25519'
  | 'add-first-approver'
  | 'add-approver-with-approval'
  | 'remove-last-approver-non-admin'
  | 'remove-last-approver-admin'
  | 'clear-address-trip';

function run(w: World, event: Event): unknown {
  switch (event) {
    case 'verify-with-ed25519': {
      const origin = 'https://example.com';
      const cd = clientData('webauthn.create', origin);
      const s = statement({ kind: 'webauthn.create', clientDataJSON: cd, verifiedOrigin: origin });
      const r = w.call({
        op: 'create_credential',
        rpId: 'example.com',
        userHandle: 'dXNlcg',
        clientDataJSON: cd,
        approval: terminal.sign(s),
      });
      return r.ok ? 'ok' : r.error;
    }
    case 'add-first-approver': {
      const r = w.call({ op: 'add_approver', key: testPhone().key });
      return r.ok ? 'ok' : r.error;
    }
    case 'add-approver-with-approval': {
      const next = testPhone();
      const s = addStatement(next);
      const approval: SignedApproval = w.paired ? w.paired.approve(s) : terminal.sign(s);
      const r = w.call({ op: 'add_approver', key: next.key, approval });
      return r.ok ? 'ok' : r.error;
    }
    case 'remove-last-approver-non-admin':
    case 'remove-last-approver-admin': {
      const id = w.paired?.key.credentialId ?? 'no-such-approver-id';
      const r = w.call(
        { op: 'remove_approver', credentialId: id },
        { approverAdmin: event === 'remove-last-approver-admin' },
      );
      return r.ok ? r.result : r.error;
    }
    case 'clear-address-trip':
      w.store.setAddressTrip({ at: 1, seen: 'https://elsewhere.example' });
      w.store.clearAddressTrip();
      return 'ok';
    default: {
      const unhandled: never = event;
      return unhandled;
    }
  }
}

const table: [ApproverMode, Event, unknown, ApproverMode][] = [
  ['unpaired', 'verify-with-ed25519', 'ok', 'unpaired'],
  ['unpaired', 'add-first-approver', 'ok', 'phone'],
  ['unpaired', 'add-approver-with-approval', 'ok', 'phone'],
  ['unpaired', 'remove-last-approver-non-admin', { removed: false }, 'unpaired'],
  ['unpaired', 'remove-last-approver-admin', { removed: false }, 'unpaired'],
  ['unpaired', 'clear-address-trip', 'ok', 'unpaired'],
  ['phone', 'verify-with-ed25519', 'untrusted_approver', 'phone'],
  ['phone', 'add-first-approver', 'missing_approval', 'phone'],
  ['phone', 'add-approver-with-approval', 'ok', 'phone'],
  ['phone', 'remove-last-approver-non-admin', 'last_approver_needs_admin', 'phone'],
  ['phone', 'remove-last-approver-admin', { removed: true }, 'unpaired'],
  ['phone', 'clear-address-trip', 'ok', 'phone'],
  ['phone-empty', 'verify-with-ed25519', 'untrusted_approver', 'phone-empty'],
  ['phone-empty', 'add-first-approver', 'missing_approval', 'phone-empty'],
  ['phone-empty', 'add-approver-with-approval', 'untrusted_approver', 'phone-empty'],
  ['phone-empty', 'remove-last-approver-non-admin', { removed: false }, 'phone-empty'],
  ['phone-empty', 'remove-last-approver-admin', { removed: false }, 'phone-empty'],
  ['phone-empty', 'clear-address-trip', 'ok', 'unpaired'],
];

describe('approver mode states: every mode against every event', () => {
  it('the table covers each mode and event exactly once', () => {
    const keys = table.map(([m, e]) => `${m} ${e}`);
    expect(new Set(keys).size).toBe(18);
  });

  for (const [mode, event, result, after] of table) {
    it(`${mode} + ${event} -> ${JSON.stringify(result)}, then ${after}`, () => {
      const w = world(mode);
      expect(run(w, event)).toEqual(result);
      expect(w.store.approverMode()).toBe(after);
    });
  }

  it('the mode survives a reopen of the key store', () => {
    for (const mode of ['unpaired', 'phone', 'phone-empty'] as const) {
      const path = join(tmpDir(), 'keys');
      const store = KeyStore.open(path, 'pw');
      if (mode !== 'unpaired')
        store.addApprover({ ...testPhone().key, signCount: 0, createdAt: 1 });
      if (mode === 'phone-empty') store.removeAllApprovers();
      expect(KeyStore.open(path, 'pw').approverMode()).toBe(mode);
    }
  });

  it('derives the mode from the stored latch and the approver count', () => {
    expect(approverModeOf(false, 0)).toBe('unpaired');
    expect(approverModeOf(true, 0)).toBe('phone-empty');
    expect(approverModeOf(true, 2)).toBe('phone');
    expect(approverModeOf(false, 1)).toBe('phone');
  });

  it('only an unpaired signer counts Ed25519 keys or pairs without an approval', () => {
    expect(approverModeRules('unpaired')).toEqual({
      ed25519Counts: true,
      pairingNeedsApproval: false,
    });
    for (const mode of ['phone', 'phone-empty'] as const) {
      expect(approverModeRules(mode)).toEqual({ ed25519Counts: false, pairingNeedsApproval: true });
    }
  });
});
