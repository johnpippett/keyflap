import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  nativeApproverDescriptor,
  nativeKeyId,
  nativePairingProofBytes,
} from '@aab/signer/approval';
import { afterEach, describe, expect, it } from 'vitest';
import { KeyStore } from '../../signer/src/keystore.ts';
import { SignerHandler } from '../../signer/src/server.ts';
import {
  nextPairingState,
  type PairingEvent,
  type PairingState,
  pairingDevice,
  pairingStatus,
} from '../src/pairing-state.ts';
import { PhoneApprover } from '../src/phone.ts';

const states: Record<PairingState['kind'], PairingState> = {
  open: { kind: 'open' },
  ceremony: { kind: 'ceremony', challenge: 'c1' },
  verifying: { kind: 'verifying', device: 'native' },
  waiting: { kind: 'waiting', device: 'native' },
  paired: { kind: 'paired', device: 'native', token: 't1' },
  done: { kind: 'done', device: 'native' },
  failed: { kind: 'failed', device: 'native' },
};

const events: Record<PairingEvent['kind'], PairingEvent> = {
  options: { kind: 'options', challenge: 'c2' },
  finish_web: { kind: 'finish_web' },
  finish_native: { kind: 'finish_native' },
  paired: { kind: 'paired', token: 't2' },
  needs_approval: { kind: 'needs_approval' },
  rejected: { kind: 'rejected' },
  approval_failed: { kind: 'approval_failed' },
  token_taken: { kind: 'token_taken' },
};

type K = PairingState['kind'];
type E = PairingEvent['kind'];
const moves: Partial<Record<K, Partial<Record<E, PairingState>>>> = {
  open: {
    options: { kind: 'ceremony', challenge: 'c2' },
    finish_native: { kind: 'verifying', device: 'native' },
  },
  ceremony: {
    options: { kind: 'ceremony', challenge: 'c2' },
    finish_web: { kind: 'verifying', device: 'web' },
  },
  verifying: {
    paired: { kind: 'paired', device: 'native', token: 't2' },
    needs_approval: { kind: 'waiting', device: 'native' },
    rejected: { kind: 'open' },
  },
  waiting: {
    paired: { kind: 'paired', device: 'native', token: 't2' },
    approval_failed: { kind: 'failed', device: 'native' },
  },
  paired: { token_taken: { kind: 'done', device: 'native' } },
};

describe('pairing states: every state against every event', () => {
  for (const k of Object.keys(states) as K[]) {
    for (const e of Object.keys(events) as E[]) {
      const want = moves[k]?.[e];
      it(`${k} + ${e} -> ${want ? want.kind : 'unchanged'}`, () => {
        const from = states[k];
        const next = nextPairingState(from, events[e]);
        if (want) expect(next).toEqual(want);
        else expect(next).toBe(from);
      });
    }
  }

  it('reports the strings the page and the iOS app read, never ceremony or verifying', () => {
    expect(
      Object.fromEntries(Object.values(states).map((s) => [s.kind, pairingStatus(s)])),
    ).toEqual({
      open: 'open',
      ceremony: 'open',
      verifying: 'open',
      waiting: 'waiting',
      paired: 'paired',
      done: 'done',
      failed: 'failed',
    });
  });

  it('knows which kind of device a pairing belongs to', () => {
    expect(pairingDevice(states.open)).toBeNull();
    expect(pairingDevice(states.ceremony)).toBe('web');
    expect(pairingDevice({ kind: 'verifying', device: 'web' })).toBe('web');
    for (const k of ['verifying', 'waiting', 'paired', 'done', 'failed'] as const) {
      expect(pairingDevice(states[k])).toBe('native');
    }
  });
});

describe('pairing states: two finishes at once on one code', () => {
  let approver: PhoneApprover | null = null;
  afterEach(async () => {
    await approver?.close();
    approver = null;
  });

  it('only one reaches the signer; the other is refused 409', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'keyflap-pairing-'));
    const handler = new SignerHandler({
      store: KeyStore.open(join(dir, 'keys'), 'pw'),
      trustedApproverKeys: {},
    });
    const call = (op: Record<string, unknown>) => {
      const r = handler.handle(op as never);
      return r.ok ? Promise.resolve(r.result as never) : Promise.reject(new Error(r.error));
    };
    const port = await new Promise<number>((resolve) => {
      const s = createServer().listen(0, '127.0.0.1', () => {
        const p = (s.address() as { port: number }).port;
        s.close(() => resolve(p));
      });
    });
    const host = 'approver.localhost';
    const origin = `http://${host}:${port}`;
    let reachedSigner = 0;
    let release!: () => void;
    const held = new Promise<void>((r) => {
      release = r;
    });
    approver = await PhoneApprover.start({
      dir: join(dir, 'approver'),
      origin,
      listen: { host: '127.0.0.1', port },
      signer: {
        listApprovers: () => call({ op: 'list_approvers' }),
        addApprover: (r) => call({ op: 'add_approver', ...r }),
        addNativeApprover: async (r) => {
          reachedSigner++;
          await held;
          return call({ op: 'add_native_approver', ...r });
        },
        removeApprover: (id) => call({ op: 'remove_approver', credentialId: id }),
      },
      auditBefore: () => {},
      timeoutMs: 5_000,
    });
    const body = (code: string) => {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const jwk = publicKey.export({ format: 'jwk' });
      const x = jwk.x as string;
      const y = jwk.y as string;
      const descriptor = nativeApproverDescriptor({
        keyId: nativeKeyId(x, y),
        x,
        y,
        origin,
        userVerification: 'biometry',
      });
      return {
        code,
        key: { x, y },
        userVerification: 'biometry',
        proof: sign('sha256', nativePairingProofBytes(descriptor), {
          key: privateKey,
          dsaEncoding: 'der',
        }).toString('base64url'),
      };
    };
    const post = (b: unknown) =>
      new Promise<{ status: number; json: Record<string, unknown> }>((resolve, reject) => {
        const r = request(
          {
            host: '127.0.0.1',
            port,
            path: '/api/native/pair',
            method: 'POST',
            headers: { host: `${host}:${port}`, 'content-type': 'application/json' },
          },
          (res) => {
            let text = '';
            res.on('data', (c) => {
              text += c;
            });
            res.on('end', () =>
              resolve({ status: res.statusCode ?? 0, json: text ? JSON.parse(text) : {} }),
            );
          },
        );
        r.on('error', reject);
        r.end(JSON.stringify(b));
      });
    const code = new URL(approver.startPairing()).hash.slice(1);
    const first = post(body(code));
    while (reachedSigner === 0) await new Promise((r) => setTimeout(r, 5));
    const second = await post(body(code));
    expect(second).toEqual({ status: 409, json: { error: 'pairing_in_progress' } });
    release();
    expect((await first).json).toMatchObject({ status: 'paired' });
    expect(reachedSigner).toBe(1);
    expect(handler.handle({ op: 'list_approvers' } as never)).toMatchObject({
      ok: true,
      result: { native: [expect.anything()] },
    });
  });
});
