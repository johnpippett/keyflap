import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { ApproverKey, ScriptedApprover } from '@aab/approver';
import { type SpawnedSigner, spawnSigner } from '@aab/signer/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Broker } from '../src/broker.ts';
import { openDb } from '../src/db.ts';
import { AGENT, registerAgents, tmpDir } from './harness.ts';

const b = (n: number) => ({ $b: Buffer.alloc(n, 7).toString('base64url') });
const clientDataOf = (res: Awaited<ReturnType<Broker['handleWebAuthn']>>) =>
  res.ok
    ? JSON.parse(Buffer.from(res.credential.response.clientDataJSON, 'base64url').toString())
    : null;

describe('invariant 2: broker ignores page-supplied origin data', () => {
  let dir: string;
  let signer: SpawnedSigner;
  let broker: Broker;
  let approver: ScriptedApprover;
  const handle = (req: Parameters<Broker['handleWebAuthn']>[0]) =>
    broker.handleWebAuthn(req, AGENT);

  beforeAll(async () => {
    dir = tmpDir();
    const key = ApproverKey.generate();
    approver = new ScriptedApprover(key);
    signer = await spawnSigner({
      socketPath: join(dir, 'run', 's.sock'),
      storePath: join(dir, 'keys'),
      passphrase: 'pw',
      trustedApproverKeys: key.trustEntry(),
    });
    const db = openDb(join(dir, 'db.sqlite'));
    registerAgents(db, AGENT);
    broker = new Broker({ db, signer: signer.client, approver });
    broker.intents.record(AGENT.id, 'log in to example');
  });
  afterAll(async () => {
    await signer.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  const frame = {
    url: 'https://login.example.com/signin',
    isMainFrame: true,
    securityOrigin: 'https://login.example.com',
  };
  const forged = {
    origin: 'https://bank.com',
    topOrigin: 'https://bank.com',
    crossOrigin: true,
    clientDataJSON: b(40),
    verifiedOrigin: 'https://bank.com',
  };

  it('create: clientDataJSON and the approval use the frame origin', async () => {
    const res = await handle({
      kind: 'create',
      frame,
      mediation: null,
      options: {
        ...forged,
        challenge: b(32),
        rp: { id: 'example.com', name: 'Example', origin: 'https://bank.com' },
        user: { id: b(16), name: 'u', displayName: 'u' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
    });
    expect(res.ok).toBe(true);
    expect(clientDataOf(res)).toMatchObject({
      type: 'webauthn.create',
      origin: 'https://login.example.com',
      crossOrigin: false,
    });
    const seen = approver.seen.at(-1);
    expect(seen?.display.verifiedOrigin).toBe('https://login.example.com');
    expect(JSON.stringify(seen)).not.toContain('bank.com');
  });

  it('get: clientDataJSON and the approval use the frame origin', async () => {
    const res = await handle({
      kind: 'get',
      frame,
      mediation: null,
      options: { ...forged, challenge: b(32), rpId: 'example.com' },
    });
    expect(res.ok).toBe(true);
    expect(clientDataOf(res)).toEqual({
      type: 'webauthn.get',
      challenge: b(32).$b,
      origin: 'https://login.example.com',
      crossOrigin: false,
    });
    expect(approver.seen.at(-1)?.display.verifiedOrigin).toBe('https://login.example.com');
  });

  it('a request from a non-top-level frame is denied before any prompt', async () => {
    const before = approver.seen.length;
    const ceremonies: unknown[] = [];
    const off = broker.onCeremony((e) => ceremonies.push(e));
    const res = await handle({
      kind: 'get',
      frame: { ...frame, isMainFrame: false },
      mediation: null,
      options: { challenge: b(32), rpId: 'example.com' },
    });
    off();
    expect(res).toEqual({ ok: false, name: 'NotAllowedError' });
    expect(approver.seen.length).toBe(before);
    expect(ceremonies).toEqual([]);
  });

  it('a page cannot claim an rpId its verified origin does not cover', async () => {
    const before = approver.seen.length;
    const res = await handle({
      kind: 'get',
      frame: {
        url: 'https://example.com.evil.net/',
        isMainFrame: true,
        securityOrigin: 'https://example.com.evil.net',
      },
      mediation: null,
      options: { challenge: b(32), rpId: 'example.com', origin: 'https://example.com' },
    });
    expect(res).toEqual({ ok: false, name: 'SecurityError' });
    expect(approver.seen.length).toBe(before);
  });

  it('malformed options fail closed', async () => {
    for (const options of [
      null,
      'x',
      { challenge: 'not-bytes' },
      { challenge: b(4) },
      { challenge: { $b: '!!' } },
    ]) {
      const res = await handle({ kind: 'get', frame, mediation: null, options });
      expect(res.ok).toBe(false);
    }
  });
});
