import { generateKeyPairSync, sign } from 'node:crypto';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { openDb } from '@aab/core';
import {
  nativeApproverDescriptor,
  nativeKeyId,
  nativePairingProofBytes,
} from '@aab/signer/approval';
import { describe, expect, it } from 'vitest';
import { devBackend } from '../src/setup/backend.ts';
import { realSystem } from '../src/setup/system.ts';
import { tmpDir } from './helpers.ts';

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

function nativeApp(origin: string) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = jwk.x as string;
  const y = jwk.y as string;
  const keyId = nativeKeyId(x, y);
  const descriptor = nativeApproverDescriptor({
    keyId,
    x,
    y,
    origin,
    userVerification: 'biometry',
  });
  const proof = sign('sha256', nativePairingProofBytes(descriptor), {
    key: privateKey,
    dsaEncoding: 'der',
  }).toString('base64url');
  return {
    keyId,
    proof,
    pairBody: (code: string) => ({ code, key: { x, y }, userVerification: 'biometry', proof }),
  };
}

function postPair(
  port: number,
  body: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const r = request(
      {
        host: '127.0.0.1',
        port,
        path: '/api/native/pair',
        method: 'POST',
        headers: { host: `approver.localhost:${port}`, 'content-type': 'application/json' },
      },
      (res) => {
        let text = '';
        res.on('data', (c) => {
          text += c;
        });
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, body: JSON.parse(text || '{}') }),
        );
      },
    );
    r.on('error', reject);
    r.end(JSON.stringify(body));
  });
}

const codeOf = (url: string) => new URL(url).hash.slice(1);

function auditRows(dataDir: string): { event: string; payload: Record<string, unknown> }[] {
  const db = new DatabaseSync(join(dataDir, 'broker.sqlite'), { readOnly: true });
  try {
    return (
      db.prepare('SELECT event_type, payload_json FROM audit ORDER BY seq').all() as {
        event_type: string;
        payload_json: string;
      }[]
    ).map((r) => ({ event: r.event_type, payload: JSON.parse(r.payload_json) }));
  } finally {
    db.close();
  }
}

function stopAcceptingAuditRows(dataDir: string): void {
  const db = new DatabaseSync(join(dataDir, 'broker.sqlite'));
  try {
    db.exec(
      `CREATE TRIGGER audit_unwritable BEFORE INSERT ON audit
         BEGIN SELECT RAISE(ABORT, 'disk full at /var/lib/keyflap/core/broker.sqlite'); END`,
    );
  } finally {
    db.close();
  }
}

async function setupPairing(
  onOpen: (o: { dataDir: string; port: number; url: string }) => Promise<void>,
  beforePair: (dataDir: string) => void = () => {},
) {
  const dataDir = tmpDir();
  const port = await freePort();
  const origin = `http://approver.localhost:${port}`;
  const backend = await devBackend({
    sys: realSystem(),
    dataDir,
    mcpPort: 8765,
    home: dataDir,
    passphrase: async () => 'test-passphrase',
  });
  beforePair(dataDir);
  const result = await backend.pair({
    origin,
    listen: { host: '127.0.0.1', port },
    tls: null,
    timeoutMs: 1_500,
    signal: new AbortController().signal,
    onOpen: (url) => onOpen({ dataDir, port, url }),
  });
  return { backend, dataDir, origin, result };
}

describe('invariant 10: keyflap setup pairs a phone only after its pairing row is written', () => {
  it('refuses the phone and registers no key when the audit log stops accepting rows after the link is issued', async () => {
    let answer: Awaited<ReturnType<typeof postPair>> | null = null;
    const s = await setupPairing(async ({ dataDir, port, url }) => {
      stopAcceptingAuditRows(dataDir);
      answer = await postPair(
        port,
        nativeApp(`http://approver.localhost:${port}`).pairBody(codeOf(url)),
      );
    });
    expect(answer).toEqual({ status: 409, body: { error: 'pairing_refused' } });
    expect(s.result).toBe('timeout');
    expect(await s.backend.phonesPaired(s.origin)).toBe(0);
    expect(auditRows(s.dataDir).map((r) => r.event)).toEqual([
      'setup.pairing',
      'approver.pairing_started',
    ]);
  });

  it('issues no pairing link when the first pairing row cannot be written', async () => {
    let opened = false;
    await expect(
      setupPairing(
        async () => {
          opened = true;
        },
        (dataDir) => {
          openDb(join(dataDir, 'broker.sqlite')).close();
          stopAcceptingAuditRows(dataDir);
        },
      ),
    ).rejects.toThrow();
    expect(opened).toBe(false);
  });

  it('with the audit log writable the phone pairs and the row names only identifiers and origins', async () => {
    let app: ReturnType<typeof nativeApp> | null = null;
    let code = '';
    const s = await setupPairing(async ({ port, url }) => {
      app = nativeApp(`http://approver.localhost:${port}`);
      code = codeOf(url);
      const answer = await postPair(port, app.pairBody(code));
      expect(answer.status).toBe(200);
    });
    const paired = app as unknown as ReturnType<typeof nativeApp>;
    expect(s.result).toBe('paired');
    expect(await s.backend.phonesPaired(s.origin)).toBe(1);
    const rows = auditRows(s.dataDir);
    expect(rows.map((r) => r.event)).toEqual([
      'setup.pairing',
      'approver.pairing_started',
      'approver.pairing_accepted',
      'approver.paired',
    ]);
    expect(rows[2]?.payload).toEqual({
      origin: s.origin,
      credentialId: paired.keyId,
      first: true,
      kind: 'native',
    });
    const text = JSON.stringify(rows);
    expect(text).not.toContain(code);
    expect(text).not.toContain(paired.proof);
  });
});
