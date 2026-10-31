import { timingSafeEqual } from 'node:crypto';
import { request } from 'node:http';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { ApproverKey, ScriptedApprover } from '@aab/approver';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AgentRegistry } from '../src/agents.ts';
import { Broker } from '../src/broker.ts';
import { openDb } from '../src/db.ts';
import {
  type IntentServer,
  loadOrCreateHostToken,
  startIntentServer,
} from '../src/intent-server.ts';
import { tmpDir } from './harness.ts';

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return { ...actual, timingSafeEqual: vi.fn(actual.timingSafeEqual) };
});

const fakeSigner = {
  createCredential: () => Promise.reject(new Error('unused')),
  sign: () => Promise.reject(new Error('unused')),
  releaseSecret: () => Promise.reject(new Error('unused')),
};

function status(socketPath: string, token: string, agentId: string): Promise<number> {
  const body = JSON.stringify({ agentId, text: 'sign in to the test RP' });
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath,
        path: '/v1/intents',
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode ?? 0));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

describe('the intent socket compares the host token in constant time', () => {
  let db: DatabaseSync;
  let server: IntentServer;
  let hostToken: string;
  let agentId: string;
  let sock: string;

  beforeAll(async () => {
    const dir = tmpDir();
    db = openDb(join(dir, 'broker.sqlite'));
    const broker = new Broker({
      db,
      signer: fakeSigner,
      approver: new ScriptedApprover(ApproverKey.generate()),
    });
    const registry = new AgentRegistry(db);
    agentId = registry.add('claude-code').id;
    hostToken = loadOrCreateHostToken(join(dir, 'host-token'));
    sock = join(dir, 'run', 'intent.sock');
    server = await startIntentServer({ socketPath: sock, hostToken, registry, broker });
  });

  afterAll(async () => {
    await server.close();
    db.close();
  });

  beforeEach(() => {
    vi.mocked(timingSafeEqual).mockClear();
  });

  const variants: [string, (good: string) => string, number][] = [
    ['right', (good) => good, 201],
    ['wrong', (good) => `${good.slice(0, -1)}${good.endsWith('A') ? 'B' : 'A'}`, 401],
    ['short', () => 'x', 401],
    ['long', () => 'x'.repeat(5000), 401],
  ];

  it.each(variants)(
    'a %s token goes through timingSafeEqual on two equal-length digests',
    async (_, token, want) => {
      expect(await status(sock, token(hostToken), agentId)).toBe(want);
      const calls = vi.mocked(timingSafeEqual).mock.calls;
      expect(calls).toHaveLength(1);
      const [presented, expected] = calls[0] as [Buffer, Buffer];
      expect(presented.length).toBe(32);
      expect(expected.length).toBe(32);
    },
  );
});
