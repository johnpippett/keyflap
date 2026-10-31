import { rmSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { ApproverKey, ScriptedApprover } from '@aab/approver';
import {
  AgentRegistry,
  Broker,
  type IntentServer,
  loadOrCreateHostToken,
  openDb,
  startIntentServer,
} from '@aab/core';
import { expect } from 'vitest';
import type { CliResult } from './helpers.ts';
import { tmpDir } from './helpers.ts';

const fakeSigner = {
  createCredential: () => Promise.reject(new Error('unused')),
  sign: () => Promise.reject(new Error('unused')),
  releaseSecret: () => Promise.reject(new Error('unused')),
};

export const SECRET_WORDS = 'zebra-umbrella-7781';

export interface IntentFixture {
  dir: string;
  db: DatabaseSync;
  broker: Broker;
  registry: AgentRegistry;
  token: string;
  agentId: string;
  intents: () => { agent_id: string; text: string }[];
  expectSilentExit0: (r: CliResult) => void;
  close: () => Promise<void>;
}

export async function startIntentFixture(agentName: string): Promise<IntentFixture> {
  const dir = tmpDir();
  const db = openDb(join(dir, 'broker.sqlite'));
  const broker = new Broker({
    db,
    signer: fakeSigner,
    approver: new ScriptedApprover(ApproverKey.generate('t')),
  });
  const registry = new AgentRegistry(db);
  const token = loadOrCreateHostToken(join(dir, 'host-token'));
  const agentId = registry.add(agentName).id;
  const server: IntentServer = await startIntentServer({
    socketPath: join(dir, 'run', 'intent.sock'),
    hostToken: token,
    registry,
    broker,
  });
  return {
    dir,
    db,
    broker,
    registry,
    token,
    agentId,
    intents: () =>
      db.prepare('SELECT agent_id, text FROM intents ORDER BY created_at, rowid').all() as {
        agent_id: string;
        text: string;
      }[],
    expectSilentExit0: (r) => {
      expect(r.signal).toBeNull();
      expect(r.code).toBe(0);
      expect(r.stdout).toBe('');
      expect(r.stderr).not.toContain(token);
      expect(r.stderr).not.toContain(SECRET_WORDS);
    },
    close: async () => {
      await server.close();
      db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
