import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agents.ts';
import { openDb } from '../src/db.ts';
import { type Harness, signUpAndRegister, startHarness } from './harness.ts';

describe('invariant 6: an agent revoked by another process', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await startHarness({ daemon: { revokeWatchMs: 100 } });
    expect(await signUpAndRegister(h, 'rae')).toBe('passkey added');
  });
  afterAll(async () => h?.close());

  it('gets no assertion and no prompt, and loses its browser context', async () => {
    await h.page.goto(`${h.rp.url}login`);
    const before = h.approver.seen.length;
    const closed = new Promise<void>((r) => h.context.once('close', () => r()));

    const cli = openDb(join(h.dataDir, 'broker.sqlite'));
    try {
      expect(new AgentRegistry(cli).revoke(h.agent.id)).toBe(true);
    } finally {
      cli.close();
    }

    const res = await h.page
      .evaluate(async () => {
        try {
          await navigator.credentials.get({
            publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)) },
          });
          return 'ok';
        } catch (e) {
          return (e as Error).name;
        }
      })
      .catch(() => 'context closed');
    expect(res).not.toBe('ok');
    expect(h.approver.seen.length).toBe(before);
    await closed;
    expect(h.daemon.sessions.peek(h.agent.id)).toBeUndefined();
  });
});
