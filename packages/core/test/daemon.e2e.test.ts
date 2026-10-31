import { readFileSync, statSync } from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';
import type { AgentResolver, ToolCallObserver } from '@aab/mcp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startDaemon } from '../src/daemon.ts';
import { type Harness, startHarness } from './harness.ts';

function postIntent(socketPath: string, token: string, body: object): Promise<number> {
  return new Promise((resolve, reject) => {
    const json = JSON.stringify(body);
    const req = request(
      {
        socketPath,
        path: '/v1/intents',
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(json),
        },
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode ?? 0));
      },
    );
    req.on('error', reject);
    req.end(json);
  });
}

describe('daemon', () => {
  let h: Harness;
  const events: string[] = [];
  let deps: { resolve: AgentResolver; onToolCall: ToolCallObserver; host: string; port: number };

  beforeAll(async () => {
    h = await startHarness({
      intent: null,
      daemon: {
        mcpPort: 0,
        startMcp: async (d) => {
          deps = d;
          events.push('mcp started');
          return {
            url: 'http://127.0.0.1:65000/mcp',
            close: async () => {
              events.push('mcp closed');
            },
          };
        },
      },
    });
  });
  afterAll(async () => h?.close());

  it('lays out the data dir with tight permissions', () => {
    expect(h.daemon.intentSocketPath).toBe(join(h.dataDir, 'run', 'intent.sock'));
    expect(statSync(join(h.dataDir, 'run')).mode & 0o777).toBe(0o700);
    expect(statSync(h.daemon.intentSocketPath).mode & 0o777).toBe(0o600);
    expect(statSync(join(h.dataDir, 'host-token')).mode & 0o777).toBe(0o600);
    expect(statSync(join(h.dataDir, 'broker.sqlite')).mode & 0o777).toBe(0o600);
    expect(readFileSync(join(h.dataDir, 'host-token'), 'utf8').trim()).toBe(h.daemon.hostToken);
  });

  it('hands the MCP starter a resolver and an observer, and returns its url', async () => {
    expect(h.daemon.mcpUrl).toBe('http://127.0.0.1:65000/mcp');
    expect(deps.host).toBe('127.0.0.1');
    expect(deps.port).toBe(0);
    expect(deps.resolve(h.agent.token)?.agentId).toBe(h.agent.id);
    expect(deps.resolve('aab_agent_nope')).toBeNull();
    deps.onToolCall({ agentId: h.agent.id, tool: 'browser_snapshot', ok: false });
    const last = h.daemon.broker.audit.all().at(-1);
    expect(last?.event_type).toBe('mcp.tool_call');
    expect(JSON.parse(last?.payload_json ?? '{}')).toEqual({
      agentId: h.agent.id,
      tool: 'browser_snapshot',
      ok: false,
    });
  });

  it('a second daemon on the same data dir refuses to start', async () => {
    await expect(
      startDaemon({
        dataDir: h.dataDir,
        passphrase: 'test-passphrase',
        approver: h.approver,
        trustedApproverKeys: h.approverKey.trustEntry(),
      }),
    ).rejects.toThrow();
    expect(statSync(h.daemon.intentSocketPath).isSocket()).toBe(true);
    expect(
      await postIntent(h.daemon.intentSocketPath, h.daemon.hostToken, {
        agentId: h.agent.id,
        text: 'still here',
      }),
    ).toBe(201);
  });

  it('stop tears down MCP first and removes the intent socket', async () => {
    await h.daemon.stop();
    expect(events).toEqual(['mcp started', 'mcp closed']);
    expect(() => statSync(h.daemon.intentSocketPath)).toThrow();
    expect(h.page.isClosed()).toBe(true);
    await h.daemon.stop();
  });
});
