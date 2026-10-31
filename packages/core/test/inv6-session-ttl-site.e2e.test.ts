import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { addPasswordItem } from '../src/passwords.ts';
import { type McpHarness, startMcpHarness } from './mcp-harness.ts';

const PW = 'alice-ttl-site-pass-7q';
const CLI = join(import.meta.dirname, '..', '..', 'cli', 'src', 'main.ts');

function keyflap(dataDir: string, ...args: string[]): Promise<number> {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args, '--data-dir', dataDir], { timeout: 20_000 }, (err) =>
      resolve(err ? 1 : 0),
    );
  });
}

async function until(cond: () => boolean | Promise<boolean>, ms = 10_000): Promise<void> {
  const end = Date.now() + ms;
  while (!(await cond())) {
    if (Date.now() > end) throw new Error('timed out waiting');
    await new Promise((r) => setTimeout(r, 100));
  }
}

describe('policy section 9: a session TTL ends the whole site (review M3)', () => {
  let h: McpHarness;
  let app: string;
  const types = () => h.auditEvents().map((e) => e.type);

  beforeEach(async () => {
    h = await startMcpHarness({
      agentName: 'ttl-agent',
      rp: { users: [{ username: 'alice', password: PW }] },
      daemon: { sessionSweepMs: 200 },
    });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: PW },
    );
    app = `http://app.rp.localhost:${new URL(h.rp.url).port}`;
    const ctx = await h.context();
    await ctx.route(`${app}/**`, (r) =>
      r.fulfill({ contentType: 'text/html', body: '<h1>app</h1>' }),
    );
    await ctx.route('http://elsewhere.localhost/**', (r) =>
      r.fulfill({ contentType: 'text/html', body: '<h1>elsewhere</h1>' }),
    );
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    await h.intent('sign in to the test RP');
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
  });
  afterEach(async () => h?.close());

  async function useAppThenLeave(): Promise<void> {
    await h.mcp.ok('browser_open', { url: `${app}/` });
    await h.page().evaluate(() => localStorage.setItem('bearer', 'app-token'));
    await h.mcp.ok('browser_open', { url: 'http://elsewhere.localhost/' });
    expect(new URL(h.page().url()).hostname).toBe('elsewhere.localhost');
  }

  async function appToken(): Promise<string | null> {
    await h.mcp.ok('browser_open', { url: `${app}/` });
    return h.page().evaluate(() => localStorage.getItem('bearer'));
  }

  it("clears local storage on the site's other origins too", async () => {
    await useAppThenLeave();
    expect(await keyflap(h.dataDir, 'policy', 'set', 'rp.localhost', '--session-ttl', '2s')).toBe(
      0,
    );
    await h.mcp.ok('browser_open', { url: 'http://elsewhere.localhost/' });
    await until(() => types().includes('session.cleared'));
    expect(await appToken()).toBeNull();
  });

  it('a TTL on another origin of the site fires while the daemon runs', async () => {
    await useAppThenLeave();
    expect(await keyflap(h.dataDir, 'policy', 'set', app, '--session-ttl', '2s')).toBe(0);
    await until(() => types().includes('session.cleared'));
    const cleared = h.auditEvents().find((e) => e.type === 'session.cleared');
    expect(cleared?.payload).toMatchObject({ agentId: h.agent.id, ttlMs: 2000, via: 'ttl' });
    const cookies = await (await h.context()).cookies();
    expect(cookies.filter((c) => c.domain.endsWith('rp.localhost'))).toEqual([]);
    expect(await appToken()).toBeNull();
  });
});
