import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, lstatSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { dirname, join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { ApproverKey, ScriptedApprover } from '@aab/approver';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agents.ts';
import { Broker } from '../src/broker.ts';
import { openDb } from '../src/db.ts';
import {
  type IntentServer,
  loadOrCreateHostToken,
  MAX_INTENT_BODY,
  startIntentServer,
} from '../src/intent-server.ts';
import { tmpDir } from './harness.ts';

interface Res {
  status: number;
  body: Record<string, unknown>;
}

function post(
  socketPath: string,
  opts: {
    path?: string;
    method?: string;
    token?: string | null;
    body?: string | Buffer;
    headers?: Record<string, string>;
    holdBody?: boolean;
  },
): Promise<Res> {
  return new Promise((resolve, reject) => {
    const body = opts.body ?? '';
    let answered = false;
    const req = request(
      {
        socketPath,
        path: opts.path ?? '/v1/intents',
        method: opts.method ?? 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(body)),
          ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
          ...opts.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString();
          answered = true;
          resolve({ status: res.statusCode ?? 0, body: text ? JSON.parse(text) : {} });
          if (opts.holdBody) req.destroy();
        });
      },
    );
    req.on('error', (e) => {
      if (!answered) reject(e);
    });
    if (opts.holdBody) req.flushHeaders();
    else req.end(body);
  });
}

const fakeSigner = {
  createCredential: () => Promise.reject(new Error('unused')),
  sign: () => Promise.reject(new Error('unused')),
  releaseSecret: () => Promise.reject(new Error('unused')),
};

describe('intent socket', () => {
  let dir: string;
  let db: DatabaseSync;
  let broker: Broker;
  let registry: AgentRegistry;
  let server: IntentServer;
  let token: string;
  let sock: string;
  let agent: { id: string; name: string };

  beforeAll(async () => {
    dir = tmpDir();
    db = openDb(join(dir, 'broker.sqlite'));
    broker = new Broker({
      db,
      signer: fakeSigner,
      approver: new ScriptedApprover(ApproverKey.generate()),
    });
    registry = new AgentRegistry(db);
    agent = registry.add('claude-code');
    token = loadOrCreateHostToken(join(dir, 'host-token'));
    sock = join(dir, 'run', 'intent.sock');
    server = await startIntentServer({ socketPath: sock, hostToken: token, registry, broker });
  });
  afterAll(async () => {
    await server.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const audit = () => broker.audit.all();
  const send = (body: unknown, t: string | null = token) =>
    post(sock, { token: t, body: JSON.stringify(body) });

  it('files: run dir 0700, socket 0600, host token 0600 with 32 random bytes', () => {
    expect(statSync(dirname(sock)).mode & 0o777).toBe(0o700);
    expect(statSync(sock).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, 'host-token')).mode & 0o777).toBe(0o600);
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    expect(loadOrCreateHostToken(join(dir, 'host-token'))).toBe(token);
  });

  it('201: records the text verbatim for that agent; audit gets only its hash', async () => {
    const text = 'Sign me in to rp.localhost — "quoted", ünïcödé, <tags>\nand a second line ';
    const res = await send({ agentId: agent.id, text });
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ intentId: expect.any(String), expiresAt: expect.any(Number) });
    const live = broker.intents.latestLive(agent.id);
    expect(live).toMatchObject({ id: res.body.intentId, text, agentId: agent.id });
    const row = audit().at(-1);
    expect(row?.event_type).toBe('intent.recorded');
    expect(JSON.parse(row?.payload_json ?? '{}')).toEqual({
      intentId: res.body.intentId,
      agentId: agent.id,
      textSha256: createHash('sha256').update(text).digest('hex'),
    });
    expect(JSON.stringify(audit())).not.toContain('Sign me in');
    expect(broker.audit.verify()).toBeNull();
  });

  it('text bounds: 1 and 8000 characters accepted; 0 and 8001 refused', async () => {
    expect((await send({ agentId: agent.id, text: 'x' })).status).toBe(201);
    expect((await send({ agentId: agent.id, text: 'y'.repeat(8000) })).status).toBe(201);
    expect((await send({ agentId: agent.id, text: '' })).status).toBe(400);
    expect((await send({ agentId: agent.id, text: 'z'.repeat(8001) })).status).toBe(400);
  });

  it('400: text containing U+0000 (SQLite would truncate it there); nothing recorded', async () => {
    const before = broker.intents.latestLive(agent.id)?.id;
    for (const text of ['\u0000', 'sign in to rp\u0000 but never to my bank']) {
      expect((await send({ agentId: agent.id, text })).status).toBe(400);
    }
    expect(broker.intents.latestLive(agent.id)?.id).toBe(before);
    const ctl = 'a\u0001\u0007\u001b[2J\u007f\u009b\r\nb';
    expect((await send({ agentId: agent.id, text: ctl })).status).toBe(201);
    expect(broker.intents.latestLive(agent.id)?.text).toBe(ctl);
  });

  it('400: malformed bodies', async () => {
    for (const body of [
      'not json',
      '[]',
      'null',
      '"text"',
      JSON.stringify({ agentId: agent.id }),
      JSON.stringify({ text: 'hi' }),
      JSON.stringify({ agentId: 7, text: 'hi' }),
      JSON.stringify({ agentId: agent.id, text: 7 }),
      JSON.stringify({ agentId: agent.id, text: 'hi', origin: 'https://bank.com' }),
      Buffer.from([0x7b, 0xff, 0xfe, 0x7d]),
    ]) {
      expect((await post(sock, { token, body })).status).toBe(400);
    }
    const wrongType = await post(sock, {
      token,
      body: JSON.stringify({ agentId: agent.id, text: 'hi' }),
      headers: { 'content-type': 'text/plain' },
    });
    expect(wrongType.status).toBe(400);
  });

  it('404: nothing else is routed', async () => {
    const body = JSON.stringify({ agentId: agent.id, text: 'hi' });
    for (const [method, path] of [
      ['GET', '/v1/intents'],
      ['PUT', '/v1/intents'],
      ['POST', '/v1/intents/'],
      ['POST', '/v1/intents?x=1'],
      ['POST', '/'],
      ['GET', '/v1/agents'],
    ] as const) {
      expect((await post(sock, { method, path, token, body })).status).toBe(404);
    }
  });

  it('413: body over 64 KiB', async () => {
    const text = 'a'.repeat(MAX_INTENT_BODY);
    const over = JSON.stringify({ agentId: agent.id, text });
    const res = await post(sock, { token, body: over, holdBody: true });
    expect(res.status).toBe(413);
    const pad = MAX_INTENT_BODY - JSON.stringify({ agentId: agent.id, text: '' }).length;
    const atCap = JSON.stringify({ agentId: agent.id, text: 'b'.repeat(pad) });
    expect(Buffer.byteLength(atCap)).toBe(MAX_INTENT_BODY);
    expect((await post(sock, { token, body: atCap })).status).toBe(400);
  });

  it('refuses to start where something is already listening', async () => {
    await expect(
      startIntentServer({ socketPath: sock, hostToken: token, registry, broker }),
    ).rejects.toThrow(/already listening/);
    const stalePath = join(dir, 'run', 'stale.sock');
    const child = spawn(
      process.execPath,
      [
        '-e',
        `require('node:net').createServer().listen(${JSON.stringify(stalePath)}, () => console.log('up'))`,
      ],
      { stdio: ['ignore', 'pipe', 'inherit'] },
    );
    await new Promise<void>((r) => child.stdout?.once('data', () => r()));
    child.kill('SIGKILL');
    await new Promise<void>((r) => child.once('exit', () => r()));
    expect(lstatSync(stalePath).isSocket()).toBe(true);
    const fresh = await startIntentServer({
      socketPath: stalePath,
      hostToken: token,
      registry,
      broker,
    });
    await fresh.close();
  });

  it('host token file: refuses one readable by others, or with junk in it', () => {
    const p = join(dir, 'loose-token');
    writeFileSync(p, `${'c'.repeat(43)}\n`, { mode: 0o644 });
    chmodSync(p, 0o644);
    expect(() => loadOrCreateHostToken(p)).toThrow(/other users/);
    chmodSync(p, 0o600);
    expect(loadOrCreateHostToken(p)).toBe('c'.repeat(43));
    const junk = join(dir, 'junk-token');
    writeFileSync(junk, 'short', { mode: 0o600 });
    expect(() => loadOrCreateHostToken(junk)).toThrow(/valid token/);
    expect(readFileSync(junk, 'utf8')).toBe('short');
  });
});
