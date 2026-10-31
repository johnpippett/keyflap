import { createHash, createPrivateKey } from 'node:crypto';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { UNKNOWN_TOOL } from '@aab/mcp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { KeyStore } from '../../signer/src/keystore.ts';
import { AuditLog } from '../src/audit.ts';
import { tmpDir } from './harness.ts';
import {
  dbPath,
  keyStorePath,
  type McpHarness,
  PASSPHRASE,
  postIntent,
  startMcpHarness,
} from './mcp-harness.ts';

const INTENT = 'ZQXintent: add a passkey to my zqx account and sign in with it';
const TERMINAL = new Set(['denied', 'passkey.created', 'passkey.signed']);
const ALLOWED_FIELDS = new Set([
  'requestId',
  'agentId',
  'kind',
  'verifiedOrigin',
  'reason',
  'approved',
  'rpId',
  'credentialId',
  'tool',
  'ok',
  'origin',
  'intentId',
  'textSha256',
  'status',
]);

const EVIL_PAGE = `<!doctype html><title>evil</title><body>
<button id="go" type="button">Go</button><p id="status">idle</p>
<script>
document.getElementById('go').onclick = async () => {
  try {
    await navigator.credentials.create({ publicKey: {
      rp: { id: 'rp.localhost', name: 'ZQXevil_rp_name' },
      user: { id: new TextEncoder().encode('ZQXu'), name: 'ZQXevil_user', displayName: 'ZQXevil' },
      challenge: new TextEncoder().encode('ZQXevil_challenge_0123456789'),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    } });
  } catch (e) { document.getElementById('status').textContent = 'error: ' + e.name; }
};
</script></body>`;

const hashOf = (prev: string, seq: number, ts: number, type: string, payload: string) =>
  createHash('sha256').update(`${prev}\n${seq}\n${ts}\n${type}\n${payload}`).digest('hex');

describe('invariant 10: append-only, hash-chained audit of everything', () => {
  let h: McpHarness;
  const secrets: { label: string; value: string }[] = [];
  let unknownToolCalls = 0;
  let schemaRejected = 0;
  let rpPort: string;

  beforeAll(async () => {
    h = await startMcpHarness({ agentName: 'inv10-agent', daemon: { actionTimeoutMs: 1000 } });
    rpPort = new URL(h.rp.origin).port;
    const ctx = await h.context();
    ctx.on('response', async (res) => {
      if (!/\/api\/passkey\/(register|login)\/options$/.test(res.url())) return;
      const json = (await res.json().catch(() => ({}))) as { challenge?: string };
      if (json.challenge) secrets.push({ label: 'challenge', value: json.challenge });
    });
    ctx.on('request', (req) => {
      if (!/\/api\/passkey\/(register|login)\/verify$/.test(req.url())) return;
      const body = req.postDataJSON() as { response?: Record<string, unknown> };
      for (const [k, v] of Object.entries(body.response ?? {})) {
        if (typeof v === 'string' && v.length >= 16) secrets.push({ label: k, value: v });
      }
    });
    await ctx.route(/^http:\/\/evil\.localhost:\d+\//, (route) =>
      route.fulfill({ contentType: 'text/html', body: EVIL_PAGE }),
    );
  });
  afterAll(async () => h?.close());

  it('runs a mixed session', async () => {
    const m = h.mcp;
    expect(
      (
        await postIntent(
          h.daemon.intentSocketPath,
          { agentId: h.agent.id, text: INTENT },
          { token: 'x'.repeat(43) },
        )
      ).status,
    ).toBe(401);
    await h.intent(INTENT);

    await m.ok('browser_open', { url: `${h.rp.url}signup?zqxurl=zqxquery` });
    await m.ok('browser_type', {
      target: { css: 'input#username:not(.zqxcss)' },
      text: 'zqxtyped-user',
      submit: true,
    });
    expect(await m.err('browser_open', { url: `${h.rp.url}`, zqxextra: 'zqx' })).toMatch(
      /invalid arguments/,
    );
    schemaRejected++;
    await expect(
      m.client.callTool({ name: 'zqx_evaluate', arguments: { expression: 'zqx' } }),
    ).rejects.toThrow(/unknown tool/);
    unknownToolCalls++;

    await m.ok('browser_click', { target: { role: 'button', name: 'Add a passkey' } });
    expect(await m.ok('auth_enroll_passkey')).toEqual({ status: 'success' });

    h.approver.decide = () => false;
    await m.ok('browser_click', { target: { role: 'button', name: 'Log out' } });
    await m.ok('browser_open', { url: `${h.rp.url}login` });
    await m.ok('browser_click', { target: { role: 'button', name: 'Sign in with a passkey' } });
    expect(await m.ok('auth_login')).toEqual({ status: 'denied' });

    await m.ok('browser_open', { url: `http://evil.localhost:${rpPort}/` });
    await m.ok('browser_click', { target: { css: '#go' } });
    expect(await m.ok('auth_enroll_passkey')).toEqual({ status: 'denied' });

    h.approver.decide = () => true;
    await m.ok('browser_open', { url: `${h.rp.url}login` });
    await m.ok('browser_click', { target: { role: 'button', name: 'Sign in with a passkey' } });
    expect(await m.ok('auth_login')).toEqual({ status: 'success' });
    await expect.poll(() => h.rp.logins.at(-1)?.username).toBe('zqxtyped-user');
    await m.ok('browser_snapshot');

    expect(h.approver.seen).toHaveLength(3);
  });

  it('the chain verifies', () => {
    expect(h.daemon.broker.audit.verify()).toBeNull();
    const rows = h.daemon.broker.audit.all();
    expect(rows.map((r) => r.seq)).toEqual(rows.map((_, i) => i + 1));
  });

  it('every intent submission is logged, accepted or not, with only a hash of the text', () => {
    const ev = h.auditEvents();
    const recorded = ev.filter((e) => e.type === 'intent.recorded');
    const rejected = ev.filter((e) => e.type === 'intent.rejected');
    expect(rejected.map((e) => e.payload)).toEqual([{ status: 401, reason: 'bad_host_token' }]);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]?.payload).toEqual({
      intentId: expect.any(String),
      agentId: h.agent.id,
      textSha256: createHash('sha256').update(INTENT, 'utf8').digest('hex'),
    });
    expect((rejected[0]?.seq as number) < (recorded[0]?.seq as number)).toBe(true);
  });

  it('every MCP tool call is logged; every call that reached the browser is logged again with its origin', () => {
    const ev = h.auditEvents();
    const mcp = ev.filter((e) => e.type === 'mcp.tool_call').map((e) => e.payload);
    const port = ev.filter((e) => e.type === 'tool.call').map((e) => e.payload);
    expect(mcp).toHaveLength(h.mcp.calls + unknownToolCalls);
    expect(port).toHaveLength(h.mcp.calls - schemaRejected);
    expect(mcp.filter((p) => p.tool === UNKNOWN_TOOL)).toEqual([
      { agentId: h.agent.id, tool: UNKNOWN_TOOL, ok: false },
    ]);
    const strip = (p: Record<string, unknown>) => `${p.tool}:${p.ok}`;
    const reachedPort = mcp.filter(
      (p) => p.tool !== UNKNOWN_TOOL && !(p.tool === 'browser_open' && p.ok === false),
    );
    expect(reachedPort.map(strip)).toEqual(port.map(strip));
    for (const p of [...mcp, ...port]) expect(p.agentId).toBe(h.agent.id);
    for (const p of port.filter((x) => x.origin !== undefined)) {
      expect(p.origin).toMatch(/^http:\/\/(rp|evil)\.localhost:\d+$/);
    }
  });

  it('every request has a decision trail ending in exactly one terminal event', () => {
    const ev = h.auditEvents();
    const requests = ev.filter((e) => e.type === 'request');
    const outcome = requests.map((r) => {
      const id = r.payload.requestId;
      const related = ev.filter((e) => e.payload.requestId === id && e.seq !== r.seq);
      const terminal = related.filter((e) => TERMINAL.has(e.type));
      expect(terminal, String(id)).toHaveLength(1);
      const t = terminal[0] as (typeof terminal)[number];
      expect(t.seq).toBeGreaterThan(r.seq);
      const approvals = related.filter((e) => e.type === 'approval');
      for (const a of approvals) {
        expect(a.seq).toBeGreaterThan(r.seq);
        expect(a.seq).toBeLessThan(t.seq);
      }
      expect(related.every((e) => e.seq <= t.seq)).toBe(true);
      return [
        r.payload.kind,
        approvals.map((a) => a.payload.approved),
        t.type,
        t.payload.reason ?? null,
      ];
    });
    expect(outcome).toEqual([
      ['passkey.create', [true], 'passkey.created', null],
      ['passkey.get', [false], 'denied', 'approval_user_denied'],
      ['passkey.create', [], 'denied', 'rp_id_not_allowed_for_origin'],
      ['passkey.get', [true], 'passkey.signed', null],
    ]);
    const rows = h.daemon.db
      .prepare('SELECT id, kind, status FROM requests ORDER BY created_at, rowid')
      .all() as { id: string; kind: string; status: string }[];
    expect(rows.map((r) => r.id)).toEqual(requests.map((r) => r.payload.requestId));
    expect(rows.map((r) => r.status)).toEqual(['completed', 'denied', 'denied', 'completed']);
    const firstRequest = requests[0]?.seq as number;
    const recorded = ev.find((e) => e.type === 'intent.recorded')?.seq as number;
    expect(recorded).toBeLessThan(firstRequest);
  });

  it('payloads carry identifiers and origins only: no intent text, typed text, challenges, signatures or keys', () => {
    const rows = h.daemon.broker.audit.all();
    for (const r of rows) {
      for (const k of Object.keys(JSON.parse(r.payload_json))) {
        expect(ALLOWED_FIELDS.has(k), `${r.event_type}.${k}`).toBe(true);
      }
    }
    const text = JSON.stringify(rows);
    expect(text.toLowerCase()).not.toContain('zqx');
    expect(text).not.toContain('add a passkey');
    expect(secrets.filter((s) => s.label === 'challenge')).toHaveLength(3);
    expect(secrets.some((s) => s.label === 'signature')).toBe(true);
    expect(secrets.some((s) => s.label === 'attestationObject')).toBe(true);
    for (const a of h.approver.signed)
      secrets.push({ label: 'approval signature', value: a.signature as string });
    const store = KeyStore.open(keyStorePath(h.dataDir), PASSPHRASE);
    for (const { id } of h.daemon.broker.credentials.allPasskeyRpIds()) {
      const pk = store.get(id)?.privateKey as string;
      const jwk = createPrivateKey({
        key: Buffer.from(pk, 'base64'),
        format: 'der',
        type: 'pkcs8',
      }).export({
        format: 'jwk',
      });
      secrets.push({ label: 'pkcs8', value: pk }, { label: 'd', value: jwk.d as string });
    }
    secrets.push(
      { label: 'host token', value: h.daemon.hostToken },
      { label: 'agent token', value: h.agent.token },
    );
    for (const s of secrets) expect(text.includes(s.value), s.label).toBe(false);
  });

  it('UPDATE, DELETE and INSERT OR REPLACE on the audit table are refused, on any connection', () => {
    const raw = new DatabaseSync(dbPath(h.dataDir));
    try {
      for (const db of [h.daemon.db, raw]) {
        expect(() =>
          db.prepare(`UPDATE audit SET payload_json = '{}' WHERE seq = 1`).run(),
        ).toThrow(/append-only/);
        expect(() => db.prepare('DELETE FROM audit WHERE seq = 1').run()).toThrow(/append-only/);
        expect(() => db.prepare('DELETE FROM audit').run()).toThrow(/append-only/);
        expect(() =>
          db
            .prepare(
              `INSERT OR REPLACE INTO audit (seq, prev_hash, hash, ts, event_type, payload_json)
               VALUES (1, 'x', 'x', 0, 'forged', '{}')`,
            )
            .run(),
        ).toThrow(/append-only/);
        expect(() =>
          db
            .prepare(
              `INSERT INTO audit (seq, prev_hash, hash, ts, event_type, payload_json)
               VALUES (1, 'x', 'x', 0, 'forged', '{}') ON CONFLICT(seq) DO UPDATE SET event_type = 'forged'`,
            )
            .run(),
        ).toThrow(/append-only/);
      }
    } finally {
      raw.close();
    }
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });

  describe('tampering behind the triggers (raw connection, triggers dropped) is caught at the right seq', () => {
    const dir = tmpDir();
    let n = 0;
    let k: number;
    let total: number;
    const tamperable = (): DatabaseSync => {
      const path = join(dir, `copy-${n++}.sqlite`);
      h.daemon.db.exec(`VACUUM INTO '${path}'`);
      const db = new DatabaseSync(path);
      db.exec(
        'DROP TRIGGER IF EXISTS audit_no_update; DROP TRIGGER IF EXISTS audit_no_delete; DROP TRIGGER IF EXISTS audit_no_replace;',
      );
      return db;
    };
    afterAll(() => rmSync(dir, { recursive: true, force: true }));
    const verify = (db: DatabaseSync) => {
      try {
        return new AuditLog(db).verify();
      } finally {
        db.close();
      }
    };

    beforeAll(() => {
      const rows = h.daemon.broker.audit.all();
      total = rows.length;
      k = rows.find(
        (r) => r.event_type === 'approval' && r.payload_json.includes('"approved":false'),
      )?.seq as number;
      expect(k).toBeGreaterThan(1);
      expect(k).toBeLessThan(total);
    });

    it('an untouched copy verifies', () => {
      expect(verify(tamperable())).toBeNull();
    });

    it('edited payload, event type or timestamp: that seq', () => {
      for (const set of [
        `payload_json = replace(payload_json, 'false', 'true')`,
        `event_type = 'approval.forged'`,
        'ts = ts + 1',
        `prev_hash = '${'0'.repeat(64)}'`,
      ]) {
        const db = tamperable();
        db.prepare(`UPDATE audit SET ${set} WHERE seq = ?`).run(k);
        expect(verify(db), set).toBe(k);
      }
    });

    it('edited row with its own hash recomputed: the next seq', () => {
      const db = tamperable();
      const r = db.prepare('SELECT * FROM audit WHERE seq = ?').get(k) as {
        prev_hash: string;
        ts: number;
        event_type: string;
        payload_json: string;
      };
      const payload = r.payload_json.replace('false', 'true');
      db.prepare('UPDATE audit SET payload_json = ?, hash = ? WHERE seq = ?').run(
        payload,
        hashOf(r.prev_hash, k, r.ts, r.event_type, payload),
        k,
      );
      expect(verify(db)).toBe(k + 1);
    });

    it('a deleted row: the seq after the gap', () => {
      const db = tamperable();
      db.prepare('DELETE FROM audit WHERE seq = ?').run(k);
      expect(verify(db)).toBe(k + 1);
    });

    it('a row inserted at the end without the chain: that seq', () => {
      const db = tamperable();
      db.prepare(
        `INSERT INTO audit (seq, prev_hash, hash, ts, event_type, payload_json) VALUES (?, ?, ?, ?, 'forged', '{}')`,
      ).run(total + 1, '0'.repeat(64), '0'.repeat(64), Date.now());
      expect(verify(db)).toBe(total + 1);
    });

    it('live: dropping the trigger on the daemon database and editing a row is caught by the daemon', () => {
      const raw = new DatabaseSync(dbPath(h.dataDir));
      try {
        raw.exec('DROP TRIGGER IF EXISTS audit_no_update');
        raw
          .prepare(
            `UPDATE audit SET payload_json = replace(payload_json, 'false', 'true') WHERE seq = ?`,
          )
          .run(k);
      } finally {
        raw.close();
      }
      expect(h.daemon.broker.audit.verify()).toBe(k);
    });
  });
});

describe('invariant 10: human handoffs are audited with identifiers and origins only', () => {
  const TYPED = 'ZQXtyped-owner-text';
  const PAGE = `<h1>ZQXpage-text</h1>
<label>Note <input id="note"></label>
<label>Password <input id="pw" type="password"></label>
<script>document.getElementById('note').addEventListener('input', (e) => {
  document.cookie = 'ZQXcookie_name=' + encodeURIComponent(e.target.value) + '; path=/';
});</script>`;
  const HANDOFF_FIELDS = new Set([
    'handoffId',
    'agentId',
    'verifiedOrigin',
    'reason',
    'provider',
    'deviceId',
    'outcome',
    'durationMs',
    'inputs',
    'requestId',
    'kind',
    'withSignIn',
    'signInSkipped',
    'via',
  ]);
  let h: import('./handoff-harness.ts').HandoffHarness;

  beforeAll(async () => {
    const { startHandoffHarness } = await import('./handoff-harness.ts');
    h = await startHandoffHarness({ password: false });
  });
  afterAll(async () => h?.close());

  it('every refusal, open, start, refused input, end and handoff_open denial is in the chain', async () => {
    const { routeChallengePage } = await import('./handoff-harness.ts');
    const url = await routeChallengePage(h, '/inv10-check', PAGE, 'ZQXtitle');
    await h.mcp.ok('browser_open', { url });
    expect(await h.mcp.ok('browser_handoff', { timeoutMs: 1000 })).toEqual({ status: 'denied' });
    await h.intent('ZQXintent: get me past the check');
    const handoff = h.mcp.ok('browser_handoff', { timeoutMs: 60_000 });
    await h.openLiveView();
    await h.tapOnPhone('#pw');
    await h.phonePage.fill('#text', 'ZQXpw-attempt');
    await h.phonePage.click('#text-form button');
    await h.phonePage.locator('#input-error').waitFor({ state: 'visible' });
    await h.tapOnPhone('#note');
    await h.phonePage.fill('#text', TYPED);
    await h.phonePage.click('#text-form button');
    await h.phonePage.click('.key[data-key="Enter"]');
    await h.phonePage.click('.scroll[data-dy="400"]');
    await h
      .page()
      .evaluate(() =>
        navigator.credentials
          .get({ publicKey: { challenge: new Uint8Array(32), timeout: 2000 } })
          .catch(() => null),
      );
    await h.phonePage.click('#done');
    expect(await handoff).toEqual({ status: 'done' });

    const events = h.auditEvents();
    const types = events.map((e) => e.type);
    for (const t of [
      'handoff.denied',
      'handoff.requested',
      'handoff.started',
      'handoff.input_refused',
      'handoff.ended',
    ]) {
      expect(types, t).toContain(t);
    }
    expect(events.some((e) => e.type === 'denied' && e.payload.reason === 'handoff_open')).toBe(
      true,
    );
    const ended = events.find((e) => e.type === 'handoff.ended');
    expect(ended?.payload.inputs).toEqual({ clicks: 2, scrolls: 1, drags: 0, keys: 1, texts: 1 });
    expect(h.daemon.broker.audit.verify()).toBeNull();

    for (const e of events.filter((x) => x.type.startsWith('handoff.'))) {
      for (const k of Object.keys(e.payload))
        expect(HANDOFF_FIELDS.has(k), `${e.type}.${k}`).toBe(true);
      if (e.payload.inputs !== undefined) {
        for (const v of Object.values(e.payload.inputs as Record<string, unknown>)) {
          expect(Number.isInteger(v)).toBe(true);
        }
      }
    }
    const all = JSON.stringify(h.daemon.broker.audit.all());
    for (const leak of [
      TYPED,
      'ZQXpw-attempt',
      'ZQXpage-text',
      'ZQXtitle',
      'ZQXcookie_name',
      'ZQXintent',
    ]) {
      expect(all).not.toContain(leak);
    }
    expect(all).not.toMatch(/"x":|"y":|"dy":|\/9j\/|jpeg/);
  });
});

describe('invariant 10 (P3b): one approval for human check + sign-in is audited, identifiers only', () => {
  const GRANT_FIELDS = new Set([
    'requestId',
    'grantId',
    'agentId',
    'verifiedOrigin',
    'until',
    'singleUse',
    'handoffId',
    'reason',
  ]);
  let h: import('./handoff-harness.ts').HandoffHarness;

  beforeAll(async () => {
    const { startHandoffHarness } = await import('./handoff-harness.ts');
    h = await startHandoffHarness({ rp: { challenge: 'aws-waf', challengeAt: 'login-page' } });
  });
  afterAll(async () => h?.close());

  it('request, approval, grant.created, handoff.started (via approval), grant.armed, grant.used are chained', async () => {
    await h.intent('ZQXintent: sign me in');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const handoff = h.mcp.ok('browser_handoff', { timeoutMs: 60_000 });
    await h.phonePage.goto(`${h.approver.origin}/`);
    await h.phonePage.locator('#requests .card .approve').first().click();
    await h.phonePage.waitForURL(`${h.approver.origin}/handoff`, { timeout: 15_000 });
    await h.phonePage.locator('#live').waitFor({ state: 'visible', timeout: 15_000 });
    await h.phonePage.waitForFunction(() => {
      const img = document.querySelector('#screen') as HTMLImageElement | null;
      return img?.complete === true && img.naturalWidth > 0;
    });
    await h.tapOnPhone('#challenge-solve');
    await h.page().locator('input[name="password"]').waitFor({ timeout: 10_000 });
    await h.phonePage.click('#done');
    expect(await handoff).toEqual({ status: 'done' });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });

    const events = h.auditEvents();
    const types = events.map((e) => e.type);
    for (const t of [
      'handoff.requested',
      'request',
      'approval',
      'grant.created',
      'handoff.started',
      'handoff.ended',
      'grant.armed',
      'grant.used',
      'fill.released',
      'fill.completed',
    ]) {
      expect(types, t).toContain(t);
    }
    const req = events.find((e) => e.type === 'request' && e.payload.kind === 'handoff.sign-in');
    expect(req?.payload).toMatchObject({ agentId: h.agent.id, verifiedOrigin: h.rp.origin });
    expect(typeof req?.payload.handoffId).toBe('string');
    expect(
      events.find((e) => e.type === 'approval' && e.payload.requestId === req?.payload.requestId)
        ?.payload,
    ).toMatchObject({ approved: true });
    for (const e of events.filter((x) => x.type.startsWith('grant.'))) {
      for (const k of Object.keys(e.payload))
        expect(GRANT_FIELDS.has(k), `${e.type}.${k}`).toBe(true);
    }
    const all = JSON.stringify(h.daemon.broker.audit.all());
    expect(all).not.toContain('ZQXintent');
    expect(all).not.toMatch(/"x":|"y":|\/9j\/|jpeg/);
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});
