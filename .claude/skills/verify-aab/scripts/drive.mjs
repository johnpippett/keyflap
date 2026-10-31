import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const { REPO, RUN, EVID } = process.env;
const feature = process.argv[2];
const state = JSON.parse(readFileSync(join(RUN, 'state.json'), 'utf8'));
const agentToken = readFileSync(join(RUN, 'agent.token'), 'utf8').trim();
const hostToken = readFileSync(join(state.dataDir, 'host-token'), 'utf8').trim();
const passphrase = readFileSync(join(RUN, 'passphrase'), 'utf8').trim();
const out = join(EVID, feature.startsWith('persistence') ? 'persistence' : feature);
mkdirSync(out, { recursive: true });
const MAIN = `${REPO}/packages/cli/src/main.ts`;
const { connectAgent, postIntent } = await import(`${REPO}/packages/core/test/mcp-harness.ts`);
const { TOOL_NAMES } = await import(`${REPO}/packages/mcp/src/tools.ts`);

let failures = 0;
const log = (s) => console.log(s);
async function step(name, fn) {
  try {
    await fn();
    log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    log(`FAIL  ${name}: ${e.message}`);
  }
}
function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}
const save = (file, text) =>
  writeFileSync(join(out, file), typeof text === 'string' ? text : JSON.stringify(text, null, 2));

const rp = state.rpUrl;
const agent = { id: state.agentId, name: 'verify-agent', token: agentToken };
let mcp;
const calls = [];
async function call(tool, args = {}) {
  const result = await mcp.ok(tool, args);
  calls.push({ tool, args, result });
  appendFileSync(join(out, 'steps.jsonl'), `${JSON.stringify({ tool, args, result })}\n`);
  return result;
}
async function intent(text) {
  const r = await postIntent(state.intentSocket, { agentId: agent.id, text }, { token: hostToken });
  expect(r.status === 201, `intent socket answered ${r.status}`);
  return r.body;
}

const BLOCK = '┌─ KEYFLAP · approval requested';
const blocks = () => readFileSync(state.daemonOut, 'utf8').split(BLOCK).slice(1);
let seen = blocks().length;
async function nextPrompt(timeoutMs = 20000) {
  const t0 = Date.now();
  for (;;) {
    const b = blocks();
    if (b.length > seen && /Approve\? \[y\/N\]/.test(b[seen])) return BLOCK + b[seen++];
    if (Date.now() - t0 > timeoutMs) throw new Error('no approval prompt appeared');
    await sleep(100);
  }
}
const answer = (yes) => writeFileSync(state.approveFifo, yes ? 'y\n' : 'n\n');
let promptNo = 0;
async function withApproval(start, yes = true) {
  const pending = start();
  const prompt = await nextPrompt();
  save(`prompt-${++promptNo}.txt`, prompt);
  answer(yes);
  return { prompt, result: await pending };
}
const cli = (...args) =>
  spawnSync(
    process.execPath,
    ['--disable-warning=ExperimentalWarning', MAIN, ...args, '--data-dir', state.dataDir],
    {
      encoding: 'utf8',
      env: process.env,
      cwd: join(RUN, 'home'),
    },
  );
const auditTail = () => JSON.parse(cli('audit', 'tail', '--limit', '500', '--json').stdout);
const snapshot = async () => (await call('browser_snapshot')).snapshot;
async function snapshotUntil(pred, what, timeoutMs = 10000) {
  const t0 = Date.now();
  let snap = await snapshot();
  while (!pred(snap) && Date.now() - t0 < timeoutMs) {
    await sleep(300);
    snap = await snapshot();
  }
  expect(pred(snap), `page never showed: ${what}. Last snapshot:\n${snap}`);
  return snap;
}
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

async function leakChecks(extraSecrets = []) {
  const everything = await mcp.everything();
  const logs =
    readFileSync(state.daemonOut, 'utf8') + readFileSync(join(RUN, 'logs', 'daemon.err'), 'utf8');
  const auditText = JSON.stringify(auditTail());
  for (const [name, secret] of [
    ['host token', hostToken],
    ['key-store passphrase', passphrase],
    ...extraSecrets,
  ]) {
    expect(!everything.includes(secret), `${name} appears in what the MCP server sent the agent`);
    expect(!logs.includes(secret), `${name} appears in the daemon logs`);
    expect(!auditText.includes(secret), `${name} appears in the audit log`);
  }
}
const auditVerified = () => {
  const r = cli('audit', 'verify');
  save('audit-verify.txt', `exit ${r.status}\n${r.stdout}${r.stderr}`);
  expect(r.status === 0, `keyflap audit verify exited ${r.status}`);
};

const features = {
  async passkey() {
    const user = `pk-${Date.now().toString(36)}`;
    await step(
      'precondition: fresh stack, no passkey enrolled yet (a second one makes sign-in deny ambiguous_credential, by design)',
      async () => {
        const s = JSON.parse(cli('status', '--json').stdout);
        expect(
          s.credentials.passkeys === 0,
          `${s.credentials.passkeys} passkey(s) already enrolled: run scripts/cleanup.sh and scripts/launch.sh for a fresh stack`,
        );
      },
    );
    await step('the agent sees exactly the eight broker tools', async () => {
      const names = (await mcp.listTools()).map((t) => t.name).sort();
      expect(JSON.stringify(names) === JSON.stringify([...TOOL_NAMES].sort()), `tools: ${names}`);
      expect(names.length === 8, `expected 8 tools, got ${names.length}`);
    });
    await step(`sign up "${user}" on the test RP (a plain page form, no credential)`, async () => {
      await call('browser_open', { url: `${rp}signup` });
      const r = await call('browser_type', {
        target: { label: 'Username' },
        text: user,
        submit: true,
      });
      expect(r.url === `${rp}account`, `landed on ${r.url}`);
    });
    await step(
      'enroll a passkey: one prompt with the verbatim words, verified origin, agent, type',
      async () => {
        const words = 'add a passkey to my test RP account';
        await intent(words);
        await call('browser_click', { target: { role: 'button', name: 'Add a passkey' } });
        const { prompt, result } = await withApproval(() => call('auth_enroll_passkey'));
        expect(result.status === 'success', `auth_enroll_passkey -> ${JSON.stringify(result)}`);
        expect(prompt.includes(`"${words}"`), "prompt does not show the user's words verbatim");
        expect(
          prompt.includes(`Site:       ${state.rpOrigin}`),
          'prompt does not show the verified origin',
        );
        expect(
          prompt.includes('Agent:      verify-agent'),
          'prompt does not show the agent identity',
        );
        expect(
          prompt.includes('Credential: passkey (register)'),
          'prompt does not show the credential type and action',
        );
        const snap = await snapshotUntil(
          (t) => /passkey added/.test(t) && /Passkeys registered:\s*1/.test(t),
          '"passkey added" and "Passkeys registered: 1"',
        );
        save('snapshot-after-enroll.txt', snap);
      },
    );
    await step('sign in with the passkey after logging out: approve -> signed in', async () => {
      await call('browser_click', { target: { role: 'button', name: 'Log out' } });
      await call('browser_open', { url: `${rp}login` });
      const words = 'sign in to the test RP with my passkey';
      await intent(words);
      await call('browser_click', { target: { role: 'button', name: 'Sign in with a passkey' } });
      const { prompt, result } = await withApproval(() => call('auth_login'));
      expect(result.status === 'success', `auth_login -> ${JSON.stringify(result)}`);
      expect(prompt.includes(`"${words}"`), "sign-in prompt does not show the user's words");
      expect(
        prompt.includes('Credential: passkey (sign-in)'),
        'sign-in prompt does not show the credential type and action',
      );
      const snap = await snapshotUntil(
        (t) => t.includes(`Signed in as ${user}`),
        `"Signed in as ${user}"`,
      );
      save('snapshot-after-login.txt', snap);
    });
    await step('a denied approval fails closed: status "denied", still signed out', async () => {
      await call('browser_click', { target: { role: 'button', name: 'Log out' } });
      await call('browser_open', { url: `${rp}login` });
      await intent('sign in to the test RP with my passkey (the user will say no)');
      await call('browser_click', { target: { role: 'button', name: 'Sign in with a passkey' } });
      const { result } = await withApproval(() => call('auth_login'), false);
      expect(result.status === 'denied', `auth_login -> ${JSON.stringify(result)}`);
      const snap = await snapshotUntil(
        (t) => /error:|failed/.test(t),
        "the page's own error status after the denial",
      );
      save('snapshot-after-deny.txt', snap);
      expect(
        snap.includes('Signed out') && !snap.includes('Signed in as'),
        'page is not signed out after a denial',
      );
    });
    await step(
      'audit trail records the intents and approvals; the hash chain verifies',
      async () => {
        const events = auditTail();
        save('audit-tail.json', events);
        const types = events.map((e) => e.event);
        for (const t of [
          'intent.recorded',
          'request',
          'approval',
          'passkey.created',
          'passkey.signed',
          'denied',
        ])
          expect(types.includes(t), `audit has no ${t} (has: ${[...new Set(types)].join(', ')})`);
        const approvals = events
          .filter((e) => e.event === 'approval')
          .map((e) => e.payload.approved);
        expect(
          approvals.filter((a) => a === true).length >= 2 && approvals.includes(false),
          `approvals ${JSON.stringify(approvals)}`,
        );
        expect(
          events.some(
            (e) =>
              e.event === 'denied' &&
              e.payload.reason === 'approval_user_denied' &&
              e.payload.kind === 'passkey.get',
          ),
          'no denied/approval_user_denied for passkey.get',
        );
        auditVerified();
      },
    );
    await step('no secret reaches the agent, the logs or the audit log', async () => leakChecks());
  },

  async 'password-totp'() {
    await step('auth_status lists password + totp for the origin, no secrets', async () => {
      await call('browser_open', { url: `${rp}password/login` });
      const st = await call('auth_status');
      expect(st.origin === state.rpOrigin, `origin ${st.origin}`);
      const got = JSON.stringify(st.credentials);
      const fresh = JSON.stringify([{ type: 'password' }, { type: 'totp' }]);
      const afterPasskey = JSON.stringify([
        { type: 'passkey' },
        { type: 'password' },
        { type: 'totp' },
      ]);
      expect(got === fresh || got === afterPasskey, `credentials ${got}`);
      log(
        `      credentials: ${got} (${got === fresh ? 'fresh stack' : 'after the passkey feature'})`,
      );
    });
    await step(
      'auth_login: one approval; the broker fills password and one-time code',
      async () => {
        const words = 'sign in to the test RP with my password';
        await intent(words);
        const { prompt, result } = await withApproval(() => call('auth_login'));
        expect(result.status === 'success', `auth_login -> ${JSON.stringify(result)}`);
        expect(prompt.includes('Credential: password + one-time code'), 'prompt credential type');
        expect(prompt.includes(`"${words}"`), 'prompt words');
        const snap = await snapshotUntil(
          (t) => t.includes('Signed in as alice'),
          '"Signed in as alice"',
        );
        save('snapshot-after-login.txt', snap);
      },
    );
    await step(
      'the password and TOTP seed never reach the agent, the logs or the audit log',
      async () =>
        leakChecks([
          ['password', 'correct horse battery staple'],
          ['TOTP seed', 'JBSWY3DPEHPK3PXP'],
        ]),
    );
    await step('audit shows the fill and a verified chain', async () => {
      const events = auditTail();
      save('audit-tail.json', events);
      for (const t of ['fill.released', 'fill.completed'])
        expect(
          events.some((e) => e.event === t),
          `audit has no ${t}`,
        );
      auditVerified();
    });
  },

  async policy() {
    await step('deny rule: auth_login is denied with no prompt', async () => {
      const set = cli('policy', 'set', 'rp.localhost', '--deny');
      expect(set.status === 0, `policy set exited ${set.status}: ${set.stderr}`);
      const before = blocks().length;
      await call('browser_open', { url: `${rp}password/login` });
      await intent('sign in to the test RP with my password');
      const result = await call('auth_login');
      expect(result.status === 'denied', `auth_login -> ${JSON.stringify(result)}`);
      await sleep(1000);
      expect(blocks().length === before, 'a prompt was shown for a denied site');
      const snap = await snapshot();
      save('snapshot-after-deny.txt', snap);
      expect(!snap.includes('Signed in as'), 'signed in despite deny');
    });
    await step('policy list shows the rule; remove restores the default', async () => {
      const list = JSON.parse(cli('policy', 'list', '--json').stdout);
      save('policy-list.json', list);
      expect(
        JSON.stringify(list).includes('rp.localhost') && JSON.stringify(list).includes('deny'),
        'rule not listed',
      );
      const rm = cli('policy', 'remove', 'rp.localhost');
      expect(rm.status === 0, `policy remove exited ${rm.status}`);
      expect(
        !JSON.stringify(JSON.parse(cli('policy', 'list', '--json').stdout)).includes(
          'rp.localhost',
        ),
        'rule still listed',
      );
    });
    await step(
      'audit shows the policy denial (no approval asked) and a verified chain',
      async () => {
        const events = auditTail();
        save('audit-tail.json', events);
        expect(
          events.some((e) => e.event === 'denied' && e.payload.reason === 'policy_deny'),
          'no denied/policy_deny',
        );
        for (const t of ['policy.set', 'policy.removed'])
          expect(
            events.some((e) => e.event === t),
            `audit has no ${t}`,
          );
        auditVerified();
      },
    );
  },

  async 'agents-intents'() {
    await step('intent socket rejects a missing or wrong host token', async () => {
      const none = await postIntent(
        state.intentSocket,
        { agentId: agent.id, text: 'x' },
        { token: null },
      );
      const wrong = await postIntent(
        state.intentSocket,
        { agentId: agent.id, text: 'x' },
        { token: 'not-the-token' },
      );
      expect(
        none.status === 401 && wrong.status === 401,
        `statuses ${none.status}/${wrong.status}`,
      );
    });
    await step(
      'Claude Code hook records the prompt as an intent, prints nothing, exits 0',
      async () => {
        const words = 'hook words: open the test RP';
        const r = spawnSync(
          process.execPath,
          [
            '--disable-warning=ExperimentalWarning',
            MAIN,
            'hook',
            'claude-code',
            '--agent',
            agent.id,
            '--data-dir',
            state.dataDir,
          ],
          {
            input: JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt: words }),
            encoding: 'utf8',
            env: process.env,
            cwd: join(RUN, 'home'),
          },
        );
        expect(r.status === 0, `hook exit ${r.status}`);
        expect(r.stdout === '', 'hook wrote to stdout');
        const rec = auditTail()
          .filter((e) => e.event === 'intent.recorded')
          .at(-1);
        expect(rec?.payload.textSha256 === sha(words), 'audit does not hold the hook prompt hash');
        expect(!JSON.stringify(rec).includes(words), 'audit holds the raw prompt text');
      },
    );
    await step('a revoked agent token stops working at once', async () => {
      const add = cli('agent', 'add', 'temp-agent');
      expect(add.status === 0, `agent add exited ${add.status}`);
      const tok = /aab_agent_[A-Za-z0-9_-]{43}/.exec(add.stdout)?.[0];
      const id = /\(id ([^)]+)\)/.exec(add.stdout)?.[1];
      expect(tok && id, 'could not parse agent add output');
      const init = (t) =>
        fetch(state.mcpUrl, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${t}`,
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
              protocolVersion: '2025-06-18',
              capabilities: {},
              clientInfo: { name: 'v', version: '1' },
            },
          }),
        }).then(async (x) => {
          await x.body?.cancel();
          return x.status;
        });
      expect((await init(tok)) === 200, 'new agent token rejected');
      expect(cli('agent', 'revoke', id).status === 0, 'agent revoke failed');
      expect((await init(tok)) === 401, 'revoked token still accepted');
    });
    await step('audit trail and hash chain', async () => {
      save('audit-tail.json', auditTail());
      auditVerified();
    });
  },

  async 'status-audit'() {
    await step(
      'keyflap status --json reports agents, credentials, policies and an intact audit chain',
      async () => {
        const r = cli('status', '--json');
        expect(r.status === 0, `status exited ${r.status}`);
        const s = JSON.parse(r.stdout);
        save('status.json', s);
        expect(
          s.agents.some((a) => a.id === agent.id),
          'verify-agent not listed',
        );
        expect(s.credentials.passwords >= 1, 'seeded password not counted');
        expect(s.audit.intact === true, 'audit chain not intact');
      },
    );
    await step('audit verify exits 0; audit tail lists entries', async () => {
      auditVerified();
      expect(auditTail().length > 0, 'no audit entries');
    });
  },

  async challenge() {
    const urls = JSON.parse(
      readFileSync(join(RUN, 'logs', 'rp.out'), 'utf8')
        .split('\n')
        .find((l) => l.includes('"challenge"')),
    ).challenge;
    await step('auth_login describes the challenge outcome to the agent', async () => {
      const t = (await mcp.listTools()).find((x) => x.name === 'auth_login');
      expect(/"challenge"/.test(t.description), 'auth_login description has no challenge outcome');
      expect(
        /will not solve/.test(t.description),
        'description does not say the broker will not solve it',
      );
      expect(
        /browser_handoff/.test(t.description),
        'description does not point the agent at browser_handoff',
      );
    });
    for (const [key, provider] of [
      ['waf', 'aws-waf'],
      ['cf', 'cloudflare'],
    ]) {
      await step(
        `${provider}: one approval, the broker fills, the site answers with a check -> "challenge"`,
        async () => {
          const words = `sign in to the ${key} test site with my password`;
          await intent(words);
          await call('browser_open', { url: `${urls[key]}password/login` });
          const { prompt, result } = await withApproval(() => call('auth_login'));
          expect(result.status === 'challenge', `auth_login -> ${JSON.stringify(result)}`);
          expect(prompt.includes(`"${words}"`), 'prompt words');
          const snap = await call('browser_snapshot');
          save(`snapshot-${key}.txt`, snap.snapshot);
          expect(snap.humanCheck === true, `browser_snapshot humanCheck ${snap.humanCheck}`);
          expect(snap.snapshot.includes("Let's confirm you are human"), 'challenge page not shown');
          const st = await call('auth_status');
          expect(st.humanCheck === true, `auth_status humanCheck ${st.humanCheck}`);
          const done = auditTail()
            .filter((e) => e.event === 'fill.completed')
            .at(-1);
          expect(
            done?.payload.outcome === 'challenge' && done?.payload.humanCheck === provider,
            `fill.completed ${JSON.stringify(done?.payload)}`,
          );
        },
      );
    }
    await step(
      'a page that only *says* "confirm you are human" is not trusted: success, humanCheck false',
      async () => {
        await intent('sign in to the text test site with my password');
        await call('browser_open', { url: `${urls.text}password/login` });
        const { result } = await withApproval(() => call('auth_login'));
        expect(result.status === 'success', `auth_login -> ${JSON.stringify(result)}`);
        const snap = await call('browser_snapshot');
        save('snapshot-text.txt', snap.snapshot);
        expect(snap.snapshot.includes("Let's confirm you are human"), 'text page not shown');
        expect(snap.humanCheck === false, `humanCheck ${snap.humanCheck}`);
      },
    );
    await step(
      'the agent only ever gets a boolean: no provider name in its view; no secret leaks',
      async () => {
        const everything = await mcp.everything();
        for (const p of ['aws-waf', 'cloudflare', 'x-amzn-waf-action', 'cf-mitigated'])
          expect(!everything.includes(p), `${p} reached the agent`);
        await leakChecks([
          ['password', 'correct horse battery staple'],
          ['TOTP seed', 'JBSWY3DPEHPK3PXP'],
        ]);
        save('audit-tail.json', auditTail());
        auditVerified();
      },
    );
  },

  async 'persistence-before'() {
    await step('signed in on the test RP (broker login with one approval if needed)', async () => {
      const r = await call('browser_open', { url: `${rp}account` });
      if (r.url !== `${rp}account`) {
        await call('browser_open', { url: `${rp}password/login` });
        await intent('sign in to the test RP with my password');
        const { result } = await withApproval(() => call('auth_login'));
        expect(result.status === 'success', `auth_login -> ${JSON.stringify(result)}`);
      }
      const snap = await snapshotUntil(
        (t) => t.includes('Signed in as alice'),
        '"Signed in as alice"',
      );
      save('snapshot-before-restart.txt', snap);
    });
    await step(
      "the agent's state is saved: an encrypted 0600 file, counts in keyflap sessions list",
      async () => {
        const file = join(state.dataDir, 'browser-state', `${agent.id}.state`);
        for (let i = 0; i < 50 && !existsSync(file); i++) await sleep(200);
        expect(existsSync(file), `no ${file}`);
        expect((statSync(file).mode & 0o777) === 0o600, 'state file is not 0600');
        expect(
          (statSync(join(state.dataDir, 'browser-state')).mode & 0o777) === 0o700,
          'dir is not 0700',
        );
        const raw = readFileSync(file, 'utf8');
        expect(
          JSON.stringify(Object.keys(JSON.parse(raw)).sort()) === '["ct","iv","tag","v"]',
          'file is not the {v, iv, tag, ct} envelope',
        );
        for (const s of ['sid', 'rp.localhost', 'alice'])
          expect(!raw.includes(s), `${s} in plaintext`);
        const list = JSON.parse(cli('sessions', 'list', '--json').stdout);
        save('sessions-list-before.json', list);
        expect(
          list.sessions.some((r) => r.site === 'rp.localhost' && r.cookies >= 1),
          'rp.localhost not in sessions list',
        );
        expect(!JSON.stringify(list).includes('"value"'), 'sessions list carries values');
        const status = cli('status');
        save('status-before.txt', status.stdout);
        expect(
          /Saved sessions: 1 agents, \d+ sites/.test(status.stdout),
          'status has no saved-sessions line',
        );
        const seq = auditTail().at(-1)?.seq ?? 0;
        save('audit-seq-before.txt', String(seq));
      },
    );
  },

  async 'persistence-after'() {
    const before = Number(readFileSync(join(out, 'audit-seq-before.txt'), 'utf8'));
    await step(
      'after the restart the agent is still signed in, with no approval prompt',
      async () => {
        const r = await call('browser_open', { url: `${rp}account` });
        expect(r.url === `${rp}account`, `landed on ${r.url}`);
        const snap = await snapshotUntil(
          (t) => t.includes('Signed in as alice'),
          '"Signed in as alice"',
        );
        save('snapshot-after-restart.txt', snap);
        expect(blocks().length === 0, 'the restarted daemon showed an approval prompt');
      },
    );
    await step(
      'audit: restored (sites and counts only), no request or approval since the restart',
      async () => {
        const since = auditTail().filter((e) => e.seq > before);
        save('audit-since-restart.json', since);
        const restored = since.find((e) => e.event === 'browser_state.restored');
        expect(restored, 'no browser_state.restored');
        expect(
          restored.payload.sites.includes('rp.localhost'),
          `restored sites ${restored.payload.sites}`,
        );
        for (const t of ['request', 'approval', 'fill.released', 'passkey.signed'])
          expect(!since.some((e) => e.event === t), `${t} after the restart`);
        expect(!JSON.stringify(restored).includes('"sid"'), 'cookie name in the audit');
        auditVerified();
      },
    );
    await step('no secret reaches the agent, the logs or the audit log', async () =>
      leakChecks([
        ['password', 'correct horse battery staple'],
        ['TOTP seed', 'JBSWY3DPEHPK3PXP'],
      ]),
    );
  },
};

async function phoneShots(page, out, name) {
  const vp = page.viewportSize();
  await page.setViewportSize({ width: 390, height: 844 });
  for (const colorScheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme });
    await sleep(300);
    await page.screenshot({ path: join(out, `${name}-${colorScheme}.png`) });
  }
  await page.emulateMedia({ colorScheme: null });
  await page.setViewportSize(vp);
  await sleep(300);
  await page.screenshot({ path: join(out, `${name}.png`) });
}

async function startPhone() {
  const require = createRequire(`${REPO}/packages/core/package.json`);
  const { chromium } = require('playwright');
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 720 }, hasTouch: true });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  let total = 0;
  await ctx.exposeFunction('__aabWebAuthn', () => {
    total++;
  });
  await ctx.addInitScript(() => {
    window.__webauthn = 0;
    const get = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = (o) => {
      window.__webauthn++;
      window.__aabWebAuthn?.();
      return get(o);
    };
  });
  return { browser, ctx, page, cdp, webauthn: () => total };
}

const touchPoints = (pts) => pts.map((p, i) => ({ x: p.x, y: p.y, id: i }));
async function touches(phone, from, to, steps = 10) {
  await phone.cdp.send('Input.dispatchTouchEvent', {
    type: 'touchStart',
    touchPoints: touchPoints(from),
  });
  for (let i = 1; i <= steps; i++) {
    const at = from.map((a, k) => ({
      x: a.x + ((to[k].x - a.x) * i) / steps,
      y: a.y + ((to[k].y - a.y) * i) / steps,
    }));
    await phone.cdp.send('Input.dispatchTouchEvent', {
      type: 'touchMove',
      touchPoints: touchPoints(at),
    });
  }
  await phone.cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
}
const tapAt = (phone, p) => touches(phone, [p], [p], 1);

const zoomState = (phone) =>
  phone.page.evaluate(() => {
    const t = document.querySelector('#stage').style.transform;
    const m = /scale\(([\d.]+)\)/.exec(t);
    const d = document.querySelector('#detail');
    return {
      transform: t,
      scale: m ? Number(m[1]) : 1,
      detail: !d.hidden && d.naturalWidth > 0,
      clip: new URL(d.src || 'http://x/').searchParams.get('clip'),
    };
  });

async function onScreen(phone, pt) {
  const r = await phone.page.locator('#screen').boundingBox();
  const box = await phone.page.locator('#viewport').boundingBox();
  const p = { x: r.x + pt.x * r.width, y: r.y + pt.y * r.height };
  expect(
    p.x > box.x && p.x < box.x + box.width && p.y > box.y && p.y < box.y + box.height,
    `page point ${JSON.stringify(pt)} is off screen at ${JSON.stringify(p)}`,
  );
  return p;
}

async function schemeShots(page, out, name) {
  for (const colorScheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme });
    await sleep(300);
    await page.screenshot({ path: join(out, `${name}-${colorScheme}.png`) });
  }
  await page.emulateMedia({ colorScheme: null });
}

async function waitDetail(phone) {
  for (let i = 0; i < 50; i++) {
    const z = await zoomState(phone);
    if (z.detail) return z;
    await sleep(100);
  }
  throw new Error('no sharp region frame while zoomed');
}

async function humanButtonPoint(phone, next) {
  const { challengePage } = await import(`${REPO}/packages/test-rp/src/pages.ts`);
  const p = await phone.ctx.newPage();
  try {
    await p.setContent(challengePage(null, next));
    const b = await p.locator('#challenge-solve').boundingBox();
    return { x: (b.x + b.width / 2) / 1280, y: (b.y + b.height / 2) / 720 };
  } finally {
    await p.close();
  }
}

features.handoff = async () => {
  const origin = state.approverOrigin;
  expect(origin?.startsWith('http://approver.localhost:'), `approver origin ${origin}`);
  const urls = JSON.parse(
    readFileSync(join(RUN, 'logs', 'rp.out'), 'utf8')
      .split('\n')
      .find((l) => l.includes('"challenge"')),
  ).challenge;
  const waf = urls.hc;
  expect(waf, 'no handoff RP (waf.hc.localhost) in logs/rp.out: relaunch');
  const gate = urls.gate;
  expect(gate, 'no combined-handoff RP (gate.hc.localhost) in logs/rp.out: relaunch');
  const wafOrigin = new URL(waf).origin;
  const phone = await startPhone();
  let handoff;
  try {
    await step('pair the simulated phone with the one-time link (UV passkey)', async () => {
      const file = join(state.dataDir, 'approver', 'pairing-url');
      for (let i = 0; i < 50 && !existsSync(file); i++) await sleep(100);
      const url = readFileSync(file, 'utf8').trim();
      expect(url.startsWith(`${origin}/pair#`), 'pairing link is not on the sandbox approver');
      await phone.page.goto(url);
      await phone.page.click('#pair-button');
      await phone.page.waitForFunction(
        () => document.querySelector('#status')?.textContent === 'No pending requests.',
      );
      expect(!existsSync(file), 'pairing link still open after pairing');
    });
    await step(
      'password sign-in on the WAF test site, approved on the phone -> "challenge"',
      async () => {
        const words = 'sign in to the waf test site and get past its check';
        await intent(words);
        await call('browser_open', { url: `${waf}password/login` });
        const login = call('auth_login');
        await phone.page.goto(`${origin}/`);
        const card = phone.page.locator('#requests .card').first();
        await card.waitFor({ timeout: 20000 });
        const text = await card.textContent();
        save('phone-approval-card.txt', text);
        expect(text.includes(words), 'card does not show the words');
        expect(text.includes(wafOrigin), 'card does not show the verified origin');
        await card.locator('.approve').click();
        const r = await login;
        expect(r.status === 'challenge', `auth_login -> ${JSON.stringify(r)}`);
        const snap = await call('browser_snapshot');
        expect(snap.humanCheck === true, 'no humanCheck after the challenge');
      },
    );
    await step('browser_handoff opens one; every other tool is held meanwhile', async () => {
      handoff = mcp.ok('browser_handoff', { timeoutMs: 90000 });
      handoff.catch(() => {});
      const second = await connectAgent(state.mcpUrl, agent, {
        name: 'verify-aab-2',
        version: '1',
      });
      try {
        let msg = '';
        for (let i = 0; i < 50; i++) {
          const r = await second.call('browser_snapshot');
          msg = r.content?.[0]?.text ?? '';
          if (r.isError && /human check is in progress/.test(msg)) break;
          await sleep(100);
        }
        save('held-tool-error.txt', msg);
        expect(/human check is in progress on your page; call browser_handoff/.test(msg), msg);
      } finally {
        await second.close();
      }
      const ev = auditTail().filter((e) => e.event === 'handoff.requested');
      expect(ev.length === 1, `handoff.requested x${ev.length}`);
    });
    await step(
      'the approvals page links to it (no pixels, no approve control); /handoff starts with one Face ID',
      async () => {
        await phone.page.goto(`${origin}/`);
        const link = phone.page.locator('#handoffs a.handoff');
        await link.waitFor({ timeout: 10000 });
        const t = await link.textContent();
        save('phone-handoff-link.txt', t);
        await phoneShots(phone.page, out, 'phone-handoff-link');
        expect(t.includes(`Human check waiting on ${new URL(waf).hostname}`), t);
        await link.click();
        await phone.page.locator('#live').waitFor({ state: 'visible', timeout: 15000 });
        await phone.page.waitForFunction(() => {
          const img = document.querySelector('#screen');
          return img?.complete === true && img.naturalWidth > 0;
        });
        const chrome = await phone.page.locator('#context').textContent();
        save('phone-live-view-labels.txt', chrome);
        expect(chrome.includes(new URL(waf).hostname), 'live view does not show the host');
        expect(chrome.includes('verify-agent'), 'live view does not show the agent');
        expect(
          (await phone.page.evaluate(() => window.__webauthn)) === 1,
          'more than one WebAuthn call',
        );
        expect(
          (await phone.page.locator('.approve').count()) === 0,
          'an approve control on /handoff',
        );
        await sleep(500);
        await phoneShots(phone.page, out, 'phone-live-view');
      },
    );
    await step(
      'the owner taps "I\'m human" in the picture and taps Done -> the agent gets "done"',
      async () => {
        const pt = await humanButtonPoint(phone);
        await phone.page.setViewportSize({ width: 390, height: 844 });
        await sleep(500);
        const p0 = await onScreen(phone, pt);
        const box = await phone.page.locator('#viewport').boundingBox();
        const c = { x: Math.max(p0.x, box.x + 50), y: p0.y };
        await touches(
          phone,
          [
            { x: c.x - 15, y: c.y },
            { x: c.x + 15, y: c.y },
          ],
          [
            { x: c.x - 45, y: c.y },
            { x: c.x + 45, y: c.y },
          ],
        );
        const pinched = await zoomState(phone);
        expect(Math.abs(pinched.scale - 3) < 0.05, `pinch scale ${pinched.transform}`);
        await touches(
          phone,
          [
            { x: box.x + 100, y: box.y + 90 },
            { x: box.x + 180, y: box.y + 90 },
          ],
          [
            { x: box.x + 220, y: box.y + 100 },
            { x: box.x + 300, y: box.y + 100 },
          ],
        );
        const panned = await zoomState(phone);
        expect(
          panned.scale === pinched.scale && panned.transform !== pinched.transform,
          `two-finger pan ${pinched.transform} -> ${panned.transform}`,
        );
        const z = await waitDetail(phone);
        expect(/^[\d.]+,[\d.]+,[\d.]+,[\d.]+$/.test(z.clip ?? ''), `clip ${z.clip}`);
        save('phone-zoom.txt', JSON.stringify({ pinched, panned: z }, null, 2));
        await schemeShots(phone.page, out, 'phone-zoomed');
        await tapAt(phone, await onScreen(phone, pt));
        await sleep(1500);
        await schemeShots(phone.page, out, 'phone-zoomed-after-tap');
        await phone.page.click('#zoom-fit');
        expect((await zoomState(phone)).transform === '', 'Fit did not reset the zoom');
        await phone.page.setViewportSize({ width: 1280, height: 720 });
        await phoneShots(phone.page, out, 'phone-after-tap');
        await phone.page.click('#done');
        const r = await handoff;
        expect(r.status === 'done', `browser_handoff -> ${JSON.stringify(r)}`);
      },
    );
    await step('the agent continues, signed in, no human check', async () => {
      const snap = await snapshotUntil(
        (t) => t.includes('Signed in as alice'),
        '"Signed in as alice"',
      );
      save('snapshot-after-handoff.txt', snap);
      const st = await call('auth_status');
      expect(st.humanCheck === false, 'humanCheck still true');
    });
    await step(
      'audit: requested, started, ended done with counts only; nothing from the phone reaches the agent',
      async () => {
        const events = auditTail();
        save('audit-tail.json', events);
        const ended = events.filter((e) => e.event === 'handoff.ended').at(-1);
        expect(ended?.payload.outcome === 'done', `ended ${JSON.stringify(ended?.payload)}`);
        const n = ended.payload.inputs;
        expect(
          n.clicks === 1 && (n.drags ?? 0) === 0 && (n.scrolls ?? 0) === 0,
          `inputs ${JSON.stringify(n)}`,
        );
        expect(
          events.some((e) => e.event === 'handoff.started'),
          'no handoff.started',
        );
        const everything = await mcp.everything();
        expect(
          !/"type":"image"|image\/jpeg|data:image|\/9j\//.test(everything),
          'image content reached the agent',
        );
        await leakChecks([
          ['password', 'correct horse battery staple'],
          ['TOTP seed', 'JBSWY3DPEHPK3PXP'],
        ]);
        auditVerified();
      },
    );

    const gateOrigin = new URL(gate).origin;
    const gateHost = new URL(gate).host;
    let seqBefore = 0;
    let webauthnBefore = 0;
    await step(
      'combined: the gated site shows its check before any password; browser_handoff asks ONE approval card',
      async () => {
        seqBefore = auditTail().at(-1)?.seq ?? 0;
        webauthnBefore = phone.webauthn();
        await intent('sign in to the gated test site for me');
        await call('browser_open', { url: `${gate}password/login` });
        const snap = await call('browser_snapshot');
        save('combined-snapshot-check.txt', snap.snapshot);
        expect(snap.humanCheck === true, 'no humanCheck on the gated sign-in page');
        handoff = mcp.ok('browser_handoff', { timeoutMs: 90000 });
        handoff.catch(() => {});
        await phone.page.goto(`${origin}/`);
        const card = phone.page.locator('#requests .card').first();
        await card.waitFor({ timeout: 20000 });
        const text = await card.textContent();
        save('phone-combined-card.txt', text);
        expect(text.includes(`Human check, then sign in to ${gateHost}?`), text);
        expect(text.includes('sign in to the gated test site for me'), 'no words on the card');
        expect(text.includes(gateOrigin), 'no verified origin on the card');
        expect(text.includes('verify-agent'), 'no agent on the card');
        expect(text.includes('password (sign-in)'), 'no credential type on the card');
        expect(text.includes('One sign-in within 7 minutes'), 'no broker sign-in line');
        expect(
          (await phone.page.locator('#handoffs a').count()) === 0,
          'a live-view link next to the approval card',
        );
        const req = auditTail().filter((e) => e.seq > seqBefore && e.event === 'handoff.requested');
        expect(req.length === 1 && req[0].payload.withSignIn === true, JSON.stringify(req));
      },
    );
    await step(
      'combined: one Face ID on the card opens the live view directly (no second Face ID)',
      async () => {
        await phone.page.locator('#requests .card .approve').first().click();
        await phone.page.waitForURL(`${origin}/handoff`, { timeout: 15000 });
        await phone.page.locator('#live').waitFor({ state: 'visible', timeout: 15000 });
        await phone.page.waitForFunction(() => {
          const img = document.querySelector('#screen');
          return img?.complete === true && img.naturalWidth > 0;
        });
        const chrome = await phone.page.locator('#context').textContent();
        save('phone-combined-live-view-labels.txt', chrome);
        expect(chrome.includes('signs in once without asking again'), 'no sign-in note');
        expect(
          phone.webauthn() - webauthnBefore === 1,
          `WebAuthn calls ${phone.webauthn() - webauthnBefore}`,
        );
        expect(
          (await phone.page.locator('.approve').count()) === 0,
          'an approve control on /handoff',
        );
        await sleep(500);
        await phoneShots(phone.page, out, 'phone-combined-live-view');
      },
    );
    await step('combined: tap "I\'m human", Done -> the agent gets "done"', async () => {
      const pt = await humanButtonPoint(phone, '/password/login');
      await phone.page.setViewportSize({ width: 390, height: 844 });
      await sleep(500);
      await phone.page.click('#zoom-in');
      await phone.page.click('#zoom-in');
      const plus = await zoomState(phone);
      expect(Math.abs(plus.scale - 2.25) < 0.01, `+ + scale ${plus.transform}`);
      const box = await phone.page.locator('#viewport').boundingBox();
      await touches(
        phone,
        [
          { x: box.x + 40, y: box.y + 40 },
          { x: box.x + 120, y: box.y + 40 },
        ],
        [
          { x: box.x + 340, y: box.y + 190 },
          { x: box.x + 420, y: box.y + 190 },
        ],
      );
      await waitDetail(phone);
      await schemeShots(phone.page, out, 'phone-combined-zoomed');
      await tapAt(phone, await onScreen(phone, pt));
      await sleep(1500);
      await phone.page.click('#zoom-fit');
      await phone.page.setViewportSize({ width: 1280, height: 720 });
      await phoneShots(phone.page, out, 'phone-combined-after-tap');
      await phone.page.click('#done');
      const r = await handoff;
      expect(r.status === 'done', `browser_handoff -> ${JSON.stringify(r)}`);
    });
    await step(
      'combined: auth_login signs in with no new approval (the single-use grant); exactly one approval in all',
      async () => {
        const r = await call('auth_login');
        expect(r.status === 'success', `auth_login -> ${JSON.stringify(r)}`);
        const snap = await snapshotUntil(
          (t) => t.includes('Signed in as alice'),
          '"Signed in as alice"',
        );
        save('combined-snapshot-after.txt', snap);
        expect(
          phone.webauthn() - webauthnBefore === 1,
          `WebAuthn calls ${phone.webauthn() - webauthnBefore}`,
        );
        const since = auditTail().filter((e) => e.seq > seqBefore);
        save('audit-combined.json', since);
        const approvals = since.filter((e) => e.event === 'approval');
        expect(approvals.length === 1, `approvals since: ${approvals.length}`);
        for (const t of ['grant.created', 'grant.armed', 'grant.used', 'fill.completed'])
          expect(
            since.some((e) => e.event === t),
            `no ${t}`,
          );
        const started = since.find((e) => e.event === 'handoff.started');
        expect(started?.payload.via === 'approval', `started ${JSON.stringify(started?.payload)}`);
        const used = since.find((e) => e.event === 'grant.used');
        expect(used?.payload.singleUse === true, `used ${JSON.stringify(used?.payload)}`);
        await leakChecks([
          ['password', 'correct horse battery staple'],
          ['TOTP seed', 'JBSWY3DPEHPK3PXP'],
        ]);
        auditVerified();
      },
    );
  } finally {
    await phone.browser.close().catch(() => {});
  }
};

log(`== drive ${feature} against ${state.mcpUrl} (RP ${state.rpOrigin}) ==`);
mcp = await connectAgent(state.mcpUrl, agent, { name: 'verify-aab', version: '1' });
try {
  await features[feature]();
} finally {
  await mcp.close().catch(() => {});
}
log(
  failures === 0
    ? `DONE ${feature}: all steps passed`
    : `DONE ${feature}: ${failures} step(s) failed`,
);
process.exit(failures === 0 ? 0 : 1);
