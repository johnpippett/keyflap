import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decryptState } from '../src/browser-state.ts';
import { addPasswordItem } from '../src/passwords.ts';
import { secretForms } from '../src/scrub.ts';
import { type PersistHarness, startPersistHarness, until } from './persist-harness.ts';

const PW = 'inv8 p@ss/wörd+&?"x';

const COPY_PAGE = `<!doctype html><title>Sign in</title>
<form id="f" method="post" action="/password/login">
<label>Username <input name="username" autocomplete="username"></label>
<label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
<button>Sign in</button></form>
<script>
const form = document.getElementById('f');
form.addEventListener('submit', (e) => {
  e.preventDefault();
  const v = document.getElementById('password').value;
  document.cookie = 'pwcopy=' + encodeURIComponent(v) + '; path=/; max-age=86400';
  localStorage.setItem('pwcopy', v);
  localStorage.setItem('innocent', 'same-origin-neighbour');
  const open = indexedDB.open('leak', 1);
  open.onupgradeneeded = () => open.result.createObjectStore('s');
  open.onsuccess = () => {
    const tx = open.result.transaction('s', 'readwrite');
    tx.objectStore('s').put({ deep: { list: [{ v }, JSON.stringify({ v })] } }, 'k');
    tx.oncomplete = () => form.submit();
  };
});
</script>`;

const ECHO_PAGE = `<!doctype html><title>Echo</title><pre id="out">loading</pre>
<script>
(async () => {
  const parts = ['cookies: ' + document.cookie];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    parts.push('ls ' + k + '=' + localStorage.getItem(k));
  }
  const dbs = await indexedDB.databases();
  for (const d of dbs) {
    const db = await new Promise((r) => { const o = indexedDB.open(d.name); o.onsuccess = () => r(o.result); });
    for (const s of db.objectStoreNames) {
      const all = await new Promise((r) => { const q = db.transaction(s).objectStore(s).getAll(); q.onsuccess = () => r(q.result); });
      parts.push('idb ' + d.name + ' ' + JSON.stringify(all));
    }
  }
  document.getElementById('out').textContent = parts.join('\\n');
})();
</script>`;

describe('invariant 8: a filled secret copied into site storage never persists', () => {
  let h: PersistHarness;

  beforeAll(async () => {
    h = await startPersistHarness({ rp: { users: [{ username: 'alice', password: PW }] } });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: PW },
    );
  });
  afterAll(async () => h?.close());

  const route = async (path: string, body: string) => {
    const ctx = await h.context();
    await ctx.route(new RegExp(`rp\\.localhost:\\d+/${path}$`), (r) =>
      r.fulfill({ contentType: 'text/html; charset=utf-8', body }),
    );
  };

  it('the saved file holds no spelling of the password; the session cookie is kept', async () => {
    await route('inv8-copy', COPY_PAGE);
    await h.intent('sign me in to the test RP');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}inv8-copy` });
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    const ctx = await h.context();
    expect((await ctx.cookies()).map((c) => c.name)).toEqual(
      expect.arrayContaining(['pwcopy', 'sid']),
    );
    expect(await h.page().evaluate(() => localStorage.getItem('pwcopy'))).toBe(PW);

    const { key } = await h.daemon.signer.client.browserStateKey();
    await h.stop();
    const file = JSON.parse(readFileSync(h.stateFile(), 'utf8'));
    const plain = decryptState(Buffer.from(key, 'base64url'), h.agent.id, file)?.toString('utf8');
    expect(plain).toBeDefined();
    for (const f of secretForms(PW)) expect(plain?.includes(f), f).toBe(false);
    const saved = JSON.parse(plain as string) as {
      state: { cookies: { name: string }[]; origins: { origin: string }[] };
    };
    expect(saved.state.cookies.map((c) => c.name)).toEqual(['sid']);
    expect(saved.state.origins).toEqual([]);
    expect(plain).not.toContain('same-origin-neighbour');
    await h.start();
  });

  it('after a restart (empty scrub list) an echo page shows none of it to the agent', async () => {
    await h.mcp.ok('auth_status');
    await route('inv8-echo', ECHO_PAGE);
    await h.mcp.ok('browser_open', { url: `${h.rp.url}inv8-echo` });
    let snap = '';
    await until(async () => {
      snap = (await h.mcp.ok<{ snapshot: string }>('browser_snapshot')).snapshot;
      return snap.includes('cookies:');
    });
    expect(snap).not.toContain('pwcopy');
    expect(snap).not.toContain('idb leak');
    for (const f of secretForms(PW)) expect(snap.includes(f), f).toBe(false);
    const everything = await h.mcp.everything();
    for (const f of secretForms(PW)) expect(everything.includes(f), f).toBe(false);
    const r = await h.mcp.ok<{ url: string }>('browser_open', { url: `${h.rp.url}account` });
    expect(r.url).toBe(`${h.rp.url}account`);
    const filtered = h.auditEvents().filter((e) => e.type === 'browser_state.filtered');
    expect(filtered.length).toBeGreaterThan(0);
    expect(JSON.stringify(filtered)).not.toContain('pwcopy');
  });
});
