const esc = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c,
  );

export function layout(title: string, user: string | null, body: string): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>${esc(title)} · Test RP</title>
<script src="/static/webauthn.js"></script></head>
<body>
<header><a href="/">Test RP</a> · <span id="whoami">${user ? `Signed in as ${esc(user)}` : 'Signed out'}</span>
${user ? '<form method="post" action="/logout" style="display:inline"><button id="logout">Log out</button></form>' : ''}
</header>
<main>${body}</main>
</body></html>`;
}

export const homePage = (user: string | null) =>
  layout(
    'Home',
    user,
    `<h1>Test relying party</h1>
<ul>
  <li><a href="/signup">Sign up</a></li>
  <li><a href="/login">Sign in with a passkey</a></li>
  <li><a href="/password/login">Sign in with a password</a></li>
  <li><a href="/account">Account</a></li>
</ul>`,
  );

export const signupPage = () =>
  layout(
    'Sign up',
    null,
    `<h1>Sign up</h1>
<form method="post" action="/signup">
  <label>Username <input id="username" name="username" autocomplete="username"></label>
  <button id="signup" type="submit">Create account</button>
</form>`,
  );

export const accountPage = (user: string, passkeys: number) =>
  layout(
    'Account',
    user,
    `<h1>Account</h1>
<p>Passkeys registered: <span id="passkey-count">${passkeys}</span></p>
<button id="add-passkey" type="button">Add a passkey</button>
<p id="status"></p>
<script>
document.getElementById('add-passkey').addEventListener('click', async () => {
  const status = document.getElementById('status');
  status.textContent = 'working';
  try {
    const result = await testRp.register();
    status.textContent = result.verified ? 'passkey added' : 'registration failed: ' + (result.error || '');
    if (result.verified) document.getElementById('passkey-count').textContent = String(result.count);
  } catch (e) {
    status.textContent = 'error: ' + e.name;
  }
});
</script>`,
  );

export const loginPage = (user: string | null) =>
  layout(
    'Sign in',
    user,
    `<h1>Sign in</h1>
<button id="passkey-login" type="button">Sign in with a passkey</button>
<p id="status"></p>
<p><a href="/password/login">Use a password instead</a></p>
<script>
document.getElementById('passkey-login').addEventListener('click', async () => {
  const status = document.getElementById('status');
  status.textContent = 'working';
  try {
    const result = await testRp.login();
    if (result.verified) { location.href = '/account'; return; }
    status.textContent = 'sign-in failed: ' + (result.error || '');
  } catch (e) {
    status.textContent = 'error: ' + e.name;
  }
});
</script>`,
  );

export const passwordLoginPage = (error?: string, widgetOrigin?: string) =>
  layout(
    'Password sign-in',
    null,
    `<h1>Sign in with a password</h1>
${error ? `<p id="error">${esc(error)}</p>` : ''}
${
  widgetOrigin
    ? `<script src="${esc(widgetOrigin)}/challenge/api.js" async></script>
<iframe id="bg-widget" title="background check" src="${esc(widgetOrigin)}/challenge/widget?size=invisible" width="1" height="1" style="border:0"></iframe>`
    : ''
}
<form method="post" action="/password/login">
  <label>Username <input id="username" name="username" autocomplete="username"></label>
  <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
  <button id="password-submit" type="submit">Sign in</button>
</form>`,
  );

export const identifierPage = (error?: string) =>
  layout(
    'Sign in',
    null,
    `<h1>Sign in</h1>
${error ? `<p id="error">${esc(error)}</p>` : ''}
<form method="post" action="/password/login-id">
  <label>Email or username <input id="identifier" name="username" autocomplete="username"></label>
  <button id="identifier-next" type="submit">Next</button>
</form>`,
  );

export const identifierScriptPage = () =>
  layout(
    'Sign in',
    null,
    `<h1>Log in with your email</h1>
<div role="dialog" aria-label="Cookies"><button type="button" id="cookies-accept">Accept All</button>
<button type="button" id="cookies-reject">Reject All</button></div>
<label>Email or username <input id="identifier" name="username" autocomplete="username"></label>
<button id="identifier-next" type="button">Next</button>
<button id="identifier-back" type="button">Go back</button>
<p id="clicked"></p>
<script>
for (const id of ['cookies-accept', 'cookies-reject', 'identifier-back']) {
  document.getElementById(id).addEventListener('click', () => {
    document.getElementById('clicked').textContent = id;
  });
}
document.getElementById('identifier-next').addEventListener('click', async () => {
  const username = document.getElementById('identifier').value;
  await fetch('/password/login-id', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username }),
    redirect: 'manual',
  });
  location.href = '/password/login-pw';
});
</script>`,
  );

export const identifierPasswordPage = (username: string, error?: string) =>
  layout(
    'Enter your password',
    null,
    `<h1>Welcome, ${esc(username)}</h1>
${error ? `<p id="error">${esc(error)}</p>` : ''}
<form method="post" action="/password/login-pw">
  <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
  <button id="password-submit" type="submit">Sign in</button>
</form>`,
  );

export const totpPage = (error?: string) =>
  layout(
    'Two-step verification',
    null,
    `<h1>Enter your code</h1>
${error ? `<p id="error">${esc(error)}</p>` : ''}
<form method="post" action="/password/totp">
  <label>Code <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"></label>
  <button id="totp-submit" type="submit">Verify</button>
</form>`,
  );

export const webauthnJs = `
(() => {
  const b64urlToBuf = (s) => {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  const bufToB64url = (buf) => {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  };
  const post = async (url, body) => {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ?? {}) });
    return r.json();
  };
  async function register() {
    const o = await post('/api/passkey/register/options');
    if (o.error) return { verified: false, error: o.error };
    const publicKey = {
      ...o,
      challenge: b64urlToBuf(o.challenge),
      user: { ...o.user, id: b64urlToBuf(o.user.id) },
      excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
    };
    const cred = await navigator.credentials.create({ publicKey });
    const body = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: bufToB64url(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
    };
    return post('/api/passkey/register/verify', body);
  }
  async function login() {
    const o = await post('/api/passkey/login/options');
    const publicKey = {
      ...o,
      challenge: b64urlToBuf(o.challenge),
      allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
    };
    const cred = await navigator.credentials.get({ publicKey });
    const body = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        signature: bufToB64url(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : undefined,
      },
    };
    return post('/api/passkey/login/verify', body);
  }
  window.testRp = { register, login, b64urlToBuf, bufToB64url };
})();
`;

export const challengePage = (widgetUrl: string | null, next?: string) =>
  `<!doctype html>
<html><head><meta charset="utf-8"><title>Human Verification</title></head>
<body>
<h1>Let's confirm you are human</h1>
<p>Complete the check below to continue.</p>
${widgetUrl ? `<iframe id="challenge-widget" title="challenge" src="${esc(widgetUrl)}" width="300" height="150" style="border:1px solid #888"></iframe>` : ''}
<form method="post" action="/challenge/solve">${next ? `<input type="hidden" name="next" value="${esc(next)}">` : ''}<button id="challenge-solve" type="submit">I'm human</button></form>
</body></html>`;

export const challengeWidget = () =>
  `<!doctype html><html><head><meta charset="utf-8"><title>widget</title></head>
<body style="margin:0"><div style="width:100%;height:100%;background:#eef">checking…</div></body></html>`;
