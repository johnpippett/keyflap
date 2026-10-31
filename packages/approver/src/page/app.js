const $ = (sel) => document.querySelector(sel);
const statusEl = $('#status');

const b64u = {
  decode(s) {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    return Uint8Array.from(b, (c) => c.charCodeAt(0));
  },
  encode(buf) {
    const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
    let s = '';
    for (const x of bytes) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
};

const UNSAFE =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping them is the point
  /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
const clean = (s) => String(s).replace(UNSAFE, '�');

const LABELS = {
  passkey: 'passkey',
  password: 'password',
  'password+totp': 'password + one-time code',
  totp: 'one-time code',
};

function formatDuration(ms) {
  const unit = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  const s = Math.round(ms / 1000);
  if (s < 60) return unit(s, 'second');
  const m = Math.round(s / 60);
  if (m < 60) return unit(m, 'minute');
  const h = Math.floor(m / 60);
  const rest = m % 60;
  return rest === 0 ? unit(h, 'hour') : `${unit(h, 'hour')} ${unit(rest, 'minute')}`;
}
const allowForText = (ms) =>
  `approving also lets this agent sign in here again without asking, for ${formatDuration(ms)}`;
const hostOf = (origin) => {
  try {
    return new URL(origin).host;
  } catch {
    return String(origin);
  }
};
const handoffSignInText = (ms) =>
  `One sign-in within ${formatDuration(ms)}, without asking again. Approving opens a live view of the website on this phone.`;
const platformWord = (on) => (on === 'Mac' ? 'Mac' : 'computer');
const addressChangedText = (on) =>
  `The approval address on your ${platformWord(on)} was changed. Don't approve anything until you've checked it at your ${platformWord(on)}.`;
const addressUnverifiedText = (on) =>
  `Keyflap can't check the approval address on your ${platformWord(on)} right now. Approvals are off until it can.`;
const notApprovedText = (m) =>
  m === 'approver_address_unverified'
    ? "Not approved: Keyflap can't check the approval address right now. Try again in a moment."
    : `Not approved: ${m}`;

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
  });
  let data = {};
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}

function pairError(code) {
  switch (code) {
    case 'pairing_in_progress':
    case 'no_ceremony':
      return 'this link is already being used by another device. Do not approve anything; start pairing again on the broker.';
    case 'bad_code':
    case 'code_expired':
      return 'this pairing link is invalid or expired.';
    case 'paired_at_other_origin':
    case 'pairing_refused':
      return 'the broker refused. Remove old phones with `keyflap approver remove` and pair again.';
    default:
      return code || 'pairing failed';
  }
}

async function pair(code) {
  $('#pair').hidden = false;
  statusEl.textContent = 'Not paired yet.';
  $('#pair-button').addEventListener('click', async () => {
    try {
      statusEl.textContent = 'Creating the approver passkey…';
      const { status, data: o } = await api('/api/pair/options', { code });
      if (status !== 200) throw new Error(pairError(o.error));
      const cred = await navigator.credentials.create({
        publicKey: {
          ...o,
          challenge: b64u.decode(o.challenge),
          user: { ...o.user, id: b64u.decode(o.user.id) },
          excludeCredentials: (o.excludeCredentials || []).map((c) => ({
            ...c,
            id: b64u.decode(c.id),
          })),
        },
      });
      const response = {
        id: cred.id,
        rawId: b64u.encode(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: b64u.encode(cred.response.clientDataJSON),
          attestationObject: b64u.encode(cred.response.attestationObject),
          transports: cred.response.getTransports ? cred.response.getTransports() : [],
        },
        clientExtensionResults: cred.getClientExtensionResults(),
        authenticatorAttachment: cred.authenticatorAttachment || undefined,
      };
      const fin = await api('/api/pair/finish', { code, response });
      if (fin.status === 202) {
        statusEl.textContent =
          `Check code ${clean(fin.data.check)}. On your already-paired phone, approve the ` +
          'request only if it shows this same code.';
        for (;;) {
          await new Promise((r) => setTimeout(r, 2000));
          const st = await api('/api/pair/status', { code });
          if (st.data.status === 'paired') break;
          if (st.status !== 200 || st.data.status === 'failed') throw new Error('not approved');
        }
      } else if (fin.status !== 200) {
        throw new Error(pairError(fin.data.error));
      }
      savePairCode('');
      history.replaceState(null, '', '/');
      $('#pair').hidden = true;
      statusEl.textContent = 'Paired.';
      start();
    } catch (e) {
      statusEl.textContent = `Pairing failed: ${clean(e.message || e)}`;
    }
  });
}

const cards = new Map();
let vapidPublicKey = null;
let clockOffset = 0;
const brokerNow = () => Date.now() + clockOffset;

const COMMIT_FRACTION = 0.35;
const MAX_TILT_DEGREES = 10;
const PIXELS_PER_TILT_DEGREE = 22;
const LEAVE_MS = 420;
const DRAG_IGNORES = 'input, label, button, a';
const siteSize = (text) => (text.length <= 19 ? 'large' : text.length <= 25 ? 'medium' : 'small');
const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const clamp = (n, low, high) => Math.min(high, Math.max(low, n));

let deciding = false;
async function exclusively(task) {
  if (deciding) return false;
  deciding = true;
  try {
    await task();
  } finally {
    deciding = false;
  }
  return true;
}

function orderStack() {
  [...$('#requests').children].forEach((card, i) => {
    card.inert = i > 0;
  });
}

function attachSwipe(card, onCommit) {
  const face = card.querySelector('.face');
  const yes = card.querySelector('.stamp.yes');
  const no = card.querySelector('.stamp.no');
  let drag = null;

  const isFront = () => card.parentElement?.firstElementChild === card;
  const clearStamps = () => {
    for (const stamp of [yes, no]) {
      stamp.style.opacity = '';
      stamp.classList.remove('armed');
    }
  };
  const settle = () => {
    face.classList.remove('dragging');
    face.style.transform = '';
    clearStamps();
  };
  const pop = (stamp) => {
    yes.classList.remove('armed');
    no.classList.remove('armed');
    if (!stamp) return;
    void stamp.offsetWidth;
    stamp.classList.add('armed');
  };
  const flyOff = async (direction) => {
    if (reducedMotion()) return;
    card.classList.add('leaving');
    face.style.transform = `translateX(${direction * 130}vw) rotate(${direction * 16}deg)`;
    face.style.opacity = '0';
    await new Promise((resolve) => setTimeout(resolve, LEAVE_MS));
  };

  face.addEventListener('pointerdown', (e) => {
    if (drag || deciding || !isFront() || !e.isPrimary || e.button !== 0) return;
    if (e.target.closest(DRAG_IGNORES)) return;
    drag = {
      pointerId: e.pointerId,
      startX: e.clientX,
      limit: face.offsetWidth * COMMIT_FRACTION,
      tilts: !reducedMotion(),
      armed: 0,
    };
    face.classList.add('dragging');
    face.setPointerCapture(e.pointerId);
  });
  face.addEventListener('pointermove', (e) => {
    if (!drag || e.pointerId !== drag.pointerId) return;
    const dx = e.clientX - drag.startX;
    const tilt = drag.tilts
      ? clamp(dx / PIXELS_PER_TILT_DEGREE, -MAX_TILT_DEGREES, MAX_TILT_DEGREES)
      : 0;
    face.style.transform = `translateX(${dx}px) rotate(${tilt}deg)`;
    const pull = Math.min(1, Math.abs(dx) / drag.limit);
    yes.style.opacity = dx > 0 ? String(pull) : '0';
    no.style.opacity = dx < 0 ? String(pull) : '0';
    const armed = pull >= 1 ? Math.sign(dx) : 0;
    if (armed === drag.armed) return;
    drag.armed = armed;
    pop(armed > 0 ? yes : armed < 0 ? no : null);
  });
  const end = (e, cancelled) => {
    if (!drag || e.pointerId !== drag.pointerId) return;
    const { armed } = drag;
    drag = null;
    face.classList.remove('dragging');
    if (cancelled || armed === 0) {
      settle();
      return;
    }
    if (armed > 0) settle();
    Promise.resolve(onCommit(armed))
      .then((ran) => {
        if (!ran) settle();
      })
      .catch(settle);
  };
  face.addEventListener('pointerup', (e) => end(e, false));
  face.addEventListener('pointercancel', (e) => end(e, true));
  face.addEventListener('lostpointercapture', (e) => end(e, true));

  return { settle, flyOff };
}

function renderCard(r) {
  const node = $('#request-card').content.firstElementChild.cloneNode(true);
  let combined = false;
  if (r.kind === 'pair') {
    node.querySelector('.title').textContent = 'Add another approver phone?';
    node.querySelector('.said-label').textContent = 'Requested';
    node.querySelector('.said').textContent = new Date(r.requestedAt).toLocaleString();
    node.querySelector('.site').textContent = 'this approver';
    node.querySelector('.agent').textContent = '(none)';
    node.querySelector('.credential').textContent =
      `new phone, check code ${clean(r.check)} (approve only if the new phone shows it)`;
  } else {
    const d = r.display;
    combined =
      !!d.handoffSignIn &&
      typeof d.handoffSignIn.withinMs === 'number' &&
      Number.isFinite(d.handoffSignIn.withinMs);
    node.querySelector('.title').textContent = combined
      ? `Human check, then sign in to ${clean(hostOf(d.verifiedOrigin))}?`
      : d.action === 'register'
        ? 'Register a passkey?'
        : 'Sign in?';
    node.querySelector('.said-label').textContent =
      `You said (${new Date(d.intentAt).toLocaleString()})`;
    node.querySelector('.said').textContent = `“${clean(d.intentText)}”`;
    node.querySelector('.site').textContent = clean(d.verifiedOrigin);
    node.querySelector('.agent').textContent = clean(d.agentName);
    node.querySelector('.credential').textContent =
      `${LABELS[d.credentialType] || '?'} (${d.action === 'register' ? 'register' : 'sign-in'})`;
    if (typeof d.keepSignedInSite === 'string') {
      node.querySelector('.keep').hidden = false;
      node.querySelector('.keep-text').textContent =
        `Keep me signed in on ${clean(d.keepSignedInSite)} (this agent's session is saved across broker restarts)`;
    }
    if (combined) {
      const label = node.querySelector('.allow-label');
      label.hidden = false;
      label.textContent = 'After the check';
      const allow = node.querySelector('.allow');
      allow.hidden = false;
      allow.textContent = handoffSignInText(d.handoffSignIn.withinMs);
    } else if (typeof d.allowForMs === 'number' && Number.isFinite(d.allowForMs)) {
      node.querySelector('.allow-label').hidden = false;
      const allow = node.querySelector('.allow');
      allow.hidden = false;
      allow.textContent = allowForText(d.allowForMs);
    }
  }
  const site = node.querySelector('.site');
  site.dataset.size = siteSize(site.textContent);
  const err = node.querySelector('.error');
  const face = node.querySelector('.face');
  const fail = (m) => {
    err.hidden = false;
    err.textContent = clean(m);
  };
  const swipe = attachSwipe(node, (direction) => (direction > 0 ? approveCard() : denyCard()));
  const leave = async (direction) => {
    await swipe.flyOff(direction);
    node.remove();
    orderStack();
    refresh();
  };
  const deny = async () => {
    err.hidden = true;
    try {
      const res = await api('/api/decide', { id: r.id, decision: 'deny' });
      if (res.status !== 200) throw new Error(res.data.error || 'not accepted');
      await leave(-1);
    } catch (e) {
      swipe.settle();
      fail(`Not denied: ${e.message || e}`);
      refresh();
    }
  };
  const approve = async () => {
    err.hidden = true;
    face.classList.add('waiting');
    try {
      const keep = node.querySelector('.keep-box');
      const keepSignedIn = !node.querySelector('.keep').hidden && keep.checked;
      const { status, data: c } = await api('/api/challenge', {
        id: r.id,
        ...(keepSignedIn ? { keepSignedIn: true } : {}),
      });
      if (status !== 200) throw new Error(c.error || 'request is gone');
      await AabCheck.checkStatement(c.statement, r, {
        keepSignedIn,
        descriptor: c.descriptor,
        origin: location.origin,
        now: brokerNow(),
      });
      const challenge = await AabCheck.approvalChallenge(c.statement);
      const cred = await navigator.credentials.get({
        publicKey: {
          challenge: b64u.decode(challenge),
          rpId: c.rpId,
          allowCredentials: c.allowCredentials.map((id) => ({
            type: 'public-key',
            id: b64u.decode(id),
          })),
          userVerification: 'required',
          timeout: c.timeout,
        },
      });
      const res = await api('/api/decide', {
        id: r.id,
        decision: 'approve',
        credential: {
          id: cred.id,
          response: {
            authenticatorData: b64u.encode(cred.response.authenticatorData),
            clientDataJSON: b64u.encode(cred.response.clientDataJSON),
            signature: b64u.encode(cred.response.signature),
          },
        },
      });
      if (res.status !== 200) throw new Error(res.data.error || 'not accepted');
      if (combined) {
        location.assign('/handoff');
        return;
      }
      await leave(1);
    } catch (e) {
      if (e && e.name === 'Mismatch') {
        const denied = await api('/api/decide', { id: r.id, decision: 'deny' }).then(
          (res) => res.status === 200,
          () => false,
        );
        fail(
          denied
            ? `Denied: ${e.message}. Something on the broker is not as it should be.`
            : `Not approved: ${e.message}. Something on the broker is not as it should be, and it did not take the denial.`,
        );
        return;
      }
      fail(notApprovedText(e.message || String(e)));
    } finally {
      face.classList.remove('waiting');
    }
  };
  const approveCard = () => exclusively(approve);
  const denyCard = () => exclusively(deny);
  node.querySelector('.deny').addEventListener('click', denyCard);
  node.querySelector('.approve').addEventListener('click', approveCard);
  return node;
}

function renderHandoffs(list) {
  const box = $('#handoffs');
  box.textContent = '';
  for (const h of list) {
    const node = $('#handoff-card').content.firstElementChild.cloneNode(true);
    node.querySelector('.handoff-title').textContent =
      `Human check waiting on ${clean(h.host)}, open live view`;
    node.querySelector('.handoff-agent').textContent = `Agent: ${clean(h.agentName)}`;
    box.append(node);
  }
}

const ios =
  /iPhone|iPad|iPod/.test(navigator.userAgent) ||
  (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const homeScreenApp =
  navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;

async function refresh() {
  const { status, data } = await api('/api/state');
  if (status === 401) {
    $('#install').hidden = true;
    if (data.error === 'approver_address_changed') {
      $('#reinstall').hidden = true;
      statusEl.textContent = addressChangedText(data.on);
      return false;
    }
    $('#reinstall').hidden = !homeScreenApp;
    statusEl.textContent = homeScreenApp
      ? ''
      : "This phone isn't paired with the broker. Open the pairing link the broker shows (on an iPhone, in Safari).";
    return false;
  }
  $('#reinstall').hidden = true;
  $('#install').hidden = !ios || homeScreenApp;
  if (status !== 200) {
    statusEl.textContent = 'Broker unreachable.';
    return true;
  }
  vapidPublicKey = data.vapidPublicKey;
  if (Number.isSafeInteger(data.now)) clockOffset = data.now - Date.now();
  $('#push').hidden = !('PushManager' in window) || data.push;
  if (data.push) syncPush();
  renderHandoffs(Array.isArray(data.handoffs) ? data.handoffs : []);
  const ids = new Set(data.pending.map((r) => r.id));
  for (const [id, node] of cards) {
    if (ids.has(id) || (node.isConnected && node.classList.contains('leaving'))) continue;
    node.remove();
    cards.delete(id);
  }
  for (const r of data.pending) {
    if (cards.has(r.id)) continue;
    const node = renderCard(r);
    cards.set(r.id, node);
    $('#requests').append(node);
  }
  orderStack();
  const paused = data.address && data.address.kind === 'paused';
  statusEl.textContent = paused
    ? addressUnverifiedText(data.address.on)
    : data.pending.length === 0 && !(data.handoffs && data.handoffs.length > 0)
      ? 'No pending requests.'
      : '';
  return true;
}

let timer = null;
function start() {
  const tick = async () => {
    const keep = await refresh().catch(() => true);
    if (keep) timer = setTimeout(tick, document.hidden ? 10000 : 2000);
  };
  clearTimeout(timer);
  tick();
}

async function registerPush() {
  const reg = await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  const sub =
    (await reg.pushManager.getSubscription()) ??
    (await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: b64u.decode(vapidPublicKey),
    }));
  const j = sub.toJSON();
  await api('/api/push', { subscription: { endpoint: j.endpoint, keys: j.keys } });
}

let pushSynced = false;
function syncPush() {
  if (pushSynced || !('PushManager' in window) || Notification.permission !== 'granted') return;
  pushSynced = true;
  registerPush().catch(() => {});
}

$('#push-button').addEventListener('click', async () => {
  try {
    if ((await Notification.requestPermission()) !== 'granted') return;
    await registerPush();
    pushSynced = true;
    $('#push').hidden = true;
  } catch (e) {
    statusEl.textContent = `Notifications unavailable: ${clean(e.message || e)}`;
  }
});

const clearNotifications = () =>
  navigator.serviceWorker?.ready
    .then((r) => r.getNotifications())
    .then((shown) => {
      for (const n of shown) n.close();
    })
    .catch(() => {});
clearNotifications();
document.addEventListener('visibilitychange', () => {
  if (document.hidden) return;
  clearNotifications();
  start();
});
navigator.serviceWorker
  ?.getRegistration()
  .then((r) => r?.update())
  .catch(() => {});
navigator.serviceWorker?.addEventListener('message', (e) => {
  const d = e.data;
  if (d && d.t === 'open' && d.url === '/handoff' && location.pathname !== '/handoff') {
    location.assign('/handoff');
  }
});

const PAIR_CODE_KEY = 'keyflap.pairCode';
const savedPairCode = () => {
  try {
    return sessionStorage.getItem(PAIR_CODE_KEY) || '';
  } catch {
    return '';
  }
};
const savePairCode = (code) => {
  try {
    if (code) sessionStorage.setItem(PAIR_CODE_KEY, code);
    else sessionStorage.removeItem(PAIR_CODE_KEY);
  } catch {}
};

if (location.pathname === '/pair') {
  const code = location.hash.length > 1 ? location.hash.slice(1) : savedPairCode();
  history.replaceState(null, '', '/pair');
  savePairCode(code);
  api('/api/state')
    .catch(() => ({ status: 0 }))
    .then(({ status }) => {
      if (status === 200) {
        savePairCode('');
        history.replaceState(null, '', '/');
        start();
      } else if (code) {
        pair(code);
      } else {
        statusEl.textContent = 'Not paired yet.';
        $('#lost-code').hidden = false;
      }
    });
} else {
  start();
}
