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

let current = null;
let live = false;
let ended = false;
let autoTried = false;
let frameSeq = 0;
let stateTimer = null;
let emptySince = null;

function show(id, on) {
  $(id).hidden = !on;
}

function renderContext(h) {
  show('#signin-note', h.withSignIn === true);
  $('#host').textContent = clean(h.host);
  $('#agent').textContent = clean(h.agentName);
  $('#said-label').textContent = `You said (${new Date(h.intentAt).toLocaleString()})`;
  $('#said').textContent = `“${clean(h.intentText)}”`;
  show('#context', true);
}

function end(text) {
  ended = true;
  live = false;
  current = null;
  show('#live', false);
  show('#start', false);
  show('#finish', false);
  statusEl.textContent = text;
}

function toApprovals(delayMs) {
  setTimeout(() => location.replace('/'), delayMs);
}

async function refresh() {
  const { status, data } = await api('/api/handoff/state');
  if (status === 401) {
    end("This phone isn't paired with the broker.");
    return;
  }
  if (status !== 200) {
    statusEl.textContent = 'Broker unreachable.';
    return;
  }
  const list = Array.isArray(data.handoffs) ? data.handoffs : [];
  const want = new URLSearchParams(location.search).get('id');
  const h =
    (current && list.find((x) => x.id === current.id)) ||
    (want && list.find((x) => x.id === want)) ||
    list.find((x) => x.mine) ||
    list.find((x) => !x.started) ||
    null;
  if (!h) {
    if (current || live) {
      end('The human check has ended. Back to approvals…');
      toApprovals(1200);
    } else {
      show('#context', false);
      show('#start', false);
      show('#finish', false);
      emptySince ??= Date.now();
      if (Date.now() - emptySince < 5000) {
        statusEl.textContent = 'Waiting for the human check…';
      } else {
        statusEl.textContent = 'No human check is waiting. Back to approvals…';
        ended = true;
        toApprovals(0);
      }
    }
    return;
  }
  emptySince = null;
  ended = false;
  current = h;
  renderContext(h);
  if (h.mine) {
    if (!live) goLive();
    return;
  }
  if (h.started) {
    show('#start', false);
    statusEl.textContent = 'Another device is handling this human check.';
    return;
  }
  if (h.withSignIn === true) {
    show('#start', false);
    statusEl.textContent = 'Starting the live view once you approve it on the approvals page…';
    return;
  }
  statusEl.textContent = `Human check on ${clean(h.host)}.`;
  show('#start', true);
  if (!autoTried) {
    autoTried = true;
    start().catch(() => {});
  }
}

async function start() {
  if (!current) return;
  const id = current.id;
  $('#start-button').disabled = true;
  try {
    const { status, data: c } = await api('/api/handoff/challenge', { id });
    if (status !== 200) throw new Error(c.error || 'not available');
    if (typeof c.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(c.nonce)) {
      throw new Error('not available');
    }
    const challenge = await AabCheck.handoffStartChallenge(id, c.nonce);
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: b64u.decode(challenge),
        rpId: c.rpId,
        allowCredentials: c.allowCredentials.map((x) => ({
          type: 'public-key',
          id: b64u.decode(x),
        })),
        userVerification: 'required',
        timeout: c.timeout,
      },
    });
    const res = await api('/api/handoff/start', {
      id,
      credential: {
        id: cred.id,
        response: {
          authenticatorData: b64u.encode(cred.response.authenticatorData),
          clientDataJSON: b64u.encode(cred.response.clientDataJSON),
          signature: b64u.encode(cred.response.signature),
        },
      },
    });
    if (res.status !== 200) throw new Error(res.data.error || 'not started');
    goLive();
  } catch (e) {
    statusEl.textContent = `Tap "Start live view" to continue. ${e && e.name === 'NotAllowedError' ? '' : clean(e.message || e)}`;
    throw e;
  } finally {
    $('#start-button').disabled = false;
  }
}

function goLive() {
  live = true;
  show('#start', false);
  show('#live', true);
  show('#finish', true);
  statusEl.textContent = `Live: ${clean(current.host)}. Tap the picture to click.`;
  nextFrame();
}

const Z = globalThis.AabZoom;
const viewportEl = $('#viewport');
const stageEl = $('#stage');
const detailEl = $('#detail');
let view = { s: 1, tx: 0, ty: 0 };
const box = () => ({ W: viewportEl.clientWidth, H: viewportEl.clientHeight });

function setView(v) {
  const { W, H } = box();
  view = W > 0 && H > 0 ? Z.fit(v, W, H) : { s: 1, tx: 0, ty: 0 };
  stageEl.style.transform =
    view.s === 1 ? '' : `translate(${view.tx}px, ${view.ty}px) scale(${view.s})`;
  $('#zoom-out').disabled = view.s <= Z.MIN;
  $('#zoom-fit').disabled = view.s <= Z.MIN;
  $('#zoom-in').disabled = view.s >= Z.MAX;
  if (view.s === 1) detailEl.hidden = true;
}
function zoomBy(factor) {
  const { W, H } = box();
  setView(Z.zoomAt(view, factor, W / 2, H / 2, W, H));
}
$('#zoom-in').addEventListener('click', () => zoomBy(1.5));
$('#zoom-out').addEventListener('click', () => zoomBy(1 / 1.5));
$('#zoom-fit').addEventListener('click', () => setView({ s: 1, tx: 0, ty: 0 }));
window.addEventListener('resize', () => setView(view));

let pendingClip = null;
function nextFrame() {
  if (!live || !current) return;
  const base = `/api/handoff/frame?id=${encodeURIComponent(current.id)}&n=${++frameSeq}`;
  const { W, H } = box();
  if (view.s > 1 && W > 0 && frameSeq % 4 !== 0) {
    const c = Z.clipParam(Z.visible(view, W, H), 0.05);
    pendingClip = c.rect;
    detailEl.src = `${base}&clip=${c.param}`;
  } else {
    $('#screen').src = base;
  }
}

$('#screen').addEventListener('load', () => {
  show('#unavailable', false);
  setView(view);
  setTimeout(nextFrame, 300);
});
$('#screen').addEventListener('error', () => {
  if (!live) return;
  show('#unavailable', true);
  setTimeout(nextFrame, 1000);
});
detailEl.addEventListener('load', () => {
  const r = pendingClip;
  if (r && view.s > 1) {
    detailEl.style.left = `${r.x * 100}%`;
    detailEl.style.top = `${r.y * 100}%`;
    detailEl.style.width = `${r.w * 100}%`;
    detailEl.style.height = `${r.h * 100}%`;
    detailEl.hidden = false;
  }
  setTimeout(nextFrame, 300);
});
detailEl.addEventListener('error', () => {
  detailEl.hidden = true;
  if (live) setTimeout(nextFrame, 1000);
});

async function send(input) {
  if (!live || !current) return;
  const err = $('#input-error');
  err.hidden = true;
  const r = await api('/api/handoff/input', { id: current.id, input });
  if (r.status === 422) {
    err.hidden = false;
    err.textContent = "Use the broker's sign-in for passwords";
  } else if (r.status !== 200) {
    err.hidden = false;
    err.textContent = 'Not sent.';
  }
  nextFrame();
}

const fingers = new Map();
let down = null;
let gesture = null;
const local = (e) => {
  const r = viewportEl.getBoundingClientRect();
  return { x: e.clientX - r.left, y: e.clientY - r.top };
};
const frac = (p) => {
  const { W, H } = box();
  return { ...Z.toPage(view, p.x, p.y, W, H), px: p.x, py: p.y };
};
viewportEl.addEventListener('pointerdown', (e) => {
  e.preventDefault();
  viewportEl.setPointerCapture?.(e.pointerId);
  const p = local(e);
  fingers.set(e.pointerId, p);
  if (fingers.size === 1 && !gesture) {
    down = frac(p);
  } else if (fingers.size === 2) {
    down = null;
    const [a0, b0] = [...fingers.values()];
    gesture = { v0: view, a0, b0 };
  }
});
viewportEl.addEventListener('pointermove', (e) => {
  if (!fingers.has(e.pointerId)) return;
  fingers.set(e.pointerId, local(e));
  if (gesture && fingers.size === 2) {
    const [a1, b1] = [...fingers.values()];
    const { W, H } = box();
    setView(Z.pinch(gesture.v0, gesture.a0, gesture.b0, a1, b1, W, H));
  }
});
const lift = (e) => {
  fingers.delete(e.pointerId);
  if (fingers.size === 0) gesture = null;
};
viewportEl.addEventListener('pointerup', (e) => {
  e.preventDefault();
  const known = fingers.has(e.pointerId);
  lift(e);
  if (!down || !known) return;
  const up = frac(local(e));
  const moved = Math.hypot(up.px - down.px, up.py - down.py);
  const from = { x: down.x, y: down.y };
  down = null;
  if (moved < 10) send({ type: 'click', x: up.x, y: up.y });
  else send({ type: 'drag', from, to: { x: up.x, y: up.y } });
});
viewportEl.addEventListener('pointercancel', (e) => {
  lift(e);
  down = null;
});
for (const t of ['gesturestart', 'gesturechange']) {
  viewportEl.addEventListener(t, (e) => e.preventDefault());
}

for (const b of document.querySelectorAll('.scroll')) {
  b.addEventListener('click', () => send({ type: 'scroll', dy: Number(b.dataset.dy) }));
}
for (const b of document.querySelectorAll('.key')) {
  b.addEventListener('click', () => send({ type: 'key', key: b.dataset.key }));
}
$('#text-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const t = $('#text');
  const text = t.value;
  t.value = '';
  if (text.length > 0) send({ type: 'text', text });
});

async function finish(outcome) {
  if (!current) return;
  await api('/api/handoff/finish', { id: current.id, outcome });
  end(
    outcome === 'done'
      ? 'Done. The agent continues. Back to approvals…'
      : 'Cancelled. Back to approvals…',
  );
  toApprovals(1200);
}
$('#done').addEventListener('click', () => finish('done'));
$('#cancel').addEventListener('click', () => finish('cancelled'));
$('#start-button').addEventListener('click', () => start().catch(() => {}));

function poll() {
  clearTimeout(stateTimer);
  const tick = async () => {
    await refresh().catch(() => {});
    if (!ended) stateTimer = setTimeout(tick, document.hidden ? 10000 : 2000);
  };
  tick();
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && !ended) poll();
});
navigator.serviceWorker?.addEventListener('message', (e) => {
  const d = e.data;
  if (d && d.t === 'open' && d.url === '/' && location.pathname !== '/') location.assign('/');
});
poll();
