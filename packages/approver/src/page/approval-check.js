globalThis.AabCheck = (() => {
  const APPROVAL_DOMAIN = 'aab-approval-v1\n';
  const HANDOFF_START_DOMAIN = 'aab-handoff-start-v1\n';
  const HANDOFF_SIGNIN_DOMAIN = 'aab-handoff-signin-v1\n';
  const MAX_LIFETIME_MS = 5 * 60_000;
  const STRONG_MAX_LIFETIME_MS = 60_000;
  const CLOCK_SKEW_MS = 30_000;
  const MAX_GRANT_MS = 24 * 60 * 60_000;
  const HANDOFF_GRANT_MAX_MS = 7 * 60_000;
  const KNOWN = new Set([
    'v',
    'requestId',
    'kind',
    'verifiedOrigin',
    'rpId',
    'credentialId',
    'intentHash',
    'clientDataHash',
    'userVerified',
    'issuedAt',
    'expiresAt',
    'strong',
    'grant',
    'keepSignedIn',
    'handoff',
  ]);
  const FILL_SCOPES = {
    password: 'aab-fill-v1\npassword',
    totp: 'aab-fill-v1\ntotp',
    'password+totp': 'aab-fill-v1\npassword,totp',
  };
  const DESCRIPTORS = [
    { prefix: 'aab-approver-add-v1\n', id: 'credentialId', newDevice: 'passkey' },
    { prefix: 'aab-native-approver-add-v1\n', id: 'keyId', newDevice: 'ios-app' },
  ];

  function canonicalJson(value) {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
    const entries = Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`);
    return `{${entries.join(',')}}`;
  }

  function b64url(bytes) {
    let s = '';
    for (const x of new Uint8Array(bytes)) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function sha256(text) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  }

  const sha256B64url = async (text) => b64url(await sha256(text));

  const approvalChallenge = (statement) => sha256B64url(APPROVAL_DOMAIN + canonicalJson(statement));

  const handoffStartChallenge = (id, nonce) =>
    sha256B64url(`${HANDOFF_START_DOMAIN}${id}\n${nonce}`);

  async function checkCode(descriptor) {
    let hex = '';
    for (const x of await sha256(descriptor)) hex += x.toString(16).padStart(2, '0');
    hex = hex.toUpperCase();
    return `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}`;
  }

  class Mismatch extends Error {
    constructor(what) {
      super(`the request doesn't match what this card shows (${what})`);
      this.name = 'Mismatch';
    }
  }

  const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
  const isInt = (v) => Number.isSafeInteger(v);
  const isStr = (v) => typeof v === 'string' && v.length > 0;

  function hostWithin(origin, rpId) {
    let host;
    try {
      host = new URL(origin).hostname;
    } catch {
      return false;
    }
    if (!isStr(rpId) || rpId.startsWith('.') || rpId !== rpId.toLowerCase()) return false;
    return host === rpId || host.endsWith(`.${rpId}`);
  }

  function parseDescriptor(descriptor) {
    if (typeof descriptor !== 'string') return null;
    for (const d of DESCRIPTORS) {
      if (!descriptor.startsWith(d.prefix)) continue;
      try {
        const o = JSON.parse(descriptor.slice(d.prefix.length));
        if (!isObject(o) || !isStr(o[d.id]) || !isStr(o.origin)) return null;
        return { id: o[d.id], origin: o.origin, newDevice: d.newDevice };
      } catch {
        return null;
      }
    }
    return null;
  }

  async function checkStatement(s, r, o) {
    const fail = (what) => {
      throw new Mismatch(what);
    };
    if (!isObject(s) || !isObject(r)) fail('malformed');
    for (const k of Object.keys(s)) if (!KNOWN.has(k)) fail(`unknown term ${k}`);
    if (s.v !== 1) fail('version');
    if (s.requestId !== r.id) fail('request id');
    if (s.userVerified !== true) fail('user verification');
    for (const k of ['kind', 'verifiedOrigin', 'rpId', 'intentHash', 'clientDataHash']) {
      if (!isStr(s[k])) fail(k);
    }
    if (s.credentialId !== null && !isStr(s.credentialId)) fail('credential');
    if (!isInt(s.issuedAt) || !isInt(s.expiresAt)) fail('lifetime');
    if (s.strong !== undefined && s.strong !== true) fail('strong');
    const strong = s.strong === true;
    const lifetime = s.expiresAt - s.issuedAt;
    if (lifetime <= 0 || lifetime > (strong ? STRONG_MAX_LIFETIME_MS : MAX_LIFETIME_MS)) {
      fail('lifetime');
    }
    if (!isInt(o.now) || o.now > s.expiresAt || o.now + CLOCK_SKEW_MS < s.issuedAt) {
      fail('expired');
    }
    const g = s.grant;
    if (g !== undefined) {
      if (!isObject(g) || !isStr(g.agentId) || !isInt(g.until)) fail('grant');
      const keys = Object.keys(g).sort().join(',');
      if (keys !== 'agentId,until' && !(keys === 'agentId,until,uses' && g.uses === 1)) {
        fail('grant');
      }
    }

    if (r.kind === 'pair') {
      if (s.kind !== 'approver.add') fail('kind');
      if (g !== undefined || strong || s.keepSignedIn !== undefined || s.handoff !== undefined) {
        fail('kind');
      }
      const d = parseDescriptor(o.descriptor);
      const origin = o.origin;
      if (
        !d ||
        s.clientDataHash !== (await sha256B64url(o.descriptor)) ||
        (await checkCode(o.descriptor)) !== r.check ||
        d.id !== s.credentialId ||
        d.origin !== origin ||
        d.newDevice !== r.newDevice ||
        s.verifiedOrigin !== origin ||
        s.rpId !== new URL(origin).hostname
      ) {
        fail("new phone's key");
      }
      return;
    }
    if (r.kind !== 'credential' || !isObject(r.display)) fail('unknown request type');

    const d = r.display;
    if (s.verifiedOrigin !== d.verifiedOrigin || !hostWithin(d.verifiedOrigin, s.rpId)) {
      fail('site');
    }
    const combined = d.handoffSignIn !== undefined;
    if (s.kind === 'webauthn.get' && d.action === 'sign-in' && d.credentialType === 'passkey') {
      if (s.credentialId === null) fail('credential');
      if (combined && s.handoff !== undefined) {
        const bound = await sha256B64url(HANDOFF_SIGNIN_DOMAIN + s.handoff.id);
        if (s.clientDataHash !== bound) fail('human check');
      }
    } else if (
      s.kind === 'webauthn.create' &&
      d.action === 'register' &&
      d.credentialType === 'passkey'
    ) {
      if (s.credentialId !== null) fail('credential');
    } else if (s.kind === 'fill' && d.action === 'sign-in') {
      const scope = FILL_SCOPES[d.credentialType];
      if (!scope || s.credentialId === null) fail('credential type');
      if (s.clientDataHash !== (await sha256B64url(scope))) fail('credential type');
    } else {
      fail('credential type');
    }

    const keep = s.keepSignedIn;
    if (o.keepSignedIn === true) {
      if (
        typeof d.keepSignedInSite !== 'string' ||
        !isObject(keep) ||
        Object.keys(keep).length !== 1 ||
        keep.site !== d.keepSignedInSite ||
        !strong
      ) {
        fail('keep me signed in');
      }
    } else if (keep !== undefined) {
      fail('keep me signed in');
    }

    if (combined) {
      const within = d.handoffSignIn.withinMs;
      const h = s.handoff;
      if (
        !isObject(h) ||
        Object.keys(h).length !== 1 ||
        !/^[A-Za-z0-9-]{1,64}$/.test(h.id ?? '') ||
        g === undefined ||
        g.uses !== 1 ||
        strong ||
        d.allowForMs !== undefined ||
        !isInt(within) ||
        within <= 0 ||
        within > HANDOFF_GRANT_MAX_MS ||
        g.until - s.issuedAt !== within
      ) {
        fail('human check and sign-in');
      }
      return;
    }
    if (s.handoff !== undefined || g?.uses !== undefined) fail('human check and sign-in');
    const shown = d.allowForMs;
    if (shown === undefined && g === undefined) return;
    if (
      shown === undefined ||
      g === undefined ||
      strong ||
      !isInt(shown) ||
      shown <= 0 ||
      shown > MAX_GRANT_MS ||
      g.until - s.issuedAt !== shown
    ) {
      fail('allow-for window');
    }
  }

  return {
    canonicalJson,
    sha256B64url,
    approvalChallenge,
    handoffStartChallenge,
    checkCode,
    checkStatement,
    Mismatch,
  };
})();
