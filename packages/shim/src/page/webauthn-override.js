(() => {
  const BINDING = '__aabWebAuthn';
  if (!window.isSecureContext || !navigator.credentials) return;
  const CC = window.CredentialsContainer;
  if (typeof CC !== 'function') return;

  const apply = Reflect.apply;
  const defineProperty = Object.defineProperty;
  const objectCreate = Object.create;
  const DOMExc = DOMException;
  const PromiseCtor = Promise;
  const nativeGet = CC.prototype.get;
  const nativeCreate = CC.prototype.create;
  const protoOf = (name) =>
    typeof window[name] === 'function' ? window[name].prototype : Object.prototype;
  const PKC_PROTO = protoOf('PublicKeyCredential');
  const ATTESTATION_PROTO = protoOf('AuthenticatorAttestationResponse');
  const ASSERTION_PROTO = protoOf('AuthenticatorAssertionResponse');

  const callBroker = (...args) => {
    const fn = window[BINDING];
    if (typeof fn !== 'function')
      return PromiseCtor.resolve({ ok: false, name: 'NotAllowedError' });
    return fn(...args);
  };

  const toB64url = (buf) => {
    const bytes =
      buf instanceof ArrayBuffer
        ? new Uint8Array(buf)
        : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const fromB64url = (s) => {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };

  const serialize = (v, depth = 0) => {
    if (depth > 8) return null;
    if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return { $b: toB64url(v) };
    if (Array.isArray(v)) return v.slice(0, 256).map((x) => serialize(x, depth + 1));
    if (v && typeof v === 'object') {
      const out = {};
      for (const k of Object.keys(v)) {
        if (typeof v[k] !== 'function' && k !== 'signal') out[k] = serialize(v[k], depth + 1);
      }
      return out;
    }
    if (typeof v === 'function' || typeof v === 'symbol' || typeof v === 'bigint') return null;
    return v;
  };

  const define = (obj, props) => {
    for (const [k, value] of Object.entries(props)) {
      defineProperty(obj, k, { value, enumerable: true, configurable: true });
    }
    return obj;
  };

  const toCredential = (c, kind) => {
    const r = c.response;
    const response = objectCreate(kind === 'create' ? ATTESTATION_PROTO : ASSERTION_PROTO);
    define(response, { clientDataJSON: fromB64url(r.clientDataJSON) });
    if (kind === 'create') {
      define(response, {
        attestationObject: fromB64url(r.attestationObject),
        getTransports: () => [...(r.transports || [])],
        getAuthenticatorData: () => fromB64url(r.authenticatorData),
        getPublicKey: () => (r.publicKey ? fromB64url(r.publicKey) : null),
        getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
      });
    } else {
      define(response, {
        authenticatorData: fromB64url(r.authenticatorData),
        signature: fromB64url(r.signature),
        userHandle: r.userHandle ? fromB64url(r.userHandle) : null,
      });
    }
    const json = () => ({
      id: c.id,
      rawId: c.id,
      type: c.type,
      authenticatorAttachment: c.authenticatorAttachment,
      clientExtensionResults: { ...c.clientExtensionResults },
      response:
        kind === 'create'
          ? {
              clientDataJSON: r.clientDataJSON,
              attestationObject: r.attestationObject,
              authenticatorData: r.authenticatorData,
              transports: [...(r.transports || [])],
              publicKey: r.publicKey,
              publicKeyAlgorithm: r.publicKeyAlgorithm,
            }
          : {
              clientDataJSON: r.clientDataJSON,
              authenticatorData: r.authenticatorData,
              signature: r.signature,
              userHandle: r.userHandle || undefined,
            },
    });
    const cred = objectCreate(PKC_PROTO);
    return define(cred, {
      id: c.id,
      rawId: fromB64url(c.id),
      type: c.type,
      authenticatorAttachment: c.authenticatorAttachment,
      response,
      getClientExtensionResults: () => ({ ...c.clientExtensionResults }),
      toJSON: json,
    });
  };

  const aborted = () => new DOMExc('The operation was aborted.', 'AbortError');

  const run = async (kind, publicKey, mediation, signal) => {
    if (signal?.aborted) throw aborted();
    const pending = callBroker(kind, serialize(publicKey), mediation ?? null);
    const result = signal
      ? await PromiseCtor.race([
          pending,
          new PromiseCtor((_, reject) => signal.addEventListener('abort', () => reject(aborted()))),
        ])
      : await pending;
    if (!result?.ok) {
      const name = result?.name || 'NotAllowedError';
      throw new DOMExc('The operation either timed out or was not allowed.', name);
    }
    return toCredential(result.credential, kind);
  };

  const GET_KEYS = ['mediation', 'signal', 'password', 'federated', 'identity', 'otp', 'digital'];
  const CREATE_KEYS = ['mediation', 'signal', 'password', 'federated', 'digital'];
  const passThrough = (native, self, options, keys) => {
    if (options === undefined || options === null) return apply(native, self, []);
    const safe = objectCreate(null);
    for (let i = 0; i < keys.length; i++) {
      const v = options[keys[i]];
      if (v !== undefined) safe[keys[i]] = v;
    }
    return apply(native, self, [safe]);
  };

  const overrides = {
    get(options) {
      const publicKey = options == null ? undefined : options.publicKey;
      if (publicKey == null) return passThrough(nativeGet, this, options, GET_KEYS);
      const mediation = options.mediation;
      const signal = options.signal;
      if (mediation === 'conditional') {
        return new PromiseCtor((_, reject) => {
          signal?.addEventListener('abort', () => reject(aborted()));
        });
      }
      return run('get', publicKey, mediation, signal);
    },
    create(options) {
      const publicKey = options == null ? undefined : options.publicKey;
      if (publicKey == null) return passThrough(nativeCreate, this, options, CREATE_KEYS);
      return run('create', publicKey, options.mediation, options.signal);
    },
  };

  const lock = (obj, name, value) =>
    defineProperty(obj, name, { value, enumerable: true, writable: false, configurable: false });
  for (const target of [CC.prototype, navigator.credentials]) {
    lock(target, 'get', overrides.get);
    lock(target, 'create', overrides.create);
  }

  const PKC = window.PublicKeyCredential;
  if (PKC) {
    const stub = (name, value) =>
      defineProperty(PKC, name, { value, enumerable: true, writable: false, configurable: false });
    stub('isUserVerifyingPlatformAuthenticatorAvailable', async () => true);
    stub('isConditionalMediationAvailable', async () => false);
    stub('getClientCapabilities', async () => ({
      conditionalCreate: false,
      conditionalGet: false,
      hybridTransport: false,
      passkeyPlatformAuthenticator: true,
      userVerifyingPlatformAuthenticator: true,
      relatedOrigins: false,
      signalAllAcceptedCredentials: false,
      signalCurrentUserDetails: false,
      signalUnknownCredential: false,
    }));
    for (const name of [
      'signalUnknownCredential',
      'signalAllAcceptedCredentials',
      'signalCurrentUserDetails',
    ]) {
      if (name in PKC) stub(name, undefined);
    }
  }
})();
