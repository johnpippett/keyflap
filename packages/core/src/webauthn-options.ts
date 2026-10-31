export class Deny extends Error {
  readonly name_: 'NotAllowedError' | 'InvalidStateError' | 'NotSupportedError' | 'SecurityError';
  readonly reason: string;
  constructor(reason: string, name: Deny['name_'] = 'NotAllowedError') {
    super(reason);
    this.reason = reason;
    this.name_ = name;
  }
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

function bytes(v: unknown, field: string, min: number, max: number): Uint8Array {
  if (!isObj(v) || typeof v.$b !== 'string' || !/^[A-Za-z0-9_-]*$/.test(v.$b)) {
    throw new Deny(`bad_${field}`, 'NotAllowedError');
  }
  const b = new Uint8Array(Buffer.from(v.$b, 'base64url'));
  if (b.length < min || b.length > max) throw new Deny(`bad_${field}`);
  return b;
}

function optString(v: unknown, field: string, max = 256): string | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'string' || v.length > max) throw new Deny(`bad_${field}`);
  return v;
}

function credentialList(v: unknown, field: string): Uint8Array[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.length > 64) throw new Deny(`bad_${field}`);
  return v
    .filter((d) => isObj(d) && (d.type === undefined || d.type === 'public-key'))
    .map((d) => bytes((d as Obj).id, field, 1, 1023));
}

export interface GetOptions {
  challenge: Uint8Array;
  rpId: string | undefined;
  allowCredentials: Uint8Array[];
  userVerification: string | undefined;
}

export function parseGetOptions(raw: unknown): GetOptions {
  if (!isObj(raw)) throw new Deny('bad_options');
  return {
    challenge: bytes(raw.challenge, 'challenge', 16, 1024),
    rpId: optString(raw.rpId, 'rpId'),
    allowCredentials: credentialList(raw.allowCredentials, 'allowCredentials'),
    userVerification: optString(raw.userVerification, 'userVerification'),
  };
}

export interface CreateOptions {
  challenge: Uint8Array;
  rpId: string | undefined;
  userId: Uint8Array;
  userName: string | undefined;
  excludeCredentials: Uint8Array[];
  credProps: boolean;
}

export function parseCreateOptions(raw: unknown): CreateOptions {
  if (!isObj(raw)) throw new Deny('bad_options');
  const rp = isObj(raw.rp) ? raw.rp : {};
  const user = isObj(raw.user) ? raw.user : null;
  if (!user) throw new Deny('bad_user');
  const params = Array.isArray(raw.pubKeyCredParams) ? raw.pubKeyCredParams : [];
  const es256 =
    params.length === 0 ||
    params.some(
      (p) => isObj(p) && (p.type === undefined || p.type === 'public-key') && p.alg === -7,
    );
  if (!es256) throw new Deny('no_supported_algorithm', 'NotSupportedError');
  if (raw.attestation === 'enterprise')
    throw new Deny('enterprise_attestation', 'NotSupportedError');
  const extensions = isObj(raw.extensions) ? raw.extensions : {};
  return {
    challenge: bytes(raw.challenge, 'challenge', 16, 1024),
    rpId: optString(rp.id, 'rpId'),
    userId: bytes(user.id, 'user_id', 1, 64),
    userName: optString(user.name, 'user_name', 512),
    excludeCredentials: credentialList(raw.excludeCredentials, 'excludeCredentials'),
    credProps: extensions.credProps === true,
  };
}
