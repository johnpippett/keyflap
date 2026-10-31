import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Socket } from 'node:net';
import type {
  FillField,
  NativeApproverKey,
  SignedApproval,
  SignerAuthorization,
  WebAuthnApproverKey,
} from './approval.ts';
import type { AddressState } from './approver-address.ts';

export const MAX_FRAME_BYTES = 256 * 1024;

export interface HelloFrame {
  t: 'hello';
  nonce: string;
}
export interface RequestFrame {
  t: 'req';
  seq: number;
  body: string;
  mac: string;
}
export interface ResponseFrame {
  t: 'res';
  seq: number;
  body: string;
  mac: string;
}
export type Frame = HelloFrame | RequestFrame | ResponseFrame;

export function macFor(
  key: Buffer,
  direction: 'req' | 'res',
  nonce: string,
  seq: number,
  body: string,
): string {
  return createHmac('sha256', key)
    .update(`${direction}\n${nonce}\n${seq}\n`)
    .update(body)
    .digest('base64url');
}

export function macEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export function writeFrame(socket: Socket, frame: Frame): void {
  const payload = Buffer.from(JSON.stringify(frame), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length);
  socket.write(Buffer.concat([header, payload]));
}

export function readFrames(
  socket: Socket,
  onFrame: (frame: Frame) => void,
  onError: (err: Error) => void,
): void {
  let buf = Buffer.alloc(0);
  let failed = false;
  const fail = (err: Error) => {
    failed = true;
    buf = Buffer.alloc(0);
    try {
      onError(err);
    } catch {
      socket.destroy();
    }
  };
  socket.on('data', (chunk: Buffer) => {
    if (failed || socket.destroyed) return;
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4 && !failed && !socket.destroyed) {
      const len = buf.readUInt32BE(0);
      if (len > MAX_FRAME_BYTES) return fail(new Error('frame too large'));
      if (buf.length < 4 + len) break;
      const raw = buf.subarray(4, 4 + len).toString('utf8');
      buf = buf.subarray(4 + len);
      let frame: unknown;
      try {
        frame = JSON.parse(raw);
      } catch {
        return fail(new Error('malformed frame'));
      }
      if (!isPlainObject(frame)) return fail(new Error('malformed frame'));
      try {
        onFrame(frame as unknown as Frame);
      } catch {
        return fail(new Error('frame handler failed'));
      }
    }
  });
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  return Object.getPrototypeOf(v) === Object.prototype;
}

export interface CreateCredentialRequest {
  op: 'create_credential';
  rpId: string;
  userHandle: string;
  clientDataJSON: string;
  approval: SignedApproval;
}
export interface CreateCredentialResult {
  credentialId: string;
  publicKey: { x: string; y: string };
}

export interface SignRequest {
  op: 'sign';
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  approval: SignerAuthorization;
}
export interface SignResult {
  signature: string;
}

export interface PingRequest {
  op: 'ping';
}

export interface StoreItemRequest {
  op: 'store_item';
  domain: string;
  password: string;
  totp?: { secret: string; algorithm?: string; digits?: number; period?: number };
}
export interface StoreItemResult {
  itemId: string;
}

export interface DeleteItemRequest {
  op: 'delete_item';
  itemId: string;
}
export interface DeleteItemResult {
  deleted: boolean;
}

export interface ReleaseSecretRequest {
  op: 'release_secret';
  itemId: string;
  field: FillField;
  approval: SignerAuthorization;
}
export interface ReleaseSecretResult {
  value: string;
}

export interface SignerSourcesConfig {
  protonPass?: { bin: string; env: Record<string, string>; vault?: string; sha256?: string };
  onePassword?: { bin: string; env: Record<string, string>; vault?: string; sha256?: string };
}

export interface ListSourceItemsRequest {
  op: 'list_source_items';
  source: string;
}
export interface ListSourceItemsResult {
  items: { ref: string; hosts: string[]; username: string | null; hasTotp: boolean }[];
}

export interface ListApproversRequest {
  op: 'list_approvers';
}
export interface ListApproversResult {
  approvers: WebAuthnApproverKey[];
  native?: NativeApproverKey[];
}

export interface AddApproverRequest {
  op: 'add_approver';
  key: { credentialId: string; x: string; y: string; rpId: string; origin: string };
  approval?: SignedApproval;
}
export interface AddApproverResult {
  added: true;
}

export interface AddNativeApproverRequest {
  op: 'add_native_approver';
  key: { x: string; y: string; origin: string; userVerification: 'biometry' };
  proof: string;
  approval?: SignedApproval;
}
export interface AddNativeApproverResult {
  added: true;
  keyId: string;
}

export interface RemoveApproverRequest {
  op: 'remove_approver';
  credentialId: string;
}
export interface RemoveApproverResult {
  removed: boolean;
}

export interface BrowserStateKeyRequest {
  op: 'browser_state_key';
}
export interface BrowserStateKeyResult {
  key: string;
}

export interface AcceptHandoffGrantRequest {
  op: 'accept_handoff_grant';
  approval: SignedApproval;
}
export interface AcceptHandoffGrantResult {
  grantId: string;
  until: number;
}

export interface DropGrantRequest {
  op: 'drop_grant';
  grantId: string;
}
export interface DropGrantResult {
  dropped: boolean;
}

export interface ApproverAddressRequest {
  op: 'approver_address';
  pending: boolean;
}
export interface ClearApproverAddressRequest {
  op: 'clear_approver_address';
}
export interface ApproverAddressResult {
  state: AddressState;
}

export type SignerRequest =
  | CreateCredentialRequest
  | SignRequest
  | PingRequest
  | StoreItemRequest
  | DeleteItemRequest
  | ReleaseSecretRequest
  | ListSourceItemsRequest
  | ListApproversRequest
  | AddApproverRequest
  | AddNativeApproverRequest
  | RemoveApproverRequest
  | BrowserStateKeyRequest
  | AcceptHandoffGrantRequest
  | DropGrantRequest
  | ApproverAddressRequest
  | ClearApproverAddressRequest;

export type SignerResponse<T = unknown> = { ok: true; result: T } | { ok: false; error: string };
