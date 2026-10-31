import { type ChildProcess, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { connect, type Socket } from 'node:net';
import { fileURLToPath } from 'node:url';
import type { SignedApproval, TrustedApproverKeys } from './approval.ts';
import type { ApproverAddress } from './approver-address.ts';
import { assertUnixSocketPath } from './platform.ts';
import {
  type AcceptHandoffGrantResult,
  type AddApproverRequest,
  type AddApproverResult,
  type AddNativeApproverRequest,
  type AddNativeApproverResult,
  type ApproverAddressResult,
  type BrowserStateKeyResult,
  type CreateCredentialRequest,
  type CreateCredentialResult,
  type DeleteItemResult,
  type DropGrantResult,
  type Frame,
  type ListApproversResult,
  type ListSourceItemsResult,
  macEquals,
  macFor,
  type ReleaseSecretRequest,
  type ReleaseSecretResult,
  type RemoveApproverResult,
  readFrames,
  type SignerRequest,
  type SignerResponse,
  type SignerSourcesConfig,
  type SignRequest,
  type SignResult,
  type StoreItemRequest,
  type StoreItemResult,
  writeFrame,
} from './protocol.ts';

export class SignerDenied extends Error {}

export class SignerClient {
  private socket: Socket;
  private nonce = '';
  private seq = 0;
  private readonly key: Buffer;
  private readonly pending = new Map<
    number,
    { resolve: (r: SignerResponse) => void; reject: (e: Error) => void }
  >();
  private ready: Promise<void>;
  private rejectReady: (e: Error) => void = () => {};
  private closed = false;
  private readonly closeListeners: ((err: Error) => void)[] = [];

  constructor(socketPath: string, channelKey: Buffer) {
    this.key = channelKey;
    assertUnixSocketPath(socketPath, 'signer socket');
    this.socket = connect(socketPath);
    this.ready = new Promise((resolve, reject) => {
      this.rejectReady = reject;
      this.socket.once('error', reject);
      readFrames(
        this.socket,
        (frame: Frame) => {
          if (frame.t === 'hello' && !this.nonce) {
            if (typeof frame.nonce !== 'string' || frame.nonce.length === 0) {
              return this.fail(new Error('bad hello frame'));
            }
            this.nonce = frame.nonce;
            resolve();
            return;
          }
          if (
            frame.t !== 'res' ||
            !this.nonce ||
            !Number.isInteger(frame.seq) ||
            typeof frame.body !== 'string' ||
            typeof frame.mac !== 'string'
          ) {
            return this.fail(new Error('unexpected frame'));
          }
          const waiter = this.pending.get(frame.seq);
          if (!waiter) return this.fail(new Error('unexpected response'));
          this.pending.delete(frame.seq);
          if (!macEquals(frame.mac, macFor(this.key, 'res', this.nonce, frame.seq, frame.body))) {
            waiter.reject(new Error('signer response failed authentication'));
            return this.fail(new Error('bad response mac'));
          }
          let res: SignerResponse;
          try {
            res = JSON.parse(frame.body) as SignerResponse;
          } catch {
            res = { ok: false, error: 'bad_response' };
          }
          if (typeof res !== 'object' || res === null || typeof res.ok !== 'boolean') {
            res = { ok: false, error: 'bad_response' };
          }
          waiter.resolve(res);
        },
        (err) => this.fail(err),
      );
    });
    this.ready.catch(() => {});
    this.socket.on('error', (err) => this.fail(err));
    this.socket.on('close', () => this.fail(new Error('signer connection closed')));
  }

  private fail(err: Error): void {
    this.rejectReady(err);
    for (const w of this.pending.values()) w.reject(err);
    this.pending.clear();
    if (!this.closed) {
      this.closed = true;
      this.socket.destroy();
      for (const l of this.closeListeners.splice(0)) l(err);
    }
  }

  onUnexpectedClose(listener: (err: Error) => void): void {
    if (this.closed) return;
    this.closeListeners.push(listener);
  }

  async call<T>(req: SignerRequest): Promise<T> {
    await this.ready;
    if (this.closed) throw new Error('signer connection closed');
    const seq = ++this.seq;
    const body = JSON.stringify(req);
    const res = await new Promise<SignerResponse>((resolve, reject) => {
      this.pending.set(seq, { resolve, reject });
      writeFrame(this.socket, {
        t: 'req',
        seq,
        body,
        mac: macFor(this.key, 'req', this.nonce, seq, body),
      });
    });
    if (!res.ok) throw new SignerDenied(typeof res.error === 'string' ? res.error : 'denied');
    return res.result as T;
  }

  ping(): Promise<{ pong: true }> {
    return this.call({ op: 'ping' });
  }

  createCredential(req: Omit<CreateCredentialRequest, 'op'>): Promise<CreateCredentialResult> {
    return this.call({ op: 'create_credential', ...req });
  }

  sign(req: Omit<SignRequest, 'op'>): Promise<SignResult> {
    return this.call({ op: 'sign', ...req });
  }

  storeItem(req: Omit<StoreItemRequest, 'op'>): Promise<StoreItemResult> {
    return this.call({ op: 'store_item', ...req });
  }

  deleteItem(itemId: string): Promise<DeleteItemResult> {
    return this.call({ op: 'delete_item', itemId });
  }

  releaseSecret(req: Omit<ReleaseSecretRequest, 'op'>): Promise<ReleaseSecretResult> {
    return this.call({ op: 'release_secret', ...req });
  }

  listSourceItems(source: string): Promise<ListSourceItemsResult> {
    return this.call({ op: 'list_source_items', source });
  }

  listApprovers(): Promise<ListApproversResult> {
    return this.call({ op: 'list_approvers' });
  }

  addApprover(req: Omit<AddApproverRequest, 'op'>): Promise<AddApproverResult> {
    return this.call({ op: 'add_approver', ...req });
  }

  addNativeApprover(req: Omit<AddNativeApproverRequest, 'op'>): Promise<AddNativeApproverResult> {
    return this.call({ op: 'add_native_approver', ...req });
  }

  removeApprover(credentialId: string): Promise<RemoveApproverResult> {
    return this.call({ op: 'remove_approver', credentialId });
  }

  browserStateKey(): Promise<BrowserStateKeyResult> {
    return this.call({ op: 'browser_state_key' });
  }

  acceptHandoffGrant(approval: SignedApproval): Promise<AcceptHandoffGrantResult> {
    return this.call({ op: 'accept_handoff_grant', approval });
  }

  dropGrant(grantId: string): Promise<DropGrantResult> {
    return this.call({ op: 'drop_grant', grantId });
  }

  approverAddress(o: { pending: boolean }): Promise<ApproverAddressResult> {
    return this.call({ op: 'approver_address', pending: o.pending });
  }

  clearApproverAddress(): Promise<ApproverAddressResult> {
    return this.call({ op: 'clear_approver_address' });
  }

  close(): void {
    this.closed = true;
    this.socket.destroy();
  }
}

export interface SpawnSignerOptions {
  socketPath: string;
  storePath: string;
  passphrase: string;
  trustedApproverKeys: TrustedApproverKeys;
  highRiskDomains?: readonly string[];
  approverAdmin?: boolean;
  sources?: SignerSourcesConfig;
  approverAddress?: ApproverAddress;
  onLog?: (line: string) => void;
}

export interface SignerHandle {
  client: SignerClient;
  process: ChildProcess | null;
  stop(): Promise<void>;
}

export interface SpawnedSigner extends SignerHandle {
  process: ChildProcess;
}

const MAIN = fileURLToPath(new URL('./main.ts', import.meta.url));

export async function spawnSigner(opts: SpawnSignerOptions): Promise<SpawnedSigner> {
  assertUnixSocketPath(opts.socketPath, 'signer socket');
  const channelKey = randomBytes(32);
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', MAIN], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH ?? '' },
  });
  child.stderr?.setEncoding('utf8');
  child.stderr?.on('data', (d: string) => {
    for (const line of d.split('\n')) if (line) opts.onLog?.(line);
  });
  child.stdin?.write(
    `${JSON.stringify({
      socketPath: opts.socketPath,
      storePath: opts.storePath,
      channelKey: channelKey.toString('base64url'),
      passphrase: opts.passphrase,
      trustedApproverKeys: opts.trustedApproverKeys,
      highRiskDomains: opts.highRiskDomains ?? [],
      approverAdmin: opts.approverAdmin === true,
      ...(opts.sources ? { sources: opts.sources } : {}),
      ...(opts.approverAddress ? { approverAddress: opts.approverAddress } : {}),
    })}\n`,
  );
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('signer did not start')), 15_000);
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`signer exited early (${code})`));
    });
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (d: string) => {
      if (d.includes('ready')) {
        clearTimeout(timer);
        resolve();
      }
    });
  });
  const client = new SignerClient(opts.socketPath, channelKey);
  await client.ping();
  return {
    client,
    process: child,
    async stop() {
      client.close();
      if (child.exitCode !== null) return;
      await new Promise<void>((resolve) => {
        child.once('exit', () => resolve());
        child.kill('SIGTERM');
      });
    },
  };
}

export async function connectSigner(opts: {
  socketPath: string;
  channelKey: Buffer;
}): Promise<SignerHandle> {
  if (opts.channelKey.length < 32) throw new Error('channel key too short');
  const client = new SignerClient(opts.socketPath, opts.channelKey);
  try {
    await client.ping();
  } catch (err) {
    client.close();
    throw err;
  }
  return {
    client,
    process: null,
    async stop() {
      client.close();
    },
  };
}
