import { execFile } from 'node:child_process';
import {
  type CredentialSource,
  loginHosts,
  parseTotpUri,
  SourceError,
  type SourceItemInfo,
  type SourceSecret,
} from './source.ts';
import { ToolLauncher, type ToolProblem, type ToolSpec, type ToolTrust } from './tool.ts';

export const ONE_PASSWORD_KIND = '1password';

export const OP_TOOL: ToolSpec = {
  command: 'op',
  installHint:
    "from 1Password's signed package (apt/dnf repository or the release zip), never a copy from your home",
  connect: 'sudo keyflap password-source add 1password',
};

const ID = /^[A-Za-z0-9]{26}$/;
const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_OUTPUT = 8 * 1024 * 1024;

export interface OnePasswordSourceOptions {
  bin: string;
  trust: ToolTrust;
  onToolRefused?: (e: { tool: string; path: string; problem: ToolProblem; detail: string }) => void;
  env?: Record<string, string>;
  vault?: string;
  timeoutMs?: number;
  concurrency?: number;
}

export function onePasswordRef(vaultId: string, itemId: string): string {
  if (!ID.test(vaultId) || !ID.test(itemId)) throw new SourceError('bad_ref');
  return `${ONE_PASSWORD_KIND}:${vaultId}:${itemId}`;
}

export function parseOnePasswordRef(ref: unknown): { vaultId: string; itemId: string } | null {
  if (typeof ref !== 'string') return null;
  const parts = ref.split(':');
  if (parts.length !== 3 || parts[0] !== ONE_PASSWORD_KIND) return null;
  const [, vaultId, itemId] = parts as [string, string, string];
  return ID.test(vaultId) && ID.test(itemId) ? { vaultId, itemId } : null;
}

type Field = Record<string, unknown>;

interface ReadItem {
  urls: unknown[];
  fields: Field[];
  state: unknown;
}

export class OnePasswordSource implements CredentialSource {
  readonly kind = ONE_PASSWORD_KIND;
  private readonly tool: ToolLauncher;
  private readonly env: Record<string, string>;
  private readonly vault: string | undefined;
  private readonly timeoutMs: number;
  private readonly concurrency: number;
  private readonly cache = new Map<string, { stamp: string; info: SourceItemInfo }>();

  constructor(opts: OnePasswordSourceOptions) {
    if (typeof opts.bin !== 'string' || opts.bin.length === 0) throw new Error('no op bin');
    if (opts.trust?.mode !== 'system' && opts.trust?.mode !== 'same-user') {
      throw new Error('op: no tool trust mode');
    }
    this.tool = new ToolLauncher(OP_TOOL, opts.bin, opts.trust, opts.onToolRefused);
    this.env = { ...(opts.env ?? {}) };
    this.vault = opts.vault;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.concurrency = Math.max(1, opts.concurrency ?? 4);
  }

  async list(): Promise<SourceItemInfo[]> {
    const listed: { ref: string; vaultId: string; itemId: string; stamp: string }[] = [];
    for (const vaultId of await this.vaultIds()) {
      const items = await this.json([
        'item',
        'list',
        `--vault=${vaultId}`,
        '--categories=Login',
        '--format=json',
      ]);
      if (!Array.isArray(items)) throw new SourceError('source_bad_output');
      for (const it of items as Record<string, unknown>[]) {
        if (typeof it !== 'object' || it === null || it.category !== 'LOGIN') continue;
        if (typeof it.id !== 'string' || !ID.test(it.id)) continue;
        if ((it.vault as { id?: unknown } | undefined)?.id !== vaultId) continue;
        const version = typeof it.version === 'number' ? String(it.version) : '';
        const updated = typeof it.updated_at === 'string' ? it.updated_at : '';
        listed.push({
          ref: onePasswordRef(vaultId, it.id),
          vaultId,
          itemId: it.id,
          stamp: version || updated ? `${version}|${updated}` : '',
        });
      }
    }
    const stale = listed.filter((l) => !l.stamp || this.cache.get(l.ref)?.stamp !== l.stamp);
    await pool(stale, this.concurrency, async (l) => {
      let item: ReadItem;
      try {
        item = await this.get(l.vaultId, l.itemId, false);
      } catch (err) {
        if (err instanceof SourceError && err.reason === 'source_item_not_found') {
          this.cache.delete(l.ref);
          return;
        }
        throw err;
      }
      const user = usernameOf(item.fields);
      this.cache.set(l.ref, {
        stamp: l.stamp,
        info: {
          ref: l.ref,
          hosts: hostsOf(item.urls),
          username: user && user.length <= 256 ? user : null,
          hasTotp: otpFields(item.fields).length === 1,
        },
      });
    });
    const live = new Set(listed.map((l) => l.ref));
    for (const ref of this.cache.keys()) if (!live.has(ref)) this.cache.delete(ref);
    return listed.flatMap((l) => {
      const c = this.cache.get(l.ref);
      return c ? [c.info] : [];
    });
  }

  async fetch(ref: string, _reason: string): Promise<SourceSecret> {
    const p = parseOnePasswordRef(ref);
    if (!p) throw new SourceError('bad_ref');
    const item = await this.get(p.vaultId, p.itemId, true);
    if (item.state !== undefined && item.state !== null && item.state !== 'ACTIVE') {
      throw new SourceError('source_item_inactive');
    }
    const pw = item.fields.filter((f) => f.purpose === 'PASSWORD');
    const password = pw.length === 1 ? pw[0]?.value : undefined;
    if (typeof password !== 'string') throw new SourceError('source_bad_output');
    const otp = otpFields(item.fields);
    const uri = otp.length === 1 ? otp[0]?.value : undefined;
    return {
      hosts: hostsOf(item.urls),
      password,
      totp: typeof uri === 'string' ? parseTotpUri(uri) : null,
    };
  }

  private async vaultIds(): Promise<string[]> {
    const vaults = await this.json(['vault', 'list', '--format=json']);
    if (!Array.isArray(vaults)) throw new SourceError('source_bad_output');
    const ids = (vaults as Record<string, unknown>[])
      .filter((v) => typeof v === 'object' && v !== null)
      .filter((v) => this.vault === undefined || v.name === this.vault)
      .map((v) => v.id)
      .filter((id): id is string => typeof id === 'string' && ID.test(id));
    if (this.vault !== undefined && ids.length === 0) {
      throw new SourceError('source_vault_not_found');
    }
    if (this.vault !== undefined && ids.length > 1) throw new SourceError('source_vault_ambiguous');
    return ids;
  }

  private async get(vaultId: string, itemId: string, reveal: boolean): Promise<ReadItem> {
    const data = await this.json([
      'item',
      'get',
      itemId,
      `--vault=${vaultId}`,
      '--format=json',
      ...(reveal ? ['--reveal'] : []),
    ]);
    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
      throw new SourceError('source_bad_output');
    }
    const item = data as Record<string, unknown>;
    if (item.id !== itemId || (item.vault as { id?: unknown } | undefined)?.id !== vaultId) {
      throw new SourceError('source_bad_output');
    }
    if (item.category !== 'LOGIN') throw new SourceError('source_not_a_login');
    const fields = item.fields === undefined ? [] : item.fields;
    const urls = item.urls === undefined ? [] : item.urls;
    if (!Array.isArray(fields) || !Array.isArray(urls)) throw new SourceError('source_bad_output');
    return {
      urls,
      fields: fields.filter((f): f is Field => typeof f === 'object' && f !== null),
      state: item.state,
    };
  }

  private async json(args: string[]): Promise<unknown> {
    const out = await this.run(args);
    try {
      return JSON.parse(out);
    } catch {
      throw new SourceError('source_bad_output');
    }
  }

  private run(args: string[]): Promise<string> {
    let bin: string;
    try {
      bin = this.tool.path();
    } catch (err) {
      return Promise.reject(err);
    }
    const env: Record<string, string> = {
      PATH: process.env.PATH ?? '',
      ...this.env,
      OP_CACHE: 'false',
      OP_BIOMETRIC_UNLOCK_ENABLED: 'false',
    };
    return new Promise((resolve, reject) => {
      execFile(
        bin,
        args,
        {
          env,
          timeout: this.timeoutMs,
          killSignal: 'SIGKILL',
          maxBuffer: MAX_OUTPUT,
          windowsHide: true,
        },
        (err, stdout, stderr) => {
          if (!err) return resolve(stdout);
          const e = err as NodeJS.ErrnoException & { killed?: boolean; code?: unknown };
          if (e.code === 'ENOENT' || e.code === 'EACCES') {
            return reject(new SourceError('source_unavailable'));
          }
          if (e.killed) return reject(new SourceError('source_timeout'));
          if (e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
            return reject(new SourceError('source_bad_output'));
          }
          reject(new SourceError(classify(String(stderr))));
        },
      ).stdin?.end();
    });
  }
}

function classify(stderr: string): string {
  if (/rate limit|too many requests|\b429\b/i.test(stderr)) return 'source_rate_limited';
  if (
    /not (currently )?signed in|sign ?in|unauthori[sz]ed|\b401\b|invalid .*token|token .*(invalid|expired|revoked)|authenticat|DecodeSACredentials/i.test(
      stderr,
    )
  ) {
    return 'source_not_logged_in';
  }
  if (/isn't a vault|vault .*not found|no vault/i.test(stderr)) return 'source_vault_not_found';
  if (/isn't an item|not found|could not find|does ?n[o']t exist|no such/i.test(stderr)) {
    return 'source_item_not_found';
  }
  return 'source_failed';
}

function hostsOf(urls: unknown[]): string[] {
  return loginHosts(
    urls.map((u) => (typeof u === 'object' && u !== null ? (u as { href?: unknown }).href : u)),
  );
}

function usernameOf(fields: Field[]): string | null {
  const u = fields.filter((f) => f.purpose === 'USERNAME');
  const v = u.length === 1 ? u[0]?.value : undefined;
  return typeof v === 'string' && v.trim().length > 0 ? v.trim() : null;
}

function otpFields(fields: Field[]): Field[] {
  return fields.filter((f) => f.type === 'OTP');
}

async function pool<T>(items: T[], n: number, fn: (t: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) await fn(items[next++] as T);
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
}
