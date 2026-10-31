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

export const PROTON_PASS_KIND = 'proton-pass';

export const PASS_CLI_TOOL: ToolSpec = {
  command: 'pass-cli',
  installHint:
    "from Proton's pass-cli download or your distribution's package, never a copy from your home",
  connect: 'sudo keyflap password-source add proton-pass',
};

const ID = /^[A-Za-z0-9_=-]{1,256}$/;
const LIST_REASON = 'Keyflap broker: matching saved logins to sites';
const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_OUTPUT = 8 * 1024 * 1024;

export interface ProtonPassSourceOptions {
  bin: string;
  trust: ToolTrust;
  onToolRefused?: (e: { tool: string; path: string; problem: ToolProblem; detail: string }) => void;
  env?: Record<string, string>;
  vault?: string;
  timeoutMs?: number;
  concurrency?: number;
}

export function protonRef(shareId: string, itemId: string): string {
  if (!ID.test(shareId) || !ID.test(itemId)) throw new SourceError('bad_ref');
  return `${PROTON_PASS_KIND}:${shareId}:${itemId}`;
}

export function parseProtonRef(ref: unknown): { shareId: string; itemId: string } | null {
  if (typeof ref !== 'string') return null;
  const parts = ref.split(':');
  if (parts.length !== 3 || parts[0] !== PROTON_PASS_KIND) return null;
  const [, shareId, itemId] = parts as [string, string, string];
  return ID.test(shareId) && ID.test(itemId) ? { shareId, itemId } : null;
}

interface ViewedLogin {
  shareId: string;
  itemId: string;
  state: unknown;
  login: Record<string, unknown>;
}

export class ProtonPassSource implements CredentialSource {
  readonly kind = PROTON_PASS_KIND;
  private readonly tool: ToolLauncher;
  private readonly env: Record<string, string>;
  private readonly vault: string | undefined;
  private readonly timeoutMs: number;
  private readonly concurrency: number;
  private readonly cache = new Map<string, { mtime: string; info: SourceItemInfo }>();

  constructor(opts: ProtonPassSourceOptions) {
    if (typeof opts.bin !== 'string' || opts.bin.length === 0) throw new Error('no pass-cli bin');
    if (opts.trust?.mode !== 'system' && opts.trust?.mode !== 'same-user') {
      throw new Error('pass-cli: no tool trust mode');
    }
    this.tool = new ToolLauncher(PASS_CLI_TOOL, opts.bin, opts.trust, opts.onToolRefused);
    this.env = { ...(opts.env ?? {}) };
    this.vault = opts.vault;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.concurrency = Math.max(1, opts.concurrency ?? 6);
  }

  async list(): Promise<SourceItemInfo[]> {
    const listed: { ref: string; shareId: string; itemId: string; mtime: string }[] = [];
    for (const shareId of await this.shareIds()) {
      const data = await this.json(
        [
          'item',
          'list',
          `--share-id=${shareId}`,
          '--filter-type',
          'login',
          '--filter-state',
          'active',
          '--output',
          'json',
        ],
        LIST_REASON,
      );
      const items = (data as { items?: unknown }).items;
      if (!Array.isArray(items)) throw new SourceError('source_bad_output');
      for (const it of items as Record<string, unknown>[]) {
        if (it?.item_type !== 'login' || it.state !== 'Active') continue;
        if (typeof it.id !== 'string' || !ID.test(it.id) || it.share_id !== shareId) continue;
        listed.push({
          ref: protonRef(shareId, it.id),
          shareId,
          itemId: it.id,
          mtime: typeof it.modify_time === 'string' ? it.modify_time : '',
        });
      }
    }
    const stale = listed.filter((l) => this.cache.get(l.ref)?.mtime !== l.mtime || !l.mtime);
    await pool(stale, this.concurrency, async (l) => {
      let v: ViewedLogin;
      try {
        v = await this.view(l.shareId, l.itemId, LIST_REASON);
      } catch (err) {
        if (err instanceof SourceError && err.reason === 'source_item_not_found') {
          this.cache.delete(l.ref);
          return;
        }
        throw err;
      }
      const user = nonEmpty(v.login.username) ?? nonEmpty(v.login.email);
      this.cache.set(l.ref, {
        mtime: l.mtime,
        info: {
          ref: l.ref,
          hosts: loginHosts(Array.isArray(v.login.urls) ? v.login.urls : []),
          username: user && user.length <= 256 ? user : null,
          hasTotp: totpOf(v.login) !== null,
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

  async fetch(ref: string, reason: string): Promise<SourceSecret> {
    const p = parseProtonRef(ref);
    if (!p) throw new SourceError('bad_ref');
    const v = await this.view(p.shareId, p.itemId, reason);
    if (v.state !== 'Active') throw new SourceError('source_item_inactive');
    const password = v.login.password;
    if (typeof password !== 'string') throw new SourceError('source_bad_output');
    return {
      hosts: loginHosts(Array.isArray(v.login.urls) ? v.login.urls : []),
      password,
      totp: totpOf(v.login),
    };
  }

  private async shareIds(): Promise<string[]> {
    const data = await this.json(['vault', 'list', '--output', 'json'], LIST_REASON);
    const vaults = (data as { vaults?: unknown }).vaults;
    if (!Array.isArray(vaults)) throw new SourceError('source_bad_output');
    const ids = (vaults as Record<string, unknown>[])
      .filter((v) => this.vault === undefined || v?.name === this.vault)
      .map((v) => v?.share_id)
      .filter((id): id is string => typeof id === 'string' && ID.test(id));
    if (this.vault !== undefined && ids.length === 0) {
      throw new SourceError('source_vault_not_found');
    }
    return ids;
  }

  private async view(shareId: string, itemId: string, reason: string): Promise<ViewedLogin> {
    const data = await this.json(
      ['item', 'view', `--share-id=${shareId}`, `--item-id=${itemId}`, '--output', 'json'],
      reason,
    );
    const item = (data as { item?: Record<string, unknown> }).item;
    if (typeof item !== 'object' || item === null) throw new SourceError('source_bad_output');
    if (item.id !== itemId || item.share_id !== shareId) throw new SourceError('source_bad_output');
    const login = (item.content as { content?: { Login?: unknown } } | undefined)?.content?.Login;
    if (typeof login !== 'object' || login === null) throw new SourceError('source_not_a_login');
    return { shareId, itemId, state: item.state, login: login as Record<string, unknown> };
  }

  private async json(args: string[], reason: string): Promise<unknown> {
    const out = await this.run(args, reason);
    try {
      return JSON.parse(out);
    } catch {
      throw new SourceError('source_bad_output');
    }
  }

  private run(args: string[], reason: string): Promise<string> {
    let bin: string;
    try {
      bin = this.tool.path();
    } catch (err) {
      return Promise.reject(err);
    }
    const env: Record<string, string> = {
      PATH: process.env.PATH ?? '',
      ...this.env,
      PROTON_PASS_NO_UPDATE_CHECK: '1',
      PROTON_PASS_AGENT_REASON: reason,
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
  if (/log ?in|logged out|logout|not authenticated|no session|encryption key/i.test(stderr)) {
    return 'source_not_logged_in';
  }
  if (/not find|not found|does not exist|no such/i.test(stderr)) return 'source_item_not_found';
  return 'source_failed';
}

function totpOf(login: Record<string, unknown>): SourceSecret['totp'] {
  return typeof login.totp_uri === 'string' ? parseTotpUri(login.totp_uri) : null;
}

function nonEmpty(v: unknown): string | null {
  return typeof v === 'string' && v.trim().length > 0 ? v.trim() : null;
}

async function pool<T>(items: T[], n: number, fn: (t: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) await fn(items[next++] as T);
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
}
