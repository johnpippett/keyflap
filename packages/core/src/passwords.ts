import { mkdirSync } from 'node:fs';
import { isIP } from 'node:net';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import type { ApproverAddress } from '@aab/signer/approver-address';
import { type SignerClient, spawnSigner } from '@aab/signer/client';
import type { DeleteItemResult, StoreItemResult } from '@aab/signer/protocol';
import { AuditLog } from './audit.ts';
import { CredentialRepo } from './db.ts';
import { hasUnsafeText } from './display-text.ts';
import { registrableDomain } from './origin.ts';

export interface ItemSigner {
  storeItem(req: {
    domain: string;
    password: string;
    totp?: { secret: string; algorithm?: string; digits?: number; period?: number };
  }): Promise<StoreItemResult>;
  deleteItem(itemId: string): Promise<DeleteItemResult>;
}

export interface TotpInput {
  secret: string;
  algorithm?: string;
  digits?: number;
  period?: number;
}

export function siteDomain(site: string): string | null {
  const s = site.trim();
  if (s.length === 0 || s.length > 2048) return null;
  let host: string;
  try {
    host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`).hostname;
  } catch {
    return null;
  }
  if (!host || isIP(host.replace(/^\[|\]$/g, '')) !== 0) return null;
  return registrableDomain(host);
}

export function parseTotpInput(input: string): TotpInput {
  const s = input.trim();
  if (!/^otpauth:/i.test(s)) return { secret: s };
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    throw new Error('not a valid otpauth:// URI');
  }
  if (url.host.toLowerCase() !== 'totp') throw new Error('only otpauth://totp/ URIs are supported');
  const secret = url.searchParams.get('secret');
  if (!secret) throw new Error('the otpauth:// URI has no secret');
  const out: TotpInput = { secret };
  const alg = url.searchParams.get('algorithm');
  if (alg) out.algorithm = alg.toUpperCase();
  const digits = url.searchParams.get('digits');
  if (digits) out.digits = Number(digits);
  const period = url.searchParams.get('period');
  if (period) out.period = Number(period);
  return out;
}

export async function addPasswordItem(
  deps: { signer: ItemSigner; db: DatabaseSync; now?: () => number },
  item: { site: string; username: string | null; password: string; totp?: TotpInput },
): Promise<{ id: string; domain: string }> {
  const domain = siteDomain(item.site);
  if (!domain) throw new Error(`"${item.site}" has no registrable domain`);
  if (item.username !== null && (item.username.length > 256 || hasUnsafeText(item.username))) {
    throw new Error('username must be at most 256 printable characters');
  }
  const { itemId } = await deps.signer.storeItem({
    domain,
    password: item.password,
    ...(item.totp ? { totp: item.totp } : {}),
  });
  const now = deps.now ?? Date.now;
  try {
    new CredentialRepo(deps.db).insertPassword({
      itemId,
      domain,
      username: item.username,
      hasTotp: item.totp !== undefined,
      now: now(),
    });
    new AuditLog(deps.db, now).append('credential.added', {
      credentialId: itemId,
      type: 'password',
      domain,
      totp: item.totp !== undefined,
    });
  } catch (err) {
    await deps.signer.deleteItem(itemId).catch(() => {});
    throw err;
  }
  return { id: itemId, domain };
}

export async function removePasswordItem(
  deps: { signer: ItemSigner; db: DatabaseSync; now?: () => number },
  id: string,
): Promise<boolean> {
  const repo = new CredentialRepo(deps.db);
  const row = repo.allPasswords().find((r) => r.id === id);
  if (!row) return false;
  if (row.source !== 'signer') {
    throw new Error(`that item comes from ${row.source}; remove or edit it there`);
  }
  await deps.signer.deleteItem(row.signer_ref);
  repo.deletePassword(id);
  new AuditLog(deps.db, deps.now ?? Date.now).append('credential.removed', {
    credentialId: id,
    type: 'password',
  });
  return true;
}

export function signerPaths(dataDir: string): { socketPath: string; storePath: string } {
  return {
    socketPath: join(dataDir, 'run', 'signer.sock'),
    storePath: join(dataDir, 'signer', 'keys.enc.json'),
  };
}

export class SignerBusyError extends Error {}

export async function withItemSigner<T>(
  dataDir: string,
  passphrase: string,
  fn: (signer: SignerClient) => Promise<T>,
  opts: { approverAdmin?: boolean; approverAddress?: ApproverAddress } = {},
): Promise<T> {
  mkdirSync(join(dataDir, 'signer'), { recursive: true, mode: 0o700 });
  let spawned: Awaited<ReturnType<typeof spawnSigner>>;
  const log: string[] = [];
  try {
    spawned = await spawnSigner({
      ...signerPaths(dataDir),
      passphrase,
      trustedApproverKeys: {},
      approverAdmin: opts.approverAdmin === true,
      ...(opts.approverAddress ? { approverAddress: opts.approverAddress } : {}),
      onLog: (l) => log.push(l),
    });
  } catch {
    for (let i = 0; i < 20 && log.length === 0; i++) await new Promise((r) => setTimeout(r, 25));
    const text = log.join('\n');
    if (/locked by a live process|already listening/.test(text)) {
      throw new SignerBusyError(
        'the key store is in use (is `keyflap daemon` running?); stop the daemon first',
      );
    }
    if (/unsupported state|unable to authenticate|bad decrypt/i.test(text)) {
      throw new SignerBusyError('wrong passphrase for the key store');
    }
    throw new SignerBusyError('could not start the signer');
  }
  try {
    return await fn(spawned.client);
  } finally {
    await spawned.stop();
  }
}
