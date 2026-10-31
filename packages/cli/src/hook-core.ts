import { lstatSync, readFileSync } from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { unixSocketPathProblem } from '@aab/signer/platform';

export const MAX_HOOK_INPUT = 1024 * 1024;
export const MAX_PROMPT = 8000;
export const DEFAULT_HOOK_TIMEOUT_MS = 3_000;
const HOST_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export type HookOutcome = 'recorded' | 'skipped' | 'failed';

export type ParsedHookInput = { prompt: string } | { skip: string };

export type HookParser = (raw: Buffer) => ParsedHookInput;

export interface HookOptions {
  dataDir: string;
  hostTokenPath?: string;
  socketPath?: string;
  agentId: string;
  stdin: Readable;
  log: (line: string) => void;
  timeoutMs?: number;
}

export class HookFailure extends Error {}

function readInput(stdin: Readable, signal: AbortSignal): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const done = (err: Error | null, value?: Buffer) => {
      stdin.off('data', onData);
      stdin.off('end', onEnd);
      stdin.off('error', onError);
      signal.removeEventListener('abort', onAbort);
      if (err) {
        stdin.pause();
        reject(err);
      } else resolve(value as Buffer);
    };
    const onData = (c: Buffer | string) => {
      const b = typeof c === 'string' ? Buffer.from(c) : c;
      size += b.length;
      if (size > MAX_HOOK_INPUT) return done(new HookFailure('hook input too large'));
      chunks.push(b);
    };
    const onEnd = () => done(null, Buffer.concat(chunks));
    const onError = () => done(new HookFailure('could not read hook input'));
    const onAbort = () => done(new HookFailure('timed out reading hook input'));
    stdin.on('data', onData);
    stdin.once('end', onEnd);
    stdin.once('error', onError);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

export function parseHookObject(raw: Buffer): Record<string, unknown> {
  let input: unknown;
  try {
    input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch {
    throw new HookFailure('malformed hook input (not JSON)');
  }
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new HookFailure('malformed hook input (not an object)');
  }
  return input as Record<string, unknown>;
}

export function checkedPrompt(prompt: string): ParsedHookInput {
  if (prompt.trim().length === 0) return { skip: 'empty prompt' };
  if (prompt.length > MAX_PROMPT) {
    throw new HookFailure(`prompt longer than ${MAX_PROMPT} characters; not recorded`);
  }
  return { prompt };
}

export function readHostToken(dataDir: string, path: string = join(dataDir, 'host-token')): string {
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(path);
  } catch (err) {
    throw new HookFailure(
      `cannot read host token (${(err as NodeJS.ErrnoException).code ?? 'error'}); is the daemon set up in ${dataDir}?`,
    );
  }
  if (!st.isFile()) throw new HookFailure('host token is not a regular file');
  if ((st.mode & 0o077) !== 0) throw new HookFailure('host token is accessible to other users');
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new HookFailure('host token is owned by another user');
  }
  let token: string;
  try {
    token = readFileSync(path, 'utf8').trim();
  } catch (err) {
    throw new HookFailure(
      `cannot read host token (${(err as NodeJS.ErrnoException).code ?? 'error'})`,
    );
  }
  if (!HOST_TOKEN_RE.test(token)) throw new HookFailure('host token file is malformed');
  return token;
}

function postIntent(
  socketPath: string,
  token: string,
  agentId: string,
  text: string,
  signal: AbortSignal,
): Promise<number> {
  const body = JSON.stringify({ agentId, text });
  return new Promise((resolve, reject) => {
    const tooLong = unixSocketPathProblem(socketPath, 'intent socket');
    if (tooLong) {
      reject(new HookFailure(tooLong));
      return;
    }
    const req = request(
      {
        socketPath,
        path: '/v1/intents',
        method: 'POST',
        signal,
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode ?? 0));
        res.on('error', () => reject(new HookFailure('intent socket response failed')));
      },
    );
    req.on('error', (err: NodeJS.ErrnoException) => {
      if (signal.aborted) return reject(new HookFailure('intent socket timed out'));
      const hint =
        err.code === 'ENOENT' || err.code === 'ECONNREFUSED'
          ? ' (is `keyflap daemon` running?)'
          : '';
      reject(new HookFailure(`cannot reach intent socket: ${err.code ?? 'error'}${hint}`));
    });
    req.end(body);
  });
}

const STATUS_TEXT: Record<number, string> = {
  400: 'bad request',
  401: 'host token rejected',
  404: 'unknown or revoked agent',
  413: 'too large',
};

export async function runHook(opts: HookOptions, parse: HookParser): Promise<HookOutcome> {
  const signal = AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_HOOK_TIMEOUT_MS);
  try {
    const parsed = parse(await readInput(opts.stdin, signal));
    if ('skip' in parsed) return 'skipped';
    const token = readHostToken(opts.dataDir, opts.hostTokenPath);
    const status = await postIntent(
      opts.socketPath ?? join(opts.dataDir, 'run', 'intent.sock'),
      token,
      opts.agentId,
      parsed.prompt,
      signal,
    );
    if (status === 201) return 'recorded';
    throw new HookFailure(`intent socket answered ${status} ${STATUS_TEXT[status] ?? 'error'}`);
  } catch (err) {
    const msg = err instanceof HookFailure ? err.message : 'unexpected error';
    try {
      opts.log(`keyflap hook: intent not recorded: ${msg}`);
    } catch {}
    return 'failed';
  }
}
