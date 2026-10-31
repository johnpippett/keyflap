import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AgentRegistry } from './agents.ts';
import type { Broker } from './broker.ts';
import { listenUnix } from './unix-socket.ts';

export const MAX_INTENT_BODY = 64 * 1024;
export const MAX_INTENT_TEXT = 8000;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export function loadOrCreateHostToken(path: string): string {
  try {
    writeFileSync(path, `${randomBytes(32).toString('base64url')}\n`, {
      mode: 0o600,
      flag: 'wx',
    });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
  }
  const st = lstatSync(path);
  if (!st.isFile()) throw new Error(`host token: ${path} is not a regular file`);
  if ((st.mode & 0o077) !== 0) {
    throw new Error(`host token: ${path} is accessible to other users; chmod 600 it or delete it`);
  }
  chmodSync(path, 0o600);
  const token = readFileSync(path, 'utf8').trim();
  if (!TOKEN_RE.test(token)) throw new Error(`host token: ${path} does not hold a valid token`);
  return token;
}

export interface IntentServerOptions {
  socketPath: string;
  listenFd?: number;
  hostToken: string;
  registry: AgentRegistry;
  broker: Broker;
}

export interface IntentServer {
  socketPath: string;
  close(): Promise<void>;
}

const digest = (s: string) => createHash('sha256').update(s, 'utf8').digest();

class HttpError extends Error {
  readonly status: number;
  readonly reason: string;
  constructor(status: number, reason: string) {
    super(reason);
    this.status = status;
    this.reason = reason;
  }
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  const declared = req.headers['content-length'];
  if (declared !== undefined && Number(declared) > MAX_INTENT_BODY) {
    return Promise.reject(new HttpError(413, 'body_too_large'));
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on('data', (c: Buffer) => {
      if (done) return;
      size += c.length;
      if (size > MAX_INTENT_BODY) {
        done = true;
        req.pause();
        reject(new HttpError(413, 'body_too_large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!done) {
        done = true;
        resolve(Buffer.concat(chunks));
      }
    });
    req.on('error', (err) => {
      if (!done) {
        done = true;
        reject(err);
      }
    });
  });
}

function parseIntent(body: Buffer): { agentId: string; text: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    throw new HttpError(400, 'bad_json');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new HttpError(400, 'bad_body');
  }
  const o = parsed as Record<string, unknown>;
  if (Object.keys(o).some((k) => k !== 'agentId' && k !== 'text')) {
    throw new HttpError(400, 'unknown_field');
  }
  if (typeof o.agentId !== 'string' || o.agentId.length === 0 || o.agentId.length > 128) {
    throw new HttpError(400, 'bad_agent_id');
  }
  if (typeof o.text !== 'string' || o.text.length === 0 || o.text.length > MAX_INTENT_TEXT) {
    throw new HttpError(400, 'bad_text');
  }
  if (o.text.includes('\u0000')) throw new HttpError(400, 'bad_text');
  return { agentId: o.agentId, text: o.text };
}

export async function startIntentServer(opts: IntentServerOptions): Promise<IntentServer> {
  const expected = digest(opts.hostToken);
  const { broker, registry } = opts;

  const authorized = (req: IncomingMessage): boolean => {
    const h = req.headers.authorization;
    if (typeof h !== 'string') return false;
    const m = /^Bearer ([^\s]+)$/i.exec(h);
    return m !== null && timingSafeEqual(digest(m[1] as string), expected);
  };

  const send = (res: ServerResponse, status: number, body: object, close = false) => {
    const json = JSON.stringify(body);
    res.writeHead(status, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(json),
      ...(close ? { connection: 'close' } : {}),
    });
    res.end(json);
  };

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    let agentId: string | undefined;
    try {
      if (req.method !== 'POST' || req.url !== '/v1/intents') throw new HttpError(404, 'no_route');
      if (!authorized(req)) throw new HttpError(401, 'bad_host_token');
      const type = req.headers['content-type'] ?? '';
      if (!/^application\/json\s*(;.*)?$/i.test(type)) throw new HttpError(400, 'content_type');
      const intent = parseIntent(await readBody(req));
      agentId = intent.agentId;
      const agent = registry.byId(intent.agentId);
      if (!agent) throw new HttpError(404, 'unknown_agent');
      const recorded = broker.intents.record(agent.id, intent.text);
      broker.audit.append('intent.recorded', {
        intentId: recorded.id,
        agentId: agent.id,
        textSha256: createHash('sha256').update(intent.text, 'utf8').digest('hex'),
      });
      send(res, 201, { intentId: recorded.id, expiresAt: recorded.expiresAt });
    } catch (err) {
      const e = err instanceof HttpError ? err : new HttpError(500, 'internal_error');
      try {
        broker.audit.append('intent.rejected', {
          status: e.status,
          reason: e.reason,
          ...(agentId !== undefined ? { agentId: agentId.slice(0, 128) } : {}),
        });
      } catch {}
      const message =
        { 400: 'bad request', 401: 'unauthorized', 404: 'not found', 413: 'body too large' }[
          e.status
        ] ?? 'internal error';
      send(res, e.status, { error: message }, e.status === 413);
    }
  };

  const server: Server = createServer((req, res) => {
    void handle(req, res);
  });
  server.headersTimeout = 5_000;
  server.requestTimeout = 10_000;
  if (opts.listenFd !== undefined) {
    const fd = opts.listenFd;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen({ fd }, () => {
        server.off('error', reject);
        resolve();
      });
    });
  } else {
    await listenUnix(server, opts.socketPath, 'intent socket');
  }

  return {
    socketPath: opts.socketPath,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}
