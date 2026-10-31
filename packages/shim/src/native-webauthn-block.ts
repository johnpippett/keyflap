import type { Browser, BrowserContext, Page } from 'playwright';

export interface CdpMessage {
  method?: string;
  sessionId?: string;
  params?: {
    sessionId?: string;
    targetId?: string;
    waitingForDebugger?: boolean;
    targetInfo?: { targetId?: string; type?: string };
    context?: {
      id?: number;
      origin?: string;
      auxData?: { isDefault?: boolean; frameId?: string };
    };
    executionContextId?: number;
    frame?: { id?: string };
  };
}
interface CrSession {
  send(method: string, params?: object): Promise<unknown>;
}
interface CrConnection {
  _transport: { onmessage?: (message: CdpMessage) => void };
  _rawSend(sessionId: string, method: string, params: unknown): unknown;
  _sessions: Map<string, CrSession>;
  rootSession: CrSession;
}

interface Covered {
  sessionId: string;
  session: CrSession;
  enabled: Promise<boolean>;
}

const ENABLE_PARAMS = { enableUI: false };
const installed = new WeakSet<object>();

function fail(what: string): never {
  throw new Error(`native WebAuthn block: ${what} (Playwright internals changed?)`);
}

export function toImpl(clientObject: object): unknown {
  const conn = (clientObject as { _connection?: { toImpl?: (x: object) => unknown } })._connection;
  if (typeof conn?.toImpl !== 'function') fail('client connection has no toImpl');
  return conn.toImpl(clientObject);
}

function crConnectionOf(browser: Browser): CrConnection {
  const conn = (toImpl(browser) as { _connection?: Partial<CrConnection> } | undefined)
    ?._connection;
  if (
    !conn ||
    typeof conn._rawSend !== 'function' ||
    !(conn._sessions instanceof Map) ||
    typeof conn.rootSession?.send !== 'function' ||
    typeof conn._transport?.onmessage !== 'function'
  ) {
    fail('unexpected CRConnection shape');
  }
  return conn as CrConnection;
}

function targetIdOf(page: Page): string | undefined {
  const id = (toImpl(page) as { delegate?: { _targetId?: unknown } } | undefined)?.delegate
    ?._targetId;
  return typeof id === 'string' ? id : undefined;
}

export interface NativeWebAuthnBlock {
  cover(context: BrowserContext): Promise<void>;
}

export function installNativeWebAuthnBlock(
  browser: Browser,
  opts: {
    observe?: (msg: CdpMessage) => void;
  } = {},
): NativeWebAuthnBlock {
  const conn = crConnectionOf(browser);
  if (installed.has(conn)) fail('already installed on this browser');
  installed.add(conn);

  const paused = new Map<string, string>();
  const covered = new Map<string, Covered>();

  const closeTarget = (targetId: string) => {
    conn.rootSession.send('Target.closeTarget', { targetId }).catch(() => {});
  };
  const enable = (targetId: string, session: CrSession): Promise<boolean> =>
    session.send('WebAuthn.enable', ENABLE_PARAMS).then(
      () => true,
      () => {
        closeTarget(targetId);
        return false;
      },
    );

  const observe = (msg: CdpMessage) => {
    const p = msg.params;
    if (msg.method === 'Target.attachedToTarget') {
      if (
        p?.waitingForDebugger === true &&
        p.targetInfo?.type === 'page' &&
        typeof p.sessionId === 'string' &&
        typeof p.targetInfo.targetId === 'string'
      ) {
        paused.set(p.sessionId, p.targetInfo.targetId);
      }
    } else if (msg.method === 'Target.detachedFromTarget' && typeof p?.sessionId === 'string') {
      paused.delete(p.sessionId);
      for (const [targetId, c] of covered) {
        if (c.sessionId === p.sessionId) {
          covered.delete(targetId);
        } else if (p.targetId === undefined || p.targetId === targetId) {
          c.enabled = enable(targetId, c.session);
        }
      }
    }
  };

  const transport = conn._transport;
  const onmessage = transport.onmessage as (message: CdpMessage) => void;
  transport.onmessage = (msg: CdpMessage) => {
    try {
      observe(msg);
    } catch {}
    try {
      opts.observe?.(msg);
    } catch {}
    onmessage(msg);
  };

  const rawSend = conn._rawSend.bind(conn);
  conn._rawSend = (sessionId: string, method: string, params: unknown) => {
    if (method === 'Runtime.runIfWaitingForDebugger') {
      const targetId = paused.get(sessionId);
      if (targetId !== undefined) {
        paused.delete(sessionId);
        const session = conn._sessions.get(sessionId);
        if (session) {
          covered.set(targetId, { sessionId, session, enabled: enable(targetId, session) });
        } else {
          closeTarget(targetId);
        }
      }
    }
    return rawSend(sessionId, method, params);
  };

  const isCovered = async (page: Page): Promise<boolean> => {
    try {
      const targetId = targetIdOf(page);
      const c = targetId === undefined ? undefined : covered.get(targetId);
      return c ? await c.enabled : false;
    } catch {
      return false;
    }
  };

  const contexts = new WeakSet<BrowserContext>();
  return {
    async cover(context: BrowserContext): Promise<void> {
      if (contexts.has(context)) throw new Error('native WebAuthn block: context already covered');
      contexts.add(context);
      context.on('page', (page) => {
        void isCovered(page).then((ok) => {
          if (!ok) page.close().catch(() => {});
        });
      });
      const probe = await context.newPage();
      const ok = await isCovered(probe);
      await probe.close();
      if (!ok) fail('probe page was not covered');
    },
  };
}
