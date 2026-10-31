import type { Frame } from 'playwright';
import { type CdpMessage, toImpl } from './native-webauthn-block.ts';

interface ContextRecord {
  sessionId: string;
  contextId: number;
  origin: string;
}

export class DocumentOrigins {
  private readonly byFrame = new Map<string, ContextRecord>();

  observe(msg: CdpMessage): void {
    const sessionId = typeof msg.sessionId === 'string' ? msg.sessionId : '';
    switch (msg.method) {
      case 'Runtime.executionContextCreated': {
        const c = msg.params?.context;
        const frameId = c?.auxData?.frameId;
        if (c?.auxData?.isDefault !== true || typeof frameId !== 'string') return;
        if (typeof c.id !== 'number') return;
        const origin = typeof c.origin === 'string' ? c.origin : '';
        this.byFrame.set(frameId, { sessionId, contextId: c.id, origin });
        return;
      }
      case 'Runtime.executionContextDestroyed': {
        const id = msg.params?.executionContextId;
        for (const [frameId, r] of this.byFrame) {
          if (r.sessionId === sessionId && r.contextId === id) this.byFrame.delete(frameId);
        }
        return;
      }
      case 'Page.frameNavigated': {
        const frameId = msg.params?.frame?.id;
        if (typeof frameId === 'string') this.byFrame.delete(frameId);
        return;
      }
      case 'Runtime.executionContextsCleared':
        this.dropSession(sessionId);
        return;
      case 'Target.detachedFromTarget':
        if (typeof msg.params?.sessionId === 'string') this.dropSession(msg.params.sessionId);
        return;
    }
  }

  private dropSession(sessionId: string): void {
    for (const [frameId, r] of this.byFrame) {
      if (r.sessionId === sessionId) this.byFrame.delete(frameId);
    }
  }

  originOf(frameId: string): string | null {
    const r = this.byFrame.get(frameId);
    return r && r.origin.length > 0 ? r.origin : null;
  }
}

const registry = new WeakMap<object, DocumentOrigins>();

export function registerDocumentOrigins(browser: object, origins: DocumentOrigins): void {
  registry.set(browser, origins);
}

export interface TrustedFrame {
  url: string;
  isMainFrame: boolean;
  securityOrigin: string | null;
}

function frameIdOf(frame: Frame): string | null {
  const id = (toImpl(frame) as { _id?: unknown } | undefined)?._id;
  return typeof id === 'string' && id.length > 0 ? id : null;
}

export function trustedFrame(frame: Frame): TrustedFrame {
  let url = '';
  let isMainFrame = false;
  let securityOrigin: string | null = null;
  try {
    url = frame.url();
    isMainFrame = frame.parentFrame() === null;
    const browser = frame.page().context().browser();
    const origins = browser ? registry.get(browser) : undefined;
    const id = frameIdOf(frame);
    securityOrigin = origins && id ? origins.originOf(id) : null;
  } catch {
    securityOrigin = null;
  }
  return { url, isMainFrame, securityOrigin };
}
