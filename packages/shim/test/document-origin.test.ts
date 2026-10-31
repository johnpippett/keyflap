import { describe, expect, it } from 'vitest';
import { DocumentOrigins } from '../src/document-origin.ts';
import type { CdpMessage } from '../src/native-webauthn-block.ts';

const FRAME = 'FRAME-1';
const OTHER_FRAME = 'FRAME-2';
const ORIGIN = 'https://login.example.com';

const created = (
  o: {
    frameId?: string;
    id?: number;
    origin?: unknown;
    isDefault?: boolean;
    sessionId?: string;
  } = {},
): CdpMessage => ({
  method: 'Runtime.executionContextCreated',
  ...(o.sessionId === undefined ? {} : { sessionId: o.sessionId }),
  params: {
    context: {
      id: o.id ?? 1,
      origin: (o.origin ?? ORIGIN) as string,
      auxData: { isDefault: o.isDefault ?? true, frameId: o.frameId ?? FRAME },
    },
  },
});

describe('document origins are unknown until Chromium reports them, and again after anything that could change them', () => {
  it('a default context reports its origin; nothing else does', () => {
    const origins = new DocumentOrigins();
    expect(origins.originOf(FRAME)).toBeNull();
    origins.observe(created());
    expect(origins.originOf(FRAME)).toBe(ORIGIN);
    expect(origins.originOf(OTHER_FRAME)).toBeNull();
  });

  it.each([
    ['a non-string origin', { origin: 42 }],
    ['an empty origin', { origin: '' }],
    ['a context that is not the default world', { isDefault: false }],
  ])('%s is never recorded', (_name, over) => {
    const origins = new DocumentOrigins();
    origins.observe(created(over));
    expect(origins.originOf(FRAME)).toBeNull();
  });

  it('a non-default context cannot replace the default one', () => {
    const origins = new DocumentOrigins();
    origins.observe(created());
    origins.observe(created({ id: 2, isDefault: false, origin: 'https://evil.example.net' }));
    expect(origins.originOf(FRAME)).toBe(ORIGIN);
  });

  it('a later default context for the frame replaces the earlier one, including with an unusable one', () => {
    const origins = new DocumentOrigins();
    origins.observe(created());
    origins.observe(created({ id: 2, origin: 'https://other.example.com' }));
    expect(origins.originOf(FRAME)).toBe('https://other.example.com');
    origins.observe(created({ id: 3, origin: 7 }));
    expect(origins.originOf(FRAME)).toBeNull();
  });

  it('a navigation commit drops the record until the new document reports', () => {
    const origins = new DocumentOrigins();
    origins.observe(created());
    origins.observe({ method: 'Page.frameNavigated', params: { frame: { id: OTHER_FRAME } } });
    expect(origins.originOf(FRAME)).toBe(ORIGIN);
    origins.observe({ method: 'Page.frameNavigated', params: { frame: { id: FRAME } } });
    expect(origins.originOf(FRAME)).toBeNull();
    origins.observe(created({ id: 2, origin: 'https://next.example.com' }));
    expect(origins.originOf(FRAME)).toBe('https://next.example.com');
  });

  it('a destroyed context drops its record, but only for the same session and context id', () => {
    const origins = new DocumentOrigins();
    origins.observe(created({ id: 7, sessionId: 'A' }));
    const destroyed = (id: number, sessionId: string): CdpMessage => ({
      method: 'Runtime.executionContextDestroyed',
      sessionId,
      params: { executionContextId: id },
    });
    origins.observe(destroyed(8, 'A'));
    origins.observe(destroyed(7, 'B'));
    expect(origins.originOf(FRAME)).toBe(ORIGIN);
    origins.observe(destroyed(7, 'A'));
    expect(origins.originOf(FRAME)).toBeNull();
  });

  it('the destroy of an old context does not drop the new document that replaced it', () => {
    const origins = new DocumentOrigins();
    origins.observe(created({ id: 1, sessionId: 'A' }));
    origins.observe(created({ id: 2, sessionId: 'A', origin: 'https://next.example.com' }));
    origins.observe({
      method: 'Runtime.executionContextDestroyed',
      sessionId: 'A',
      params: { executionContextId: 1 },
    });
    expect(origins.originOf(FRAME)).toBe('https://next.example.com');
  });

  it('contexts cleared and a detached session drop every frame of that session only', () => {
    const origins = new DocumentOrigins();
    origins.observe(created({ frameId: 'a1', sessionId: 'A' }));
    origins.observe(created({ frameId: 'a2', id: 2, sessionId: 'A' }));
    origins.observe(created({ frameId: 'b1', id: 3, sessionId: 'B' }));
    origins.observe({ method: 'Runtime.executionContextsCleared', sessionId: 'A' });
    expect([origins.originOf('a1'), origins.originOf('a2'), origins.originOf('b1')]).toEqual([
      null,
      null,
      ORIGIN,
    ]);
    origins.observe(created({ frameId: 'a1', id: 4, sessionId: 'A' }));
    origins.observe({ method: 'Target.detachedFromTarget', params: { sessionId: 'B' } });
    expect([origins.originOf('a1'), origins.originOf('b1')]).toEqual([ORIGIN, null]);
  });

  it('malformed messages change nothing and never throw', () => {
    const origins = new DocumentOrigins();
    origins.observe(created());
    const junk: CdpMessage[] = [
      {},
      { method: 'Runtime.executionContextCreated' },
      { method: 'Runtime.executionContextCreated', params: {} },
      { method: 'Runtime.executionContextCreated', params: { context: {} } },
      {
        method: 'Runtime.executionContextCreated',
        params: {
          context: {
            id: 'x' as unknown as number,
            origin: ORIGIN,
            auxData: { isDefault: true, frameId: FRAME },
          },
        },
      },
      {
        method: 'Runtime.executionContextCreated',
        params: {
          context: {
            id: 9,
            origin: ORIGIN,
            auxData: { isDefault: true, frameId: 5 as unknown as string },
          },
        },
      },
      { method: 'Runtime.executionContextDestroyed' },
      { method: 'Page.frameNavigated' },
      { method: 'Page.frameNavigated', params: { frame: { id: 5 as unknown as string } } },
      { method: 'Target.detachedFromTarget' },
      { method: 'Target.detachedFromTarget', params: { sessionId: 5 as unknown as string } },
      { method: 'Something.else', sessionId: 'A' },
    ];
    for (const m of junk) expect(() => origins.observe(m), JSON.stringify(m)).not.toThrow();
    expect(origins.originOf(FRAME)).toBe(ORIGIN);
  });
});
