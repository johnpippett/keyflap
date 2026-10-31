import type { Browser } from 'playwright';
import { describe, expect, it } from 'vitest';
import { DocumentOrigins } from '../src/document-origin.ts';
import { type CdpMessage, installNativeWebAuthnBlock } from '../src/native-webauthn-block.ts';

function fakeBrowser(handled: CdpMessage[], order: string[]) {
  const transport: { onmessage: (m: CdpMessage) => void } = {
    onmessage: (m) => {
      handled.push(m);
      order.push(`playwright:${m.method}`);
    },
  };
  const connection = {
    _transport: transport,
    _rawSend: () => undefined,
    _sessions: new Map(),
    rootSession: { send: async () => ({}) },
  };
  const browser = { _connection: { toImpl: () => ({ _connection: connection }) } };
  return { browser: browser as unknown as Browser, transport };
}

const message = (method: string): CdpMessage => ({ method });

describe('the CDP observer taps messages without ever breaking Playwright', () => {
  it('every message reaches the observer first and Playwright after, in order', () => {
    const handled: CdpMessage[] = [];
    const order: string[] = [];
    const { browser, transport } = fakeBrowser(handled, order);
    installNativeWebAuthnBlock(browser, {
      observe: (m) => void order.push(`observer:${m.method}`),
    });
    transport.onmessage(message('A'));
    transport.onmessage(message('B'));
    expect(order).toEqual(['observer:A', 'playwright:A', 'observer:B', 'playwright:B']);
    expect(handled.map((m) => m.method)).toEqual(['A', 'B']);
  });

  it('a throwing observer does not stop Playwright from seeing the message, or the next one', () => {
    const handled: CdpMessage[] = [];
    const { browser, transport } = fakeBrowser(handled, []);
    installNativeWebAuthnBlock(browser, {
      observe: () => {
        throw new Error('observer bug');
      },
    });
    expect(() => transport.onmessage(message('A'))).not.toThrow();
    expect(() => transport.onmessage(message('B'))).not.toThrow();
    expect(handled.map((m) => m.method)).toEqual(['A', 'B']);
  });

  it('works without an observer, and still hands Playwright the same message object', () => {
    const handled: CdpMessage[] = [];
    const { browser, transport } = fakeBrowser(handled, []);
    installNativeWebAuthnBlock(browser);
    const m = message('A');
    transport.onmessage(m);
    expect(handled).toEqual([m]);
    expect(handled[0]).toBe(m);
  });

  it('a document origin is recorded before Playwright handles the message that reports it', () => {
    const origins = new DocumentOrigins();
    const seenByPlaywright: (string | null)[] = [];
    const { browser, transport } = fakeBrowser([], []);
    const original = transport.onmessage;
    transport.onmessage = (m) => {
      seenByPlaywright.push(origins.originOf('F'));
      original(m);
    };
    installNativeWebAuthnBlock(browser, { observe: (m) => origins.observe(m) });
    transport.onmessage({
      method: 'Runtime.executionContextCreated',
      params: {
        context: {
          id: 1,
          origin: 'https://login.example.com',
          auxData: { isDefault: true, frameId: 'F' },
        },
      },
    });
    expect(seenByPlaywright).toEqual(['https://login.example.com']);
  });

  it.each([
    ['_rawSend', (c: Record<string, unknown>) => delete c._rawSend],
    ['_sessions', (c: Record<string, unknown>) => delete c._sessions],
    ['rootSession.send', (c: Record<string, unknown>) => (c.rootSession = {})],
    ['_transport.onmessage', (c: Record<string, unknown>) => (c._transport = {})],
    ['_transport', (c: Record<string, unknown>) => delete c._transport],
  ])('refuses a connection missing %s, instead of installing nothing', (_name, remove) => {
    const connection: Record<string, unknown> = {
      _transport: { onmessage: () => {} },
      _rawSend: () => undefined,
      _sessions: new Map(),
      rootSession: { send: async () => ({}) },
    };
    remove(connection);
    const browser = { _connection: { toImpl: () => ({ _connection: connection }) } };
    expect(() => installNativeWebAuthnBlock(browser as unknown as Browser)).toThrow(
      /unexpected CRConnection shape/,
    );
  });

  it('refuses a client object that Playwright cannot map to its implementation', () => {
    expect(() => installNativeWebAuthnBlock({} as unknown as Browser)).toThrow(
      /client connection has no toImpl/,
    );
  });
});
