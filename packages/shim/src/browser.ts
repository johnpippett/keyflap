import { readFileSync } from 'node:fs';
import {
  type Browser,
  type BrowserContext,
  type BrowserContextOptions,
  chromium,
} from 'playwright';
import { DocumentOrigins, registerDocumentOrigins, trustedFrame } from './document-origin.ts';
import { installNativeWebAuthnBlock, type NativeWebAuthnBlock } from './native-webauthn-block.ts';
import type { ShimWebAuthnRequest, ShimWebAuthnResult, WebAuthnHandler } from './types.ts';

export const BINDING_NAME = '__aabWebAuthn';

const OVERRIDE_SCRIPT = readFileSync(
  new URL('./page/webauthn-override.js', import.meta.url),
  'utf8',
);

export type BrowserChannel = 'chromium';

export interface ManagedBrowserOptions {
  headless?: boolean;
  channel?: BrowserChannel;
  sandbox?: boolean;
  launchArgs?: string[];
}

export type StorageState = Exclude<BrowserContextOptions['storageState'], string | undefined>;

export interface NewContextOptions {
  storageState?: StorageState;
}

export interface ManagedBrowser {
  browser: Browser;
  newContext(onWebAuthn: WebAuthnHandler, opts?: NewContextOptions): Promise<BrowserContext>;
  close(): Promise<void>;
}

const DENY: ShimWebAuthnResult = { ok: false, name: 'NotAllowedError' };

export async function launchManagedBrowser(
  opts: ManagedBrowserOptions = {},
): Promise<ManagedBrowser> {
  const browser = await chromium.launch({
    headless: opts.headless ?? true,
    ...(opts.channel ? { channel: opts.channel } : {}),
    ...(opts.sandbox ? { chromiumSandbox: true } : {}),
    args: opts.launchArgs ?? [],
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
  });
  let block: NativeWebAuthnBlock;
  const origins = new DocumentOrigins();
  try {
    block = installNativeWebAuthnBlock(browser, { observe: (m) => origins.observe(m) });
    registerDocumentOrigins(browser, origins);
  } catch (err) {
    await browser.close().catch(() => {});
    throw err;
  }
  const contexts = new Set<BrowserContext>();
  let closed = false;

  const newContext = async (
    onWebAuthn: WebAuthnHandler,
    opts: NewContextOptions = {},
  ): Promise<BrowserContext> => {
    if (closed) throw new Error('managed browser is closed');
    const context = await browser.newContext({
      acceptDownloads: false,
      ...(opts.storageState ? { storageState: opts.storageState } : {}),
    });
    contexts.add(context);
    context.on('close', () => contexts.delete(context));
    try {
      await block.cover(context);
      await context.exposeBinding(
        BINDING_NAME,
        async (
          source,
          kind: unknown,
          options: unknown,
          mediation: unknown,
        ): Promise<ShimWebAuthnResult> => {
          try {
            if (kind !== 'create' && kind !== 'get') return DENY;
            const req: ShimWebAuthnRequest = {
              kind,
              frame: trustedFrame(source.frame),
              options,
              mediation: typeof mediation === 'string' ? mediation : null,
            };
            return await onWebAuthn(req, { page: source.page });
          } catch {
            return DENY;
          }
        },
      );
      await context.addInitScript({ content: OVERRIDE_SCRIPT });
    } catch (err) {
      await context.close().catch(() => {});
      throw err;
    }
    return context;
  };

  return {
    browser,
    newContext,
    close: async () => {
      closed = true;
      for (const c of [...contexts]) await c.close().catch(() => {});
      await browser.close().catch(() => {});
    },
  };
}
