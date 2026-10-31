import type { Frame, Page, Request, Response } from 'playwright';

export interface HumanCheck {
  provider: string;
}

interface FrameRule {
  provider: string;
  hosts: readonly string[];
  interactive(url: URL): boolean;
}

const always = () => true;

export const CHALLENGE_PROVIDERS: readonly FrameRule[] = [
  { provider: 'aws-waf', hosts: ['captcha.awswaf.com'], interactive: always },
  { provider: 'aws-waf', hosts: ['token.awswaf.com'], interactive: () => false },
  { provider: 'cloudflare', hosts: ['challenges.cloudflare.com'], interactive: always },
  {
    provider: 'hcaptcha',
    hosts: ['hcaptcha.com'],
    interactive: (u) => {
      const frame = new URLSearchParams(u.hash.slice(1)).get('frame');
      return frame === 'checkbox' || frame === 'challenge';
    },
  },
  {
    provider: 'recaptcha',
    hosts: ['www.google.com', 'www.recaptcha.net'],
    interactive: (u) => {
      const m = /^\/recaptcha\/(?:api2|enterprise)\/(anchor|bframe)$/.exec(u.pathname);
      if (!m) return false;
      if (m[1] === 'bframe') return true;
      return u.searchParams.get('size') !== 'invisible';
    },
  },
  { provider: 'arkose', hosts: ['arkoselabs.com', 'funcaptcha.com'], interactive: always },
  { provider: 'datadome', hosts: ['geo.captcha-delivery.com'], interactive: always },
  { provider: 'human', hosts: ['captcha.px-cdn.net', 'perimeterx.net'], interactive: always },
];

const PATH_SCOPED: Record<string, RegExp> = {
  'www.google.com': /^\/recaptcha\//,
  'www.recaptcha.net': /^\/recaptcha\//,
};

export function hostMatches(host: string, suffix: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const s = suffix.toLowerCase();
  return h === s || h.endsWith(`.${s}`);
}

export const MIN_WIDGET_PX = 60;

export interface FrameVerdict {
  provider: string;
  interactive: boolean;
}

export function classifyUrl(raw: string, extraHosts: readonly string[] = []): FrameVerdict | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  const host = u.hostname;
  for (const h of extraHosts) {
    if (hostMatches(host, h)) return { provider: 'test', interactive: true };
  }
  for (const rule of CHALLENGE_PROVIDERS) {
    const hit = rule.hosts.find((h) => hostMatches(host, h));
    if (!hit) continue;
    const scope = PATH_SCOPED[hit];
    if (scope && !scope.test(u.pathname)) continue;
    return { provider: rule.provider, interactive: rule.interactive(u) };
  }
  return null;
}

export function classifyDocumentResponse(headers: Record<string, string>): string | null {
  const waf = (headers['x-amzn-waf-action'] ?? '').trim().toLowerCase();
  if (waf === 'captcha' || waf === 'challenge') return 'aws-waf';
  const cf = (headers['cf-mitigated'] ?? '').trim().toLowerCase();
  if (cf === 'challenge') return 'cloudflare';
  return null;
}

interface DocRecord {
  url: string;
  status: number;
  provider: string | null;
}

export class ChallengeWatch {
  readonly extraHosts: readonly string[];
  private readonly page: Page;
  private doc: DocRecord | null = null;
  private readonly seen = new Map<string, string>();
  private readonly onResponse: (r: Response) => void;
  private readonly onRequest: (r: Request) => void;
  private readonly onNavigated: (f: Frame) => void;

  constructor(page: Page, opts: { extraHosts?: readonly string[] } = {}) {
    this.page = page;
    this.extraHosts = opts.extraHosts ?? [];
    this.onResponse = (r) => {
      try {
        const req = r.request();
        if (!req.isNavigationRequest() || r.frame() !== page.mainFrame()) return;
        this.doc = {
          url: r.url(),
          status: r.status(),
          provider: classifyDocumentResponse(r.headers()),
        };
      } catch {}
    };
    this.onRequest = (r) => {
      try {
        const v = classifyUrl(r.url(), this.extraHosts);
        if (v) this.seen.set(new URL(r.url()).hostname, v.provider);
      } catch {}
    };
    this.onNavigated = (f) => {
      if (f === page.mainFrame()) this.seen.clear();
    };
    page.on('response', this.onResponse);
    page.on('request', this.onRequest);
    page.on('framenavigated', this.onNavigated);
  }

  documentChallenge(): string | null {
    const d = this.doc;
    if (!d || d.provider === null || this.page.isClosed()) return null;
    const strip = (s: string) => s.split('#')[0];
    return strip(this.page.mainFrame().url()) === strip(d.url) ? d.provider : null;
  }

  requestedHosts(): string[] {
    return [...this.seen.keys()];
  }

  dispose(): void {
    this.page.off('response', this.onResponse);
    this.page.off('request', this.onRequest);
    this.page.off('framenavigated', this.onNavigated);
  }
}

const withTimeout = <T>(p: Promise<T>, ms: number, fallback: T): Promise<T> =>
  new Promise<T>((resolve) => {
    const t = setTimeout(() => resolve(fallback), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      () => {
        clearTimeout(t);
        resolve(fallback);
      },
    );
  });

async function visibleWidget(frame: Frame): Promise<boolean> {
  const el = await frame.frameElement().catch(() => null);
  if (!el) return false;
  try {
    if (!(await el.isVisible())) return false;
    const box = await el.boundingBox();
    return box !== null && box.width >= MIN_WIDGET_PX && box.height >= MIN_WIDGET_PX;
  } finally {
    await el.dispose().catch(() => {});
  }
}

export async function detectHumanCheck(
  page: Page,
  watch: ChallengeWatch | null,
  opts: { timeoutMs?: number } = {},
): Promise<HumanCheck | null> {
  if (page.isClosed()) return null;
  const fromDoc = watch?.documentChallenge() ?? null;
  if (fromDoc) return { provider: fromDoc };
  const extra = watch?.extraHosts ?? [];
  const scan = async (): Promise<HumanCheck | null> => {
    for (const f of page.frames()) {
      if (f === page.mainFrame() || f.isDetached()) continue;
      const v = classifyUrl(f.url(), extra);
      if (!v?.interactive) continue;
      if (await visibleWidget(f)) return { provider: v.provider };
    }
    return null;
  };
  return withTimeout(scan(), opts.timeoutMs ?? 3_000, null);
}
