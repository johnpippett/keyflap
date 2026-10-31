import type {
  AgentBrowserPort,
  AuthOutcome,
  AuthStatus,
  HandoffOutcome,
  Locator,
  PageInfo,
  SnapshotResult,
} from '@aab/mcp';
import { ToolError } from '@aab/mcp';
import { errors, type Page, type Locator as PwLocator } from 'playwright';
import type { AgentIdentity, Broker } from './broker.ts';
import { detectStep, FillDriver } from './fill.ts';
import { type HandoffManager, handoffWaitMs } from './handoff.ts';
import { registrableDomain, rpIdAllowedForHost, verifiedOriginOfPage } from './origin.ts';
import { REDACTED, scrubDeep, scrubString, truncateScrubbed } from './scrub.ts';
import type { AgentSession, AgentSessions } from './sessions.ts';

export const DEFAULT_AUTH_TIMEOUT_MS = 30_000;
export const MAX_AUTH_TIMEOUT_MS = 120_000;
const DEFAULT_ACTION_TIMEOUT_MS = 10_000;
const DEFAULT_NAVIGATION_TIMEOUT_MS = 30_000;
const MAX_URL = 8192;
const MAX_LOCATOR_STRING = 1000;
const MAX_TYPED = 10_000;
const MAX_SNAPSHOT = 200_000;
const MAX_SENSITIVE_FIELDS = 50;
const DEFAULT_EXCLUSIVE_WAIT_MS = 20_000;

export const SENSITIVE_FIELDS_CSS = [
  'input[type="password" i]',
  '[autocomplete~="one-time-code" i]',
  '[autocomplete~="current-password" i]',
  '[autocomplete~="new-password" i]',
].join(', ');

export { REDACTED };

const TEXT_FIELDS_CSS = 'input, textarea, [contenteditable]:not([contenteditable="false" i])';

export interface AgentPortOptions {
  agent: AgentIdentity;
  sessions: AgentSessions;
  broker: Broker;
  isActive: () => boolean;
  actionTimeoutMs?: number;
  navigationTimeoutMs?: number;
  fillStepTimeoutMs?: number;
  exclusiveWaitMs?: number;
  refreshCredentials?: () => Promise<void>;
  handoffs?: HandoffManager | null;
}

export const HANDOFF_IN_PROGRESS =
  'a human check is in progress on your page; call browser_handoff to wait for it';

interface CallCtx {
  exclusive<T>(fn: () => Promise<T>): Promise<T>;
}

type Obj = Record<string, unknown>;
const isPlainObject = (v: unknown): v is Obj => {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting them is the point
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

function str(v: unknown, field: string, max = MAX_LOCATOR_STRING): string {
  if (typeof v !== 'string' || v.length === 0 || v.length > max || CONTROL.test(v)) {
    throw new ToolError(`target.${field} must be a non-empty string of at most ${max} characters`);
  }
  return v;
}

const LOCATOR_KINDS = ['role', 'text', 'label', 'placeholder', 'css'] as const;
type LocatorKind = (typeof LOCATOR_KINDS)[number];
const LOCATOR_EXTRAS: Record<LocatorKind, readonly string[]> = {
  role: ['name', 'exact'],
  text: ['exact'],
  label: ['exact'],
  placeholder: ['exact'],
  css: [],
};

const ENGINE_PREFIX = /^\s*[a-zA-Z0-9_+\-:*]+\s*=/;
export function checkCss(css: string): string {
  if (css.includes('>>')) throw new ToolError('target.css must be plain CSS (no ">>" chains)');
  const t = css.trimStart();
  if (ENGINE_PREFIX.test(t) || t.startsWith('//') || t.startsWith('..') || /^["'`]/.test(t)) {
    throw new ToolError('target.css must be plain CSS (no selector-engine prefixes)');
  }
  return css;
}

export type ParsedLocator =
  | { kind: 'role'; role: string; name?: string; exact?: boolean }
  | { kind: 'text' | 'label' | 'placeholder'; value: string; exact?: boolean }
  | { kind: 'css'; css: string };

export function parseLocator(target: unknown): ParsedLocator {
  if (!isPlainObject(target)) throw new ToolError('target must be an object');
  const keys = Object.keys(target);
  const kinds = LOCATOR_KINDS.filter((k) => keys.includes(k));
  if (kinds.length !== 1) {
    throw new ToolError(`target must have exactly one of: ${LOCATOR_KINDS.join(', ')}`);
  }
  const kind = kinds[0] as LocatorKind;
  for (const k of keys) {
    if (k !== kind && !LOCATOR_EXTRAS[kind].includes(k)) {
      throw new ToolError(`target.${k} is not allowed with target.${kind}`);
    }
  }
  let exact: boolean | undefined;
  if ('exact' in target) {
    if (typeof target.exact !== 'boolean') throw new ToolError('target.exact must be a boolean');
    exact = target.exact;
  }
  const withExact = <T extends object>(o: T) => (exact === undefined ? o : { ...o, exact });
  switch (kind) {
    case 'role': {
      const role = str(target.role, 'role', 64);
      if (!/^[a-z]+$/.test(role)) throw new ToolError('target.role must be an ARIA role name');
      const name = 'name' in target ? str(target.name, 'name') : undefined;
      return withExact(name === undefined ? { kind, role } : { kind, role, name });
    }
    case 'css':
      return { kind, css: checkCss(str(target.css, 'css')) };
    default:
      return withExact({ kind, value: str(target[kind], kind) });
  }
}

function toPlaywright(page: Page, l: ParsedLocator): PwLocator {
  const ex = 'exact' in l && l.exact !== undefined ? { exact: l.exact } : {};
  switch (l.kind) {
    case 'role':
      return page.getByRole(l.role as Parameters<Page['getByRole']>[0], {
        ...(l.name !== undefined ? { name: l.name } : {}),
        ...ex,
      });
    case 'text':
      return page.getByText(l.value, ex);
    case 'label':
      return page.getByLabel(l.value, ex);
    case 'placeholder':
      return page.getByPlaceholder(l.value, ex);
    case 'css':
      return page.locator(`css=${l.css}`);
  }
}

function parseTimeout(opts: unknown): number {
  if (opts === undefined || opts === null) return DEFAULT_AUTH_TIMEOUT_MS;
  if (!isPlainObject(opts)) throw new ToolError('options must be an object');
  const t = opts.timeoutMs;
  if (t === undefined) return DEFAULT_AUTH_TIMEOUT_MS;
  if (typeof t !== 'number' || !Number.isFinite(t) || t < 0) {
    throw new ToolError('timeoutMs must be a non-negative number');
  }
  return Math.min(Math.max(Math.floor(t), 1), MAX_AUTH_TIMEOUT_MS);
}

function actionError(err: unknown, timeoutMs: number): never {
  if (err instanceof ToolError) throw err;
  const msg = err instanceof Error ? err.message : '';
  if (/strict mode violation/i.test(msg)) {
    throw new ToolError('the target matched more than one element; be more specific');
  }
  if (err instanceof errors.TimeoutError) {
    throw new ToolError(
      `no matching element was found, or it never became actionable, within ${Math.round(timeoutMs / 1000)} s`,
    );
  }
  if (/not an <input>|not an input|cannot type|cannot be filled|not editable/i.test(msg)) {
    throw new ToolError('the target is not an editable text field');
  }
  if (/has been closed/i.test(msg)) throw new ToolError('the page was closed');
  if (/unknown role|unexpected token|not a valid selector|selector/i.test(msg)) {
    throw new ToolError('invalid target');
  }
  throw err;
}

function pageOrigin(page: Page | null): string | undefined {
  if (!page || page.isClosed()) return undefined;
  try {
    const u = new URL(page.url());
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : undefined;
  } catch {
    return undefined;
  }
}

export function nodePrefix(line: string): string | null {
  const m = /^\s*- [a-z]+/.exec(line);
  if (!m) return null;
  let i = m[0].length;
  if (line.startsWith(' "', i)) {
    let j = i + 2;
    while (j < line.length && line[j] !== '"') j += line[j] === '\\' ? 2 : 1;
    if (j >= line.length) return null;
    i = j + 1;
  }
  while (line.startsWith(' [', i)) {
    const k = line.indexOf(']', i);
    if (k < 0) return null;
    i = k + 1;
  }
  return line.slice(0, i).trimStart();
}

const indentOf = (line: string) => line.length - line.trimStart().length;
const VALUE_ROLES = /^- (textbox|searchbox|spinbutton|combobox)\b/;

export function redactSnapshot(
  snapshot: string,
  sensitive: { prefixes: Set<string>; values: string[] },
  allValues = false,
): string {
  const lines = snapshot.split('\n');
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    const prefix = nodePrefix(line);
    const hit =
      prefix !== null &&
      (sensitive.prefixes.has(prefix) || (allValues && VALUE_ROLES.test(prefix)));
    if (!hit || prefix === null) {
      out.push(line);
      continue;
    }
    const rest = line.slice(indentOf(line) + prefix.length);
    out.push(
      `${' '.repeat(indentOf(line))}${prefix}${rest.startsWith(':') ? `: ${REDACTED}` : ''}`,
    );
    const ind = indentOf(line);
    while (i + 1 < lines.length && indentOf(lines[i + 1] as string) > ind) i++;
  }
  let text = out.join('\n');
  for (const v of sensitive.values) {
    if (v.length < 4) continue;
    const forms = new Set([v, JSON.stringify(v).slice(1, -1)]);
    for (const f of forms) text = text.split(f).join(REDACTED);
  }
  return text;
}

async function sensitiveFields(
  page: Page,
): Promise<{ prefixes: Set<string>; values: string[] } | null> {
  const loc = page.locator(`css=${SENSITIVE_FIELDS_CSS}`);
  const n = await loc.count();
  if (n > MAX_SENSITIVE_FIELDS) return null;
  const prefixes = new Set<string>();
  const values: string[] = [];
  for (let i = 0; i < n; i++) {
    const el = loc.nth(i);
    const value = await el.inputValue({ timeout: 1000 }).catch(() => '');
    if (value) values.push(value);
    const snap = await el.ariaSnapshot({ timeout: 1000 }).catch(() => '');
    for (const line of snap.split('\n')) {
      const p = nodePrefix(line);
      if (p !== null) {
        prefixes.add(p);
        break;
      }
    }
  }
  return { prefixes, values };
}

export class AgentPort implements AgentBrowserPort {
  private readonly agent: AgentIdentity;
  private readonly sessions: AgentSessions;
  private readonly broker: Broker;
  private readonly isActive: () => boolean;
  private readonly actionTimeoutMs: number;
  private readonly navigationTimeoutMs: number;
  private readonly fillStepTimeoutMs: number | undefined;
  private callSeq = 0;
  private readonly inflight = new Map<number, Promise<void>>();
  private gate: Promise<void> | null = null;
  private exclusiveTurn: Promise<void> = Promise.resolve();
  private inflightChanged: () => void = () => {};
  private readonly exclusiveWaitMs: number;
  private readonly refreshCredentials: (() => Promise<void>) | undefined;
  private readonly handoffs: HandoffManager | null;

  constructor(opts: AgentPortOptions) {
    this.agent = opts.agent;
    this.sessions = opts.sessions;
    this.broker = opts.broker;
    this.isActive = opts.isActive;
    this.actionTimeoutMs = opts.actionTimeoutMs ?? DEFAULT_ACTION_TIMEOUT_MS;
    this.navigationTimeoutMs = opts.navigationTimeoutMs ?? DEFAULT_NAVIGATION_TIMEOUT_MS;
    this.fillStepTimeoutMs = opts.fillStepTimeoutMs;
    this.exclusiveWaitMs = opts.exclusiveWaitMs ?? DEFAULT_EXCLUSIVE_WAIT_MS;
    this.refreshCredentials = opts.refreshCredentials;
    this.handoffs = opts.handoffs ?? null;
  }

  private removeInflight(id: number): void {
    if (this.inflight.delete(id)) this.inflightChanged();
  }

  private async drainInflight(ms: number): Promise<void> {
    const deadline = Date.now() + ms;
    while (this.inflight.size > 0) {
      const left = deadline - Date.now();
      if (left <= 0) throw new Error('other tool calls did not finish in time');
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, left);
        this.inflightChanged = () => {
          clearTimeout(timer);
          resolve();
        };
      });
    }
  }

  private async call<T>(
    tool: string,
    fn: (s: AgentSession, ctx: CallCtx) => Promise<T>,
  ): Promise<T> {
    let ok = false;
    let id = 0;
    let finish: () => void = () => {};
    try {
      while (this.gate) await this.gate;
      id = ++this.callSeq;
      const running = new Promise<void>((r) => {
        finish = r;
      });
      this.inflight.set(id, running);
      if (!this.isActive()) throw new ToolError('this agent has been revoked');
      if (tool !== 'browser_handoff' && this.handoffs?.isOpen(this.agent.id)) {
        throw new ToolError(HANDOFF_IN_PROGRESS);
      }
      const session = await this.sessions.get(this.agent);
      session.markDirty();
      const ctx: CallCtx = { exclusive: (f) => this.exclusive(id, running, f) };
      const result = await fn(session, ctx);
      const scrubbed = scrubDeep(result, session.secrets());
      ok = true;
      return scrubbed;
    } finally {
      if (id) this.removeInflight(id);
      finish();
      const origin = pageOrigin(this.sessions.peek(this.agent.id)?.currentPage() ?? null);
      this.broker.audit.append('tool.call', {
        agentId: this.agent.id,
        tool,
        ok,
        ...(origin ? { origin } : {}),
      });
    }
  }

  private async exclusive<T>(self: number, running: Promise<void>, fn: () => Promise<T>) {
    this.removeInflight(self);
    const prev = this.exclusiveTurn;
    let done!: () => void;
    this.exclusiveTurn = new Promise<void>((r) => {
      done = r;
    });
    let open: (() => void) | null = null;
    try {
      await prev;
      const gate = new Promise<void>((r) => {
        open = r;
      });
      this.gate = gate;
      await this.drainInflight(this.exclusiveWaitMs);
      return await fn();
    } finally {
      this.gate = null;
      (open as (() => void) | null)?.();
      this.inflight.set(self, running);
      done();
    }
  }

  private requirePage(s: AgentSession): Page {
    const page = s.currentPage();
    if (!page) throw new ToolError('no page is open; use browser_open first');
    return page;
  }

  private async info(s: AgentSession): Promise<PageInfo> {
    const page = s.currentPage();
    if (!page) return { url: 'about:blank', title: '' };
    const title = await page.title().catch(() => '');
    return { url: page.url(), title };
  }

  private async settle(page: Page): Promise<void> {
    await page.waitForLoadState('domcontentloaded', { timeout: 5_000 }).catch(() => {});
  }

  open(url: string): Promise<PageInfo> {
    return this.call('browser_open', async (s) => {
      if (typeof url !== 'string' || url.length === 0 || url.length > MAX_URL) {
        throw new ToolError('url must be a non-empty string');
      }
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        throw new ToolError('url is not a valid absolute URL');
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new ToolError('only http and https URLs can be opened');
      }
      const page = s.currentPage() ?? (await s.newPage());
      const go = () =>
        page.goto(parsed.href, {
          waitUntil: 'domcontentloaded',
          timeout: this.navigationTimeoutMs,
        });
      try {
        try {
          await go();
        } catch (err) {
          if (!/interrupted by another navigation/.test(err instanceof Error ? err.message : '')) {
            throw err;
          }
          const landed = await page
            .waitForURL(parsed.href, { waitUntil: 'domcontentloaded', timeout: 5_000 })
            .then(
              () => true,
              () => false,
            );
          if (!landed) await go();
        }
      } catch (err) {
        await page.waitForLoadState('load', { timeout: 2_000 }).catch(() => {});
        if (err instanceof errors.TimeoutError) throw new ToolError('navigation timed out');
        const code = /net::ERR_[A-Z_]+/.exec(err instanceof Error ? err.message : '');
        throw new ToolError(`navigation failed${code ? `: ${code[0]}` : ''}`);
      }
      return this.info(s);
    });
  }

  click(target: Locator): Promise<PageInfo> {
    return this.call('browser_click', async (s) => {
      const parsed = parseLocator(target);
      const page = this.requirePage(s);
      try {
        await toPlaywright(page, parsed).click({ timeout: this.actionTimeoutMs });
      } catch (err) {
        actionError(err, this.actionTimeoutMs);
      }
      await this.settle(page);
      return this.info(s);
    });
  }

  type(target: Locator, text: string, opts?: { submit?: boolean }): Promise<PageInfo> {
    return this.call('browser_type', async (s) => {
      const parsed = parseLocator(target);
      if (typeof text !== 'string' || text.length > MAX_TYPED) {
        throw new ToolError(`text must be a string of at most ${MAX_TYPED} characters`);
      }
      if (opts !== undefined && opts !== null) {
        if (!isPlainObject(opts) || Object.keys(opts).some((k) => k !== 'submit')) {
          throw new ToolError('options may only contain submit');
        }
        if (opts.submit !== undefined && typeof opts.submit !== 'boolean') {
          throw new ToolError('submit must be a boolean');
        }
      }
      const page = this.requirePage(s);
      const loc = toPlaywright(page, parsed);
      try {
        await loc.waitFor({ state: 'attached', timeout: this.actionTimeoutMs });
        if ((await loc.and(page.locator(`css=${TEXT_FIELDS_CSS}`)).count()) === 0) {
          throw new ToolError('the target is not an editable text field');
        }
        if ((await loc.and(page.locator(`css=${SENSITIVE_FIELDS_CSS}`)).count()) > 0) {
          throw new ToolError(
            'this is a password or one-time-code field; the agent cannot type into it. Use auth_login.',
          );
        }
        await loc.fill(text, { timeout: this.actionTimeoutMs });
        if (opts?.submit) await loc.press('Enter', { timeout: this.actionTimeoutMs });
      } catch (err) {
        actionError(err, this.actionTimeoutMs);
      }
      await this.settle(page);
      return this.info(s);
    });
  }

  snapshot(): Promise<SnapshotResult> {
    return this.call('browser_snapshot', async (s) => {
      const page = this.requirePage(s);
      const before = await sensitiveFields(page).catch(() => null);
      let raw: string;
      try {
        raw = await page.locator('body').ariaSnapshot({ timeout: this.actionTimeoutMs });
      } catch (err) {
        actionError(err, this.actionTimeoutMs);
      }
      const after = await sensitiveFields(page).catch(() => null);
      let snapshot: string;
      if (before && after) {
        snapshot = redactSnapshot(raw, {
          prefixes: new Set([...before.prefixes, ...after.prefixes]),
          values: [...before.values, ...after.values],
        });
      } else {
        snapshot = redactSnapshot(raw, { prefixes: new Set(), values: [] }, true);
      }
      const secrets = s.secrets();
      snapshot = scrubString(snapshot, secrets);
      if (snapshot.length > MAX_SNAPSHOT) {
        snapshot = `${truncateScrubbed(snapshot, MAX_SNAPSHOT, secrets)}\n[snapshot truncated]`;
      }
      const humanCheck = (await s.humanCheck(page)) !== null;
      return { ...(await this.info(s)), snapshot, humanCheck };
    });
  }

  private status(
    page: Page | null,
  ): Omit<AuthStatus, 'humanCheck'> & { host: string | null; domain: string | null } {
    if (!page) return { origin: null, host: null, domain: null, credentials: [] };
    const o = verifiedOriginOfPage(page);
    if (!o.ok) return { origin: null, host: null, domain: null, credentials: [] };
    const credentials: AuthStatus['credentials'] = this.broker.credentials
      .allPasskeyRpIds()
      .filter((c) => rpIdAllowedForHost(c.rp_id, o.host))
      .map(() => ({ type: 'passkey' as const }));
    const domain = registrableDomain(o.host);
    if (domain) {
      for (const item of this.broker.credentials.passwordsForDomain(domain)) {
        credentials.push({ type: 'password' });
        if (item.has_totp) credentials.push({ type: 'totp' });
      }
    }
    return { origin: o.origin, host: o.host, domain, credentials };
  }

  private async freshStatus(page: Page | null): Promise<ReturnType<AgentPort['status']>> {
    const st = this.status(page);
    if (st.origin === null || st.credentials.length > 0 || !this.refreshCredentials) return st;
    await this.refreshCredentials();
    return this.status(page);
  }

  authStatus(): Promise<AuthStatus> {
    return this.call('auth_status', async (s) => {
      const page = s.currentPage();
      const { origin, credentials } = await this.freshStatus(page);
      const humanCheck = page ? (await s.humanCheck(page)) !== null : false;
      return { origin, credentials, humanCheck };
    });
  }

  authLogin(opts?: { timeoutMs?: number }): Promise<AuthOutcome> {
    return this.call('auth_login', async (s, ctx) => {
      const timeoutMs = parseTimeout(opts);
      const page = s.currentPage();
      const st = await this.freshStatus(page);
      if (!page || st.origin === null || st.host === null) {
        return { status: 'unsupported', reason: 'not_eligible' };
      }
      if (s.hasCeremony('get', page)) {
        return { status: await s.waitForCeremony('get', page, timeoutMs) };
      }
      const hasPasskey = st.credentials.some((c) => c.type === 'passkey');
      const hasPassword = st.credentials.some((c) => c.type === 'password');
      if (hasPassword && st.domain) {
        const det = await detectStep(page, st.domain).catch(() => ({ kind: 'none' }) as const);
        if (det.kind === 'step') {
          const driver = new FillDriver({
            page,
            origin: { origin: st.origin, host: st.host },
            domain: st.domain,
            first: det.step,
            exclusive: (f) => ctx.exclusive(f),
            remember: (v) => s.rememberSecret(v),
            humanCheck: () => s.humanCheck(page),
            actionTimeoutMs: Math.min(this.actionTimeoutMs, 5_000),
            ...(this.fillStepTimeoutMs ? { stepTimeoutMs: this.fillStepTimeoutMs } : {}),
          });
          return { status: await this.broker.fill(this.agent, driver) };
        }
        if (det.kind === 'ambiguous' || det.kind === 'cross_site') {
          this.broker.refuseFill(
            this.agent,
            st.origin,
            det.kind === 'ambiguous' ? 'ambiguous_form' : 'form_targets_other_site',
          );
        }
        if (!hasPasskey) return { status: 'unsupported', reason: 'not_eligible' };
      }
      if (!hasPasskey) return { status: 'unsupported', reason: 'no_credential' };
      return { status: await s.waitForCeremony('get', page, timeoutMs) };
    });
  }

  handoff(opts?: { timeoutMs?: number }): Promise<HandoffOutcome> {
    return this.call('browser_handoff', async (s) => {
      let t: number | undefined;
      if (opts !== undefined && opts !== null) {
        if (!isPlainObject(opts) || Object.keys(opts).some((k) => k !== 'timeoutMs')) {
          throw new ToolError('options may only contain timeoutMs');
        }
        if (opts.timeoutMs !== undefined) {
          if (typeof opts.timeoutMs !== 'number' || !Number.isFinite(opts.timeoutMs)) {
            throw new ToolError('timeoutMs must be a number');
          }
          t = opts.timeoutMs;
        }
      }
      if (!this.handoffs) return { status: 'unsupported', reason: 'not_available' };
      return this.handoffs.request(s, handoffWaitMs(t));
    });
  }

  authEnrollPasskey(opts?: { timeoutMs?: number }): Promise<AuthOutcome> {
    return this.call('auth_enroll_passkey', async (s) => {
      const timeoutMs = parseTimeout(opts);
      const page = s.currentPage();
      const st = this.status(page);
      if (!page || st.origin === null) return { status: 'unsupported', reason: 'not_eligible' };
      const outcome = await s.waitForCeremony('create', page, timeoutMs);
      return { status: outcome };
    });
  }
}
