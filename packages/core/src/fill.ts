import type { FillField } from '@aab/signer/approval';
import type { ElementHandle, Page, Locator as PwLocator } from 'playwright';
import type { FillPerformResult, FillStepKind, FillTarget } from './broker.ts';
import type { HumanCheck } from './challenge.ts';
import type { PasswordRow } from './db.ts';
import { checkOriginUrl, registrableDomain, verifiedOriginOfPage } from './origin.ts';

const LOGIN_PASSWORD_CSS = 'input[type="password" i]:not([autocomplete~="new-password" i])';
const OTP_CSS = 'input[autocomplete~="one-time-code" i]:not([type="hidden" i])';
const USERNAME_CSS = 'input[autocomplete~="username" i]:not([type="hidden" i])';
const EMAIL_CSS = 'input[type="email" i], input[autocomplete~="email" i]:not([type="hidden" i])';
const TEXT_CSS = 'input[type="text" i], input:not([type])';
const MAX_SCANNED_INPUTS = 200;
const SUBMIT_IN_FORM_CSS =
  'button:not([type]), button[type="submit" i], input[type="submit" i], input[type="image" i]';
const SUBMIT_NAME = /^\s*(next|continue|sign ?in|log ?in|login|submit|verify)\s*$/i;

export interface FillStep {
  kind: FillStepKind;
  field: PwLocator;
  username: PwLocator | null;
  otp: PwLocator | null;
}

export type Detection =
  | { kind: 'none' }
  | { kind: 'ambiguous' }
  | { kind: 'cross_site' }
  | { kind: 'step'; step: FillStep };

const visible = (l: PwLocator) => l.filter({ visible: true });

async function single(l: PwLocator): Promise<PwLocator | null | 'many'> {
  const v = visible(l);
  const n = await v.count();
  if (n === 0) return null;
  return n === 1 ? v.first() : 'many';
}

async function pick(scope: PwLocator | Page, selectors: string[]): Promise<PwLocator | null> {
  for (const css of selectors) {
    const found = await single(scope.locator(`css=${css}`));
    if (found === 'many') return null;
    if (found) return found;
  }
  return null;
}

async function baseUrl(page: Page): Promise<string | null> {
  const base = page.locator('css=base[href]');
  if ((await base.count()) === 0) return page.url();
  const href = await base.first().getAttribute('href', { timeout: 1000 });
  try {
    return new URL(href ?? '', page.url()).href;
  } catch {
    return null;
  }
}

async function formSubmitsTo(page: Page, field: PwLocator, domain: string): Promise<boolean> {
  if ((await field.getAttribute('form', { timeout: 1000 })) !== null) return false;
  const base = await baseUrl(page);
  if (base === null) return false;
  const targets: (string | null)[] = [];
  const outside = page.locator('css=[form][formaction]');
  const m = await outside.count();
  if (m > 50) return false;
  for (let i = 0; i < m; i++) {
    targets.push(await outside.nth(i).getAttribute('formaction', { timeout: 1000 }));
  }
  const form = field.locator('xpath=ancestor::form[1]');
  if ((await form.count()) > 0) {
    targets.push(await form.getAttribute('action', { timeout: 1000 }));
    const buttons = form.locator('css=[formaction]');
    const n = await buttons.count();
    if (n > 50) return false;
    for (let i = 0; i < n; i++) {
      targets.push(await buttons.nth(i).getAttribute('formaction', { timeout: 1000 }));
    }
  }
  for (const t of targets) {
    if (t === null || t.trim() === '') continue;
    let url: URL;
    try {
      url = new URL(t, base);
    } catch {
      return false;
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
    if (registrableDomain(url.hostname) !== domain) return false;
  }
  return true;
}

async function usernameFor(
  password: PwLocator,
  scope: PwLocator | Page,
  inForm: boolean,
): Promise<PwLocator | null> {
  const named = await single(scope.locator(`css=${USERNAME_CSS}`));
  if (named === 'many') return null;
  if (named) return named;
  const css = inForm ? `${EMAIL_CSS}, ${TEXT_CSS}` : EMAIL_CSS;
  const before = visible(
    scope.locator(`css=${css}`).and(password.locator('xpath=preceding::input')),
  );
  const n = await before.count();
  return n === 0 ? null : before.nth(n - 1);
}

export async function detectStep(page: Page, domain: string): Promise<Detection> {
  if (page.isClosed()) return { kind: 'none' };
  const password = await single(page.locator(`css=${LOGIN_PASSWORD_CSS}`));
  if (password === 'many') return { kind: 'ambiguous' };
  if (password) {
    const form = password.locator('xpath=ancestor::form[1]');
    const inForm = (await form.count()) === 1;
    const scope = inForm ? form : page;
    const username = await usernameFor(password, scope, inForm);
    const otp = inForm ? await single(form.locator(`css=${OTP_CSS}`)) : null;
    for (const f of [password, username, otp === 'many' ? null : otp]) {
      if (f && !(await formSubmitsTo(page, f, domain))) return { kind: 'cross_site' };
    }
    return {
      kind: 'step',
      step: {
        kind: 'password',
        field: password,
        username,
        otp: otp === 'many' ? null : otp,
      },
    };
  }
  const otp = await single(page.locator(`css=${OTP_CSS}`));
  if (otp === 'many') return { kind: 'ambiguous' };
  if (otp) {
    if (!(await formSubmitsTo(page, otp, domain))) return { kind: 'cross_site' };
    return { kind: 'step', step: { kind: 'otp', field: otp, username: null, otp: null } };
  }
  const ident = await pick(page, [USERNAME_CSS, EMAIL_CSS]);
  if (ident) {
    if (!(await formSubmitsTo(page, ident, domain))) return { kind: 'cross_site' };
    return { kind: 'step', step: { kind: 'identifier', field: ident, username: null, otp: null } };
  }
  return { kind: 'none' };
}

export interface FillDriverOptions {
  page: Page;
  origin: { origin: string; host: string };
  domain: string;
  first: FillStep;
  exclusive: <T>(fn: () => Promise<T>) => Promise<T>;
  remember: (secret: string) => void;
  humanCheck?: () => Promise<HumanCheck | null>;
  stepTimeoutMs?: number;
  actionTimeoutMs?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const SUBMIT_CLICK_AFTER_MS = 1_500;
const CHALLENGE_SHOWN_MS = 750;
const CHALLENGE_SETTLE_MS = 2_000;

export class FillDriver implements FillTarget {
  readonly origin: { origin: string; host: string };
  readonly first: FillStepKind;
  private readonly o: FillDriverOptions;
  private readonly stepTimeoutMs: number;
  private readonly actionTimeoutMs: number;

  constructor(o: FillDriverOptions) {
    this.o = o;
    this.origin = o.origin;
    this.first = o.first.kind;
    this.stepTimeoutMs = o.stepTimeoutMs ?? 10_000;
    this.actionTimeoutMs = o.actionTimeoutMs ?? 5_000;
  }

  private onOrigin(): boolean {
    const o = verifiedOriginOfPage(this.o.page);
    return o.ok && o.origin === this.origin.origin;
  }

  private onUrlOrigin(): boolean {
    const page = this.o.page;
    if (page.isClosed()) return false;
    const o = checkOriginUrl(page.url());
    return o.ok && o.origin === this.origin.origin;
  }

  private async handle(l: PwLocator): Promise<ElementHandle<HTMLElement | SVGElement>> {
    const h = await l.elementHandle({ timeout: this.actionTimeoutMs });
    if (!h) throw new Error('field_gone');
    if ((await h.ownerFrame()) !== this.o.page.mainFrame()) throw new Error('not_main_frame');
    return h;
  }

  perform(ctx: {
    item: PasswordRow;
    release: (field: FillField) => Promise<string>;
  }): Promise<FillPerformResult> {
    return this.o.exclusive(() => this.run(ctx));
  }

  private async checkHuman(): Promise<HumanCheck | null> {
    if (!this.o.humanCheck) return null;
    return this.o.humanCheck().catch(() => null);
  }

  private async run(ctx: {
    item: PasswordRow;
    release: (field: FillField) => Promise<string>;
  }): Promise<FillPerformResult> {
    const secrets: string[] = [];
    const filled: ElementHandle[] = [];
    const done = new Set<FillStepKind>();
    const release = async (field: FillField) => {
      const v = await ctx.release(field);
      secrets.push(v);
      this.o.remember(v);
      return v;
    };
    try {
      if (!this.onOrigin()) throw new Error('origin_changed');
      const again = await detectStep(this.o.page, this.o.domain);
      if (again.kind !== 'step' || again.step.kind !== this.first) throw new Error('step_changed');
      let step: FillStep | null = again.step;
      while (step) {
        const submitted = await this.fillStep(step, ctx.item, release, filled);
        done.add(step.kind);
        if (step.kind === 'password' && step.otp) done.add('otp');
        step = await this.next(done, filled, ctx.item, submitted);
      }
      if (this.o.humanCheck && !this.o.page.isClosed()) {
        await this.o.page
          .waitForLoadState('load', { timeout: CHALLENGE_SETTLE_MS })
          .catch(() => {});
        const hc = await this.checkHuman();
        if (hc) return { outcome: 'challenge', humanCheck: hc.provider };
      }
      return { outcome: 'success' };
    } catch (err) {
      if (err instanceof RepeatedStep) return { outcome: 'failed' };
      if (err instanceof ChallengeShown) return { outcome: 'challenge', humanCheck: err.provider };
      throw err;
    } finally {
      await this.clear(secrets, filled);
      for (const h of filled) await h.dispose().catch(() => {});
    }
  }

  private async fillStep(
    step: FillStep,
    item: PasswordRow,
    release: (field: FillField) => Promise<string>,
    filled: ElementHandle[],
  ): Promise<PwLocator> {
    const field = await this.handle(step.field);
    filled.push(field);
    const user = step.username && item.username ? await this.handle(step.username) : null;
    const otp = step.otp && item.has_totp ? await this.handle(step.otp) : null;
    if (user) filled.push(user);
    if (otp) filled.push(otp);

    const typeInto = async (h: ElementHandle, value: string) => {
      if (!this.onOrigin()) throw new Error('origin_changed');
      const timeout = this.actionTimeoutMs;
      await h.fill('', { timeout });
      await h.type(value, { timeout });
      if ((await h.inputValue({ timeout })) !== value) {
        if (!this.onOrigin()) throw new Error('origin_changed');
        await h.fill(value, { timeout });
      }
    };
    if (!this.onOrigin()) throw new Error('origin_changed');
    switch (step.kind) {
      case 'identifier':
        if (!item.username) throw new Error('no_username');
        await typeInto(field, item.username);
        break;
      case 'password':
        if (user && item.username) {
          const current = await user.inputValue({ timeout: this.actionTimeoutMs });
          if (current !== item.username) await typeInto(user, item.username);
        }
        await typeInto(field, await release('password'));
        if (otp) await typeInto(otp, await release('totp'));
        break;
      case 'otp':
        await typeInto(field, await release('totp'));
        break;
    }
    if (!this.onOrigin()) throw new Error('origin_changed');
    await (otp ?? field).press('Enter', { timeout: this.actionTimeoutMs });
    return otp && step.otp ? step.otp : step.field;
  }

  private async submitButton(field: PwLocator): Promise<PwLocator | null> {
    const form = field.locator('xpath=ancestor::form[1]');
    if ((await form.count()) === 1) {
      const b = await single(form.locator(`css=${SUBMIT_IN_FORM_CSS}`));
      return b === 'many' ? null : b;
    }
    const b = await single(this.o.page.getByRole('button', { name: SUBMIT_NAME }));
    return b === 'many' ? null : b;
  }

  private async next(
    done: Set<FillStepKind>,
    filled: ElementHandle[],
    item: PasswordRow,
    submitted: PwLocator,
  ): Promise<FillStep | null> {
    const page = this.o.page;
    const start = Date.now();
    const deadline = start + this.stepTimeoutMs;
    let clicked = false;
    let goneSince: number | null = null;
    let challengeSince: number | null = null;
    await page.waitForLoadState('domcontentloaded', { timeout: 2_000 }).catch(() => {});
    while (Date.now() < deadline) {
      if (page.isClosed() || !this.onUrlOrigin()) return null;
      if (!this.onOrigin()) {
        await sleep(200);
        continue;
      }
      const stillThere = await anyVisible(filled);
      const det = await detectStep(page, this.o.domain).catch(() => ({ kind: 'none' }) as const);
      if (det.kind === 'step') {
        const k = det.step.kind;
        const allowed =
          (k === 'password' && !done.has('password')) ||
          (k === 'otp' && !done.has('otp') && item.has_totp === 1);
        if (allowed) return det.step;
        if (!stillThere && (done.has(k) || k === 'otp')) throw new RepeatedStep();
      }
      if (!stillThere) {
        goneSince ??= Date.now();
        challengeSince = null;
        if (Date.now() - goneSince >= 750) return null;
      } else {
        goneSince = null;
        const hc = await this.checkHuman();
        if (hc) {
          challengeSince ??= Date.now();
          if (Date.now() - challengeSince >= CHALLENGE_SHOWN_MS)
            throw new ChallengeShown(hc.provider);
        } else {
          challengeSince = null;
          if (!clicked && Date.now() - start >= SUBMIT_CLICK_AFTER_MS) {
            clicked = true;
            await this.clickSubmit(submitted);
          }
        }
      }
      await sleep(200);
    }
    throw new RepeatedStep();
  }

  private async clickSubmit(field: PwLocator): Promise<void> {
    try {
      const button = await this.submitButton(field);
      if (!button || !this.onOrigin()) return;
      await button.click({ timeout: this.actionTimeoutMs });
    } catch {}
  }

  private async clear(secrets: string[], filled: ElementHandle[]): Promise<void> {
    if (secrets.length === 0) return;
    const page = this.o.page;
    if (page.isClosed()) return;
    const holds = (v: string) => secrets.includes(v);
    for (const h of filled) {
      const v = await h.inputValue({ timeout: 1000 }).catch(() => null);
      if (v !== null && holds(v)) await h.fill('', { timeout: 1000 }).catch(() => {});
    }
    const inputs = page.locator('css=input, textarea');
    const n = Math.min(await inputs.count().catch(() => 0), MAX_SCANNED_INPUTS);
    for (let i = 0; i < n; i++) {
      const el = inputs.nth(i);
      const v = await el.inputValue({ timeout: 1000 }).catch(() => null);
      if (v !== null && v.length > 0 && secrets.some((s) => v.includes(s))) {
        await el.fill('', { timeout: 1000 }).catch(() => {});
      }
    }
  }
}

class RepeatedStep extends Error {}

class ChallengeShown extends Error {
  readonly provider: string;
  constructor(provider: string) {
    super('challenge');
    this.provider = provider;
  }
}

async function anyVisible(handles: ElementHandle[]): Promise<boolean> {
  for (const h of handles) {
    if (await h.isVisible().catch(() => false)) return true;
  }
  return false;
}
