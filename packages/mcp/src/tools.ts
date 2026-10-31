import { z } from 'zod';
import type { AgentBrowserPort, Locator } from './port.ts';

const MEDIUM = 2_000;

const exact = z.boolean().optional();

const locatorSchema = z.union([
  z.strictObject({
    role: z.string().min(1).max(64),
    name: z.string().max(MEDIUM).optional(),
    exact,
  }),
  z.strictObject({ text: z.string().min(1).max(MEDIUM), exact }),
  z.strictObject({ label: z.string().min(1).max(MEDIUM), exact }),
  z.strictObject({ placeholder: z.string().min(1).max(MEDIUM), exact }),
  z.strictObject({ css: z.string().min(1).max(MEDIUM) }),
]);

const timeoutMs = z.number().int().min(1_000).max(120_000).optional();

const LOCATOR_HELP =
  'Pick the element with exactly one of: {"role": "button", "name": "Sign in"} (ARIA role plus accessible name, preferred), ' +
  '{"text": "..."}, {"label": "..."} (form field by its label), {"placeholder": "..."}, or {"css": "..."} (plain CSS selector). ' +
  'Add "exact": true for exact (case-sensitive, whole-string) matching instead of substring matching.';

const OUTCOME_HELP =
  'Returns {"status": "success"} when the broker completed the sign-in (passkey ceremony done, or password form filled ' +
  'and submitted), {"status": "denied"} when the user (or broker policy) declined, {"status": "failed"} when the broker ' +
  'submitted a password form but the site kept showing it (e.g. it rejected the password) or asked for a ' +
  'one-time code the broker has no seed for, ' +
  '{"status": "challenge"} when the broker submitted the form and the site answered with a human check ' +
  '(a CAPTCHA or "confirm you are human" page): the broker will not solve it, and you must not try to; call ' +
  'browser_handoff to ask the user to complete it on their phone, then continue, ' +
  '{"status": "unsupported", "reason": ...} when there is no usable credential or the page is not eligible, or ' +
  '{"status": "timeout"} when the page did not start a passkey ceremony in time. Do not retry a denial or failure ' +
  'on your own; tell the user. Take a browser_snapshot afterwards to see where the site landed.';

interface ToolDef<S extends z.ZodType> {
  name: string;
  title: string;
  description: string;
  schema: S;
  run(port: AgentBrowserPort, args: z.infer<S>): Promise<unknown>;
}

function tool<S extends z.ZodType>(def: ToolDef<S>): ToolDef<z.ZodType> {
  return def as unknown as ToolDef<z.ZodType>;
}

export const TOOLS: readonly ToolDef<z.ZodType>[] = [
  tool({
    name: 'browser_open',
    title: 'Open URL',
    description:
      'Navigate your broker-managed browser tab to an http(s) URL and wait for it to load. ' +
      'Returns the resulting {url, title}. Other schemes (javascript:, data:, file:, ...) are refused. ' +
      'Use browser_snapshot to read the page.',
    schema: z.strictObject({ url: z.string().min(1).max(4096) }),
    run: (port, args) => port.open(args.url),
  }),
  tool({
    name: 'browser_click',
    title: 'Click element',
    description: `Click one element on the current page. ${LOCATOR_HELP} Returns the page {url, title} after the click. To sign in with a passkey, click the site's own "Sign in with a passkey" (or similar) button, then call auth_login.`,
    schema: z.strictObject({ target: locatorSchema }),
    run: (port, args) => port.click(args.target as Locator),
  }),
  tool({
    name: 'browser_type',
    title: 'Type into field',
    description: `Fill a text field on the current page with the given text (replacing its contents). ${LOCATOR_HELP} Set "submit": true to press Enter afterwards. Returns the page {url, title}. Never type passwords or one-time codes: you do not have them, and the broker signs in for you via auth_login.`,
    schema: z.strictObject({
      target: locatorSchema,
      text: z.string().max(10_000),
      submit: z.boolean().optional(),
    }),
    run: (port, args) =>
      args.submit === undefined
        ? port.type(args.target as Locator, args.text)
        : port.type(args.target as Locator, args.text, { submit: args.submit }),
  }),
  tool({
    name: 'browser_snapshot',
    title: 'Page snapshot',
    description:
      'Read the current page as an accessibility snapshot. Returns {url, title, snapshot, humanCheck}. ' +
      'Password and one-time-code fields are redacted. Use the roles and names in the snapshot to build locators. ' +
      'humanCheck is true when the broker detects a human check (CAPTCHA) on the page; never try to solve one, ' +
      'call browser_handoff instead.',
    schema: z.strictObject({}),
    run: (port) => port.snapshot(),
  }),
  tool({
    name: 'auth_status',
    title: 'Sign-in options',
    description:
      'Ask the broker what it could sign in with on the current page. Returns {origin, credentials, humanCheck}: the ' +
      'verified origin of the page (null if it is not eligible, e.g. not https), the credential types the broker holds ' +
      'for it (e.g. [{"type": "passkey"}]), and whether the page shows a human check (CAPTCHA) right now. Never ' +
      'returns secrets or account names.',
    schema: z.strictObject({}),
    run: (port) => port.authStatus(),
  }),
  tool({
    name: 'auth_login',
    title: 'Sign in',
    description:
      'Tell the broker you are at a login wall and let it sign in for you; it picks the method. Password sites: open the ' +
      'login page (the one with the username/email or password field, or the one-time-code page) and call auth_login; ' +
      'the broker fills and submits the form itself, including a following password or one-time-code step. Do not type ' +
      "the username, password or code yourself. Passkey sites: click the site's passkey / sign-in button (browser_click), " +
      "then call auth_login; the broker waits for the page's passkey request (up to timeoutMs, default 30000, max 120000; " +
      'a request that already started counts). Either way the user approves on their own device first, and you never see ' +
      'or handle credentials. ' +
      OUTCOME_HELP,
    schema: z.strictObject({ timeoutMs }),
    run: (port, args) =>
      args.timeoutMs === undefined
        ? port.authLogin()
        : port.authLogin({ timeoutMs: args.timeoutMs }),
  }),
  tool({
    name: 'auth_enroll_passkey',
    title: 'Add a passkey',
    description:
      'Let the broker register its own passkey with the site. Use on the site\'s "add a passkey" / security settings ' +
      'page: click the button that creates a passkey (browser_click), then call auth_enroll_passkey. The broker waits for ' +
      "the page's passkey registration request (up to timeoutMs, default 30000, max 120000), asks the user to approve on " +
      'their own device, and creates the passkey; the private key never leaves the broker. ' +
      OUTCOME_HELP,
    schema: z.strictObject({ timeoutMs }),
    run: (port, args) =>
      args.timeoutMs === undefined
        ? port.authEnrollPasskey()
        : port.authEnrollPasskey({ timeoutMs: args.timeoutMs }),
  }),
  tool({
    name: 'browser_handoff',
    title: 'Ask the user to pass a human check',
    description:
      'When the page shows a human check (auth_login returned {"status": "challenge"}, or humanCheck is true), ask ' +
      'the user to complete it themselves: the broker notifies their paired phone, which shows a live view of this ' +
      'page only. Never try to solve a check yourself. The call waits up to timeoutMs (default 45000, 1000 to ' +
      '120000) and returns {"status": "done"} (the user finished; continue with browser_snapshot, and call ' +
      'auth_login if the page is a sign-in page: the user may already have approved it), "cancelled", ' +
      '"expired" (the broker ends a handoff after 5 minutes), "pending" (still open: call browser_handoff again to ' +
      'keep waiting), "denied" (not allowed now, e.g. no recent request from the user or too many handoffs), or ' +
      '{"status": "unsupported", "reason": ...} (no phone approver, no eligible page, or no human check detected). ' +
      'While a handoff is open every other tool fails; you never see what the user sees or types.',
    schema: z.strictObject({ timeoutMs }),
    run: (port, args) =>
      args.timeoutMs === undefined ? port.handoff() : port.handoff({ timeoutMs: args.timeoutMs }),
  }),
];

export const TOOL_NAMES: readonly string[] = Object.freeze(TOOLS.map((t) => t.name));

export function findTool(name: string): ToolDef<z.ZodType> | undefined {
  return TOOLS.find((t) => t.name === name);
}

export function inputJsonSchema(def: ToolDef<z.ZodType>): {
  type: 'object';
  [k: string]: unknown;
} {
  const { $schema: _ignored, ...schema } = z.toJSONSchema(def.schema) as Record<string, unknown>;
  return { ...schema, type: 'object' };
}
