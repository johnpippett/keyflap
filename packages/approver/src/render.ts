import { plainStyle, type TermStyle } from './term-style.ts';
import type { ApprovalRequest } from './types.ts';

function clean(s: string): string {
  return s.replace(
    // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping them is the point
    /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    '\ufffd',
  );
}

const CREDENTIAL_LABELS: Record<ApprovalRequest['display']['credentialType'], string> = {
  passkey: 'passkey',
  password: 'password',
  'password+totp': 'password + one-time code',
  totp: 'one-time code',
};

export function formatDuration(ms: number): string {
  const unit = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;
  const s = Math.round(ms / 1000);
  if (s < 60) return unit(s, 'second');
  const m = Math.round(s / 60);
  if (m < 60) return unit(m, 'minute');
  const h = Math.floor(m / 60);
  const rest = m % 60;
  return rest === 0 ? unit(h, 'hour') : `${unit(h, 'hour')} ${unit(rest, 'minute')}`;
}

export function allowForText(ms: number): string {
  return `approving also lets this agent sign in here again without asking, for ${formatDuration(ms)}`;
}

export function handoffSignInTitle(verifiedOrigin: string): string {
  let host = verifiedOrigin;
  try {
    host = new URL(verifiedOrigin).host;
  } catch {}
  return `Human check, then sign in to ${host}`;
}
export function handoffSignInText(ms: number): string {
  return `One sign-in within ${formatDuration(ms)}, without asking again. Approving opens a live view of the website on this phone.`;
}

export function renderPrompt(req: ApprovalRequest, style: TermStyle = plainStyle): string {
  const d = req.display;
  const when = new Date(d.intentAt).toISOString();
  const bar = style.dim('│');
  const field = (label: string, value: string) => `${bar} ${style.dim(label)}${value}`;
  return [
    '',
    style.level === 0
      ? '┌─ KEYFLAP · approval requested ──────────────────────────'
      : `${style.dim('┌─')} ${style.header('approval requested')} ${style.dim('─'.repeat(31))}`,
    field(`You said (${when}):`, ''),
    ...clean(d.intentText)
      .split('\n')
      .map((l) => `${bar}   ${style.bold(`"${l}"`)}`),
    field('Site:       ', style.ok(clean(d.verifiedOrigin))),
    field('Agent:      ', clean(d.agentName)),
    field('Credential: ', `${CREDENTIAL_LABELS[d.credentialType] ?? '?'} (${d.action})`),
    ...(typeof d.allowForMs === 'number'
      ? [field('Allow-for:  ', allowForText(d.allowForMs))]
      : []),
    ...(d.handoffSignIn
      ? [
          field('Then:       ', clean(handoffSignInTitle(d.verifiedOrigin))),
          field('            ', handoffSignInText(d.handoffSignIn.withinMs)),
        ]
      : []),
    style.dim('└──────────────────────────────────────────────────────────'),
    `${style.head('Approve?')} ${style.dim('[y/N]')} `,
  ].join('\n');
}
