import { type AddressPhase, type AddressState, addressPhase } from '@aab/signer/approver-address';
import { type AddressSummaryText, addressSummary } from '../approver-address.ts';

export interface AddressSummary {
  phase: AddressPhase;
  summary: AddressSummaryText;
  line: string;
  fix: string | null;
}

export interface Snapshot {
  phones: number;
  agents: number;
  passwords: number;
  passwordSource: string | null;
  address: AddressSummary | null;
}

export type AddressWords = (state: AddressState) => { line: string; fix: string | null };

export class StatusShapeError extends Error {}

const ADDRESS_KINDS = new Set(['unwatched', 'ok', 'paused', 'latched']);

function count(v: unknown, what: string): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
    throw new StatusShapeError(`the status has no ${what} count`);
  }
  return v;
}

export function parseStatus(text: string, words: AddressWords): Snapshot {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new StatusShapeError('the status is not JSON');
  }
  const service = (json as { service?: { core?: unknown; signer?: unknown } } | null)?.service;
  const core = (service?.core ?? {}) as Record<string, unknown>;
  const signer = (service?.signer ?? {}) as Record<string, unknown>;
  const raw = signer.address as { kind?: unknown } | undefined;
  const state: AddressState =
    raw && typeof raw.kind === 'string' && ADDRESS_KINDS.has(raw.kind)
      ? (raw as AddressState)
      : { kind: 'unwatched' };
  const source = core.passwordSource;
  const w = words(state);
  return {
    phones: count(signer.approvers, 'phone'),
    agents: count(core.agents, 'agent'),
    passwords: count(core.passwords, 'password'),
    passwordSource: typeof source === 'string' ? source : null,
    address: {
      phase: addressPhase(state, Date.now()),
      summary: addressSummary(state),
      line: w.line,
      fix: w.fix,
    },
  };
}

export function sourceName(kind: string): string {
  if (kind === 'proton-pass') return 'Proton Pass';
  if (kind === '1password') return '1Password';
  return kind;
}

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`;

const ADDRESS_MARK: Readonly<Record<AddressPhase, string>> = {
  ok: '✓ ',
  latched: '✗ ',
  holding: '! ',
  paused: '! ',
  unwatched: '',
};

function addressLine(a: AddressSummary): string {
  const more = a.summary.more ? ` Tab shows ${a.summary.more}.` : '';
  return `${ADDRESS_MARK[a.phase]}${a.summary.text}${more}`;
}

export function overview(s: Snapshot): { short: string; full: string } {
  const phones =
    s.phones === 0
      ? '! No phone paired: nothing can be approved. Phones, then Pair a phone.'
      : `✓ ${plural(s.phones, 'phone')} paired.`;
  const counts = [
    plural(s.agents, 'agent'),
    plural(s.passwords, 'password'),
    ...(s.passwordSource ? [sourceName(s.passwordSource)] : []),
  ].join(' · ');
  return {
    short: [phones, ...(s.address ? [addressLine(s.address)] : []), counts].join('\n'),
    full: [
      `Phones:      ${s.phones} paired`,
      ...(s.address
        ? [
            `Address:     ${s.address.line}`,
            ...(s.address.fix ? [`             fix: ${s.address.fix}`] : []),
          ]
        : []),
      `Agents:      ${s.agents}`,
      `Passwords:   ${s.passwords}${s.passwordSource ? ` (and ${sourceName(s.passwordSource)})` : ''}`,
    ].join('\n'),
  };
}
