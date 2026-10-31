import {
  type AddressState,
  type ApproverAddress,
  addressPhase,
  PAUSE_DETAIL,
  plainText,
  type ServeVerdict,
  UNREADABLE_DETAIL,
} from '@aab/signer/approver-address';
import type { System } from './setup/system.ts';
import { serveCommand, serveResetCommand, tailscaleBin } from './setup/tailscale.ts';

export function isTailnetOrigin(origin: string): boolean {
  return new URL(origin).hostname.endsWith('.ts.net');
}

export function listenTarget(listen: { host: string; port: number }): string {
  const host = listen.host.includes(':') ? `[${listen.host}]` : listen.host;
  return `http://${host}:${listen.port}`;
}

export function devApproverAddress(
  origin: string,
  listen: { host: string; port: number },
  sys: System,
): ApproverAddress | undefined {
  if (!isTailnetOrigin(origin)) return undefined;
  const bin = tailscaleBin(sys);
  return {
    origin,
    target: listenTarget(listen),
    ...(bin ? { tailscale: { via: 'cli', bin } } : {}),
  };
}

export const APPROVALS_OFF = 'Approvals are off until it is fixed at this computer.';

export function addressRefusalLines(words: AddressWords): string {
  return [
    `the approval address is ${words.line}.`,
    ...(words.approvalsOff ? [`  ${words.approvalsOff}`] : []),
    `  fix: ${words.fix}`,
  ].join('\n');
}

export interface AddressFixes {
  serve: string;
  reset: string;
  pair: string;
  reinstall: string;
  startTailscale: string;
}

export function pausedFix(detail: string, f: AddressFixes): string {
  if (
    detail === UNREADABLE_DETAIL.noCli ||
    detail === UNREADABLE_DETAIL.cannotRun ||
    detail === UNREADABLE_DETAIL.tokenUnreadable ||
    detail.startsWith(UNREADABLE_DETAIL.notTrusted)
  ) {
    return f.reinstall;
  }
  return f.startTailscale;
}

export interface AddressWords {
  line: string;
  fix: string | null;
  approvalsOff: string | null;
}

const WAIT_FIX = 'wait a moment: approvals resume by themselves once Tailscale answers';

const SHOWN_MAX = 160;
const shown = (s: string) => plainText(s, SHOWN_MAX);

function waitingFor(detail: string): string {
  if (detail === PAUSE_DETAIL.offline) return `${PAUSE_DETAIL.offline} yet`;
  if (detail === UNREADABLE_DETAIL.notRunning) return detail;
  return 'Tailscale is not answering yet';
}

function wrongFix(seen: string, f: AddressFixes): string {
  const reset = servedOnlyByProxy(seen)
    ? ''
    : `${f.reset} (it clears every serve setting on this computer), then `;
  return `${reset}${f.serve}, then ${f.pair}`;
}

function sinceTrip(
  latest: ServeVerdict | undefined,
  seen: string,
  f: AddressFixes,
): { now: string; fix: string } {
  switch (latest?.kind) {
    case 'ok':
      return {
        now: '. It is right again now',
        fix: `pair your phone again to turn approvals back on: ${f.pair}`,
      };
    case 'mismatch':
      return {
        now: latest.seen === seen ? '. It is still wrong' : `. Now: ${shown(latest.seen)}`,
        fix: wrongFix(latest.seen, f),
      };
    case 'offline':
      return { now: `. Now ${PAUSE_DETAIL.offline}`, fix: wrongFix(seen, f) };
    case 'unreadable':
      return { now: `. Now it can't be read: ${shown(latest.detail)}`, fix: wrongFix(seen, f) };
    case undefined:
      return { now: '', fix: wrongFix(seen, f) };
  }
}

export function addressWords(
  state: AddressState,
  address: { origin: string; target: string },
  fixes: () => AddressFixes,
  now: number = Date.now(),
): AddressWords {
  switch (state.kind) {
    case 'ok':
      return {
        line: `ok (${address.origin} -> ${address.target}, watched)`,
        fix: null,
        approvalsOff: null,
      };
    case 'latched': {
      const after = sinceTrip(state.latest?.verdict, state.seen, fixes());
      return {
        line: `off: it was changed at ${new Date(state.at).toISOString()} (${shown(state.seen)}), so phones were signed out to be safe${after.now}`,
        fix: after.fix,
        approvalsOff: APPROVALS_OFF,
      };
    }
    case 'paused':
      if (addressPhase(state, now) === 'holding') {
        return {
          line: `waiting for Tailscale: ${waitingFor(state.detail)}`,
          fix: WAIT_FIX,
          approvalsOff: null,
        };
      }
      if (state.detail === PAUSE_DETAIL.offline) {
        return {
          line: `paused: ${PAUSE_DETAIL.offline}`,
          fix: fixes().startTailscale,
          approvalsOff: APPROVALS_OFF,
        };
      }
      return {
        line: `unreadable: ${shown(state.detail)}`,
        fix: pausedFix(state.detail, fixes()),
        approvalsOff: APPROVALS_OFF,
      };
    case 'unwatched':
      return { line: 'not watched (not a Tailscale name)', fix: null, approvalsOff: null };
  }
}

export interface AddressSummaryText {
  text: string;
  more: 'how' | 'why' | null;
}

export function addressSummary(state: AddressState, now: number = Date.now()): AddressSummaryText {
  switch (addressPhase(state, now)) {
    case 'ok':
      return { text: 'The approval address is watched and right.', more: null };
    case 'latched':
      return state.kind === 'latched' && state.latest?.verdict.kind === 'ok'
        ? {
            text: 'The address is right again, but phones were signed out: pair one again.',
            more: null,
          }
        : { text: 'The approval address changed, so phones were signed out.', more: 'how' };
    case 'holding':
      return {
        text: 'Waiting for Tailscale to answer: approvals resume by themselves.',
        more: null,
      };
    case 'paused':
      return state.kind === 'paused' && state.detail === PAUSE_DETAIL.offline
        ? { text: 'Tailscale is not connected, so approvals are paused.', more: 'why' }
        : { text: 'The approval address cannot be read right now.', more: 'why' };
    case 'unwatched':
      return { text: 'The approval address is not watched (not a Tailscale name).', more: null };
  }
}

function servedOnlyByProxy(seen: string): boolean {
  return seen.includes(' proxies to ') || seen.startsWith('nothing is served at ');
}

export function serveFor(
  sys: System,
  address: { origin: string; target: string },
  service: boolean,
): string {
  const port = Number(new URL(address.origin).port || 443);
  return serveCommand(sys, { service, port, target: address.target });
}

export function devAddressFixes(sys: System, address: { origin: string; target: string }) {
  return {
    serve: serveFor(sys, address, false),
    reset: serveResetCommand(sys, false),
    pair: `keyflap approver pair --approver-origin ${address.origin} (daemon stopped), then start the daemon again`,
    reinstall:
      'install Tailscale (tailscale.com/download) so `tailscale` is on your PATH, then start the daemon again',
    startTailscale: 'start Tailscale (tailscale up), then start the daemon again',
  } satisfies AddressFixes;
}
