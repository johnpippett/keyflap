import type { AddressState } from '@aab/signer/approver-address';
import {
  type AddressFixes,
  type AddressWords,
  addressRefusalLines,
  addressWords,
  serveFor,
} from '../approver-address.ts';
import { parseJsonFile } from '../setup/claude-config.ts';
import type { System } from '../setup/system.ts';
import { serveResetCommand } from '../setup/tailscale.ts';
import type { ServiceManager } from './manager.ts';
import type { ServicePaths } from './paths.ts';

export interface ServiceAddress {
  origin: string;
  target: string;
}

export function serviceAddress(sys: System, paths: ServicePaths): ServiceAddress | null {
  const cfg = parseJsonFile(sys.readFile(paths.signerConfig)) as {
    approverAddress?: { origin?: unknown; target?: unknown };
  } | null;
  const a = cfg?.approverAddress;
  return typeof a?.origin === 'string' && typeof a.target === 'string'
    ? { origin: a.origin, target: a.target }
    : null;
}

export function serviceAddressFixes(
  sys: System,
  m: ServiceManager,
  address: ServiceAddress,
): AddressFixes {
  const sudo = m.kind === 'launchd' ? '' : 'sudo ';
  return {
    serve: `${sudo}${serveFor(sys, address, true)}`,
    reset: `${sudo}${serveResetCommand(sys, true)}`,
    pair: 'sudo keyflap approver pair',
    reinstall:
      m.kind === 'launchd'
        ? `re-run ${m.installer} with the same options: it lets the signer read Tailscale's setting. It needs the standalone Tailscale app (tailscale.com/download) or tailscaled; the App Store app can't be read`
        : `install Tailscale at a root-only path (/usr/bin/tailscale), then re-run ${m.installer} with --tailscale-bin /usr/bin/tailscale`,
    startTailscale:
      m.kind === 'launchd'
        ? 'start Tailscale (open the Tailscale app and connect), then sudo keyflap doctor'
        : 'start Tailscale (tailscale up), then sudo keyflap doctor',
  };
}

export function serviceAddressWords(
  state: AddressState,
  o: { sys: System; m: ServiceManager; paths: ServicePaths },
): AddressWords {
  const address = serviceAddress(o.sys, o.paths) ?? { origin: '?', target: '?' };
  return addressWords(state, address, () => serviceAddressFixes(o.sys, o.m, address));
}

export function addressRefusalText(
  state: Extract<AddressState, { kind: 'latched' | 'paused' }>,
  o: { sys: System; m: ServiceManager; paths: ServicePaths },
): string {
  return addressRefusalLines(serviceAddressWords(state, o));
}

export async function clearApproverAddress(
  admin: <T>(socket: string, op: string) => Promise<T>,
  paths: ServicePaths,
): Promise<AddressState> {
  const { state } = await admin<{ state: AddressState }>(
    paths.signerAdminSocket,
    'approver.address.clear',
  );
  return state;
}
