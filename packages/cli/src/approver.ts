import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { encodeQr, renderQrTerminal } from '@aab/approver';
import { withItemSigner } from '@aab/core';
import type { NativeApproverKey, WebAuthnApproverKey } from '@aab/signer/approval';
import type { ApproverAddress } from '@aab/signer/approver-address';
import {
  addressRefusalLines,
  addressWords,
  devAddressFixes,
  devApproverAddress,
} from './approver-address.ts';
import type { DevPairPhone } from './args.ts';
import { getPassphrase } from './daemon.ts';
import type { Unlock } from './passphrase.ts';
import { realSystem } from './setup/system.ts';

type Out = (text: string) => void;

export class ApproverCliError extends Error {}

async function withSigner<T>(
  dataDir: string,
  fn: (s: Parameters<Parameters<typeof withItemSigner>[2]>[0]) => Promise<T>,
  approverAdmin = false,
  approverAddress?: ApproverAddress,
  unlock: Unlock = () => getPassphrase(dataDir),
): Promise<T> {
  const passphrase = await unlock();
  return withItemSigner(dataDir, passphrase, fn, {
    approverAdmin,
    ...(approverAddress ? { approverAddress } : {}),
  });
}

const START_DAEMON =
  'Start the daemon (keyflap daemon --unprotected --approver phone …): it offers pairing.';

export async function approverPair(
  opts: { dataDir: string; phone: DevPairPhone },
  out: Out,
): Promise<void> {
  const sys = realSystem();
  const address = devApproverAddress(opts.phone.origin, opts.phone.listen, sys);
  if (!address) {
    out(
      `Approval address: not watched (not a Tailscale name), nothing to re-check.\n${START_DAEMON}\n`,
    );
    return;
  }
  const { state } = await withSigner(opts.dataDir, (s) => s.clearApproverAddress(), true, address);
  const words = addressWords(state, address, () => devAddressFixes(sys, address));
  if (state.kind === 'latched' || state.kind === 'paused') {
    throw new ApproverCliError(addressRefusalLines(words));
  }
  out(`Approval address: ${words.line}\n${START_DAEMON}\n`);
}

export async function approverList(
  opts: { dataDir: string; json: boolean; unlock?: Unlock },
  out: Out,
): Promise<{ approvers: WebAuthnApproverKey[]; native: NativeApproverKey[] }> {
  const { approvers, native = [] } = await withSigner(
    opts.dataDir,
    (s) => s.listApprovers(),
    false,
    undefined,
    opts.unlock,
  );
  const items = [
    ...approvers.map((a) => ({
      id: a.credentialId,
      type: 'passkey',
      origin: a.origin,
      createdAt: a.createdAt,
    })),
    ...native.map((a) => ({
      id: a.keyId,
      type: 'ios-app',
      origin: a.origin,
      createdAt: a.createdAt,
    })),
  ];
  if (opts.json) {
    out(`${JSON.stringify(items, null, 2)}\n`);
  } else if (items.length === 0) {
    out('No phone approvers. Start the daemon with --approver phone to pair one.\n');
  } else {
    for (const i of items) {
      out(`${i.id}  ${i.type.padEnd(7)}  ${i.origin}  ${new Date(i.createdAt).toISOString()}\n`);
    }
  }
  return { approvers, native };
}

export function approverQr(opts: { dataDir: string }, out: Out): void {
  const file = join(opts.dataDir, 'approver', 'pairing-url');
  if (!existsSync(file)) {
    throw new ApproverCliError(
      'no pairing link is open: start the daemon with --approver phone (add --pair for another phone)',
    );
  }
  const url = readFileSync(file, 'utf8').trim();
  out(`${renderQrTerminal(encodeQr(url), process.stdout)}\n`);
  out('Point your iPhone camera at this (it opens in Safari), or open the link on your phone:\n');
  out(`  ${url}\n`);
  out(
    'Pair in Safari first, then Share > Add to Home Screen: iOS copies the pairing into the\n' +
      'home-screen app only when you add it.\n',
  );
}

export async function approverRemove(
  opts: { dataDir: string; id: string; unlock?: Unlock },
  out: Out,
) {
  const { removed } = await withSigner(
    opts.dataDir,
    (s) => s.removeApprover(opts.id),
    true,
    undefined,
    opts.unlock,
  );
  if (!removed) throw new ApproverCliError(`no phone approver with id ${opts.id}`);
  out(
    `Removed phone approver ${opts.id}. Its device can no longer approve.` +
      ' With no phone left, the next `keyflap daemon --approver phone` offers pairing again.\n',
  );
}
