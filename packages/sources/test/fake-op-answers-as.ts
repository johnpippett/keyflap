#!/usr/bin/env node
interface Substitute {
  vaultId?: string;
  itemId?: string;
}

const raw = process.env.KEYFLAP_FAKE_ANSWER_AS;
const at = process.argv.indexOf('get');
if (raw && at > 0 && process.argv[at - 1] === 'item') {
  const swap = JSON.parse(raw) as Substitute;
  process.argv = process.argv.map((arg, i) => {
    if (i === at + 1 && swap.itemId !== undefined) return swap.itemId;
    if (arg.startsWith('--vault=') && swap.vaultId !== undefined) return `--vault=${swap.vaultId}`;
    return arg;
  });
}
await import('./fake-op.ts');
