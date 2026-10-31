#!/usr/bin/env node
interface Substitute {
  shareId?: string;
  itemId?: string;
}

const raw = process.env.KEYFLAP_FAKE_ANSWER_AS;
if (raw && process.argv.includes('view')) {
  const swap = JSON.parse(raw) as Substitute;
  process.argv = process.argv.map((arg) => {
    if (arg.startsWith('--share-id=') && swap.shareId !== undefined) {
      return `--share-id=${swap.shareId}`;
    }
    if (arg.startsWith('--item-id=') && swap.itemId !== undefined) {
      return `--item-id=${swap.itemId}`;
    }
    return arg;
  });
}
await import('./fake-pass-cli.ts');
