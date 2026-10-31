#!/usr/bin/env node
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.env.KEYFLAP_FAKE_TAILSCALE_DIR ?? '';
const argv = process.argv.slice(2);
const ANSWERS: Record<string, string> = {
  'serve status --json': 'serve.json',
  'status --json --peers=false': 'status.json',
};

appendFileSync(
  join(dir, 'calls.jsonl'),
  `${JSON.stringify({ argv, env: Object.keys(process.env).sort() })}\n`,
);
const readsServe = argv[0] === 'serve';
const sentinel = (name: string) => existsSync(join(dir, name));
if (readsServe && sentinel('hang')) setInterval(() => {}, 1_000);
else main();

function main(): void {
  if (sentinel('down')) {
    process.stderr.write(
      `Failed to connect to local Tailscale daemon for /localapi/v0/${argv[0] === 'status' ? 'status' : 'serve-config'}; not running? Error: dial unix /var/run/tailscale/tailscaled.sock: connect: no such file or directory\n`,
    );
    process.exit(1);
  }
  if (readsServe && sentinel('fail')) {
    process.stderr.write('getting serve config: 500 Internal Server Error: backend error\n');
    process.exit(1);
  }
  if (readsServe && sentinel('garbage')) {
    process.stdout.write('this is not json\n');
    process.exit(0);
  }
  const file = ANSWERS[argv.join(' ')];
  if (file === undefined) {
    process.stderr.write(`this fake does not answer "${argv.join(' ')}"\n`);
    process.exit(2);
  }
  process.stdout.write(readFileSync(join(dir, file), 'utf8'), () => process.exit(0));
}
