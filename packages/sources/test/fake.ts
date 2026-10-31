import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FakeOpAccount, FakeOpItem } from './fake-op.ts';
import type { FakeItem, FakeVaultFile } from './fake-pass-cli.ts';

export type { FakeItem, FakeOpAccount, FakeOpItem, FakeVaultFile };

export const FAKE_PASS_CLI = fileURLToPath(new URL('./fake-pass-cli.ts', import.meta.url));

export interface FakeCall {
  argv: string[];
  reason: string | null;
  env: string[];
}

export interface FakePassCli {
  bin: string;
  dir: string;
  env: Record<string, string>;
  write(data: FakeVaultFile): void;
  update(fn: (data: FakeVaultFile) => void): void;
  calls(): FakeCall[];
}

export function fakePassCli(data: FakeVaultFile): FakePassCli {
  const dir = mkdtempSync(join(tmpdir(), 'keyflap-fake-pass-'));
  const file = join(dir, 'vault.json');
  const write = (d: FakeVaultFile) => writeFileSync(file, JSON.stringify(d));
  write(data);
  writeFileSync(join(dir, 'calls.jsonl'), '');
  return {
    bin: FAKE_PASS_CLI,
    dir,
    env: { PROTON_PASS_SESSION_DIR: dir },
    write,
    update(fn) {
      const d = JSON.parse(readFileSync(file, 'utf8')) as FakeVaultFile;
      fn(d);
      write(d);
    },
    calls: () =>
      readFileSync(join(dir, 'calls.jsonl'), 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as FakeCall),
  };
}

export const FAKE_OP = fileURLToPath(new URL('./fake-op.ts', import.meta.url));

export interface FakeOpCall {
  argv: string[];
  env: string[];
}

export interface FakeOp {
  bin: string;
  dir: string;
  env: Record<string, string>;
  write(data: FakeOpAccount): void;
  update(fn: (data: FakeOpAccount) => void): void;
  calls(): FakeOpCall[];
}

export function fakeOp(data: FakeOpAccount): FakeOp {
  const dir = mkdtempSync(join(tmpdir(), 'keyflap-fake-op-'));
  const file = join(dir, 'account.json');
  const write = (d: FakeOpAccount) => writeFileSync(file, JSON.stringify(d));
  write(data);
  writeFileSync(join(dir, 'calls.jsonl'), '');
  return {
    bin: FAKE_OP,
    dir,
    env: { KEYFLAP_FAKE_OP_DIR: dir, OP_SERVICE_ACCOUNT_TOKEN: data.token },
    write,
    update(fn) {
      const d = JSON.parse(readFileSync(file, 'utf8')) as FakeOpAccount;
      fn(d);
      write(d);
    },
    calls: () =>
      readFileSync(join(dir, 'calls.jsonl'), 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as FakeOpCall),
  };
}

export const FAKE_TAILSCALE = fileURLToPath(new URL('./fake-tailscale.ts', import.meta.url));

export type FakeTailscaleSentinel = 'hang' | 'fail' | 'down' | 'garbage';

export interface FakeTailscale {
  bin: string;
  dir: string;
  env: Record<string, string>;
  serve(config: unknown): void;
  serveRaw(text: string): void;
  status(status: unknown): void;
  statusRaw(text: string): void;
  set(sentinel: FakeTailscaleSentinel, on: boolean): void;
  calls(): FakeOpCall[];
}

export function serveConfig(o: { host: string; port: number; target: string }): unknown {
  return {
    TCP: { [String(o.port)]: { HTTPS: true } },
    Web: { [`${o.host}:${o.port}`]: { Handlers: { '/': { Proxy: o.target } } } },
  };
}

export function tailscaleStatus(o: { onTailnet: boolean }): unknown {
  return o.onTailnet
    ? {
        BackendState: 'Running',
        TailscaleIPs: ['100.101.102.103'],
        Self: { InNetworkMap: true, Online: true },
      }
    : { BackendState: 'NoState', TailscaleIPs: null, Self: { InNetworkMap: false, Online: false } };
}

export function fakeTailscale(
  config: unknown,
  status: unknown = tailscaleStatus({ onTailnet: true }),
): FakeTailscale {
  const dir = mkdtempSync(join(tmpdir(), 'keyflap-fake-tailscale-'));
  const file = join(dir, 'serve.json');
  const serveRaw = (text: string) => writeFileSync(file, text);
  serveRaw(JSON.stringify(config));
  const statusRaw = (text: string) => writeFileSync(join(dir, 'status.json'), text);
  statusRaw(JSON.stringify(status));
  writeFileSync(join(dir, 'calls.jsonl'), '');
  return {
    bin: FAKE_TAILSCALE,
    dir,
    env: { KEYFLAP_FAKE_TAILSCALE_DIR: dir },
    serve: (c) => serveRaw(JSON.stringify(c)),
    serveRaw,
    status: (st) => statusRaw(JSON.stringify(st)),
    statusRaw,
    set(sentinel, on) {
      if (on) writeFileSync(join(dir, sentinel), '');
      else rmSync(join(dir, sentinel), { force: true });
    },
    calls: () =>
      readFileSync(join(dir, 'calls.jsonl'), 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as FakeOpCall),
  };
}
