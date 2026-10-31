import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { checkTool, checkToolLocation } from '@aab/sources';
import {
  type FakeTailscale,
  fakeTailscale,
  serveConfig,
  tailscaleStatus,
} from '@aab/sources/testing';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type ApprovalStatement,
  approverDescriptor,
  type GrantedApproval,
  type SignedApproval,
  sha256B64url,
} from '../src/approval.ts';
import {
  type AddressState,
  type ApproverAddress,
  addressPhase,
  compareServeConfig,
  GRACE_WINDOW_MS,
  nextAddressState,
  parseApproverAddress,
  type ServeConfigVerdict,
  type ServeVerdict,
  TAILSCALE_TOOL,
  tailnetPresence,
  type WatchedAddressState,
} from '../src/approver-address.ts';
import { SignerDenied, type SpawnedSigner, spawnSigner } from '../src/client.ts';
import {
  authData,
  clientData,
  statement,
  testApprover,
  testNativePhone,
  testPhone,
  tmpDir,
} from './helpers.ts';

const HOST = 'mac.tail1234.ts.net';
const PORT = 8766;
const TARGET = 'http://127.0.0.1:8766';
const EXPECTED = { host: HOST, port: PORT, target: TARGET };
const KEY = `${HOST}:${PORT}`;

const measuredOnTheMac = {
  TCP: { '8766': { HTTPS: true } },
  Web: { [KEY]: { Handlers: { '/': { Proxy: TARGET } } } },
};

function withWeb(entry: unknown, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ ...measuredOnTheMac, Web: { [KEY]: entry }, ...extra });
}

describe('invariant 5 (the approval address): compareServeConfig is exact', () => {
  const table: [string, string, ServeConfigVerdict][] = [
    ['the measured Mac config', JSON.stringify(measuredOnTheMac), { kind: 'ok' }],
    [
      'a trailing slash on the proxy',
      withWeb({ Handlers: { '/': { Proxy: `${TARGET}/` } } }),
      { kind: 'ok' },
    ],
    [
      'unknown top-level keys (Tailscale adds fields)',
      JSON.stringify({ ...measuredOnTheMac, ETag: 'abc', Services: {} }),
      { kind: 'ok' },
    ],
    [
      'an empty serve config (harmless only off the tailnet: see tailnetPresence)',
      '{}',
      { kind: 'empty' },
    ],
    ['null (what tailscaled answers before it has a netmap)', 'null', { kind: 'empty' }],
    ['empty Web and TCP maps', JSON.stringify({ TCP: {}, Web: {} }), { kind: 'empty' }],
    [
      'only another port of the same name served (nothing at ours: latches while on the tailnet)',
      JSON.stringify({
        TCP: { '443': { HTTPS: true } },
        Web: { [`${HOST}:443`]: { Handlers: { '/': { Proxy: 'http://127.0.0.1:3000' } } } },
      }),
      { kind: 'empty' },
    ],
    [
      'HTTPS on the port without a web handler (partial)',
      JSON.stringify({ TCP: measuredOnTheMac.TCP }),
      { kind: 'mismatch', seen: `${PORT} is in use, but not for ${KEY}` },
    ],
    [
      'Funnel for the address with nothing else',
      JSON.stringify({ AllowFunnel: { [KEY]: true } }),
      { kind: 'mismatch', seen: `${KEY} is on Funnel` },
    ],
    [
      'Funnel set to false for the address with nothing else (still not nothing)',
      JSON.stringify({ AllowFunnel: { [KEY]: false } }),
      { kind: 'mismatch', seen: `${PORT} is in use, but not for ${KEY}` },
    ],
    [
      'only a foreground session on the port',
      JSON.stringify({ Foreground: { s1: { TCP: { '8766': { HTTPS: true } } } } }),
      { kind: 'mismatch', seen: 'a foreground serve session uses 8766' },
    ],
    [
      'another proxy target',
      withWeb({ Handlers: { '/': { Proxy: 'http://127.0.0.1:9999' } } }),
      { kind: 'mismatch', seen: `${KEY} proxies to "http://127.0.0.1:9999"` },
    ],
    [
      'localhost spelled differently (no normalisation)',
      withWeb({ Handlers: { '/': { Proxy: 'http://localhost:8766' } } }),
      { kind: 'mismatch', seen: `${KEY} proxies to "http://localhost:8766"` },
    ],
    [
      'a second handler path',
      withWeb({ Handlers: { '/': { Proxy: TARGET }, '/api': { Proxy: 'http://127.0.0.1:1' } } }),
      { kind: 'mismatch', seen: `${KEY} also handles "/api"` },
    ],
    [
      'a static path instead of a proxy',
      withWeb({ Handlers: { '/': { Path: '/srv/evil' } } }),
      { kind: 'mismatch', seen: `${KEY} / is not a plain proxy` },
    ],
    [
      'a proxy with an extra setting',
      withWeb({ Handlers: { '/': { Proxy: TARGET, Text: 'x' } } }),
      { kind: 'mismatch', seen: `${KEY} / is not a plain proxy` },
    ],
    [
      'an unknown key inside the web entry',
      withWeb({ Handlers: { '/': { Proxy: TARGET } }, Extra: true }),
      { kind: 'mismatch', seen: `${KEY} has an unexpected setting` },
    ],
    [
      'the port forwarded raw instead of terminated as HTTPS',
      JSON.stringify({ ...measuredOnTheMac, TCP: { '8766': { TCPForward: '127.0.0.1:8766' } } }),
      { kind: 'mismatch', seen: 'TCP 8766 is forwarded' },
    ],
    [
      'HTTPS plus a forward on the port',
      JSON.stringify({
        ...measuredOnTheMac,
        TCP: { '8766': { HTTPS: true, TCPForward: '127.0.0.1:1' } },
      }),
      { kind: 'mismatch', seen: 'TCP 8766 is forwarded' },
    ],
    [
      'no TCP entry for the port',
      JSON.stringify({ Web: measuredOnTheMac.Web }),
      { kind: 'mismatch', seen: 'TCP 8766 is not served' },
    ],
    [
      'another host name served on the same port',
      JSON.stringify({
        ...measuredOnTheMac,
        Web: { ...measuredOnTheMac.Web, [`other.ts.net:${PORT}`]: { Handlers: {} } },
      }),
      { kind: 'mismatch', seen: `"other.ts.net:${PORT}" is also served on ${PORT}` },
    ],
    [
      'Funnel on the approver address',
      JSON.stringify({ ...measuredOnTheMac, AllowFunnel: { [KEY]: true } }),
      { kind: 'mismatch', seen: `${KEY} is on Funnel` },
    ],
    [
      'a foreground session on the port',
      JSON.stringify({
        ...measuredOnTheMac,
        Foreground: { s1: { TCP: { '8766': { HTTPS: true } }, Web: {} } },
      }),
      { kind: 'mismatch', seen: 'a foreground serve session uses 8766' },
    ],
    [
      'a foreground session on another port',
      JSON.stringify({
        ...measuredOnTheMac,
        Foreground: { s1: { Web: { 'x.ts.net:9000': { Handlers: {} } } } },
      }),
      { kind: 'ok' },
    ],
    ['not JSON', 'this is not json', { kind: 'mismatch', seen: 'the serve setting is not JSON' }],
    ['empty output', '', { kind: 'mismatch', seen: 'the serve setting is not JSON' }],
    ['a JSON list', '[]', { kind: 'mismatch', seen: 'the serve setting is not a serve config' }],
    [
      'a JSON string',
      '"ok"',
      { kind: 'mismatch', seen: 'the serve setting is not a serve config' },
    ],
  ];
  for (const [name, json, verdict] of table) {
    it(`${name}: ${verdict.kind}`, () => {
      expect(compareServeConfig(json, EXPECTED)).toEqual(verdict);
    });
  }

  it('an https origin without a port is served on 443', () => {
    const cfg = JSON.stringify({
      TCP: { '443': { HTTPS: true } },
      Web: { 'h.ts.net:443': { Handlers: { '/': { Proxy: TARGET } } } },
    });
    expect(compareServeConfig(cfg, { host: 'h.ts.net', port: 443, target: TARGET })).toEqual({
      kind: 'ok',
    });
  });
});

describe('invariant 5 (the approval address): the state machine', () => {
  const T = 1_000;
  const G = 30;
  const ok: WatchedAddressState = { kind: 'ok', checkedAt: 1 };
  const paused: WatchedAddressState = { kind: 'paused', since: 2, detail: 'x' };
  const holding: WatchedAddressState = {
    kind: 'paused',
    since: 2,
    detail: 'Tailscale is not running',
    graceSince: 2,
    graceUntil: 2 + G,
  };
  const latched: WatchedAddressState = { kind: 'latched', at: 3, seen: 'y' };
  const good: ServeVerdict = { kind: 'ok' };
  const wrong: ServeVerdict = { kind: 'mismatch', seen: 'z' };
  const dark: ServeVerdict = { kind: 'unreadable', detail: 'w' };
  const down: ServeVerdict = { kind: 'unreadable', detail: 'Tailscale is not running' };
  const offline: ServeVerdict = { kind: 'offline' };
  const notConnected = 'Tailscale is not connected';
  const longAgo = T - GRACE_WINDOW_MS;
  const table: [string, WatchedAddressState, ServeVerdict, AddressState][] = [
    ['ok + ok stays ok with a fresh check time', ok, good, { kind: 'ok', checkedAt: T }],
    ['ok + mismatch latches', ok, wrong, { kind: 'latched', at: T, seen: 'z' }],
    ['ok + unreadable pauses, with no grace', ok, dark, { kind: 'paused', since: T, detail: 'w' }],
    [
      'ok + nothing served while off the tailnet pauses with a grace',
      ok,
      offline,
      { kind: 'paused', since: T, detail: notConnected, graceSince: T, graceUntil: T + G },
    ],
    [
      'ok + Tailscale not running pauses with a grace',
      ok,
      down,
      {
        kind: 'paused',
        since: T,
        detail: 'Tailscale is not running',
        graceSince: T,
        graceUntil: T + G,
      },
    ],
    [
      'ok soon after a grace + a restart cause gets only what is left of that grace',
      { kind: 'ok', checkedAt: T - 1, graceSince: T - 10 },
      offline,
      {
        kind: 'paused',
        since: T,
        detail: notConnected,
        graceSince: T - 10,
        graceUntil: T - 10 + G,
      },
    ],
    [
      'ok after a used-up grace + a restart cause gets none until the window has passed',
      { kind: 'ok', checkedAt: T - 1, graceSince: T - G },
      offline,
      { kind: 'paused', since: T, detail: notConnected, graceSince: T - G },
    ],
    [
      'ok long after a grace + a restart cause gets a fresh one',
      { kind: 'ok', checkedAt: T - 1, graceSince: longAgo },
      offline,
      { kind: 'paused', since: T, detail: notConnected, graceSince: T, graceUntil: T + G },
    ],
    ['paused + ok resumes', paused, good, { kind: 'ok', checkedAt: T }],
    [
      'holding + ok resumes, remembering when its grace began',
      holding,
      good,
      { kind: 'ok', checkedAt: T, graceSince: 2 },
    ],
    [
      'ok forgets a grace once the window has passed',
      { kind: 'ok', checkedAt: T - 1, graceSince: longAgo },
      good,
      { kind: 'ok', checkedAt: T },
    ],
    ['paused + mismatch latches', paused, wrong, { kind: 'latched', at: T, seen: 'z' }],
    ['holding + mismatch latches', holding, wrong, { kind: 'latched', at: T, seen: 'z' }],
    [
      'paused + unreadable keeps the pause start, takes the new detail',
      paused,
      dark,
      { kind: 'paused', since: 2, detail: 'w' },
    ],
    [
      'holding + off the tailnet keeps the start and the grace end',
      holding,
      offline,
      { kind: 'paused', since: 2, detail: notConnected, graceSince: 2, graceUntil: 2 + G },
    ],
    [
      'holding + a cause no restart explains drops the grace',
      holding,
      dark,
      { kind: 'paused', since: 2, detail: 'w', graceSince: 2 },
    ],
    [
      'paused without a grace + a restart cause gets none',
      paused,
      down,
      { kind: 'paused', since: 2, detail: 'Tailscale is not running' },
    ],
    [
      'latched + ok stays latched, noting the latest reading',
      latched,
      good,
      { ...latched, latest: { checkedAt: T, verdict: good } },
    ],
    [
      'latched + mismatch stays latched with the first seen',
      latched,
      wrong,
      { ...latched, latest: { checkedAt: T, verdict: wrong } },
    ],
    [
      'latched + unreadable stays latched',
      latched,
      dark,
      { ...latched, latest: { checkedAt: T, verdict: dark } },
    ],
    [
      'latched + off the tailnet stays latched',
      latched,
      offline,
      { ...latched, latest: { checkedAt: T, verdict: offline } },
    ],
  ];
  for (const [name, state, verdict, next] of table) {
    it(name, () => {
      expect(nextAddressState(state, verdict, T, G)).toEqual(next);
    });
  }

  it('the phase: a pause inside its grace is holding, after it a pause', () => {
    expect(addressPhase(holding, 2 + G - 1)).toBe('holding');
    expect(addressPhase(holding, 2 + G)).toBe('paused');
    expect(addressPhase(paused, 0)).toBe('paused');
    expect(addressPhase(ok, 0)).toBe('ok');
    expect(addressPhase(latched, 0)).toBe('latched');
    expect(addressPhase({ kind: 'unwatched' }, 0)).toBe('unwatched');
  });
});

describe('invariant 5 (the approval address): nothing served is harmless only while this machine is off the tailnet', () => {
  const statusUnreadable = {
    kind: 'unreadable',
    detail: "Tailscale's status cannot be read",
  } as const;
  const table: [string, unknown, ReturnType<typeof tailnetPresence>][] = [
    ['running with a netmap', tailscaleStatus({ onTailnet: true }), 'on'],
    ['just started, no netmap yet', tailscaleStatus({ onTailnet: false }), 'off'],
    [
      'starting before the netmap, empty address list',
      { BackendState: 'Starting', TailscaleIPs: [], Self: { InNetworkMap: false } },
      'off',
    ],
    [
      'stopped, netmap kept (counts as on: latching is the safe side)',
      { BackendState: 'Stopped', TailscaleIPs: ['100.1.2.3'], Self: { InNetworkMap: true } },
      'on',
    ],
    [
      'running with no netmap (tailscaled can keep Running then)',
      { BackendState: 'Running', TailscaleIPs: null, Self: { InNetworkMap: false } },
      'on',
    ],
    [
      'no netmap but addresses',
      { BackendState: 'NoState', TailscaleIPs: ['100.1.2.3'], Self: { InNetworkMap: false } },
      'on',
    ],
    [
      'addresses that are not a list',
      { BackendState: 'NoState', TailscaleIPs: '100.1.2.3', Self: { InNetworkMap: false } },
      'on',
    ],
    ['null', null, statusUnreadable],
    ['no Self', { BackendState: 'NoState', TailscaleIPs: null }, statusUnreadable],
    ['no BackendState', { TailscaleIPs: null, Self: { InNetworkMap: false } }, statusUnreadable],
    [
      'Self without InNetworkMap',
      { BackendState: 'NoState', TailscaleIPs: null, Self: {} },
      statusUnreadable,
    ],
  ];
  for (const [name, status, want] of table) {
    it(name, () => {
      expect(tailnetPresence(JSON.stringify(status))).toEqual(want);
    });
  }
  it('output that is not JSON is unreadable', () => {
    expect(tailnetPresence('not json')).toEqual(statusUnreadable);
  });
});

describe('invariant 5 (the approval address): what the serve config says is quoted, plain and short', () => {
  it('a proxy target cannot pass for Keyflap words or reach the terminal raw', () => {
    const trick = `http://x\u001b[2J\u202e). It is right again now${'a'.repeat(300)}`;
    const v = compareServeConfig(
      JSON.stringify({
        TCP: { [String(PORT)]: { HTTPS: true } },
        Web: { [KEY]: { Handlers: { '/': { Proxy: trick } } } },
      }),
      { host: HOST, port: PORT, target: TARGET },
    );
    expect(v.kind).toBe('mismatch');
    const seen = v.kind === 'mismatch' ? v.seen : '';
    expect(seen.startsWith(`${KEY} proxies to "http://x[2J). It is right again now`)).toBe(true);
    expect(seen.endsWith('…"')).toBe(true);
    expect(seen).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u);
    expect(seen.length).toBeLessThan(KEY.length + 120);
  });
});

describe('invariant 5 (the approval address): the config boundary', () => {
  const where = 'signer config: approverAddress';
  const good = { origin: `https://${HOST}:${PORT}`, target: TARGET };
  const parse = (v: unknown, pollMs: 'allow' | 'refuse' = 'refuse') =>
    parseApproverAddress(v, { where, pollMs });

  it('accepts the shape the installer writes', () => {
    expect(parse(good)).toEqual(good);
    const cli = { via: 'cli', bin: '/usr/bin/tailscale' };
    expect(parse({ ...good, tailscale: cli })).toEqual({ ...good, tailscale: cli });
    const env = { HOME: '/var/empty' };
    expect(parse({ ...good, tailscale: { ...cli, env } })).toEqual({
      ...good,
      tailscale: { ...cli, env },
    });
    const localApi = { via: 'localapi', dir: '/Library/Tailscale' };
    expect(parse({ ...good, tailscale: localApi })).toEqual({ ...good, tailscale: localApi });
    const pollMs = { idle: 100, fast: 20, timeout: 500 };
    expect(parse({ ...good, pollMs }, 'allow')).toEqual({ ...good, pollMs });
    const withGrace = { ...pollMs, grace: 300 };
    expect(parse({ ...good, pollMs: withGrace }, 'allow')).toEqual({ ...good, pollMs: withGrace });
  });

  const bad: [string, unknown, RegExp][] = [
    ['not an object', 'x', /must be an object/],
    ['an unknown key', { ...good, extra: 1 }, /unknown key "extra"/],
    ['no origin', { target: TARGET }, /origin must be/],
    ['an origin with a path', { ...good, origin: `https://${HOST}:${PORT}/x` }, /origin must be/],
    ['a non-web origin', { ...good, origin: `ftp://${HOST}:${PORT}` }, /origin must be/],
    ['a target without a port', { ...good, target: 'http://127.0.0.1' }, /target must be/],
    ['an https target', { ...good, target: 'https://127.0.0.1:8766' }, /target must be/],
    ['a target with a path', { ...good, target: 'http://127.0.0.1:8766/x' }, /target must be/],
    [
      'a relative bin',
      { ...good, tailscale: { via: 'cli', bin: 'tailscale' } },
      /tailscale.bin must be/,
    ],
    [
      'a pinned SHA-256: tailscale runs only from a root-only path',
      { ...good, tailscale: { via: 'cli', bin: '/usr/bin/tailscale', sha256: 'a'.repeat(64) } },
      /unknown key "tailscale.sha256"/,
    ],
    [
      'a non-string env value',
      { ...good, tailscale: { via: 'cli', bin: '/usr/bin/tailscale', env: { A: 1 } } },
      /tailscale.env must map/,
    ],
    [
      'an unknown tailscale key',
      { ...good, tailscale: { via: 'cli', bin: '/usr/bin/tailscale', args: [] } },
      /unknown key "tailscale.args"/,
    ],
    [
      'a reader without a via',
      { ...good, tailscale: { bin: '/usr/bin/tailscale' } },
      /tailscale.via must be "cli" or "localapi"/,
    ],
    [
      'a relative LocalAPI directory',
      { ...good, tailscale: { via: 'localapi', dir: 'Library/Tailscale' } },
      /tailscale.dir must be an absolute path/,
    ],
    [
      'a LocalAPI reader with a bin (one way to read, not two)',
      { ...good, tailscale: { via: 'localapi', dir: '/Library/Tailscale', bin: '/usr/bin/x' } },
      /unknown key "tailscale.bin"/,
    ],
    [
      'a token in the config (the signer reads it from Tailscale each time)',
      { ...good, tailscale: { via: 'localapi', dir: '/Library/Tailscale', token: 'x' } },
      /unknown key "tailscale.token"/,
    ],
    [
      'pollMs in service mode',
      { ...good, pollMs: { idle: 1, fast: 1, timeout: 1 } },
      /pollMs is for dev mode/,
    ],
  ];
  for (const [name, v, re] of bad) {
    it(`refuses ${name}`, () => {
      expect(() => parse(v)).toThrow(re);
    });
  }

  it('refuses a malformed pollMs even where it is allowed', () => {
    expect(() => parse({ ...good, pollMs: { idle: 0, fast: 1, timeout: 1 } }, 'allow')).toThrow(
      /pollMs.idle/,
    );
    expect(() => parse({ ...good, pollMs: { idle: 1, fast: 1 } }, 'allow')).toThrow(
      /pollMs.timeout/,
    );
  });
});

describe('invariant 5 (the approval address): the signer runs only a tailscale nobody but root can change', () => {
  it("refuses the Tailscale app's CLI in /Applications, which an admin user can replace", () => {
    const app = '/Applications/Tailscale.app/Contents/MacOS/Tailscale';
    const loc = checkToolLocation(app, TAILSCALE_TOOL);
    expect(loc).toMatchObject({
      ok: false,
      detail: `${app} is not in a system bin directory or /opt/keyflap/tools/tailscale/`,
    });
    expect(checkTool(app, TAILSCALE_TOOL)).toMatchObject({ ok: false, problem: 'untrusted' });
    expect(checkTool(app, TAILSCALE_TOOL, 'a'.repeat(64))).toMatchObject({
      ok: false,
      problem: 'untrusted',
    });
  });
});

const ORIGIN = `https://${HOST}:${PORT}`;
const CORRECT = serveConfig({ host: HOST, port: PORT, target: TARGET });
const WRONG = serveConfig({ host: HOST, port: PORT, target: 'http://127.0.0.1:9999' });
const QUICK = { idle: 200, fast: 50, timeout: 400 };
const RP = 'example.com';
const SITE = 'https://example.com';

type Log = { event: string; [k: string]: unknown };

const terminal = testApprover('terminal');
const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

interface Running {
  signer: SpawnedSigner;
  logs: Log[];
  storePath: string;
}

const running: SpawnedSigner[] = [];
afterEach(async () => {
  for (const s of running.splice(0)) await s.stop();
});

async function start(o: {
  storePath?: string;
  address?: ApproverAddress | null;
  fake?: FakeTailscale;
  pollMs?: ApproverAddress['pollMs'];
  approverAdmin?: boolean;
  trusted?: Record<string, string>;
}): Promise<Running> {
  const dir = tmpDir();
  const storePath = o.storePath ?? join(dir, 'keys');
  const logs: Log[] = [];
  const address: ApproverAddress | undefined =
    o.address === null
      ? undefined
      : (o.address ?? {
          origin: ORIGIN,
          target: TARGET,
          ...(o.fake ? { tailscale: { via: 'cli', bin: o.fake.bin, env: o.fake.env } } : {}),
          pollMs: o.pollMs ?? QUICK,
        });
  const signer = await spawnSigner({
    socketPath: join(dir, 'run', 's.sock'),
    storePath,
    passphrase: 'pw',
    trustedApproverKeys: o.trusted ?? terminal.trusted,
    approverAdmin: o.approverAdmin === true,
    ...(address ? { approverAddress: address } : {}),
    onLog: (line) => {
      try {
        logs.push(JSON.parse(line) as Log);
      } catch {}
    },
  });
  running.push(signer);
  return { signer, logs, storePath };
}

async function outcome(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (err) {
    return err instanceof SignerDenied ? err.message : `other: ${(err as Error).message}`;
  }
}

function createStatement(over: Partial<ApprovalStatement> = {}) {
  const cd = clientData('webauthn.create', SITE);
  return {
    cd,
    s: statement({
      kind: 'webauthn.create',
      rpId: RP,
      verifiedOrigin: SITE,
      clientDataJSON: cd,
      ...over,
    }),
  };
}

async function createWith(
  r: Running,
  approve: (s: ApprovalStatement) => SignedApproval,
  over: Partial<ApprovalStatement> = {},
): Promise<string> {
  const { cd, s } = createStatement(over);
  const res = await r.signer.client.createCredential({
    rpId: RP,
    userHandle: 'dXNlcg',
    clientDataJSON: cd,
    approval: approve(s),
  });
  return res.credentialId;
}

const terminalCreate = (r: Running, over: Partial<ApprovalStatement> = {}) =>
  outcome(createWith(r, (s) => terminal.sign(s), over));

const phoneCreate = (r: Running, phone: ReturnType<typeof testPhone>) =>
  outcome(createWith(r, (s) => phone.approve({ ...s, userVerified: true })));

async function addressState(r: Running, pending = false): Promise<AddressState> {
  return (await r.signer.client.approverAddress({ pending })).state;
}

async function waitFor(
  r: Running,
  pred: (s: AddressState) => boolean,
  ms = 6_000,
): Promise<AddressState> {
  const until = Date.now() + ms;
  let last = await addressState(r);
  while (!pred(last)) {
    if (Date.now() > until) throw new Error(`timed out waiting; state is ${JSON.stringify(last)}`);
    await sleep(25);
    last = await addressState(r);
  }
  return last;
}

const waitKind = (r: Running, kind: AddressState['kind']) => waitFor(r, (s) => s.kind === kind);

function approverAdd(
  by: ReturnType<typeof testPhone>,
  key: ReturnType<typeof testPhone>['key'],
): SignedApproval {
  return by.approve({
    ...statement({ clientDataJSON: '' }),
    kind: 'approver.add',
    verifiedOrigin: key.origin,
    rpId: key.rpId,
    credentialId: key.credentialId,
    clientDataHash: sha256B64url(approverDescriptor(key)),
    userVerified: true,
  });
}

async function approverCount(r: Running): Promise<number> {
  const l = await r.signer.client.listApprovers();
  return l.approvers.length + (l.native?.length ?? 0);
}

describe('invariant 5 (the approval address): the signer refuses to approve for an address it does not own', () => {
  it('a correct serve config allows approvals and pairing', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await start({ fake });
    expect(await addressState(r)).toMatchObject({ kind: 'ok' });
    expect(await terminalCreate(r)).toBe('ok');
    const phone = testPhone();
    expect(await outcome(r.signer.client.addApprover({ key: phone.key }))).toBe('ok');
    expect(await phoneCreate(r, phone)).toBe('ok');
    expect(
      fake
        .calls()
        .every((c) =>
          ['serve status --json', 'status --json --peers=false'].includes(c.argv.join(' ')),
        ),
    ).toBe(true);
  });

  it('no address configured: unwatched, and nothing is gated', async () => {
    const r = await start({ address: null });
    expect(await addressState(r)).toEqual({ kind: 'unwatched' });
    expect(await terminalCreate(r)).toBe('ok');
    expect(await outcome(r.signer.client.clearApproverAddress())).toBe('admin_required');
  });

  it('a mismatch latches: approvers go, approvals and grant uses are refused, the trip is logged, and the latch survives a restart', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await start({ fake });
    const credentialId = await createWith(r, (s) => terminal.sign(s));
    const cd = clientData('webauthn.get', SITE);
    const getStatement = (over: Partial<ApprovalStatement> = {}) =>
      statement({
        kind: 'webauthn.get',
        rpId: RP,
        verifiedOrigin: SITE,
        credentialId,
        clientDataJSON: cd,
        ...over,
      });
    const sign = (approval: SignedApproval | GrantedApproval) =>
      outcome(
        r.signer.client.sign({
          credentialId,
          authenticatorData: authData(RP),
          clientDataJSON: cd,
          approval,
        }),
      );
    const granted = getStatement({ grant: { agentId: 'agent-1', until: Date.now() + 600_000 } });
    expect(await sign(terminal.sign(granted))).toBe('ok');
    const useGrant = (): GrantedApproval => ({
      statement: getStatement({ requestId: randomUUID() }),
      grantId: granted.requestId,
      agentId: 'agent-1',
    });
    expect(await sign(useGrant())).toBe('ok');
    const phone = testPhone();
    expect(await outcome(r.signer.client.addApprover({ key: phone.key }))).toBe('ok');
    expect(await approverCount(r)).toBe(1);

    fake.serve(WRONG);
    const latched = await waitKind(r, 'latched');
    expect(latched).toMatchObject({
      kind: 'latched',
      seen: `${HOST}:${PORT} proxies to "http://127.0.0.1:9999"`,
    });
    expect(await approverCount(r)).toBe(0);
    expect(await phoneCreate(r, phone)).toBe('approver_address_latched');
    expect(await terminalCreate(r)).toBe('approver_address_latched');
    expect(await sign(useGrant())).toBe('approver_address_latched');
    expect(await outcome(r.signer.client.addApprover({ key: testPhone().key }))).toBe(
      'approver_address_latched',
    );
    const tripped = r.logs.find((l) => l.event === 'approver_address_tripped');
    expect(tripped).toMatchObject({
      seen: `${HOST}:${PORT} proxies to "http://127.0.0.1:9999"`,
      approversRemoved: 1,
    });

    await r.signer.stop();
    fake.serve(CORRECT);
    const again = await start({ fake, storePath: r.storePath });
    expect(await addressState(again)).toEqual({
      ...latched,
      latest: { checkedAt: expect.any(Number), verdict: { kind: 'ok' } },
    });
    expect(await terminalCreate(again)).toBe('approver_address_latched');
    expect(await outcome(again.signer.client.addApprover({ key: testPhone().key }))).toBe(
      'approver_address_latched',
    );
    expect(await approverCount(again)).toBe(0);
  });

  it('an unreadable config pauses without latching, keeps the approvers, and resumes', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await start({ fake });
    const phone = testPhone();
    expect(await outcome(r.signer.client.addApprover({ key: phone.key }))).toBe('ok');
    const cases: ['hang' | 'fail' | 'down', string][] = [
      ['fail', 'tailscale exited 1'],
      ['down', 'Tailscale is not running'],
      ['hang', 'tailscale timed out'],
    ];
    for (const [sentinel, detail] of cases) {
      fake.set(sentinel, true);
      expect(await waitKind(r, 'paused')).toMatchObject({ kind: 'paused', detail });
      expect(await phoneCreate(r, phone)).toBe('approver_address_unverified');
      expect(await terminalCreate(r)).toBe('approver_address_unverified');
      expect(await approverCount(r)).toBe(1);
      fake.set(sentinel, false);
      await waitKind(r, 'ok');
      expect(await phoneCreate(r, phone)).toBe('ok');
    }
    const events = r.logs.map((l) => l.event);
    expect(events.filter((e) => e === 'approver_address_unreadable')).toHaveLength(3);
    expect(events.filter((e) => e === 'approver_address_readable').length).toBeGreaterThanOrEqual(
      3,
    );
    expect(events).not.toContain('approver_address_tripped');
  });

  it('a serve setting only a serve writer could make unreadable latches: over the size cap, or not JSON', async () => {
    const cases: [(f: FakeTailscale) => void, string][] = [
      [
        (f) => f.serveRaw(`{"Web":{"x":"${'a'.repeat(1_100_000)}"}}`),
        'the serve setting is over 1 MiB',
      ],
      [(f) => f.set('garbage', true), 'the serve setting is not JSON'],
      [(f) => f.serveRaw('[]'), 'the serve setting is not a serve config'],
    ];
    for (const [spoil, seen] of cases) {
      const fake = fakeTailscale(CORRECT);
      const r = await start({ fake });
      expect(await outcome(r.signer.client.addApprover({ key: testPhone().key }))).toBe('ok');
      spoil(fake);
      expect(await waitFor(r, (s) => s.kind !== 'ok', 5_000)).toMatchObject({
        kind: 'latched',
        seen,
      });
      expect(await approverCount(r)).toBe(0);
    }
  });

  it('each check reads the status first, then the serve setting once', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await start({ fake });
    fake.serve({});
    expect(await waitFor(r, (s) => s.kind !== 'ok', 5_000)).toMatchObject({
      kind: 'latched',
      seen: `nothing is served at ${HOST}:${PORT}`,
    });
    await sleep(300);
    const reads = fake.calls().map((c) => c.argv[0]);
    if (reads.at(-1) === 'status') reads.pop();
    expect(reads.length).toBeGreaterThanOrEqual(4);
    expect(reads).toEqual(reads.map((_, i) => (i % 2 === 0 ? 'status' : 'serve')));
  });

  it('a missing binary, and no CLI at all, pause rather than pass', async () => {
    const missing = await start({
      address: {
        origin: ORIGIN,
        target: TARGET,
        tailscale: { via: 'cli', bin: '/nonexistent/keyflap/tailscale' },
        pollMs: QUICK,
      },
    });
    expect(await addressState(missing)).toMatchObject({
      kind: 'paused',
      detail: 'tailscale cannot be run',
    });
    expect(await terminalCreate(missing)).toBe('approver_address_unverified');

    const none = await start({ address: { origin: ORIGIN, target: TARGET } });
    expect(await addressState(none)).toMatchObject({
      kind: 'paused',
      detail: 'no tailscale CLI configured',
    });
    expect(await terminalCreate(none)).toBe('approver_address_unverified');
    expect(await outcome(none.signer.client.addApprover({ key: testPhone().key }))).toBe(
      'approver_address_unverified',
    );
  });

  it('while an approval is pending the checks speed up, so a flip shorter than the idle interval is caught', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await start({ fake, pollMs: { idle: 1_500, fast: 100, timeout: 1_000 } });
    const idleCalls = fake.calls().length;
    await sleep(700);
    expect(fake.calls().length - idleCalls).toBeLessThanOrEqual(1);
    expect(await addressState(r, true)).toMatchObject({ kind: 'ok' });
    fake.serve(WRONG);
    await sleep(600);
    fake.serve(CORRECT);
    expect(await waitFor(r, (s) => s.kind === 'latched', 3_000)).toMatchObject({
      kind: 'latched',
      seen: `${HOST}:${PORT} proxies to "http://127.0.0.1:9999"`,
    });
  });

  it('pairing is refused while latched: first-use passkey and native', async () => {
    const fake = fakeTailscale(WRONG);
    const r = await start({ fake });
    expect(await addressState(r)).toMatchObject({ kind: 'latched' });
    expect(await outcome(r.signer.client.addApprover({ key: testPhone().key }))).toBe(
      'approver_address_latched',
    );
    const native = testNativePhone();
    expect(
      await outcome(r.signer.client.addNativeApprover({ key: native.key, proof: native.proof() })),
    ).toBe('approver_address_latched');
    expect(await approverCount(r)).toBe(0);
  });

  it('pairing is refused while paused, including an approved approver.add, and works again after', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await start({ fake });
    const phone = testPhone();
    expect(await outcome(r.signer.client.addApprover({ key: phone.key }))).toBe('ok');
    const second = testPhone({ rpId: phone.key.rpId, origin: phone.key.origin });
    fake.set('fail', true);
    await waitKind(r, 'paused');
    expect(
      await outcome(
        r.signer.client.addApprover({ key: second.key, approval: approverAdd(phone, second.key) }),
      ),
    ).toBe('approver_address_unverified');
    const native = testNativePhone({ origin: phone.key.origin });
    expect(
      await outcome(r.signer.client.addNativeApprover({ key: native.key, proof: native.proof() })),
    ).toBe('approver_address_unverified');
    fake.set('fail', false);
    await waitKind(r, 'ok');
    expect(
      await outcome(
        r.signer.client.addApprover({ key: second.key, approval: approverAdd(phone, second.key) }),
      ),
    ).toBe('ok');
    expect(await approverCount(r)).toBe(2);
  });

  it('only the admin path clears a latch, and only when the address reads correct', async () => {
    const fake = fakeTailscale(WRONG);
    const r = await start({ fake });
    expect(await addressState(r)).toMatchObject({ kind: 'latched' });
    expect(await outcome(r.signer.client.clearApproverAddress())).toBe('admin_required');
    expect(await addressState(r)).toMatchObject({ kind: 'latched' });
    await r.signer.stop();

    const admin = await start({ fake, storePath: r.storePath, approverAdmin: true });
    fake.serve({});
    expect((await admin.signer.client.clearApproverAddress()).state).toEqual({
      kind: 'latched',
      at: expect.any(Number),
      seen: `${HOST}:${PORT} proxies to "http://127.0.0.1:9999"`,
      latest: {
        checkedAt: expect.any(Number),
        verdict: { kind: 'mismatch', seen: `nothing is served at ${HOST}:${PORT}` },
      },
    });
    fake.set('fail', true);
    expect((await admin.signer.client.clearApproverAddress()).state).toMatchObject({
      kind: 'latched',
    });
    fake.set('fail', false);
    expect(await terminalCreate(admin)).toBe('approver_address_latched');

    fake.serve(CORRECT);
    expect((await admin.signer.client.clearApproverAddress()).state).toMatchObject({ kind: 'ok' });
    expect((await admin.signer.client.clearApproverAddress()).state).toMatchObject({ kind: 'ok' });
    expect(admin.logs.filter((l) => l.event === 'approver_address_cleared')).toHaveLength(1);
    expect(await terminalCreate(admin)).toBe('ok');
    expect(await outcome(admin.signer.client.addApprover({ key: testPhone().key }))).toBe('ok');
    await admin.signer.stop();

    const back = await start({ fake, storePath: r.storePath });
    expect(await addressState(back)).toMatchObject({ kind: 'ok' });
    expect(await approverCount(back)).toBe(1);
  });
});
