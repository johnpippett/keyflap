import { randomUUID } from 'node:crypto';
import { rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import {
  type FakeTailscale,
  fakeTailscale,
  serveConfig,
  tailscaleStatus,
} from '@aab/sources/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ApprovalStatement, GrantedApproval, SignedApproval } from '../src/approval.ts';
import type { AddressState, ApproverAddress } from '../src/approver-address.ts';
import { SignerDenied, type SpawnedSigner, spawnSigner } from '../src/client.ts';
import { type FakeLocalApi, fakeLocalApi } from './fake-localapi.ts';
import { authData, clientData, statement, testApprover, testPhone, tmpDir } from './helpers.ts';

const HOST = 'mac.tail1234.ts.net';
const PORT = 8766;
const TARGET = 'http://127.0.0.1:8766';
const ORIGIN = `https://${HOST}:${PORT}`;
const KEY = `${HOST}:${PORT}`;
const CORRECT = serveConfig({ host: HOST, port: PORT, target: TARGET });
const WRONG = serveConfig({ host: HOST, port: PORT, target: 'http://127.0.0.1:9999' });
const ON = tailscaleStatus({ onTailnet: true });
const OFF = tailscaleStatus({ onTailnet: false });
const NOT_CONNECTED = 'Tailscale is not connected';
const GRACE = 20_000;
const QUICK = { idle: 100, fast: 40, timeout: 3_000, grace: GRACE };
const RP = 'example.com';
const SITE = 'https://example.com';

const terminal = testApprover('terminal');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const signers: SpawnedSigner[] = [];
const fakes: FakeLocalApi[] = [];
afterEach(async () => {
  for (const s of signers.splice(0)) await s.stop();
  for (const f of fakes.splice(0)) await f.close();
});

type Log = { event: string; [k: string]: unknown };

interface Running {
  signer: SpawnedSigner;
  logs: Log[];
  storePath: string;
}

async function start(
  tailscale: ApproverAddress['tailscale'],
  storePath?: string,
): Promise<Running> {
  const dir = tmpDir();
  const logs: Log[] = [];
  const path = storePath ?? join(dir, 'keys');
  const signer = await spawnSigner({
    socketPath: join(dir, 'run', 's.sock'),
    storePath: path,
    passphrase: 'pw',
    trustedApproverKeys: terminal.trusted,
    approverAddress: { origin: ORIGIN, target: TARGET, tailscale, pollMs: QUICK },
    onLog: (line) => {
      try {
        logs.push(JSON.parse(line) as Log);
      } catch {}
    },
  });
  signers.push(signer);
  return { signer, logs, storePath: path };
}

const viaCli = (fake: FakeTailscale) => start({ via: 'cli', bin: fake.bin, env: fake.env });

async function outcome(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (err) {
    return err instanceof SignerDenied ? err.message : `other: ${(err as Error).message}`;
  }
}

async function addressState(r: Running): Promise<AddressState> {
  return (await r.signer.client.approverAddress({ pending: true })).state;
}

async function waitFor(r: Running, pred: (s: AddressState) => boolean): Promise<AddressState> {
  const until = Date.now() + 15_000;
  let last = await addressState(r);
  while (!pred(last)) {
    if (Date.now() > until) throw new Error(`timed out; state is ${JSON.stringify(last)}`);
    await sleep(20);
    last = await addressState(r);
  }
  return last;
}

const pausedWith = (r: Running, detail: string) =>
  waitFor(r, (s) => s.kind === 'paused' && s.detail === detail);

function phoneCreate(r: Running, phone: ReturnType<typeof testPhone>): Promise<string> {
  const cd = clientData('webauthn.create', SITE);
  const s = statement({
    kind: 'webauthn.create',
    rpId: RP,
    verifiedOrigin: SITE,
    clientDataJSON: cd,
  });
  return outcome(
    r.signer.client.createCredential({
      rpId: RP,
      userHandle: 'dXNlcg',
      clientDataJSON: cd,
      approval: phone.approve({ ...s, userVerified: true }),
    }),
  );
}

async function withGrant(r: Running) {
  const cd = clientData('webauthn.create', SITE);
  const created = await r.signer.client.createCredential({
    rpId: RP,
    userHandle: 'dXNlcg',
    clientDataJSON: cd,
    approval: terminal.sign(
      statement({ kind: 'webauthn.create', rpId: RP, verifiedOrigin: SITE, clientDataJSON: cd }),
    ),
  });
  const getCd = clientData('webauthn.get', SITE);
  const getStatement = (over: Partial<ApprovalStatement> = {}) =>
    statement({
      kind: 'webauthn.get',
      rpId: RP,
      verifiedOrigin: SITE,
      credentialId: created.credentialId,
      clientDataJSON: getCd,
      ...over,
    });
  const sign = (approval: SignedApproval | GrantedApproval) =>
    outcome(
      r.signer.client.sign({
        credentialId: created.credentialId,
        authenticatorData: authData(RP),
        clientDataJSON: getCd,
        approval,
      }),
    );
  const granted = getStatement({ grant: { agentId: 'agent-1', until: Date.now() + 600_000 } });
  expect(await sign(terminal.sign(granted))).toBe('ok');
  return () =>
    sign({
      statement: getStatement({ requestId: randomUUID() }),
      grantId: granted.requestId,
      agentId: 'agent-1',
    });
}

async function approverCount(r: Running): Promise<number> {
  const l = await r.signer.client.listApprovers();
  return l.approvers.length + (l.native?.length ?? 0);
}

function closedPort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

function repoint(dir: string, port: number): void {
  rmSync(join(dir, 'ipnport'), { force: true });
  symlinkSync(String(port), join(dir, 'ipnport'));
}

describe('invariant 5 (the approval address): a Tailscale restart pauses approvals and never trips the latch; nothing served while on the tailnet does', {
  timeout: 60_000,
}, () => {
  it('LocalAPI (the Mac): refused, no token file, an empty token, then null, then correct: phones and grants stay, approvals are refused only while it lasts', async () => {
    const before = await fakeLocalApi(CORRECT);
    const after = await fakeLocalApi(null, OFF);
    fakes.push(before, after);
    const r = await start({ via: 'localapi', dir: before.dir });
    const useGrant = await withGrant(r);
    const phone = testPhone();
    expect(await outcome(r.signer.client.addApprover({ key: phone.key }))).toBe('ok');
    expect(await useGrant()).toBe('ok');

    repoint(before.dir, await closedPort());
    const refused = await pausedWith(r, 'Tailscale is not running');
    expect(refused).toMatchObject({
      graceUntil: refused.kind === 'paused' && refused.since + GRACE,
    });
    expect(await phoneCreate(r, phone)).toBe('approver_address_unverified');
    expect(await useGrant()).toBe('approver_address_unverified');

    repoint(before.dir, after.port);
    await sleep(QUICK.idle * 2);
    expect(await addressState(r)).toMatchObject({
      kind: 'paused',
      detail: 'Tailscale is not running',
      since: refused.kind === 'paused' ? refused.since : -1,
    });

    writeFileSync(join(before.dir, `sameuserproof-${after.port}`), '');
    expect(await pausedWith(r, "Tailscale's token cannot be read")).toMatchObject({
      graceUntil: refused.kind === 'paused' && refused.graceUntil,
    });
    expect(await phoneCreate(r, phone)).toBe('approver_address_unverified');

    writeFileSync(join(before.dir, `sameuserproof-${after.port}`), `${after.token}\n`);
    expect(await pausedWith(r, NOT_CONNECTED)).toMatchObject({
      graceUntil: refused.kind === 'paused' && refused.graceUntil,
    });
    expect(await phoneCreate(r, phone)).toBe('approver_address_unverified');
    expect(await useGrant()).toBe('approver_address_unverified');
    after.serve({});
    await sleep(QUICK.idle * 2);
    expect(await addressState(r)).toMatchObject({ kind: 'paused' });

    after.serve(CORRECT);
    after.status(ON);
    await waitFor(r, (s) => s.kind === 'ok');
    expect(await approverCount(r)).toBe(1);
    expect(await phoneCreate(r, phone)).toBe('ok');
    expect(await useGrant()).toBe('ok');
    const events = r.logs.map((l) => l.event);
    expect(events).not.toContain('approver_address_tripped');
    expect(events).toContain('approver_address_readable');
  });

  it('CLI (Linux): tailscaled not answering, then null: the same pause, and it resumes by itself', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await viaCli(fake);
    const phone = testPhone();
    expect(await outcome(r.signer.client.addApprover({ key: phone.key }))).toBe('ok');

    fake.set('down', true);
    const down = await pausedWith(r, 'Tailscale is not running');
    expect(down.kind === 'paused' && down.graceUntil).toBe(
      down.kind === 'paused' && down.since + GRACE,
    );
    expect(await phoneCreate(r, phone)).toBe('approver_address_unverified');
    fake.status(OFF);
    fake.serveRaw('null');
    fake.set('down', false);
    expect(await pausedWith(r, NOT_CONNECTED)).toMatchObject({
      graceUntil: down.kind === 'paused' && down.graceUntil,
    });
    fake.serve(CORRECT);
    fake.status(ON);
    await waitFor(r, (s) => s.kind === 'ok');
    expect(await approverCount(r)).toBe(1);
    expect(await phoneCreate(r, phone)).toBe('ok');
    expect(r.logs.map((l) => l.event)).not.toContain('approver_address_tripped');
  });

  it('a pause no restart explains has no grace, and a restart pause loses its grace once one appears', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await viaCli(fake);
    fake.set('fail', true);
    const failed = await pausedWith(r, 'tailscale exited 1');
    expect(failed).not.toHaveProperty('graceUntil');
    fake.set('fail', false);
    fake.set('down', true);
    expect(await pausedWith(r, 'Tailscale is not running')).not.toHaveProperty('graceUntil');
    fake.set('down', false);
    await waitFor(r, (s) => s.kind === 'ok');

    fake.status(OFF);
    fake.serve({});
    expect(await pausedWith(r, NOT_CONNECTED)).toHaveProperty('graceUntil');
    fake.serve(CORRECT);
    fake.set('hang', true);
    expect(await pausedWith(r, 'tailscale timed out')).not.toHaveProperty('graceUntil');
    fake.set('hang', false);
    await waitFor(r, (s) => s.kind === 'ok');
  });

  it('nothing served while Tailscale says this machine is on the tailnet latches at once: no pause, no grace', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await viaCli(fake);
    const phone = testPhone();
    expect(await outcome(r.signer.client.addApprover({ key: phone.key }))).toBe('ok');
    fake.serve({});
    expect(await waitFor(r, (s) => s.kind !== 'ok')).toMatchObject({
      kind: 'latched',
      seen: `nothing is served at ${KEY}`,
    });
    expect(await approverCount(r)).toBe(0);
    expect(await phoneCreate(r, phone)).toBe('approver_address_latched');
  });

  it('LocalAPI: null while on the tailnet latches too', async () => {
    const f = await fakeLocalApi(CORRECT);
    fakes.push(f);
    const r = await start({ via: 'localapi', dir: f.dir });
    await waitFor(r, (s) => s.kind === 'ok');
    f.serve(null);
    expect(await waitFor(r, (s) => s.kind !== 'ok')).toMatchObject({
      kind: 'latched',
      seen: `nothing is served at ${KEY}`,
    });
  });

  it('nothing served and a status that cannot be read is a pause with no grace, never harmless', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await viaCli(fake);
    fake.statusRaw('not json');
    fake.serve({});
    expect(await pausedWith(r, "Tailscale's status cannot be read")).not.toHaveProperty(
      'graceUntil',
    );
    fake.serve(CORRECT);
    await waitFor(r, (s) => s.kind === 'ok');
  });

  it('one grace per incident: a second restart soon after gets only what is left of the first grace', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await viaCli(fake);
    fake.set('down', true);
    const first = await pausedWith(r, 'Tailscale is not running');
    const until = first.kind === 'paused' ? first.graceUntil : -1;
    expect(until).toBeGreaterThan(Date.now());
    fake.set('down', false);
    await waitFor(r, (s) => s.kind === 'ok');
    fake.set('down', true);
    expect(await pausedWith(r, 'Tailscale is not running')).toMatchObject({ graceUntil: until });
    fake.set('down', false);
    await waitFor(r, (s) => s.kind === 'ok');
  });

  it('something else served at the address still latches, removes the phones and refuses', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await viaCli(fake);
    const phone = testPhone();
    expect(await outcome(r.signer.client.addApprover({ key: phone.key }))).toBe('ok');
    fake.set('down', true);
    await pausedWith(r, 'Tailscale is not running');
    fake.set('down', false);
    fake.serve(WRONG);
    expect(await waitFor(r, (s) => s.kind === 'latched')).toMatchObject({
      seen: `${KEY} proxies to "http://127.0.0.1:9999"`,
    });
    expect(await approverCount(r)).toBe(0);
    expect(await phoneCreate(r, phone)).toBe('approver_address_latched');
  });

  const partial: [string, unknown, string][] = [
    [
      'HTTPS on the port with no web handler',
      { TCP: { [String(PORT)]: { HTTPS: true } } },
      `${PORT} is in use, but not for ${KEY}`,
    ],
    [
      'a raw forward on the port',
      { TCP: { [String(PORT)]: { TCPForward: '127.0.0.1:1' } } },
      `${PORT} is in use, but not for ${KEY}`,
    ],
    [
      'a web handler with no HTTPS listener',
      { Web: { [KEY]: { Handlers: { '/': { Proxy: TARGET } } } } },
      `TCP ${PORT} is not served`,
    ],
    [
      'Funnel turned on for the address alone',
      { AllowFunnel: { [KEY]: true } },
      `${KEY} is on Funnel`,
    ],
    [
      'another name on the port',
      { Web: { [`other.ts.net:${PORT}`]: { Handlers: { '/': { Proxy: TARGET } } } } },
      `${PORT} is in use, but not for ${KEY}`,
    ],
    [
      'a foreground session on the port',
      { Foreground: { s1: { TCP: { [String(PORT)]: { HTTPS: true } } } } },
      `a foreground serve session uses ${PORT}`,
    ],
  ];
  for (const [name, config, seen] of partial) {
    it(`a partial config latches: ${name}`, async () => {
      const fake = fakeTailscale(CORRECT);
      const r = await viaCli(fake);
      expect(await outcome(r.signer.client.addApprover({ key: testPhone().key }))).toBe('ok');
      fake.serve(config);
      expect(await waitFor(r, (s) => s.kind === 'latched')).toMatchObject({ seen });
      expect(await approverCount(r)).toBe(0);
    });
  }

  it('something served only on another port of the same name leaves ours empty while on the tailnet: a trip', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await viaCli(fake);
    fake.serve(serveConfig({ host: HOST, port: 443, target: 'http://127.0.0.1:3000' }));
    expect(await waitFor(r, (s) => s.kind !== 'ok')).toMatchObject({
      kind: 'latched',
      seen: `nothing is served at ${KEY}`,
    });
  });
});

describe('invariant 5 (the approval address): after a trip the signer keeps reading, for status only', {
  timeout: 60_000,
}, () => {
  it('latched stays latched and refuses, while its latest reading follows the setting, across a restart too', async () => {
    const fake = fakeTailscale(CORRECT);
    const r = await viaCli(fake);
    fake.serve(WRONG);
    const tripped = await waitFor(r, (s) => s.kind === 'latched');
    const seen = `${KEY} proxies to "http://127.0.0.1:9999"`;
    expect(tripped).toMatchObject({ seen });
    const at = tripped.kind === 'latched' ? tripped.at : -1;

    fake.serve(CORRECT);
    expect(
      await waitFor(r, (s) => s.kind === 'latched' && s.latest?.verdict.kind === 'ok'),
    ).toMatchObject({ kind: 'latched', at, seen, latest: { verdict: { kind: 'ok' } } });
    expect(await phoneCreate(r, testPhone())).toBe('approver_address_latched');
    expect(await outcome(r.signer.client.addApprover({ key: testPhone().key }))).toBe(
      'approver_address_latched',
    );

    fake.status(OFF);
    fake.serve({});
    expect(
      await waitFor(r, (s) => s.kind === 'latched' && s.latest?.verdict.kind === 'offline'),
    ).toMatchObject({ at, seen });
    fake.serve(serveConfig({ host: HOST, port: PORT, target: 'http://127.0.0.1:7777' }));
    expect(
      await waitFor(r, (s) => s.kind === 'latched' && s.latest?.verdict.kind === 'mismatch'),
    ).toMatchObject({
      at,
      seen,
      latest: { verdict: { kind: 'mismatch', seen: `${KEY} proxies to "http://127.0.0.1:7777"` } },
    });

    await r.signer.stop();
    fake.serve(CORRECT);
    fake.status(ON);
    const again = await start({ via: 'cli', bin: fake.bin, env: fake.env }, r.storePath);
    expect(await addressState(again)).toMatchObject({
      kind: 'latched',
      at,
      seen,
      latest: { verdict: { kind: 'ok' } },
    });
    expect(await phoneCreate(again, testPhone())).toBe('approver_address_latched');
  });
});
