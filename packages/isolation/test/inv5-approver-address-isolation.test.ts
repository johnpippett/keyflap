import { describe, expect, it } from 'vitest';
import { AGENT_USER, NODE, PROBE_DIR } from './container.ts';
import {
  APPROVER_TARGET,
  SERVE_FILE,
  STATUS_FILE,
  serveConfig,
  tailscaleStatus,
  writeServeConfig,
  writeTailscaleStatus,
} from './fake-tailscale.ts';
import { env, host, skipReason, whereOn } from './helpers.ts';
import { KEYFLAP, PHONE_LOG, pairProbePhone, waitFor } from './pair.ts';
import { auditEvents, auditPayloads, auditTail, L } from './platform.ts';
import type { Outcome } from './probe/attempt.ts';

const WRONG_TARGET = 'http://127.0.0.1:9999';
const USER = 'address-user';
const RP_HOST = 'rp5.localhost';
const RP_PORT = 3005;
const RP_URL = `http://${RP_HOST}:${RP_PORT}/`;
const RP_UNIT = 'test-rp5';

interface SignerStatus {
  service: { signer: { approvers: number; address: { kind: string; seen?: string } } };
}

describe.skipIf(skipReason !== null || L.os !== 'linux')(
  `invariant 5: the approval address is watched (${whereOn('linux')})`,
  () => {
    const statusJson = () =>
      JSON.parse(
        host().exec([KEYFLAP, 'status', '--json'], { check: true }).stdout,
      ) as SignerStatus;
    const address = () => statusJson().service.signer.address;
    const approvers = () =>
      JSON.parse(host().exec([KEYFLAP, 'approver', 'list', '--json'], { check: true }).stdout) as
        | unknown[]
        | { approvers: unknown[] };
    const approverCount = () => {
      const a = approvers();
      return Array.isArray(a) ? a.length : a.approvers.length;
    };
    const sleep = (s: number) => host().exec(['sleep', String(s)]);

    function addAgent(): { id: string; token: string; tokenFile: string } {
      const h = host();
      const added = h.exec([KEYFLAP, 'agent', 'add', 'address-agent'], { check: true }).stdout;
      const id = /\(id ([0-9a-f-]{36})\)/.exec(added)?.[1];
      const token = /(aab_agent_[A-Za-z0-9_-]{43})/.exec(added)?.[1];
      if (!id || !token) throw new Error('agent add printed no id/token');
      const tokenFile = `${L.hookDir}/agent-${id}.token`;
      h.as(AGENT_USER, ['sh', '-c', `umask 077; cat >${tokenFile}`], { input: `${token}\n` });
      return { id, token, tokenFile };
    }

    function probe(agent: { id: string; token: string }, action: 'enroll' | 'login') {
      const r = host().as(
        AGENT_USER,
        [
          NODE,
          `${PROBE_DIR}/address.ts`,
          JSON.stringify({
            mcpUrl: env.mcpUrl,
            token: agent.token,
            agentId: agent.id,
            rp: RP_URL,
            user: USER,
            action,
          }),
        ],
        { timeoutMs: 180_000 },
      );
      expect(r.status, r.stderr).toBe(0);
      return JSON.parse(r.stdout) as {
        hook: { status: number };
        result: { status: string };
        signedInAs?: string | null;
      };
    }

    it('a repointed serve config trips the signer: approvals denied, phones removed, audited, pairing refused until it is fixed and cleared at the machine', () => {
      const h = host();
      expect(address().kind).toBe('ok');
      expect(h.exec([KEYFLAP, 'status'], { check: true }).stdout).toContain(
        `Address:     ok (http://approver.localhost:8766 -> ${APPROVER_TARGET}, watched)`,
      );
      const agent = addAgent();
      h.exec(
        [
          'systemd-run',
          `--unit=${RP_UNIT}`,
          '--collect',
          '--property=WorkingDirectory=/',
          NODE,
          `${PROBE_DIR}/rp.ts`,
          RP_HOST,
          String(RP_PORT),
        ],
        { check: true },
      );
      try {
        waitFor(
          h,
          'the second test RP',
          [
            NODE,
            '-e',
            `fetch('http://127.0.0.1:${RP_PORT}/').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))`,
          ],
          () => true,
          30_000,
        );
        const enrolled = probe(agent, 'enroll');
        expect(enrolled.hook.status).toBe(0);
        expect(enrolled.result).toEqual({ status: 'success' });
        expect(approverCount()).toBe(1);
        const trippedBefore = auditEvents(h, ['approver.address_tripped']).length;

        const signerAddress = (o: string) => (JSON.parse(o) as SignerStatus).service.signer.address;
        writeTailscaleStatus(h, false);
        writeServeConfig(h, 'null');
        waitFor(
          h,
          'nothing served while Tailscale has no netmap (a restart) to pause, not trip',
          [KEYFLAP, 'status', '--json'],
          (o) => signerAddress(o).kind === 'paused',
          30_000,
        );
        expect(address()).toMatchObject({ detail: 'Tailscale is not connected' });
        expect(approverCount(), 'a restart-shaped pause keeps the phones').toBe(1);
        writeServeConfig(h, serveConfig(APPROVER_TARGET));
        writeTailscaleStatus(h, true);
        waitFor(
          h,
          'the pause to end by itself',
          [KEYFLAP, 'status', '--json'],
          (o) => signerAddress(o).kind === 'ok',
          30_000,
        );
        expect(approverCount()).toBe(1);
        expect(auditEvents(h, ['approver.address_tripped'])).toHaveLength(trippedBefore);

        writeServeConfig(h, serveConfig(WRONG_TARGET));
        waitFor(
          h,
          'the signer to drop every phone',
          [KEYFLAP, 'approver', 'list', '--json'],
          (o) => {
            const a = JSON.parse(o) as unknown[] | { approvers: unknown[] };
            return (Array.isArray(a) ? a : a.approvers).length === 0;
          },
          30_000,
        );
        expect(address()).toMatchObject({
          kind: 'latched',
          seen: `approver.localhost:8766 proxies to "${WRONG_TARGET}"`,
        });
        waitFor(
          h,
          'the core to audit the trip',
          ['true'],
          () => auditEvents(h, ['approver.address_tripped']).length > trippedBefore,
          20_000,
        );

        const signedBefore = auditEvents(h, ['passkey.signed']).length;
        const denied = probe(agent, 'login');
        expect(denied.hook.status).toBe(0);
        expect(denied.result).toEqual({ status: 'denied' });
        expect(denied.signedInAs).toBeNull();
        expect(auditEvents(h, ['passkey.signed'])).toHaveLength(signedBefore);
        expect(auditPayloads(h, 'denied').at(-1)).toMatchObject({
          agentId: agent.id,
          verifiedOrigin: RP_URL.slice(0, -1),
          reason: 'approval_approver_address_changed',
        });

        const refused = h.exec([KEYFLAP, 'approver', 'pair']);
        expect(refused.status).not.toBe(0);
        expect(refused.stderr).toContain('the approval address is off: it was changed at');
        expect(refused.stderr).toContain(`approver.localhost:8766 proxies to "${WRONG_TARGET}"`);
        expect(refused.stderr).toMatch(
          /fix: sudo \S*tailscale serve --bg --https=8766 http:\/\/127\.0\.0\.1:8766, then sudo keyflap approver pair/,
        );
        expect(approverCount()).toBe(0);
        const status = h.exec([KEYFLAP, 'status'], { check: true }).stdout;
        expect(status).toMatch(
          /Address: {5}off: it was changed at \S+ \(approver\.localhost:8766 proxies to "http:\/\/127\.0\.0\.1:9999"\), so phones were signed out to be safe/,
        );
        expect(status).toContain('fix: ');

        writeServeConfig(h, serveConfig(APPROVER_TARGET));
        sleep(3);
        expect(address().kind, 'a latch does not clear itself when the config is fixed').toBe(
          'latched',
        );
        const rightAgain = h.exec([KEYFLAP, 'status'], { check: true }).stdout;
        expect(rightAgain).toContain('so phones were signed out to be safe. It is right again now');
        expect(rightAgain).toContain(
          'fix: pair your phone again to turn approvals back on: sudo keyflap approver pair',
        );

        expect(pairProbePhone(h, PHONE_LOG)).toContain('/pair#');
        expect(address().kind).toBe('ok');
        expect(approverCount()).toBe(1);
        expect(auditEvents(h, ['approver.address_cleared'])).toContain('approver.address_cleared');

        const again = probe(agent, 'login');
        expect(
          again.result,
          auditTail(h, 30) + h.exec(['tail', '-n', '5', PHONE_LOG]).stdout,
        ).toEqual({ status: 'success' });
        expect(again.signedInAs).toBe(USER);
      } finally {
        h.exec(['systemctl', 'stop', `${RP_UNIT}.service`]);
        h.exec([KEYFLAP, 'agent', 'revoke', agent.id]);
        h.exec(['rm', '-f', agent.tokenFile]);
        if (h.exec(['cat', SERVE_FILE]).stdout !== serveConfig(APPROVER_TARGET)) {
          writeServeConfig(h, serveConfig(APPROVER_TARGET));
        }
        if (h.exec(['cat', STATUS_FILE]).stdout !== tailscaleStatus(true)) {
          writeTailscaleStatus(h, true);
        }
      }
    });

    it('a LocalAPI port link in a root-only directory is refused while another uid owns it, since its owner can repoint it', () => {
      const h = host();
      const dir = '/root/kf-ipn';
      const link = `${dir}/ipnport`;
      h.exec(['install', '-d', '-m', '0755', dir], { check: true });
      h.exec(['ln', '-sfn', '41112', link], { check: true });
      const read = () => {
        const r = h.exec([NODE, `${PROBE_DIR}/localapi-port.ts`, dir], { timeoutMs: 60_000 });
        expect(r.status, r.stderr).toBe(0);
        return JSON.parse(r.stdout) as { kind: string; detail?: string };
      };
      try {
        const uid = h.exec(['id', '-u', AGENT_USER], { check: true }).stdout.trim();
        h.exec(['chown', '-h', AGENT_USER, link], { check: true });
        expect(read()).toEqual({
          kind: 'untrusted',
          detail: `${link} is owned by uid ${uid}, not root: its owner can repoint it`,
        });
        h.exec(['chown', '-h', 'root', link], { check: true });
        expect(read()).toEqual({ kind: 'failed', detail: 'Tailscale is not running' });
      } finally {
        h.exec(['rm', '-rf', dir]);
      }
    });

    it("the signer unit's sandbox can connect to a unix socket under /run, where tailscaled listens", () => {
      const h = host();
      const unit = h.exec(['systemctl', 'cat', 'keyflap-signer.service'], { check: true }).stdout;
      const sandbox = unit
        .split('\n')
        .map((l) => l.trim())
        .filter((l) =>
          /^(NoNewPrivileges|Protect[A-Za-z]+|Private[A-Za-z]+|Restrict[A-Za-z]+|LockPersonality|SystemCall[A-Za-z]+|CapabilityBoundingSet|AmbientCapabilities|UMask|LimitCORE)=/.test(
            l,
          ),
        );
      expect(sandbox).toContain('ProtectSystem=strict');
      expect(sandbox).toContain('RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6');
      const dir = '/run/keyflap-test';
      const sock = `${dir}/tailscaled.sock`;
      h.exec(['install', '-d', '-m', '0755', dir], { check: true });
      const listener = `require('node:net').createServer((s) => s.end()).listen(${JSON.stringify(sock)}, () => require('node:fs').chmodSync(${JSON.stringify(sock)}, 0o666))`;
      h.exec(['systemd-run', '--unit=test-sock', '--collect', NODE, '-e', listener], {
        check: true,
      });
      try {
        waitFor(h, 'the test socket', ['test', '-S', sock], () => true, 10_000);
        const r = h.exec(
          [
            'systemd-run',
            '--wait',
            '--pipe',
            '--quiet',
            '--collect',
            `--uid=${L.users.signer}`,
            `--gid=${L.users.signer}`,
            ...sandbox.map((p) => `--property=${p}`),
            NODE,
            `${PROBE_DIR}/attempt.ts`,
            JSON.stringify([{ kind: 'connect', path: sock }]),
          ],
          { timeoutMs: 60_000 },
        );
        expect(r.status, r.stderr).toBe(0);
        const outcomes = JSON.parse(r.stdout) as Outcome[];
        expect(outcomes.map((o) => (o.ok ? 'ok' : o.code))).toEqual(['ok']);
      } finally {
        h.exec(['systemctl', 'stop', 'test-sock.service']);
        h.exec(['rm', '-rf', dir]);
      }
    });
  },
);
