import { describe, expect, it } from 'vitest';
import { env, host, outcomes, skipReason, where } from './helpers.ts';
import { L } from './platform.ts';

const S = L.sockets;
const KEYFLAP = '/usr/local/bin/keyflap';

describe.skipIf(skipReason !== null)(`invariant 9: service mode (${where})`, () => {
  it('the user uid cannot connect to the signer or either admin socket', () => {
    const r = outcomes({
      signer: { kind: 'connect', path: S.signer },
      signerAdmin: { kind: 'connect', path: S.signerAdmin },
      signerDir: { kind: 'list', path: S.signerDir },
      coreAdmin: { kind: 'connect', path: S.coreAdmin },
    });
    expect(r).toEqual({
      signer: 'EACCES',
      signerAdmin: 'EACCES',
      signerDir: 'EACCES',
      coreAdmin: 'EACCES',
    });
    expect(outcomes({ a: { kind: 'connect', path: S.signerAdmin } }, L.users.signer)).toEqual({
      a: 'EACCES',
    });
    expect(outcomes({ a: { kind: 'connect', path: S.coreAdmin } }, L.users.core)).toEqual({
      a: 'EACCES',
    });
  });

  it('only keyflap-core reaches the signer socket, and only root the admin sockets', () => {
    const r = outcomes({ signer: { kind: 'connect', path: S.signer } }, L.users.core);
    expect(r.signer).toBe('ok');
    const h = host();
    const stat = (p: string) => {
      const fmt = L.os === 'darwin' ? ['-f', '%Su:%Sg %Lp'] : ['-c', '%U:%G %a'];
      return h.exec(['stat', ...fmt, p]).stdout.trim();
    };
    expect(stat(S.signer)).toBe(`${L.users.signer}:${L.users.core} 660`);
    expect(stat(S.signerDir)).toBe(`root:${L.users.core} 750`);
    for (const s of [S.coreAdmin, S.signerAdmin]) {
      expect(stat(s), s).toBe(`root:${L.adminSocketGroup} 600`);
    }
    expect(stat(S.intent).replace(/:\S+/, '')).toBe(`${L.agentUser} 600`);
    expect(outcomes({ intent: { kind: 'connect', path: S.intent } })).toEqual({ intent: 'ok' });
  });

  it('a connection without the channel key gets nothing from the signer', () => {
    const script = `
      const net = require('node:net');
      const s = net.connect(${JSON.stringify(S.signer)});
      let buf = Buffer.alloc(0); const frames = [];
      s.on('data', (d) => { buf = Buffer.concat([buf, d]);
        while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
          frames.push(JSON.parse(buf.subarray(4, 4 + buf.readUInt32BE(0)).toString()));
          buf = buf.subarray(4 + buf.readUInt32BE(0));
          if (frames.length === 1) {
            const body = JSON.stringify({ op: 'list_approvers' });
            const p = Buffer.from(JSON.stringify({ t: 'req', seq: 1, body, mac: 'AAAA' }));
            const h = Buffer.alloc(4); h.writeUInt32BE(p.length); s.write(Buffer.concat([h, p]));
          }
        } });
      s.on('close', () => { console.log(JSON.stringify(frames.map((f) => f.t))); });
      s.on('error', () => {});`;
    const r = host().as(L.users.core, [L.node, '-e', script]);
    expect(JSON.parse(r.stdout)).toEqual(['hello']);
  });

  it("admin commands from the user's uid are refused; root's work", () => {
    const h = host();
    const agentNames = () =>
      (
        JSON.parse(h.exec([KEYFLAP, 'agent', 'list', '--json'], { check: true }).stdout) as {
          name: string;
        }[]
      ).map((a) => a.name);
    const namesBefore = agentNames();
    const users = L.os === 'darwin' ? [L.agentUser, env.otherUser as string] : [L.agentUser];
    for (const user of users) {
      for (const cmd of [
        ['agent', 'list'],
        ['agent', 'add', 'rogue'],
        ['password', 'list'],
        ['approver', 'list'],
        ['approver', 'pair'],
        ['status'],
      ]) {
        const r = h.as(user, [KEYFLAP, ...cmd]);
        expect(r.status, `${user}: ${cmd.join(' ')}`).not.toBe(0);
        expect(r.stderr, `${user}: ${cmd.join(' ')}`).toMatch(/root-only: run this with sudo/);
      }
    }
    expect(agentNames()).toEqual(namesBefore);
    expect(namesBefore).not.toContain('rogue');
    const approvers = h.exec([KEYFLAP, 'approver', 'list', '--json'], { check: true });
    expect(JSON.parse(approvers.stdout)).toHaveLength(1);
  });
});
