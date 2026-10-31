import { describe, expect, it } from 'vitest';
import { host, outcomes, skipReason, where } from './helpers.ts';
import { L, LABELS, launchdPid, NODE, owner, PAGE, sha256 } from './platform.ts';
import type { Attempt } from './probe/attempt.ts';

const PORT = 8766;

function served(path: string): { status: number; sha256: string } {
  const script = `
    const http = require('node:http');
    const crypto = require('node:crypto');
    http.get({ host: '127.0.0.1', port: ${PORT}, path: ${JSON.stringify(path)},
      headers: { host: 'approver.localhost:${PORT}' } }, (res) => {
      const h = crypto.createHash('sha256');
      res.on('data', (c) => h.update(c));
      res.on('end', () => console.log(JSON.stringify({ status: res.statusCode, sha256: h.digest('hex') })));
    }).on('error', (e) => { console.log(JSON.stringify({ status: 0, sha256: e.code })); });`;
  const r = host().exec([NODE, '-e', script], { check: true });
  return JSON.parse(r.stdout) as { status: number; sha256: string };
}

const binds: Record<string, Attempt> =
  L.os === 'darwin'
    ? {
        loopback: { kind: 'bind', host: '127.0.0.1', port: PORT },
        loopback6: { kind: 'bind', host: '::1', port: PORT },
        any: { kind: 'bind', host: '0.0.0.0', port: PORT },
        any6: { kind: 'bind', host: '::', port: PORT },
      }
    : {
        loopback: { kind: 'bind', host: '127.0.0.1', port: PORT },
        any: { kind: 'bind', host: '0.0.0.0', port: PORT },
      };
const inUse = Object.fromEntries(Object.keys(binds).map((k) => [k, 'EADDRINUSE']));

describe.skipIf(skipReason !== null)(
  `invariant 5: the approver page is not the core's (${where})`,
  () => {
    it('the page on the approver port is the root-owned install, served by keyflap-web', () => {
      const h = host();
      for (const f of ['app.js', 'approval-check.js', 'handoff.js', 'handoff-zoom.js', 'sw.js']) {
        expect(served(`/${f}`), f).toEqual({ status: 200, sha256: sha256(h, `${PAGE}/${f}`) });
      }
      if (L.os === 'darwin') {
        const front = launchdPid(h, LABELS.approver);
        expect(h.exec(['ps', '-o', 'user=', '-p', String(front)]).stdout.trim()).toBe(L.users.web);
      } else {
        const show = (p: string) =>
          h
            .exec(['systemctl', 'show', '-p', p, '--value', 'keyflap-approver.service'])
            .stdout.trim();
        expect(show('User')).toBe('keyflap-web');
        expect(show('RestrictAddressFamilies')).toBe('AF_UNIX');
      }
      const wheel = L.os === 'darwin' ? 'wheel' : 'root';
      expect([owner(h, PAGE), owner(h, `${PAGE}/app.js`)]).toEqual([
        `root:${wheel} 755`,
        `root:${wheel} 644`,
      ]);
    });

    it("the core's uid can't take the approver port, even while the front is stopped", () => {
      expect(outcomes(binds, L.users.core)).toEqual(inUse);
      const h = host();
      if (L.os === 'darwin') {
        const listeners = h.exec([
          'lsof',
          '-nP',
          '-a',
          '-p',
          '1',
          `-iTCP:${PORT}`,
          '-sTCP:LISTEN',
          '-Fn',
        ]);
        expect(
          listeners.stdout
            .split('\n')
            .filter((l) => l.startsWith('n'))
            .sort(),
        ).toEqual([`n127.0.0.1:${PORT}`, `n[::1]:${PORT}`]);
        const front = launchdPid(h, LABELS.approver);
        h.exec(['kill', '-9', String(front)], { check: true });
        expect(outcomes(binds, L.users.core)).toEqual(inUse);
        expect(served('/').status).toBe(200);
        expect(launchdPid(h, LABELS.approver)).not.toBe(front);
        return;
      }
      h.exec(['systemctl', 'stop', 'keyflap-approver.service'], { check: true });
      try {
        expect(outcomes(binds, L.users.core)).toEqual(inUse);
        expect(served('/').status).toBe(200);
      } finally {
        h.exec(['systemctl', 'start', 'keyflap-approver.service']);
      }
    });

    it("the core's uid can't change the page files", () => {
      expect(
        outcomes(
          {
            appJs: { kind: 'write', path: `${PAGE}/app.js` },
            check: { kind: 'write', path: `${PAGE}/approval-check.js` },
            newFile: { kind: 'create', dir: PAGE },
          },
          L.users.core,
        ),
      ).toEqual({ appJs: 'EACCES', check: 'EACCES', newFile: 'EACCES' });
    });

    it("only the front reaches the core's API socket", () => {
      const h = host();
      expect(owner(h, L.sockets.approverDir)).toBe(`root:${L.users.web} 750`);
      expect(owner(h, L.sockets.approverApi)).toBe(`root:${L.users.web} 660`);
      const api = { api: { kind: 'connect' as const, path: L.sockets.approverApi } };
      expect(outcomes(api)).toEqual({ api: 'EACCES' });
      expect(outcomes(api, L.users.web)).toEqual({ api: 'ok' });
      expect(outcomes(api, L.users.core)).toEqual({ api: 'EACCES' });
    });
  },
);
