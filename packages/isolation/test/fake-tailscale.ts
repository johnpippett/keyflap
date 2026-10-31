import { dirname } from 'node:path';
import { AGENT_USER } from './container.ts';
import type { Host } from './platform.ts';

export const FAKE_TAILSCALE = '/usr/bin/tailscale';
export const SERVE_FILE = '/var/lib/keyflap-test/serve.json';
export const STATUS_FILE = '/var/lib/keyflap-test/status.json';
export const APPROVER_TARGET = 'http://127.0.0.1:8766';

export function serveConfig(proxy: string): string {
  const cfg = {
    TCP: { '8766': { HTTPS: true } },
    Web: { 'approver.localhost:8766': { Handlers: { '/': { Proxy: proxy } } } },
  };
  return `${JSON.stringify(cfg)}\n`;
}

export function tailscaleStatus(onTailnet: boolean): string {
  const st = onTailnet
    ? { BackendState: 'Running', TailscaleIPs: ['100.101.102.103'], Self: { InNetworkMap: true } }
    : { BackendState: 'NoState', TailscaleIPs: null, Self: { InNetworkMap: false } };
  return `${JSON.stringify(st)}\n`;
}

const SCRIPT = [
  '#!/bin/sh',
  `case "$1" in status) exec cat ${STATUS_FILE} ;; *) exec cat ${SERVE_FILE} ;; esac`,
  '',
].join('\n');

function writeAsAgent(c: Host, file: string, text: string): void {
  const r = c.as(AGENT_USER, ['sh', '-c', `cat >${file}`], { input: text });
  if (r.status !== 0) throw new Error(`writing ${file} as ${AGENT_USER}: ${r.stderr}`);
}

export function writeServeConfig(c: Host, json: string): void {
  writeAsAgent(c, SERVE_FILE, json);
}

export function writeTailscaleStatus(c: Host, onTailnet: boolean): void {
  writeAsAgent(c, STATUS_FILE, tailscaleStatus(onTailnet));
}

export function plantFakeTailscale(c: Host): void {
  c.exec(['sh', '-c', `cat >${FAKE_TAILSCALE} && chmod 0755 ${FAKE_TAILSCALE}`], {
    input: SCRIPT,
    check: true,
  });
  c.exec(['install', '-d', '-m', '0755', dirname(SERVE_FILE)], { check: true });
  for (const file of [SERVE_FILE, STATUS_FILE]) {
    c.exec(['install', '-m', '0644', '-o', AGENT_USER, '-g', AGENT_USER, '/dev/null', file], {
      check: true,
    });
  }
  writeServeConfig(c, serveConfig(APPROVER_TARGET));
  writeTailscaleStatus(c, true);
}
