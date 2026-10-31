import type { System } from './system.ts';

export const APPROVER_PORT = 8766;

export const MACOS_APP_CLI = '/Applications/Tailscale.app/Contents/MacOS/Tailscale';

const ROOT_TAILSCALE = ['/usr/bin/tailscale', '/usr/sbin/tailscale', '/usr/local/bin/tailscale'];

function rootOnly(sys: System, path: string): boolean {
  for (let p = path; ; p = p.slice(0, Math.max(1, p.lastIndexOf('/')))) {
    const st = sys.stat(p);
    if (st?.uid !== 0 || (st.mode & 0o022) !== 0) return false;
    if (p === '/') return true;
  }
}

export interface TailscaleCli {
  path: string;
  asUser: boolean;
}

export function tailscaleCli(sys: System, service: boolean): TailscaleCli | null {
  const isFile = (p: string) => sys.stat(p)?.isFile === true;
  const app = sys.platform === 'darwin' ? [MACOS_APP_CLI] : [];
  if (!service) {
    if (sys.which('tailscale')) return { path: 'tailscale', asUser: false };
    const p = app.find(isFile);
    return p ? { path: p, asUser: false } : null;
  }
  const candidates = [...ROOT_TAILSCALE, ...app].filter(isFile);
  const root = candidates.find((p) => rootOnly(sys, p));
  if (root) return { path: root, asUser: false };
  return candidates[0] ? { path: candidates[0], asUser: true } : null;
}

export interface TailscaleInfo {
  running: boolean;
  dnsName: string | null;
  httpsEnabled: boolean;
  problem: string | null;
}

export function parseTailscaleStatus(json: string): TailscaleInfo {
  let s: Record<string, unknown>;
  try {
    s = JSON.parse(json) as Record<string, unknown>;
  } catch {
    return { running: false, dnsName: null, httpsEnabled: false, problem: 'unreadable status' };
  }
  const state = typeof s.BackendState === 'string' ? s.BackendState : 'unknown';
  const self = (s.Self ?? {}) as Record<string, unknown>;
  const raw = typeof self.DNSName === 'string' ? self.DNSName.replace(/\.$/, '') : '';
  const dnsName = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(raw) ? raw.toLowerCase() : null;
  const certs = Array.isArray(s.CertDomains) ? (s.CertDomains as unknown[]) : [];
  const httpsEnabled =
    dnsName !== null && certs.some((c) => typeof c === 'string' && c.toLowerCase() === dnsName);
  if (state !== 'Running') {
    return {
      running: false,
      dnsName,
      httpsEnabled,
      problem: state === 'NeedsLogin' ? 'not logged in (run: tailscale up)' : `state ${state}`,
    };
  }
  if (!dnsName) {
    return { running: true, dnsName, httpsEnabled, problem: 'MagicDNS is off for this tailnet' };
  }
  if (!httpsEnabled) {
    return {
      running: true,
      dnsName,
      httpsEnabled,
      problem:
        'HTTPS certificates are not enabled for this tailnet (admin console: DNS > HTTPS Certificates)',
    };
  }
  return { running: true, dnsName, httpsEnabled, problem: null };
}

export function tailscaleBin(sys: System): string | null {
  const cli = tailscaleCli(sys, false);
  if (!cli) return null;
  return cli.path.startsWith('/') ? cli.path : sys.which(cli.path);
}

export function tailscaleOrigin(dnsName: string, port = APPROVER_PORT): string {
  return `https://${dnsName}:${port}`;
}

export function serveArgs(port = APPROVER_PORT, target = `http://127.0.0.1:${APPROVER_PORT}`) {
  return ['serve', '--bg', `--https=${port}`, target];
}

function serveBin(sys: System, service: boolean): string {
  return (service ? tailscaleCli(sys, true)?.path : tailscaleBin(sys)) ?? 'tailscale';
}

export function serveCommand(
  sys: System,
  o: { service: boolean; port: number; target: string },
): string {
  return [serveBin(sys, o.service), ...serveArgs(o.port, o.target)].join(' ');
}

export function serveResetCommand(sys: System, service: boolean): string {
  return `${serveBin(sys, service)} serve reset`;
}

export function serveState(
  json: string,
  dnsName: string,
  port = APPROVER_PORT,
  target = `http://127.0.0.1:${APPROVER_PORT}`,
): 'served' | 'free' | 'conflict' {
  let s: Record<string, unknown>;
  try {
    s = JSON.parse(json || '{}') as Record<string, unknown>;
  } catch {
    return 'free';
  }
  const web = (s.Web ?? {}) as Record<string, { Handlers?: Record<string, { Proxy?: string }> }>;
  const site = web[`${dnsName}:${port}`];
  const tcp = (s.TCP ?? {}) as Record<string, unknown>;
  if (!site) return tcp[String(port)] ? 'conflict' : 'free';
  const proxy = site.Handlers?.['/']?.Proxy;
  if (!proxy) return 'conflict';
  const norm = (u: string) => u.replace(/\/$/, '').replace('://localhost:', '://127.0.0.1:');
  return norm(proxy) === norm(target) ? 'served' : 'conflict';
}
