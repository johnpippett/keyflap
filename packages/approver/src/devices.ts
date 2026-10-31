import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import type { ApnsEnvironment } from './apns.ts';
import type { PushSubscription } from './webpush.ts';

export type DeviceKind = 'web' | 'native';

export interface Device {
  id: string;
  tokenHash: string;
  credentialId: string;
  createdAt: number;
  kind?: DeviceKind;
  push?: PushSubscription;
  apns?: { token: string; environment: ApnsEnvironment };
}

const hash = (token: string) => createHash('sha256').update(token).digest('base64url');

export class DeviceStore {
  private devices: Device[];
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
    this.devices = existsSync(path)
      ? ((JSON.parse(readFileSync(path, 'utf8')) as { devices: Device[] }).devices ?? [])
      : [];
  }

  list(): readonly Device[] {
    return this.devices;
  }

  add(
    credentialId: string,
    now = Date.now(),
    kind: DeviceKind = 'web',
  ): { device: Device; token: string } {
    const token = randomBytes(32).toString('base64url');
    const device: Device = {
      id: `dev_${randomBytes(8).toString('base64url')}`,
      tokenHash: hash(token),
      credentialId,
      createdAt: now,
      kind,
    };
    this.devices.push(device);
    this.flush();
    return { device, token };
  }

  byToken(token: unknown, kind: DeviceKind = 'web'): Device | undefined {
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return undefined;
    const h = Buffer.from(hash(token));
    return this.devices.find((d) => {
      const b = Buffer.from(d.tokenHash);
      return (d.kind ?? 'web') === kind && b.length === h.length && timingSafeEqual(b, h);
    });
  }

  setApns(deviceId: string, apns: Device['apns']): void {
    const d = this.devices.find((x) => x.id === deviceId);
    if (!d) return;
    if (apns) d.apns = { token: apns.token, environment: apns.environment };
    else delete d.apns;
    this.flush();
  }

  remove(deviceId: string): boolean {
    const before = this.devices.length;
    this.devices = this.devices.filter((d) => d.id !== deviceId);
    if (this.devices.length === before) return false;
    this.flush();
    return true;
  }

  setPush(deviceId: string, push: PushSubscription | undefined): void {
    const d = this.devices.find((x) => x.id === deviceId);
    if (!d) return;
    if (push) d.push = push;
    else delete d.push;
    this.flush();
  }

  retainCredentials(trusted: ReadonlySet<string>): void {
    const before = this.devices.length;
    this.devices = this.devices.filter((d) => trusted.has(d.credentialId));
    if (this.devices.length !== before) this.flush();
  }

  private flush(): void {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify({ devices: this.devices }), { mode: 0o600 });
    renameSync(tmp, this.path);
  }
}
