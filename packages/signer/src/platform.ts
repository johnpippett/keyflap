export function maxUnixSocketPathBytes(platform: string = process.platform): number {
  return platform === 'linux' ? 108 : 103;
}

export function unixSocketPathProblem(
  path: string,
  what: string,
  platform: string = process.platform,
): string | null {
  const max = maxUnixSocketPathBytes(platform);
  const n = Buffer.byteLength(path);
  if (n <= max) return null;
  return (
    `${what}: ${path} is ${n} bytes, but unix socket paths are limited to ${max} bytes on ` +
    `${platform}. Use a shorter directory (for example a shorter --data-dir).`
  );
}

export function assertUnixSocketPath(path: string, what: string): void {
  const problem = unixSocketPathProblem(path, what);
  if (problem) throw new Error(problem);
}

export const SERVICE_PLATFORMS = {
  linux: { manager: 'systemd' },
  darwin: { manager: 'launchd' },
} as const;

export type ServicePlatform = keyof typeof SERVICE_PLATFORMS;
export type ServiceManagerKind = (typeof SERVICE_PLATFORMS)[ServicePlatform]['manager'];

export function servicePlatform(platform: string = process.platform): ServicePlatform | null {
  return Object.hasOwn(SERVICE_PLATFORMS, platform) ? (platform as ServicePlatform) : null;
}

export function servicePlatformProblem(platform: string = process.platform): string | null {
  if (servicePlatform(platform) !== null) return null;
  return (
    `service mode needs Linux with systemd or macOS with launchd; it is not built for ${platform} ` +
    '(docs/MAC_PLAN.md). Use same-user dev mode: keyflap daemon --unprotected'
  );
}
