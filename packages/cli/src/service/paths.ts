export const LINUX_SERVICE_PATHS = {
  prefix: '/opt/keyflap',
  coreConfig: '/etc/keyflap/core.json',
  signerConfig: '/etc/keyflap/signer.json',
  approverConfig: '/etc/keyflap/approver.json',
  coreData: '/var/lib/keyflap/core',
  signerData: '/var/lib/keyflap/signer',
  hookDir: '/var/lib/keyflap/hook',
  hostToken: '/var/lib/keyflap/hook/host-token',
  intentSocket: '/run/keyflap/intent.sock',
  adminSocket: '/run/keyflap/admin.sock',
  signerSocket: '/run/keyflap-signer/signer.sock',
  signerAdminSocket: '/run/keyflap-signer/admin.sock',
  approverApiSocket: '/run/keyflap-approver/api.sock',
  wrapper: '/usr/local/bin/keyflap',
  opToken: '/etc/keyflap/credentials/op-service-account-token.cred',
} as const;

export type ServicePaths = { [K in keyof typeof LINUX_SERVICE_PATHS]: string };

export const DARWIN_SERVICE_PATHS: ServicePaths = {
  prefix: '/opt/keyflap',
  coreConfig: '/Library/Keyflap/etc/core.json',
  signerConfig: '/Library/Keyflap/etc/signer.json',
  approverConfig: '/Library/Keyflap/etc/approver.json',
  coreData: '/Library/Keyflap/data/core',
  signerData: '/Library/Keyflap/data/signer',
  hookDir: '/Library/Keyflap/hook',
  hostToken: '/Library/Keyflap/hook/host-token',
  intentSocket: '/Library/Keyflap/run/core/intent.sock',
  adminSocket: '/Library/Keyflap/run/core/admin.sock',
  signerSocket: '/Library/Keyflap/run/signer/signer.sock',
  signerAdminSocket: '/Library/Keyflap/run/signer/admin.sock',
  approverApiSocket: '/Library/Keyflap/run/approver/api.sock',
  wrapper: '/usr/local/bin/keyflap',
  opToken: '/Library/Keyflap/credentials/signer/op-service-account-token',
};

export const SERVICE_PATHS_BY_PLATFORM = {
  linux: LINUX_SERVICE_PATHS,
  darwin: DARWIN_SERVICE_PATHS,
} as const satisfies Record<string, ServicePaths>;

export function servicePaths(platform: string = process.platform): ServicePaths {
  return Object.hasOwn(SERVICE_PATHS_BY_PLATFORM, platform)
    ? SERVICE_PATHS_BY_PLATFORM[platform as keyof typeof SERVICE_PATHS_BY_PLATFORM]
    : LINUX_SERVICE_PATHS;
}

export const SERVICE_PATHS: ServicePaths = servicePaths();

export function isServiceMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.KEYFLAP_MODE === 'service';
}
