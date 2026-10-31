import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { hasKeyFile } from '../key-file.ts';

export type DevInstall = 'dev' | 'simple';

export function devInstallAt(dataDir: string): DevInstall | null {
  if (hasKeyFile(dataDir)) return 'simple';
  if (existsSync(join(dataDir, 'broker.sqlite'))) return 'dev';
  if (existsSync(join(dataDir, 'signer', 'keys.enc.json'))) return 'dev';
  return null;
}
