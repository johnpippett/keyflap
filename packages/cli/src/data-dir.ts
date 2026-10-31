import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const DATA_DIR_NAME = '.keyflap';
export const LEGACY_DATA_DIR_NAME = '.aab';

export function defaultDataDir(
  home: string = homedir(),
  exists: (path: string) => boolean = existsSync,
): string {
  const dir = join(home, DATA_DIR_NAME);
  const legacy = join(home, LEGACY_DATA_DIR_NAME);
  return !exists(dir) && exists(legacy) ? legacy : dir;
}

export function legacyDataDirNotice(dataDir: string, home: string = homedir()): string | null {
  if (dataDir !== join(home, LEGACY_DATA_DIR_NAME)) return null;
  return (
    'keyflap: using ~/.aab, the data dir from before the rename. To move it: stop the daemon, ' +
    'mv ~/.aab ~/.keyflap, and change ~/.aab to ~/.keyflap in your Claude Code sandbox and deny rules.'
  );
}
