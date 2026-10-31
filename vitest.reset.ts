import { afterAll, vi } from 'vitest';

const envAtFileStart = { ...process.env };
const cwdAtFileStart = process.cwd();

afterAll(() => {
  for (const key of Object.keys(process.env)) {
    if (!(key in envAtFileStart)) delete process.env[key];
  }
  Object.assign(process.env, envAtFileStart);
  if (process.cwd() !== cwdAtFileStart) process.chdir(cwdAtFileStart);
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.resetModules();
});
