import { defineConfig } from 'vitest/config';
import { E2E_EXCLUDE, E2E_INCLUDE } from './scripts/lib/e2e-files.ts';
import { findModuleMockingFiles } from './scripts/lib/module-mocks.ts';

const unitInclude = ['packages/*/test/**/*.test.ts', 'scripts/**/*.test.ts'];
const unitExclude = ['packages/*/test/**/*.e2e.test.ts', 'packages/isolation/**'];

const sharedWorkers = process.env.KEYFLAP_TEST_SHARED_WORKERS === '1';

const moduleMockingUnitFiles = sharedWorkers
  ? findModuleMockingFiles(import.meta.dirname, unitInclude, unitExclude)
  : [];

const unit = {
  testTimeout: 15_000,
  setupFiles: ['./vitest.setup.ts'],
};

const sharedWorkerUnit = {
  exclude: [...unitExclude, ...moduleMockingUnitFiles],
  isolate: false,
  setupFiles: ['./vitest.setup.ts', './vitest.reset.ts'],
};

const isolatedUnitProject =
  moduleMockingUnitFiles.length === 0
    ? []
    : [{ test: { ...unit, name: 'unit-isolated', include: moduleMockingUnitFiles } }];

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          ...unit,
          name: 'unit',
          include: unitInclude,
          exclude: unitExclude,
          ...(sharedWorkers ? sharedWorkerUnit : {}),
        },
      },
      ...isolatedUnitProject,
      {
        test: {
          name: 'e2e',
          include: E2E_INCLUDE,
          exclude: E2E_EXCLUDE,
          testTimeout: 60_000,
          hookTimeout: 60_000,
          fileParallelism: false,
          setupFiles: ['./vitest.setup.ts'],
        },
      },
    ],
  },
});
