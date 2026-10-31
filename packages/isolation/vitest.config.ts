import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'isolation',
    root: import.meta.dirname,
    include: ['test/**/*.test.ts'],
    globalSetup: ['test/global-setup.ts'],
    testTimeout: 300_000,
    hookTimeout: 300_000,
    fileParallelism: false,
  },
});
