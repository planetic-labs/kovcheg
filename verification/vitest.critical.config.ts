import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      exclude: ['**/*.spec.ts', '**/*.integration-check.ts'],
      include: [
        'apps/auth/src/a2/**/*.ts',
        'apps/api/src/message-flow/**/*.ts',
        'apps/api/src/realtime/**/*.ts',
        'apps/worker/src/realtime/**/*.ts',
        'apps/worker/src/startup.ts',
      ],
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      reportsDirectory: '.artifacts/verification/deep/coverage',
    },
    include: [
      'apps/auth/src/a2/**/*.spec.ts',
      'apps/api/src/message-flow/**/*.spec.ts',
      'apps/api/src/realtime/**/*.spec.ts',
      'apps/worker/src/realtime/**/*.spec.ts',
      'apps/worker/src/startup.spec.ts',
    ],
  },
});
