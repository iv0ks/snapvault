import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts', 'src/**/*.test.ts'],
    // The integration test boots the app without touching Postgres; keep it
    // serial and deterministic.
    fileParallelism: false,
  },
});
