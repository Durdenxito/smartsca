import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  workers: 1,
  timeout: 150_000,
  use: { baseURL: 'http://127.0.0.1:5173', trace: 'retain-on-failure' },
  webServer: [
    {
      command: 'java -jar ../backend/target/smartsca-0.0.1-SNAPSHOT.jar',
      env: { SMARTSCA_ENRICHMENT_ENABLED: 'false' },
      url: 'http://127.0.0.1:8080/api/projects',
      timeout: 120_000,
    },
    {
      command: 'npm run dev -- --host 127.0.0.1 --port 5173 --strictPort',
      url: 'http://127.0.0.1:5173',
    },
  ],
});
