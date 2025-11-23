import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: [
    {
      command: 'VITE_FORCE_MOCK_DATA_INDICATOR=true vite --host 127.0.0.1 --port 4173',
      port: 4173,
      reuseExistingServer: !process.env.CI,
      cwd: './',
      env: {
        ...process.env,
        VITE_FORCE_MOCK_DATA_INDICATOR: 'true',
      },
    },
  ],
});
