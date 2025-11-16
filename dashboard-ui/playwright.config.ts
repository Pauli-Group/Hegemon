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
      command: 'python scripts/dashboard_service.py --host 127.0.0.1 --port 8001',
      port: 8001,
      reuseExistingServer: !process.env.CI,
      cwd: '..',
    },
    {
      command: 'VITE_DASHBOARD_SERVICE_URL=http://127.0.0.1:8001 vite --host 127.0.0.1 --port 4173',
      port: 4173,
      reuseExistingServer: !process.env.CI,
      cwd: './',
      env: {
        ...process.env,
        VITE_DASHBOARD_SERVICE_URL: 'http://127.0.0.1:8001',
      },
    },
  ],
});
