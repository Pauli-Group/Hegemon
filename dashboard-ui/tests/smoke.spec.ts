import { expect, test } from '@playwright/test';

const svgWrapper = (markup: string, width: number, height: number) => `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}">
  <foreignObject width="100%" height="100%">
    <div xmlns="http://www.w3.org/1999/xhtml" style="width:${width}px;height:${height}px;overflow:hidden;background:#05060a;">
      ${markup}
    </div>
  </foreignObject>
</svg>`;

async function captureSnapshot(page: import('@playwright/test').Page, name: string) {
  const viewport = page.viewportSize() ?? { width: 1280, height: 720 };
  const rootShell = page.locator('#root');
  await rootShell.waitFor({ state: 'attached' });
  const markup = await rootShell.evaluate((node) => node.innerHTML);
  const svgPayload = svgWrapper(markup, viewport.width, viewport.height);
  await expect(svgPayload).toMatchSnapshot(name);
}

test('wallet dashboard renders metrics and transfer flow', async ({ page }) => {
  await page.goto('/wallet');
  const navBadge = page.getByLabel(/Node metrics feed connection status/i).first();
  await expect(navBadge).toHaveText(/Offline/i);
  await expect(page.getByRole('heading', { name: 'Wallet operations' })).toBeVisible();
  await expect(page.getByText('Shielded balance')).toBeVisible();
  await captureSnapshot(page, 'wallet-dashboard.svg');

  await page.getByLabel('Recipient address').fill('shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq');
  await page.getByLabel('Amount (HGN)').fill('1.25');
  await page.getByLabel('Fee (HGN)').fill('0.01');
  await page.getByLabel('Memo').fill('Playwright transfer smoke test');
  await page.getByRole('button', { name: 'Send transfer' }).click();

  const toast = page.getByText(/Transaction .* submitted\./);
  await expect(toast).toBeVisible();
  const toastText = (await toast.textContent()) ?? '';
  const match = toastText.match(/Transaction ([0-9a-zA-Z-]+)\b/);
  const requirePendingRow = Boolean(process.env.CI);

  if (requirePendingRow && match) {
    const pendingRow = page.locator('table').locator('tr', { hasText: 'pending' }).first();
    await expect(pendingRow).toBeVisible();
    const prefix = match[1].slice(0, 6);
    await expect(pendingRow.locator('code', { hasText: prefix })).toBeVisible();
  } else {
    await expect(page.locator('table')).toBeVisible();
  }
});

test('network dashboard shows analytics tiles and feed', async ({ page }) => {
  await page.goto('/network');
  const navBadge = page.getByLabel(/Node metrics feed connection status/i).first();
  await expect(navBadge).toHaveText(/Offline/i);
  await expect(page.getByRole('heading', { name: 'Network analytics' })).toBeVisible();
  await expect(page.getByText('Best height')).toBeVisible();
  await expect(page.getByText('Stale rate')).toBeVisible();
  await captureSnapshot(page, 'network-console.svg');

  await expect(page.getByText('Blocks')).toBeVisible();
  await expect(page.getByText('Transactions').first()).toBeVisible();
});

test('quickstart timeline runs the end-to-end action', async ({ page }) => {
  await page.goto('/quickstart');
  const runButton = page.getByRole('button', { name: /Run quickstart/i });
  await expect(runButton).toBeVisible();
  await runButton.click();

  const copyButton = page.getByTestId('copy-logs-button');
  await expect(copyButton).toBeVisible();

  const firstStatusChip = page.getByTestId('command-status-1');
  await expect(firstStatusChip).not.toHaveText(/Pending/i, { timeout: 15000 });
});
