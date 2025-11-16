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

test('wallet dashboard renders metrics and mock transfer flow', async ({ page }) => {
  await page.goto('/wallet');
  await expect(page.getByRole('heading', { name: 'Wallet operations' })).toBeVisible();
  await expect(page.getByText('Shielded balance')).toBeVisible();
  await captureSnapshot(page, 'wallet-dashboard.svg');

  await page.getByLabel('Recipient address').fill('shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq');
  await page.getByLabel('Amount (SHC)').fill('1.25');
  await page.getByLabel('Fee (SHC)').fill('0.01');
  await page.getByLabel('Memo').fill('Playwright transfer smoke test');
  await page.getByRole('button', { name: 'Send transfer' }).click();

  await expect(page.getByText('Transfer dispatched')).toBeVisible();
  await expect(page.locator('table').locator('tr', { hasText: 'pending' }).first()).toBeVisible();
});

test('network dashboard shows analytics tiles and feed', async ({ page }) => {
  await page.goto('/network');
  await expect(page.getByRole('heading', { name: 'Network analytics' })).toBeVisible();
  await expect(page.getByText('Best height')).toBeVisible();
  await expect(page.getByText('Stale rate')).toBeVisible();
  await captureSnapshot(page, 'network-console.svg');

  await expect(page.getByText('Blocks')).toBeVisible();
  await expect(page.getByText('Transactions').first()).toBeVisible();
});
