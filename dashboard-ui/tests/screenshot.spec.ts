import { expect, test } from '@playwright/test';

const svgWrapper = (markup: string, width: number, height: number) => `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}">
  <foreignObject width="100%" height="100%">
    <div xmlns="http://www.w3.org/1999/xhtml" style="width:${width}px;height:${height}px;overflow:hidden;background:#05060a;">
      ${markup}
    </div>
  </foreignObject>
</svg>`;

test('mining console renders telemetry', async ({ page }) => {
  await page.goto('/mining');
  await page.waitForTimeout(2000);

  const viewport = page.viewportSize() ?? { width: 1280, height: 720 };
  const rootShell = page.locator('#root');
  await rootShell.waitFor({ state: 'attached' });
  const markup = await rootShell.evaluate((node) => node.innerHTML);
  const svgPayload = svgWrapper(markup, viewport.width, viewport.height);

  await expect(svgPayload).toMatchSnapshot('mining-console.svg');
});
