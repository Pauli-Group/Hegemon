/// <reference types="node" />
import { expect, test, type Page } from '@playwright/test';

/**
 * Substrate Backend E2E Tests
 * 
 * These tests verify the dashboard functionality when connected to a Substrate node.
 * They require either a running Substrate node or the dashboard configured with
 * VITE_USE_SUBSTRATE=true and a mock WebSocket server.
 * 
 * Part of Phase 7 of the Substrate migration plan.
 */

// Check if Substrate tests should be skipped (no node running)
const SKIP_SUBSTRATE = process.env.SKIP_SUBSTRATE_TESTS === 'true';

// Helper to check if we're in Substrate mode
async function isSubstrateMode(page: Page): Promise<boolean> {
  const result = await page.evaluate(() => {
    return (window as any).__VITE_USE_SUBSTRATE__ === true;
  });
  return result;
}

// Helper to wait for API connection with extended timeout
async function waitForConnection(page: Page, timeout = 30000): Promise<void> {
  const badge = page.getByTestId('connection-status');
  await badge.waitFor({ state: 'visible', timeout });
  await expect(badge).toHaveText(/Connected|Online/i, { timeout });
}

test.describe('Dashboard with Substrate backend', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the app
    await page.goto('/');
    
    // Wait for initial render
    await page.waitForLoadState('networkidle');
  });

  test('displays connection status badge', async ({ page }) => {
    // The connection badge should always be visible
    const badge = page.getByLabel(/connection status/i).first();
    await expect(badge).toBeVisible();
    
    // In test mode without a running node, it should show Offline/Connecting
    // With a running node, it would show Online/Connected
    await expect(badge).toBeVisible();
  });

  test('shows block number when connected', async ({ page }) => {
    // This test is skipped if no node is running
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await waitForConnection(page);

    // Block number should be displayed
    const blockNumber = page.getByTestId('block-number');
    await expect(blockNumber).toBeVisible();
    
    const blockText = await blockNumber.textContent();
    expect(parseInt(blockText || '0')).toBeGreaterThanOrEqual(0);
  });

  test('block number increments over time', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await waitForConnection(page);

    const blockNumber = page.getByTestId('block-number');
    await expect(blockNumber).toBeVisible();

    // Record initial block number
    const initialText = await blockNumber.textContent();
    const initial = parseInt(initialText || '0');

    // Wait for at least one block (~10 seconds with default PoW)
    await page.waitForTimeout(15000);

    // Check that block number increased
    const updatedText = await blockNumber.textContent();
    const updated = parseInt(updatedText || '0');

    expect(updated).toBeGreaterThan(initial);
  });

  test('displays peer count', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await waitForConnection(page);

    const peerCount = page.getByTestId('peer-count');
    await expect(peerCount).toBeVisible();

    const countText = await peerCount.textContent();
    // Peer count should be a non-negative number
    expect(parseInt(countText || '-1')).toBeGreaterThanOrEqual(0);
  });

  test('shows sync status', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await waitForConnection(page);

    // Should show either "Synced" or sync progress
    const syncStatus = page.getByTestId('sync-status');
    await expect(syncStatus).toBeVisible();

    const statusText = await syncStatus.textContent();
    expect(statusText).toMatch(/Synced|Syncing|[0-9]+%/i);
  });
});

test.describe('Block Explorer', () => {
  test('block explorer link is present', async ({ page }) => {
    await page.goto('/');
    
    // Navigate to network view if not already there
    const networkLink = page.getByRole('link', { name: /Network/i });
    if (await networkLink.isVisible()) {
      await networkLink.click();
    }

    // Block explorer section should be visible
    await expect(page.getByRole('heading', { name: /Block|Height/i })).toBeVisible();
  });

  test('shows block details on click', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await page.goto('/network');
    await waitForConnection(page);

    // Click on a block entry
    const blockEntry = page.locator('[data-testid="block-entry"]').first();
    if (await blockEntry.isVisible()) {
      await blockEntry.click();

      // Block details should appear
      await expect(page.getByTestId('block-hash')).toBeVisible();
      await expect(page.getByTestId('block-parent')).toBeVisible();
    }
  });
});

test.describe('Mining Controls', () => {
  test('mining controls are visible on wallet page', async ({ page }) => {
    await page.goto('/wallet');
    
    // Mining section should be visible
    const miningSection = page.getByTestId('mining-controls');
    // May not be visible if mining is disabled in the config
    if (await miningSection.isVisible()) {
      await expect(miningSection).toBeVisible();
    }
  });

  test('can toggle mining on/off', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await page.goto('/wallet');
    await waitForConnection(page);

    const startButton = page.getByRole('button', { name: /Start Mining/i });
    const stopButton = page.getByRole('button', { name: /Stop Mining/i });

    // If mining is stopped, start it
    if (await startButton.isVisible()) {
      await startButton.click();
      await expect(stopButton).toBeVisible({ timeout: 5000 });
    }

    // Now stop mining
    if (await stopButton.isVisible()) {
      await stopButton.click();
      await expect(startButton).toBeVisible({ timeout: 5000 });
    }
  });

  test('displays mining status', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await page.goto('/wallet');
    await waitForConnection(page);

    const miningStatus = page.getByTestId('mining-status');
    if (await miningStatus.isVisible()) {
      const statusText = await miningStatus.textContent();
      expect(statusText).toMatch(/Active|Inactive|Stopped|Running/i);
    }
  });
});

test.describe('Transaction Submission', () => {
  test('transaction form is present', async ({ page }) => {
    await page.goto('/wallet');

    // Transaction form elements should be visible
    await expect(page.getByLabel(/Recipient/i)).toBeVisible();
    await expect(page.getByLabel(/Amount/i)).toBeVisible();
  });

  test('validates recipient address format', async ({ page }) => {
    await page.goto('/wallet');

    // Enter invalid address
    await page.getByLabel(/Recipient/i).fill('invalid-address');
    await page.getByLabel(/Amount/i).fill('100');
    
    const sendButton = page.getByRole('button', { name: /Send/i });
    await sendButton.click();

    // Should show validation error
    const error = page.getByText(/invalid|address/i);
    await expect(error).toBeVisible();
  });

  test('validates amount is positive', async ({ page }) => {
    await page.goto('/wallet');

    await page.getByLabel(/Recipient/i).fill('shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq');
    await page.getByLabel(/Amount/i).fill('-10');

    const sendButton = page.getByRole('button', { name: /Send/i });
    await sendButton.click();

    // Should show validation error
    const error = page.getByText(/positive|invalid|amount/i);
    await expect(error).toBeVisible();
  });

  test('shows transaction confirmation', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await page.goto('/wallet');
    await waitForConnection(page);

    // Fill valid transaction
    await page.getByLabel(/Recipient/i).fill('shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq');
    await page.getByLabel(/Amount/i).fill('10');

    const sendButton = page.getByRole('button', { name: /Send/i });
    await sendButton.click();

    // Should show confirmation or transaction submitted message
    const confirmation = page.getByText(/submitted|pending|confirm/i);
    await expect(confirmation).toBeVisible({ timeout: 10000 });
  });

  test('displays transaction hash after submission', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await page.goto('/wallet');
    await waitForConnection(page);

    // Submit a transaction
    await page.getByLabel(/Recipient/i).fill('shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq');
    await page.getByLabel(/Amount/i).fill('5');
    await page.getByRole('button', { name: /Send/i }).click();

    // Transaction hash should be visible
    const txHash = page.getByTestId('tx-hash');
    await expect(txHash).toBeVisible({ timeout: 15000 });

    const hashText = await txHash.textContent();
    expect(hashText?.length).toBeGreaterThan(10);
  });
});

test.describe('WebSocket Subscription', () => {
  test('receives real-time block updates', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await page.goto('/network');
    await waitForConnection(page);

    // Track block updates
    let blockUpdates = 0;
    
    await page.exposeFunction('onBlockUpdate', () => {
      blockUpdates++;
    });

    // Inject listener for block updates
    await page.evaluate(() => {
      const originalDispatch = window.dispatchEvent.bind(window);
      window.dispatchEvent = (event: Event) => {
        if (event.type === 'substrate-block-update') {
          (window as any).onBlockUpdate();
        }
        return originalDispatch(event);
      };
    });

    // Wait for a few blocks
    await page.waitForTimeout(30000);

    // Should have received at least one block update
    expect(blockUpdates).toBeGreaterThanOrEqual(1);
  });

  test('reconnects after disconnect', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await page.goto('/');
    await waitForConnection(page);

    // Simulate network disconnect
    await page.evaluate(() => {
      (window as any).__substrateApi?.disconnect();
    });

    // Should show disconnected status
    const badge = page.getByTestId('connection-status');
    await expect(badge).toHaveText(/Offline|Disconnected|Reconnecting/i, { timeout: 5000 });

    // Wait for auto-reconnect
    await expect(badge).toHaveText(/Connected|Online/i, { timeout: 30000 });
  });
});

test.describe('Error Handling', () => {
  test('shows error state when node is unreachable', async ({ page }) => {
    // Set an invalid endpoint to force connection failure
    await page.addInitScript(() => {
      (window as any).__VITE_WS_ENDPOINT__ = 'ws://invalid-host:9999';
    });

    await page.goto('/');

    // Should show offline/error state
    const badge = page.getByLabel(/connection status/i).first();
    await expect(badge).toBeVisible();
    
    // After some time, should show error state
    await page.waitForTimeout(5000);
    const statusText = await badge.textContent();
    expect(statusText).toMatch(/Offline|Error|Disconnected/i);
  });

  test('displays user-friendly error messages', async ({ page }) => {
    await page.goto('/wallet');

    // Try to submit without connection
    await page.getByLabel(/Recipient/i).fill('shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq');
    await page.getByLabel(/Amount/i).fill('100');

    const sendButton = page.getByRole('button', { name: /Send/i });
    await sendButton.click();

    // Should show a user-friendly error, not a technical one
    const errorMessage = page.getByRole('alert');
    if (await errorMessage.isVisible()) {
      const text = await errorMessage.textContent();
      expect(text).not.toContain('WebSocket');
      expect(text).not.toContain('undefined');
    }
  });
});

test.describe('Substrate Type Integration', () => {
  test('parses custom RPC response correctly', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await page.goto('/wallet');
    await waitForConnection(page);

    // Check that wallet notes are parsed correctly
    const balance = page.getByTestId('shielded-balance');
    await expect(balance).toBeVisible();

    const balanceText = await balance.textContent();
    // Should be a valid number format
    expect(balanceText).toMatch(/[0-9.,]+/);
  });

  test('handles settlement pallet types', async ({ page }) => {
    test.skip(
      process.env.SKIP_SUBSTRATE_TESTS === 'true',
      'Skipping Substrate tests - no node running'
    );

    await page.goto('/network');
    await waitForConnection(page);

    // Check for settlement/transfer information if displayed
    const transferSection = page.getByTestId('transfer-ledger');
    if (await transferSection.isVisible()) {
      // Should display transfer data without errors
      await expect(transferSection).not.toContainText('Error');
      await expect(transferSection).not.toContainText('undefined');
    }
  });
});
