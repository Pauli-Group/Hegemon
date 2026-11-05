import { describe, it, expect, vi } from 'vitest';
import { readRewardRpc } from '../electron/rewardRpc';
import type { RewardReadMethod } from '../src/lib/rewardAccounts';
describe('read-only public account bridge', () => {
  it('uses the exact read method, response id and loopback HTTP transport', async () => {
    const fetcher = vi.fn(async (url, init) => {
      expect(url).toBe('http://127.0.0.1:9944/');
      expect(init.credentials).toBe('omit');
      const request = JSON.parse(init.body);
      expect(request.method).toBe('hegemon_rewardAccount');
      expect(request.params).toEqual([{ address: 'public', at: 'hash' }]);
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: request.id,
          result: { available_atoms: '9007199254740993' },
        }),
      );
    });
    expect(
      await readRewardRpc(
        'ws://127.0.0.1:9944',
        'hegemon_rewardAccount',
        { address: 'public', at: 'hash' },
        fetcher as typeof fetch,
      ),
    ).toEqual({ available_atoms: '9007199254740993' });
  });
  it('refuses submission, remote hosts and URL credentials before any request', async () => {
    const fetcher = vi.fn();
    for (const [url, method] of [
      ['http://127.0.0.1:9944', 'hegemon_submitAction'],
      ['https://evil.example', 'hegemon_rewardAccount'],
      ['http://user:pass@localhost:9944', 'hegemon_rewardAccount'],
    ])
      await expect(
        readRewardRpc(url, method as RewardReadMethod, {}, fetcher),
      ).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('does not turn node errors, oversized replies or mismatched ids into balances', async () => {
    for (const response of [
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 'wrong', result: {} })),
      new Response('x', { headers: { 'content-length': '2097153' } }),
    ])
      await expect(
        readRewardRpc(
          'http://localhost:9944',
          'hegemon_rewardAccountsStatus',
          {},
          vi.fn(async () => response),
        ),
      ).rejects.toThrow();
    const error = vi.fn(
      async (_url, init) =>
        new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: JSON.parse(init!.body as string).id,
            error: { code: -32601, message: 'Method not found' },
          }),
        ),
    );
    await expect(
      readRewardRpc(
        'http://localhost:9944',
        'hegemon_rewardAccountsStatus',
        {},
        error as typeof fetch,
      ),
    ).rejects.toThrow(/Method not found/);
  });
});
