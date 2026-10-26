import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NATIVE_WALLET_SYNC_TIMEOUT_MS, withNativeWalletSyncTimeout } from '../src/lib/walletSync';

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('native full-chain wallet sync deadline', () => {
  it.each([147_000, 60 * 60_000])('allows a healthy first scan lasting %i ms', async (duration) => {
    const scan = deferred<number>();
    const lock = vi.fn(async () => undefined);
    const result = withNativeWalletSyncTimeout(scan.promise, lock);
    await vi.advanceTimersByTimeAsync(duration);
    expect(lock).not.toHaveBeenCalled();
    scan.resolve(117080);
    await expect(result).resolves.toBe(117080);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('surfaces a broken-node RPC failure immediately and clears the deadline', async () => {
    const scan = deferred<number>();
    const lock = vi.fn(async () => undefined);
    const failure = new Error('node RPC request timed out after 60s');
    const observed = withNativeWalletSyncTimeout(scan.promise, lock).catch((error) => error);
    await vi.advanceTimersByTimeAsync(60_000);
    scan.reject(failure);
    expect(await observed).toBe(failure);
    expect(lock).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('preserves cancellation rejection without a later timeout lock', async () => {
    const scan = deferred<number>();
    const lock = vi.fn(async () => undefined);
    const canceled = new Error('walletd stopped');
    const observed = withNativeWalletSyncTimeout(scan.promise, lock).catch((error) => error);
    scan.reject(canceled);
    expect(await observed).toBe(canceled);
    await vi.advanceTimersByTimeAsync(NATIVE_WALLET_SYNC_TIMEOUT_MS);
    expect(lock).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('locks at the bounded deadline and ignores the resulting process-stop rejection', async () => {
    const scan = deferred<number>();
    const lock = vi.fn(async () => { scan.reject(new Error('walletd stopped')); });
    const observed = withNativeWalletSyncTimeout(scan.promise, lock).catch((error) => error);
    await vi.advanceTimersByTimeAsync(NATIVE_WALLET_SYNC_TIMEOUT_MS - 1);
    expect(lock).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(lock).toHaveBeenCalledTimes(1);
    expect((await observed).message).toMatch(/timed out after 2 hours/);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('invalidates the session synchronously before timeout rejection handlers run', async () => {
    const scan = deferred<number>();
    const order: string[] = [];
    const lock = vi.fn(() => {
      order.push('invalidate session');
      return new Promise<void>(() => undefined);
    });
    const observed = withNativeWalletSyncTimeout(scan.promise, lock).catch(() => {
      order.push('leave busy state');
    });
    vi.advanceTimersByTime(NATIVE_WALLET_SYNC_TIMEOUT_MS);
    expect(order).toEqual(['invalidate session']);
    await observed;
    expect(order).toEqual(['invalidate session', 'leave busy state']);
  });

  it('settles the deadline even when lock IPC never answers', async () => {
    const scan = deferred<number>();
    const lock = vi.fn(() => new Promise<void>(() => undefined));
    const observed = withNativeWalletSyncTimeout(scan.promise, lock).catch((error) => error);
    await vi.advanceTimersByTimeAsync(NATIVE_WALLET_SYNC_TIMEOUT_MS);
    const failure = await observed;
    expect(failure.message).toMatch(/timed out after 2 hours/);
    expect(lock).toHaveBeenCalledTimes(1);
    scan.resolve(117080);
    expect(await observed).toBe(failure);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('handles a synchronous cleanup throw without replacing the deadline error', async () => {
    const scan = deferred<number>();
    const lock = vi.fn(() => { throw new Error('lock IPC threw'); });
    const observed = withNativeWalletSyncTimeout(scan.promise, lock).catch((error) => error);
    await vi.advanceTimersByTimeAsync(NATIVE_WALLET_SYNC_TIMEOUT_MS);
    expect((await observed).message).toMatch(/timed out after 2 hours/);
    expect(lock).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('reports the deadline even if wallet locking fails', async () => {
    const scan = deferred<number>();
    const lock = vi.fn(async () => { throw new Error('lock failed'); });
    const observed = withNativeWalletSyncTimeout(scan.promise, lock).catch((error) => error);
    await vi.advanceTimersByTimeAsync(NATIVE_WALLET_SYNC_TIMEOUT_MS);
    expect((await observed).message).toMatch(/timed out after 2 hours/);
    expect(lock).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });
});
