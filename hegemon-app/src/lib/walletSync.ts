// First sync can scan the entire chain even without permitting a genesis reset. Individual
// node requests retain their own shorter RPC timeout in walletd.
export const NATIVE_WALLET_SYNC_TIMEOUT_MS = 2 * 60 * 60_000;

/** Keep healthy full-chain scans alive while bounding wedged wallet sessions. */
export function withNativeWalletSyncTimeout<T>(
  sync: Promise<T>,
  lockOnTimeout: () => Promise<void>
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let expired = false;
    const timer = setTimeout(() => {
      expired = true;
      // Start cleanup synchronously so the UI invalidates its unlocked
      // session before timeout handlers run. Never await cleanup IPC here.
      try {
        void Promise.resolve(lockOnTimeout()).catch(() => undefined);
      } catch {
        // Cleanup may throw before returning a promise; deadline still settles.
      }
      reject(new Error(
        'Wallet sync timed out after 2 hours. Reopen the wallet and check the wallet RPC URL before retrying.'
      ));
    }, NATIVE_WALLET_SYNC_TIMEOUT_MS);
    sync.then(
      (value) => {
        if (!expired) {
          clearTimeout(timer);
          resolve(value);
        }
      },
      (error) => {
        if (!expired) {
          clearTimeout(timer);
          reject(error);
        }
      }
    );
  });
}
