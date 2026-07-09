/**
 * Loopback-only wallet RPC endpoint validation.
 *
 * The desktop app's trusted default path only talks to a local node/walletd;
 * remote network participation is reached by running a local Hegemon P2P
 * relay. These helpers therefore reject any non-loopback host, credentials,
 * and fragments before an endpoint reaches wallet RPC code.
 */

const loopbackRpcHosts = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);

export const normalizeLoopbackWalletRpcEndpoint = (endpoint: string) => {
  if (typeof endpoint !== 'string') {
    throw new Error('Wallet RPC endpoint is required.');
  }
  const trimmed = endpoint.trim();
  if (!trimmed) {
    throw new Error('Wallet RPC endpoint is required.');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('Wallet RPC endpoint must be a valid URL.');
  }

  if (!['ws:', 'wss:', 'http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Wallet RPC endpoint must use ws, wss, http, or https.');
  }
  if (parsed.username || parsed.password || parsed.hash) {
    throw new Error('Wallet RPC endpoint must not include credentials or fragments.');
  }
  if (!loopbackRpcHosts.has(parsed.hostname.toLowerCase())) {
    throw new Error('Wallet RPC endpoint must be loopback. Run a local Hegemon P2P relay node for remote network access.');
  }
  return parsed.toString();
};

export const normalizeLoopbackWalletOneShotRpcEndpoint = (endpoint: string) => {
  const normalized = normalizeLoopbackWalletRpcEndpoint(endpoint);
  const parsed = new URL(normalized);
  if (parsed.protocol === 'ws:') {
    parsed.protocol = 'http:';
    return parsed.toString();
  }
  if (parsed.protocol === 'wss:') {
    parsed.protocol = 'https:';
    return parsed.toString();
  }
  return normalized;
};
