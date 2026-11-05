import { normalizeLoopbackWalletOneShotRpcEndpoint } from './rpcEndpoint';
import {
  rewardMethods,
  type RewardReadMethod,
  type RewardQuery,
} from '../src/lib/rewardAccounts';
export async function readRewardRpc(
  httpUrl: string,
  method: RewardReadMethod,
  query: RewardQuery = {},
  fetcher: typeof fetch = fetch,
): Promise<unknown> {
  if (!rewardMethods.includes(method))
    throw Error('Unsupported public account method');
  const endpoint = normalizeLoopbackWalletOneShotRpcEndpoint(httpUrl),
    id = crypto.randomUUID();
  const response = await fetcher(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'omit',
    signal: AbortSignal.timeout(15000),
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params: [query] }),
  });
  if (!response.ok) throw Error(`Node request failed (${response.status})`);
  if (Number(response.headers.get('content-length') ?? 0) > 2 * 1024 * 1024)
    throw Error('Account response exceeds limit');
  const text = await response.text();
  if (text.length > 2 * 1024 * 1024)
    throw Error('Account response exceeds limit');
  const value = JSON.parse(text);
  if (value.jsonrpc !== '2.0' || value.id !== id)
    throw Error('Node returned a mismatched response');
  if (value.error)
    throw Error(String(value.error.message || 'Node rejected account read'));
  if (!Object.hasOwn(value, 'result')) throw Error('Missing account result');
  return value.result;
}
