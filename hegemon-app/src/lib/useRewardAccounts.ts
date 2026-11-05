import { useCallback, useEffect, useRef, useState } from 'react';
import {
  checkedStatus,
  checkedAccount,
  sameRewardContext,
  type RewardStatus,
  type RewardIdentity,
  type RewardAccount,
} from './rewardAccounts';
import { validateAddress } from './addresses';
export function useRewardAccounts(
  url: string,
  genesis: string | null,
  storePath: string,
  token: string | null,
) {
  const [status, setStatus] = useState<RewardStatus | null>(null),
    [identity, setIdentity] = useState<RewardIdentity | null>(null),
    [account, setAccount] = useState<RewardAccount | null>(null),
    [error, setError] = useState<string | null>(null),
    [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<'unknown' | 'legacy' | 'accounts'>(
    'unknown',
  );
  const serial = useRef(0),
    pin = useRef<{
      url: string;
      chain: string;
      genesis?: string;
      configured: boolean;
      network: string;
    } | null>(null);
  const refresh = useCallback(async () => {
    const ticket = ++serial.current;
    setLoading(true);
    setIdentity(null);
    setAccount(null);
    setError(null);
    if (!url) {
      setStatus(null);
      setLoading(false);
      return;
    }
    try {
      const s = checkedStatus(
        await window.hegemon.node.rewardRead(
          url,
          'hegemon_rewardAccountsStatus',
        ),
      );
      if (ticket !== serial.current) return;
      if (
        pin.current?.url === url &&
        (pin.current.configured !== s.configured ||
          pin.current.network !==
            JSON.stringify(s.parameters?.network ?? null) ||
          pin.current.chain !== s.context.chain_id ||
          (s.context.genesis_hash &&
            pin.current.genesis &&
            pin.current.genesis !== s.context.genesis_hash))
      )
        throw Error(
          'Connected network changed. Select the intended node before continuing.',
        );
      pin.current = {
        url,
        configured: s.configured,
        network: JSON.stringify(s.parameters?.network ?? null),
        chain: s.context.chain_id,
        genesis: s.context.genesis_hash,
      };
      setMode(s.configured ? 'accounts' : 'legacy');
      setStatus(s);
      if (s.configured && s.parameters && token) {
        const expected = s.context.genesis_hash ?? genesis?.replace(/^0x/, '');
        if (!expected)
          throw Error(
            'Wait for the node’s genesis identity before deriving wallet accounts.',
          );
        if (genesis && expected !== genesis.replace(/^0x/, ''))
          throw Error(
            'Node genesis does not match the selected wallet connection.',
          );
        const id = (await window.hegemon.wallet.reward(
          storePath,
          token,
          'identity',
          { network: s.parameters.network, expectedGenesisHash: expected },
        )) as RewardIdentity;
        if (ticket !== serial.current) return;
        validateAddress(id.accountAddress, 'account', s.parameters.network);
        validateAddress(id.shieldedAddress, 'shielded', s.parameters.network);
        setIdentity(id);
        if (s.active) {
          const result = (await window.hegemon.node.rewardRead(
            url,
            'hegemon_rewardAccount',
            { address: id.accountAddress, at: s.context.block_hash },
          )) as { context: RewardStatus['context']; account: RewardAccount };
          if (ticket !== serial.current) return;
          if (!sameRewardContext(result.context, s.context))
            throw Error('Canonical account snapshot changed. Refresh.');
          setAccount(
            checkedAccount(result.account, s.parameters.reward_epoch_blocks),
          );
        }
      }
    } catch (e) {
      if (ticket !== serial.current) return;
      setStatus(null);
      setIdentity(null);
      setAccount(null);
      const message = e instanceof Error ? e.message : String(e);
      if (
        !pin.current &&
        /method not found|unknown method|-32601/i.test(message)
      )
        setMode('legacy');
      setError(message);
    } finally {
      if (ticket === serial.current) setLoading(false);
    }
  }, [url, genesis, storePath, token]);
  useEffect(() => {
    setStatus(null);
    setIdentity(null);
    setAccount(null);
    setMode('unknown');
    pin.current = null;
    void refresh();
    return () => {
      serial.current++;
    };
  }, [refresh]);
  return { mode, status, identity, account, error, loading, refresh };
}
export type RewardViewState = ReturnType<typeof useRewardAccounts>;
