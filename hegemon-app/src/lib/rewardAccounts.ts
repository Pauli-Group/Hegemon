import {
  validNetwork,
  validateAddress,
  type AddressNetwork,
} from './addresses';
export const rewardMethods = [
  'hegemon_rewardAccountsStatus',
  'hegemon_rewardAccount',
  'hegemon_rewardAccountsGenesis',
  'hegemon_rewardAccountsActivity',
] as const;
export type RewardReadMethod = (typeof rewardMethods)[number];
export type RewardQuery = {
  at?: string;
  address?: string;
  offset?: number;
  limit?: number;
  from_height?: string;
  action_index?: number;
};
export type RewardIdentity = {
  network: AddressNetwork;
  accountAddress: string;
  shieldedAddress: string;
  policy: unknown;
  signerKeyHash: string;
  publicKey: string;
  backup: string;
  index: number;
  submissionAvailable: false;
};
export type RewardAuthority = {
  policy_hash: string;
  required: number;
  members: number;
  signer_key_hashes: string[];
};
export type RewardAccount = {
  address: string;
  available_atoms: string;
  pending_atoms: string;
  total_atoms: string;
  claimable_next_block_atoms: string;
  next_sequence: string;
  policy_generation: string;
  is_treasury: boolean;
  pending: Array<{
    earning_epoch: string;
    release_epoch: string;
    release_height: string;
    amount_atoms: string;
  }>;
};
export type RewardContext = {
  chain_id: string;
  genesis_hash?: string;
  genesis_config_hash?: string;
  height: string;
  block_hash: string;
  accounts_root?: string;
  note_root?: string[];
};
export type RewardStatus = {
  schema: string;
  configured: boolean;
  active: boolean;
  reason?: string;
  context: RewardContext;
  parameters: null | {
    network: AddressNetwork;
    reward_epoch_blocks: string;
    treasury_address: string;
    genesis_allocation_atoms: string;
    mining_budget_atoms: string;
    max_supply_atoms: string;
    initial_treasury_authority: RewardAuthority;
  };
  supply: null | Record<string, string>;
  treasury: null | RewardAccount;
  epochs?: {
    current_reward_epoch: string | null;
    next_epoch_boundary_height: string;
    next_block_height: string;
    blocks_per_epoch: string;
  };
  governance: null | {
    policy_generation: string;
    authority: RewardAuthority;
    pending_replacement: null | {
      activation_height: string;
      approval_count: number;
      successor_authority: RewardAuthority;
      certificate_digest: string;
    };
  };
};
const UINT = /^(0|[1-9][0-9]*)$/;
export function exact(value: unknown): bigint {
  if (
    typeof value !== 'string' ||
    value.length > 20 ||
    !UINT.test(value) ||
    BigInt(value) > (1n << 64n) - 1n
  )
    throw Error('Node returned an invalid exact integer');
  return BigInt(value);
}
export function hgn(value: string) {
  const n = exact(value);
  return `${(n / 100000000n).toLocaleString('en-CA')}.${(n % 100000000n).toString().padStart(8, '0')} HGN`;
}
export function parseHgn(value: string): string | null {
  if (
    value.length > 32 ||
    !/^(0|[1-9][0-9]*)(\.[0-9]{1,8})?$/.test(value.trim())
  )
    return null;
  const [a, b = ''] = value.trim().split('.');
  const n = BigInt(a) * 100000000n + BigInt(b.padEnd(8, '0'));
  return n <= 2100000000000000n ? n.toString() : null;
}
export function sameRewardContext(a: RewardContext, b: RewardContext) {
  return (
    a.chain_id === b.chain_id &&
    a.genesis_hash === b.genesis_hash &&
    a.height === b.height &&
    a.block_hash === b.block_hash &&
    a.genesis_config_hash === b.genesis_config_hash &&
    a.accounts_root === b.accounts_root &&
    JSON.stringify(a.note_root) === JSON.stringify(b.note_root)
  );
}
export function checkedStatus(value: unknown): RewardStatus {
  const s = value as RewardStatus;
  if (
    !s ||
    s.schema !== 'hegemon.native.reward-accounts.explorer.v1' ||
    typeof s.configured !== 'boolean' ||
    typeof s.active !== 'boolean' ||
    !s.context ||
    !/^[a-f0-9]{64}$/.test(s.context.chain_id) ||
    !/^[a-f0-9]{64}$/.test(s.context.block_hash)
  )
    throw Error('Node does not provide the reward-account interface');
  exact(s.context.height);
  const authority = (a: RewardAuthority) => {
    if (
      !a ||
      !Number.isInteger(a.required) ||
      !Number.isInteger(a.members) ||
      a.required < 1 ||
      a.members < a.required ||
      a.members > 16 ||
      !/^[a-f0-9]{96}$/.test(a.policy_hash) ||
      !Array.isArray(a.signer_key_hashes) ||
      a.signer_key_hashes.length !== a.members ||
      new Set(a.signer_key_hashes).size !== a.members
    )
      throw Error('Invalid treasury authority');
    for (const k of a.signer_key_hashes)
      if (!/^[a-f0-9]{96}$/.test(k)) throw Error('Invalid signer hash');
  };
  if (s.parameters) {
    const p = s.parameters;
    validNetwork(p.network);
    validateAddress(p.treasury_address, 'account', p.network);
    authority(p.initial_treasury_authority);
    if (
      exact(p.reward_epoch_blocks) === 0n ||
      exact(p.genesis_allocation_atoms) + exact(p.mining_budget_atoms) !==
        2100000000000000n ||
      exact(p.max_supply_atoms) !== 2100000000000000n
    )
      throw Error('Invalid genesis budget/epoch parameters');
  }
  if (!s.active) {
    if (s.supply !== null || s.treasury !== null || s.governance !== null)
      throw Error('Inactive node returned account balances');
    if (s.parameters) validNetwork(s.parameters.network);
    return s;
  }
  if (
    !s.configured ||
    !s.parameters ||
    !s.supply ||
    !s.treasury ||
    !s.governance ||
    !s.context.genesis_hash
  )
    throw Error('Incomplete reward snapshot');
  if (
    !/^[a-f0-9]{64}$/.test(s.context.genesis_hash) ||
    !/^[a-f0-9]{96}$/.test(s.context.genesis_config_hash ?? '') ||
    !/^[a-f0-9]{96}$/.test(s.context.accounts_root ?? '') ||
    !Array.isArray(s.context.note_root) ||
    s.context.note_root.length !== 7
  )
    throw Error('Invalid authenticated account context');
  s.context.note_root.forEach(exact);
  authority(s.governance.authority);
  exact(s.governance.policy_generation);
  if (s.governance.pending_replacement) {
    authority(s.governance.pending_replacement.successor_authority);
    exact(s.governance.pending_replacement.activation_height);
  }
  if (
    !s.epochs ||
    exact(s.epochs.blocks_per_epoch) !== exact(s.parameters.reward_epoch_blocks)
  )
    throw Error('Missing reward epoch context');
  exact(s.epochs.next_block_height);
  exact(s.epochs.next_epoch_boundary_height);
  if (s.epochs.current_reward_epoch !== null)
    exact(s.epochs.current_reward_epoch);
  const p = s.supply;
  if (
    exact(p.shielded_atoms) +
      exact(p.available_account_atoms) +
      exact(p.pending_account_atoms) !==
      exact(p.total_issued_atoms) ||
    exact(p.genesis_allocation_atoms) + exact(p.mining_issued_atoms) !==
      exact(p.total_issued_atoms) ||
    exact(p.total_issued_atoms) + exact(p.remaining_mining_atoms) !==
      exact(p.max_supply_atoms)
  )
    throw Error('Reward supply does not reconcile');
  if (
    exact(p.max_supply_atoms) !== exact(s.parameters.max_supply_atoms) ||
    exact(p.genesis_allocation_atoms) !==
      exact(s.parameters.genesis_allocation_atoms)
  )
    throw Error('Supply differs from genesis budget');
  checkedAccount(s.treasury, s.parameters.reward_epoch_blocks);
  validateAddress(s.treasury.address, 'account', s.parameters.network);
  if (
    s.treasury.address !== s.parameters.treasury_address ||
    !s.treasury.is_treasury
  )
    throw Error('Unexpected treasury account');
  return s;
}
export function checkedAccount(a: RewardAccount, blocksPerEpoch?: string) {
  if (
    !a ||
    typeof a.address !== 'string' ||
    !Array.isArray(a.pending) ||
    a.pending.length > 2 ||
    a.pending.some(
      (b, i) =>
        i > 0 &&
        exact(a.pending[i - 1].earning_epoch) >= exact(b.earning_epoch),
    ) ||
    exact(a.total_atoms) > 2100000000000000n
  )
    throw Error('Invalid account view');
  if (
    exact(a.available_atoms) + exact(a.pending_atoms) !==
      exact(a.total_atoms) ||
    a.pending.reduce((sum, b) => {
      const height = exact(b.release_height);
      if (
        blocksPerEpoch &&
        height !== (exact(b.earning_epoch) + 2n) * exact(blocksPerEpoch) + 1n
      )
        throw Error('Invalid first-claim height');
      if (exact(b.amount_atoms) === 0n) throw Error('Empty reward bucket');
      if (exact(b.release_epoch) !== exact(b.earning_epoch) + 2n)
        throw Error('Invalid reward release epoch');
      return sum + exact(b.amount_atoms);
    }, 0n) !== exact(a.pending_atoms)
  )
    throw Error('Account balances do not reconcile');
  const n = exact(a.claimable_next_block_atoms);
  if (n < exact(a.available_atoms) || n > exact(a.total_atoms))
    throw Error('Invalid first-block claimability');
  exact(a.next_sequence);
  exact(a.policy_generation);
  return a;
}
