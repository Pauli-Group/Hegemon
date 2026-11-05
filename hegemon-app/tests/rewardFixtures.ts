import {
  encodeNetworkAddress,
  type AddressNetwork,
} from '../src/lib/addresses';
import type { RewardStatus, RewardAccount } from '../src/lib/rewardAccounts';
const network: AddressNetwork = {
  class: 'testnet',
  discriminator: Array(32).fill(9),
};
const account = encodeNetworkAddress(
  'account',
  network,
  new Uint8Array(48).fill(34),
);
export function accountFixture(): RewardAccount {
  return {
    address: account,
    available_atoms: '100000000',
    pending_atoms: '300000000',
    total_atoms: '400000000',
    claimable_next_block_atoms: '300000000',
    next_sequence: '9007199254740993',
    policy_generation: '0',
    is_treasury: true,
    pending: [
      {
        earning_epoch: '0',
        release_epoch: '2',
        release_height: '2881',
        amount_atoms: '200000000',
      },
      {
        earning_epoch: '1',
        release_epoch: '3',
        release_height: '4321',
        amount_atoms: '100000000',
      },
    ],
  };
}
export function statusFixture(): RewardStatus {
  const authority = {
    policy_hash: '01'.repeat(48),
    required: 1,
    members: 1,
    signer_key_hashes: ['02'.repeat(48)],
  };
  return {
    schema: 'hegemon.native.reward-accounts.explorer.v1',
    configured: true,
    active: true,
    context: {
      chain_id: '01'.repeat(32),
      genesis_hash: '02'.repeat(32),
      genesis_config_hash: '03'.repeat(48),
      height: '2880',
      block_hash: '04'.repeat(32),
      accounts_root: '05'.repeat(48),
      note_root: ['9007199254740993', '1', '2', '3', '4', '5', '6'],
    },
    parameters: {
      network,
      reward_epoch_blocks: '1440',
      treasury_address: account,
      genesis_allocation_atoms: '100000000',
      mining_budget_atoms: '2099999900000000',
      max_supply_atoms: '2100000000000000',
      initial_treasury_authority: authority,
    },
    supply: {
      shielded_atoms: '100000000',
      available_account_atoms: '100000000',
      pending_account_atoms: '300000000',
      total_issued_atoms: '500000000',
      genesis_allocation_atoms: '100000000',
      mining_issued_atoms: '400000000',
      remaining_mining_atoms: '2099999500000000',
      max_supply_atoms: '2100000000000000',
    },
    treasury: accountFixture(),
    governance: {
      authority,
      policy_generation: '0',
      pending_replacement: null,
    },
    epochs: {
      current_reward_epoch: '1',
      next_block_height: '2881',
      next_epoch_boundary_height: '2881',
      blocks_per_epoch: '1440',
    },
  };
}
