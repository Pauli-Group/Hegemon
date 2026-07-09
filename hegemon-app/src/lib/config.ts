import type { NodeConnection, NodeConnectionMode, NodeParticipationRole } from '../types';

export const defaultStorePath = '~/.hegemon-wallet-010';
export const canonicalTestnetP2pPort = 30333;
export const shieldedAddressPrefix = 'shca1';
export const shieldedAddressLength = 2634;
export const shieldedAddressDataCharset = /^[023456789acdefghjklmnpqrstuvwxyz]+$/;
export const shieldedAddressSeparatorPattern = /[\s\u200B\u200C\u200D\uFEFF]+/g;
export const approvedSeedEntries = ['hegemon.pauli.group:30333', 'devnet.hegemonprotocol.com:30333'] as const;
export const approvedSeeds = approvedSeedEntries.join(',');
export const hegemonNetworkName = 'Hegemon';
export const hegemonNetworkVersionLabel = 'Hegemon 0.10';
export const defaultDevConnectionLabel = hegemonNetworkName;
export const legacyDefaultConnectionLabels = new Set(['Local node', 'Native 0.10 devnet', hegemonNetworkName]);
export const legacyHegemonConnectionLabels = new Set([
  'hegemon-dev',
  'hegemon-dev P2P 0.10',
  'Hegemon Native Dev',
  'Hegemon Native Devnet',
  'Native 0.10 devnet'
]);
export const defaultDevBasePath = '~/.hegemon-node-native-010-dev';
export const legacyDesktopRpcPort = 9944;
export const legacySeedAliases: Record<string, string> = {
  'hegemon.pauli.group:31333': approvedSeeds,
  'hegemon.pauli.group:30333': approvedSeeds,
  '158.69.222.121:31333': approvedSeeds,
  '158.69.222.121:30333': approvedSeeds,
  'devnet.hegemonprotocol.com:30333': approvedSeeds,
  '51.222.86.107:30333': approvedSeeds
};
export const connectionsKey = 'hegemon.nodeConnections';
export const activeConnectionKey = 'hegemon.activeConnection';
export const walletConnectionKey = 'hegemon.walletConnection';
export const walletStorePathKey = 'hegemon.walletStorePath';
export const walletAutoLockEnabledKey = 'hegemon.walletAutoLockEnabled';
export const walletAutoLockMinutesKey = 'hegemon.walletAutoLockMinutes';
export const blockAlertEnabledKey = 'hegemon.blockAlertEnabled';
export const minWalletPassphraseLength = 12;
export const defaultRpcPort = 9955;
export const defaultP2pPort = canonicalTestnetP2pPort;
export const maxDesktopMineThreads = 4;
export const walletHistoryPageSize = 24;
export const defaultMineThreads = (() => {
  const hardwareConcurrency =
    typeof navigator !== 'undefined' && Number.isFinite(navigator.hardwareConcurrency)
      ? Number(navigator.hardwareConcurrency)
      : 1;
  const target = Math.floor(hardwareConcurrency / 4);
  return Math.max(1, Math.min(maxDesktopMineThreads, target || 1));
})();

export const participationRoleLabels: Record<NodeParticipationRole, string> = {
  full_node: 'Relay node',
  authoring_pool: 'Mining node'
};

export const connectionModeLabels: Record<NodeConnectionMode, string> = {
  local: 'Managed local',
  remote: 'Local RPC endpoint'
};

export const participationRoleMeta: Record<
  NodeParticipationRole,
  {
    statusLabel?: string;
    statusTone: 'ok' | 'warn';
    summary: string;
    guidance: string;
  }
> = {
  full_node: {
    statusTone: 'ok',
    summary: 'Verifies the network, serves wallet traffic, and relays chain state without local block production.',
    guidance:
      'Use this for wallets, verification, and relaying. Switch to Mining node only if this machine should build and mine blocks.'
  },
  authoring_pool: {
    statusLabel: 'Operator only',
    statusTone: 'warn',
    summary:
      'Runs the public block author. This node accepts proof-ready transactions, builds the commitment proof, mines locally, and broadcasts final blocks.',
    guidance:
      'Use this only on the machine that should mine blocks. Everyone else should stay on Relay node.'
  }
};

export const inferParticipationRole = (connection: NodeConnection): NodeParticipationRole => {
  if (connection.participationRole === 'full_node' || connection.participationRole === 'authoring_pool') {
    return connection.participationRole;
  }
  return connection.miningIntent || connection.minerAddress ? 'authoring_pool' : 'full_node';
};

