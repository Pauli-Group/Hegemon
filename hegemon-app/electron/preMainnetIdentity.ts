import type { CanonicalCheckpointStatus } from '../src/types';
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';

// Source: config/testnet/0.11/release.json and its source-owned manifest tuple.
export const PRE_MAINNET_GENESIS = '0xd9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3';
export const PRE_MAINNET_CHAIN_ID = '0x7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49';
export const PRE_MAINNET_MANIFEST_SHA256 = '386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754';
export const PRE_MAINNET_MANIFEST_DIGEST =
  '0x19e8d3b3d9fc14b762288f0fe63e8d7d55b14d4a9e4f52783b26d7a9e4785da6' +
  'fb78319fed1a8b2f60ebc21f0e142dc07b20d0c09ed37a9e28c7af865e6f50a0';
const SEEDS = 'hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333';

export function requirePreMainnetManifest(path: string): string {
  if (!statSync(path).isFile() || statSync(path).size > 16 * 1024) {
    throw new Error('The v0.11 network manifest is not a valid file.');
  }
  if (createHash('sha256').update(readFileSync(path)).digest('hex') !== PRE_MAINNET_MANIFEST_SHA256) {
    throw new Error('The v0.11 network manifest does not match the pinned release.');
  }
  return path;
}

/** Check configured network identity, not node freshness or canonical chain selection. */
export function preMainnetIdentity(genesis: unknown, config: unknown): CanonicalCheckpointStatus {
  const report = {
    network: 'Hegemon v0.11 pre-mainnet', seed: SEEDS, height: 0,
    expectedHash: PRE_MAINNET_GENESIS,
    actualHash: typeof genesis === 'string' ? genesis : null
  };
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ...report, status: 'unavailable', detail: 'The node did not report its network identity.' };
  }
  const value = config as Record<string, unknown>;
  if (typeof genesis !== 'string' || typeof value.networkProfile !== 'string' ||
      typeof value.chainId !== 'string' || typeof value.networkManifestDigest !== 'string') {
    return { ...report, status: 'unavailable', detail: 'The node did not report a complete v0.11 network identity.' };
  }
  if (genesis.toLowerCase() !== PRE_MAINNET_GENESIS || value.networkProfile !== 'pre-mainnet' ||
      value.chainId.toLowerCase() !== PRE_MAINNET_CHAIN_ID ||
      value.networkManifestDigest.toLowerCase() !== PRE_MAINNET_MANIFEST_DIGEST) {
    return { ...report, status: 'mismatch', detail: 'This node does not match the pinned v0.11 pre-mainnet identity.' };
  }
  return { ...report, status: 'verified',
    detail: 'Genesis, chain ID and manifest match v0.11. This does not establish sync or the canonical chain tip.' };
}
