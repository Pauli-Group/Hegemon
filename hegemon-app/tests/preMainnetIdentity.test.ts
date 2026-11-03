import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  PRE_MAINNET_CHAIN_ID,
  PRE_MAINNET_GENESIS,
  PRE_MAINNET_MANIFEST_DIGEST,
  PRE_MAINNET_MANIFEST_SHA256,
  preMainnetIdentity,
  requirePreMainnetManifest
} from '../electron/preMainnetIdentity';

const config = () => ({ networkProfile: 'pre-mainnet', chainId: PRE_MAINNET_CHAIN_ID,
  networkManifestDigest: PRE_MAINNET_MANIFEST_DIGEST });

describe('v0.11 pre-mainnet identity', () => {
  it('pins the release genesis, chain and exact manifest file', () => {
    const release = JSON.parse(readFileSync(new URL('../../config/testnet/0.11/release.json', import.meta.url), 'utf8'));
    const bytes = readFileSync(new URL('../../config/testnet/0.11/network-manifest.json', import.meta.url));
    expect(PRE_MAINNET_GENESIS).toBe(release.genesis_hash);
    expect(PRE_MAINNET_CHAIN_ID).toBe(release.chain_id);
    expect(PRE_MAINNET_MANIFEST_SHA256).toBe(release.network_manifest_sha256);
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(PRE_MAINNET_MANIFEST_SHA256);
    const manifest = JSON.parse(bytes.toString());
    const ordered = Object.fromEntries(['schema', 'profile', 'genesis_timestamp_ms', 'pow_bits', 'rules_hash',
      'launch_reference_rules_hash', 'funding_address', 'funding_subsidy_numerator',
      'funding_subsidy_denominator'].map((key) => [key, manifest[key]]));
    const digest = createHash('sha512').update('hegemon.native.network-manifest.sha512.v1\0')
      .update(JSON.stringify(ordered)).digest('hex');
    expect(`0x${digest}`).toBe(PRE_MAINNET_MANIFEST_DIGEST);
  });

  it('reports identity without claiming the node is synced or on the canonical tip', () => {
    const result = preMainnetIdentity(PRE_MAINNET_GENESIS, config());
    expect(result.status).toBe('verified');
    expect(result.detail).toMatch(/does not establish sync or the canonical chain tip/);
  });

  it('rejects a changed genesis, profile, chain or manifest', () => {
    expect(preMainnetIdentity('0x' + '00'.repeat(32), config()).status).toBe('mismatch');
    for (const change of [{ networkProfile: 'development' }, { chainId: '0x00' },
      { networkManifestDigest: '0x00' }]) {
      expect(preMainnetIdentity(PRE_MAINNET_GENESIS, { ...config(), ...change }).status).toBe('mismatch');
    }
  });

  it('treats missing or legacy node identity as unavailable rather than verified', () => {
    expect(preMainnetIdentity(null, config()).status).toBe('unavailable');
    expect(preMainnetIdentity(PRE_MAINNET_GENESIS, null).status).toBe('unavailable');
    expect(preMainnetIdentity(PRE_MAINNET_GENESIS, { networkProfile: 'legacy' }).status).toBe('unavailable');
  });

  it('refuses missing, changed and oversized manifest files before launch', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hegemon-manifest-'));
    try {
      const path = join(dir, 'manifest.json');
      expect(() => requirePreMainnetManifest(path)).toThrow();
      writeFileSync(path, '{}');
      expect(() => requirePreMainnetManifest(path)).toThrow(/pinned release/);
      writeFileSync(path, 'x'.repeat(16 * 1024 + 1));
      expect(() => requirePreMainnetManifest(path)).toThrow(/not a valid file/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
