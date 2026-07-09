import { describe, expect, it } from 'vitest';
import { computeNodeDisplayState, legacyContactWarning } from '../src/appGuards';
import type { Contact, NodeSummary } from '../src/types';

const contact = (overrides: Partial<Contact>): Contact => ({
  id: 'c1',
  name: 'Alice',
  address: 'hgn1...',
  verified: true,
  ...overrides
});

const summary = (overrides: Partial<NodeSummary>): NodeSummary =>
  ({
    connectionId: 'local',
    label: 'Local node',
    reachable: true,
    isLocal: true,
    nodeVersion: '0.10.0',
    peers: 3,
    isSyncing: false,
    bestBlock: '0xabc',
    bestNumber: 100,
    genesisHash: '0xdef',
    mining: false,
    minerAddress: null,
    miningThreads: null,
    miningSyncGateOpen: null,
    bootstrapAuthoring: null,
    hashRate: null,
    blocksFound: null,
    difficulty: null,
    nextDifficulty: null,
    blockHeight: 100,
    syncTargetHeight: 100,
    pendingExtrinsics: 0,
    peerList: null,
    canonicalCheckpoint: { status: 'verified' },
    supplyDigest: null,
    ...overrides
  }) as NodeSummary;

describe('legacyContactWarning', () => {
  it('flags 0.9 and legacy descriptors', () => {
    expect(legacyContactWarning(contact({ notes: 'created on 0.9.1' }))).toMatch(/Legacy contact/);
    expect(legacyContactWarning(contact({ name: 'legacy vendor' }))).toMatch(/Legacy contact/);
  });

  it('does not flag 0.10 contacts', () => {
    expect(legacyContactWarning(contact({ notes: 'fresh on 0.10' }))).toBeNull();
  });
});

describe('computeNodeDisplayState', () => {
  it('reports unknown/neutral without a summary', () => {
    const state = computeNodeDisplayState(null);
    expect(state.healthLabel).toBe('Unknown');
    expect(state.healthTone).toBe('neutral');
    expect(state.heightRelation).toBe('unknown');
  });

  it('reports offline when unreachable', () => {
    const state = computeNodeDisplayState(summary({ reachable: false }));
    expect(state.healthLabel).toBe('Offline');
    expect(state.healthTone).toBe('error');
  });

  it('reports healthy for an aligned verified node', () => {
    const state = computeNodeDisplayState(summary({}));
    expect(state.healthLabel).toBe('Healthy');
    expect(state.healthTone).toBe('ok');
    expect(state.heightRelation).toBe('aligned');
    expect(state.heightDelta).toBe(0);
  });

  it('reports forked on canonical mismatch', () => {
    const state = computeNodeDisplayState(
      summary({ canonicalCheckpoint: { status: 'mismatch' } as NodeSummary['canonicalCheckpoint'] })
    );
    expect(state.healthLabel).toBe('Forked');
    expect(state.healthTone).toBe('error');
  });

  it('reports syncing with network ahead metadata', () => {
    const state = computeNodeDisplayState(summary({ isSyncing: true, syncTargetHeight: 150 }));
    expect(state.healthLabel).toBe('Syncing');
    expect(state.healthTone).toBe('warn');
    expect(state.heightRelation).toBe('syncing');
    expect(state.heightDelta).toBe(-50);
  });

  it('treats startup settling (target unset, blocks present, peers up) as not syncing', () => {
    const state = computeNodeDisplayState(
      summary({ isSyncing: true, syncTargetHeight: 0, bestNumber: 42, peers: 2 })
    );
    expect(state.startupSummarySettling).toBe(true);
    expect(state.isSyncing).toBe(false);
    expect(state.syncTargetHeight).toBe(42);
  });

  it('reports mining gated when the sync gate is closed', () => {
    const state = computeNodeDisplayState(
      summary({ mining: true, miningSyncGateOpen: false })
    );
    expect(state.miningGateBlocked).toBe(true);
    expect(state.healthLabel).toBe('Mining gated');
    expect(state.healthTone).toBe('warn');
  });

  it('reports checking while the canonical checkpoint is pending', () => {
    const state = computeNodeDisplayState(
      summary({ canonicalCheckpoint: { status: 'pending' } as NodeSummary['canonicalCheckpoint'] })
    );
    expect(state.healthLabel).toBe('Checking');
    expect(state.healthTone).toBe('warn');
  });
});
