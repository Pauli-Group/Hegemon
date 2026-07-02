import type { Contact, NodeSummary } from './types';

export type StatusTone = 'ok' | 'warn' | 'neutral' | 'error';

export type NodeDisplayState = {
  peerCount: number | null;
  startupSummarySettling: boolean;
  syncTargetHeight: number | null;
  isSyncing: boolean | null;
  heightDelta: number | null;
  heightRelation: 'unknown' | 'syncing' | 'aligned' | 'local_ahead' | 'network_ahead';
  miningGateBlocked: boolean;
  healthLabel: 'Unknown' | 'Offline' | 'Mining gated' | 'Syncing' | 'Healthy';
  healthTone: StatusTone;
};

export const legacyContactWarning = (contact: Contact) => {
  const descriptor = `${contact.name} ${contact.notes ?? ''} ${contact.protocolVersion ?? ''}`.toLowerCase();
  if (/\b0\.9(?:\.1)?\b|hegemon-ovh|legacy/.test(descriptor)) {
    return 'Legacy contact. Recreate or verify this recipient on Hegemon 0.10 before sending.';
  }
  return null;
};

export const computeNodeDisplayState = (summary: NodeSummary | null | undefined): NodeDisplayState => {
  const peerCount = typeof summary?.peers === 'number' ? summary.peers : null;
  const startupSummarySettling = Boolean(
    summary?.reachable &&
      summary.isSyncing === true &&
      (summary.syncTargetHeight === 0 || summary.syncTargetHeight === null) &&
      typeof summary.bestNumber === 'number' &&
      summary.bestNumber > 0 &&
      peerCount !== null &&
      peerCount > 0
  );
  const syncTargetHeight =
    startupSummarySettling && typeof summary?.bestNumber === 'number'
      ? summary.bestNumber
      : summary?.syncTargetHeight ?? null;
  const isSyncing =
    summary?.isSyncing === null || summary?.isSyncing === undefined
      ? summary?.isSyncing ?? null
      : startupSummarySettling
        ? false
        : summary.isSyncing;
  const miningGateBlocked = Boolean(
    summary?.mining && summary.miningSyncGateOpen === false && !startupSummarySettling
  );
  const heightDelta =
    typeof summary?.bestNumber === 'number' && typeof syncTargetHeight === 'number'
      ? summary.bestNumber - syncTargetHeight
      : null;
  const heightRelation: NodeDisplayState['heightRelation'] =
    !summary || !summary.reachable || heightDelta === null
      ? 'unknown'
      : isSyncing
        ? 'syncing'
        : heightDelta === 0
          ? 'aligned'
          : heightDelta > 0
            ? 'local_ahead'
            : 'network_ahead';
  const healthLabel =
    !summary
      ? 'Unknown'
      : !summary.reachable
        ? 'Offline'
        : miningGateBlocked
          ? 'Mining gated'
          : isSyncing
            ? 'Syncing'
            : 'Healthy';
  const healthTone: StatusTone =
    !summary
      ? 'neutral'
      : !summary.reachable
        ? 'error'
        : miningGateBlocked || isSyncing
          ? 'warn'
          : 'ok';

  return {
    peerCount,
    startupSummarySettling,
    syncTargetHeight,
    isSyncing,
    heightDelta,
    heightRelation,
    miningGateBlocked,
    healthLabel,
    healthTone
  };
};
