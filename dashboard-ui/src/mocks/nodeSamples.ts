import type { MinerStatus, NoteStatus, TelemetrySnapshot, TransferRecord } from '../types/node';

export const mockTelemetry: TelemetrySnapshot = {
  hash_rate: 1250000,
  total_hashes: 12480000,
  best_height: 128,
  mempool_depth: 32,
  difficulty_bits: 50331670,
  stale_share_rate: 0.012,
};

export const mockNotes: NoteStatus = {
  leaf_count: 2048,
  depth: 32,
  root: 8731462512,
  next_index: 2050,
};

export const mockMinerStatus: MinerStatus = {
  metrics: mockTelemetry,
  is_running: true,
  target_hash_rate: 1300000,
  thread_count: 2,
  last_updated: Date.now() / 1000,
};

export const mockTransfers: TransferRecord[] = [
  {
    id: 'mock-transfer-1',
    direction: 'incoming',
    address: 'shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
    memo: 'Genesis allocation',
    amount: 42,
    fee: 0,
    status: 'confirmed',
    confirmations: 64,
    created_at: new Date().toISOString(),
  },
];
