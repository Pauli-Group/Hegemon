export interface TelemetrySnapshot {
  hash_rate: number;
  total_hashes: number;
  best_height: number;
  mempool_depth: number;
  difficulty_bits: number;
  stale_share_rate: number;
  tls_enabled?: boolean;
  mtls_enabled?: boolean;
  tor_enabled?: boolean;
  vpn_overlay?: boolean;
  exposure_scope?: string;
}

export interface NoteStatus {
  leaf_count: number;
  depth: number;
  root: number;
  next_index: number;
}

export interface MinerStatus {
  metrics: TelemetrySnapshot;
  is_running: boolean;
  target_hash_rate: number;
  thread_count: number;
  last_updated: number;
}

export interface TransferRecord {
  id: string;
  tx_id: string;
  direction: 'incoming' | 'outgoing';
  address: string;
  memo?: string | null;
  amount: number;
  fee: number;
  status: 'pending' | 'confirmed';
  confirmations: number;
  created_at: string;
}

export type WalletMode = 'Full' | 'WatchOnly';

export interface WalletStatus {
  mode: WalletMode;
  primary_address: string;
  incoming_viewing_key?: string | null;
  balances: Record<string, number>;
  last_synced_height: number;
  pending: TransferRecord[];
}

export type NodeEvent =
  | ({ type: 'telemetry' } & Pick<
      TelemetrySnapshot,
      'hash_rate' | 'mempool_depth' | 'difficulty_bits' | 'stale_share_rate'
    > & { best_height?: number; timestamp?: string })
  | { type: 'transaction'; tx_id: string; timestamp?: string }
  | { type: 'block'; height: number; hash?: string; timestamp?: string }
  | { type: 'warning'; message: string; timestamp?: string };

export interface TelemetryPoint {
  timestamp: number;
  value: number;
}
