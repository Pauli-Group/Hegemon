import type { WalletDisclosureRecord } from '../types';

export type LogLevel = 'info' | 'warn' | 'error' | 'debug';

export type LogCategory = 'mining' | 'sync' | 'network' | 'consensus' | 'storage' | 'rpc' | 'other';

export type LogEntry = {
  id: string;
  timestamp: string | null;
  level: LogLevel;
  category: LogCategory;
  message: string;
  raw: string;
  highlight?: string;
};

export type ActivityStatus = 'processing' | 'pending' | 'confirmed' | 'failed';

export type SendAttempt = {
  id: string;
  storePath: string;
  createdAt: string;
  recipient: string;
  amount: number;
  fee: number;
  memo?: string;
  status: ActivityStatus;
  txId?: string;
  error?: string;
  notesNeeded?: number;
  walletNoteCount?: number;
  maxInputs?: number;
  consolidationExpected?: number;
  consolidationExpectedBlocks?: number;
};

export type ActivityStep = {
  id: string;
  label: string;
  status: ActivityStatus;
  txId?: string;
  confirmations?: number;
};

export type ActivityEntry = {
  id: string;
  source: 'attempt' | 'wallet';
  createdAt: string;
  recipient: string;
  amount: number;
  fee: number;
  memo?: string;
  status: ActivityStatus;
  txId?: string;
  confirmations?: number;
  error?: string;
  notesNeeded?: number;
  walletNoteCount?: number;
  maxInputs?: number;
  consolidationExpected?: number;
  consolidationExpectedBlocks?: number;
  consolidationSubmitted?: number;
  consolidationConfirmed?: number;
  steps?: ActivityStep[];
};

export type DisclosureGroup = {
  txId: string;
  createdAt: string;
  outputs: WalletDisclosureRecord[];
};

export type NodeTransitionAction = 'starting' | 'stopping';

export type NodeTransition = {
  action: NodeTransitionAction;
  connectionId: string;
  startedAt: number;
};

export type UiTone = 'ok' | 'warn' | 'error' | 'neutral';
export type BlockAlertTone = 'self' | 'other';
export type BlockAlertStep = { frequency: number; duration: number; gap?: number };
export type EmptyStateIconName = 'terminal' | 'transactions' | 'contacts' | 'disclosure';
export type AppIconName =
  | 'overview'
  | 'node'
  | 'wallet'
  | 'send'
  | 'disclosure'
  | 'console'
  | 'height'
  | 'target'
  | 'sync'
  | 'key'
  | 'peers'
  | 'mining'
  | 'endpoint';
