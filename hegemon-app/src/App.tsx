import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { HashRouter, Link, NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import type {
  Contact,
  DialogOpenOptions,
  NodeConnection,
  NodeConnectionMode,
  NodeManagedStatus,
  NodeParticipationRole,
  NodeSummary,
  WalletDisclosureCreateResult,
  WalletDisclosureRecord,
  WalletDisclosureVerifyResult,
  WalletStatus,
  WalletSyncResult,
  WalletUnlockSession
} from './types';
import blockMinedAudio from './assets/sounds/block-mined.wav';
import blockReceivedAudio from './assets/sounds/block-received.wav';
import { computeNodeDisplayState, legacyContactWarning } from './appGuards';

const defaultStorePath = '~/.hegemon-wallet-native-010';
const canonicalTestnetP2pPort = 30333;
const shieldedAddressPrefix = 'shca1';
const shieldedAddressLength = 2634;
const shieldedAddressDataCharset = /^[023456789acdefghjklmnpqrstuvwxyz]+$/;
const shieldedAddressSeparatorPattern = /[\s\u200B\u200C\u200D\uFEFF]+/g;
const approvedSeeds = 'hegemon.pauli.group:30333';
const hegemonNetworkName = 'Hegemon';
const hegemonNetworkVersionLabel = 'Hegemon 0.10';
const defaultDevConnectionLabel = hegemonNetworkName;
const legacyDefaultConnectionLabels = new Set(['Local node', 'Native 0.10 devnet', hegemonNetworkName]);
const legacyHegemonConnectionLabels = new Set([
  'hegemon-dev',
  'hegemon-dev P2P 0.10',
  'Hegemon Native Dev',
  'Hegemon Native Devnet',
  'Native 0.10 devnet'
]);
const defaultDevBasePath = '~/.hegemon-node-native-010-dev';
const legacyDesktopRpcPort = 9944;
const legacySeedAliases: Record<string, string> = {
  'hegemon.pauli.group:31333': approvedSeeds,
  'hegemon.pauli.group:30333': approvedSeeds,
  '158.69.222.121:31333': approvedSeeds,
  '158.69.222.121:30333': approvedSeeds
};
const connectionsKey = 'hegemon.nodeConnections';
const activeConnectionKey = 'hegemon.activeConnection';
const walletConnectionKey = 'hegemon.walletConnection';
const walletAutoLockEnabledKey = 'hegemon.walletAutoLockEnabled';
const walletAutoLockMinutesKey = 'hegemon.walletAutoLockMinutes';
const blockAlertEnabledKey = 'hegemon.blockAlertEnabled';
const minWalletPassphraseLength = 12;
const defaultRpcPort = 9955;
const defaultP2pPort = canonicalTestnetP2pPort;
const maxDesktopMineThreads = 4;
const defaultMineThreads = (() => {
  const hardwareConcurrency =
    typeof navigator !== 'undefined' && Number.isFinite(navigator.hardwareConcurrency)
      ? Number(navigator.hardwareConcurrency)
      : 1;
  const target = Math.floor(hardwareConcurrency / 4);
  return Math.max(1, Math.min(maxDesktopMineThreads, target || 1));
})();

const participationRoleLabels: Record<NodeParticipationRole, string> = {
  full_node: 'Relay node',
  authoring_pool: 'Mining node'
};

const connectionModeLabels: Record<NodeConnectionMode, string> = {
  local: 'Managed local',
  remote: 'Local RPC endpoint'
};

const participationRoleMeta: Record<
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

const inferParticipationRole = (connection: NodeConnection): NodeParticipationRole => {
  if (connection.participationRole === 'full_node' || connection.participationRole === 'authoring_pool') {
    return connection.participationRole;
  }
  return connection.miningIntent || connection.minerAddress ? 'authoring_pool' : 'full_node';
};

const normalizeTxId = (value: string | null | undefined) => {
  if (!value) {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  return trimmed.replace(/^0x/i, '').toLowerCase();
};

const canonicalizeSeedEntry = (seed: string) => {
  const normalized = seed.trim().toLowerCase();
  if (!normalized) {
    return '';
  }
  return legacySeedAliases[normalized] ?? normalized;
};

const normalizeSeedsValue = (value: string | null | undefined) => {
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const rawSeed of (value ?? '').split(',')) {
    const seed = canonicalizeSeedEntry(rawSeed);
    if (!seed || seen.has(seed)) {
      continue;
    }
    seen.add(seed);
    normalized.push(seed);
  }
  return normalized.join(',');
};

const normalizeNetworkDisplayName = (value: string | null | undefined) => {
  const trimmed = value?.trim();
  if (!trimmed) {
    return hegemonNetworkName;
  }
  const lower = trimmed.toLowerCase();
  if (
    lower === 'hegemon network' ||
    lower === 'hegemon native' ||
    lower === 'hegemon native dev' ||
    lower === 'native 0.10 devnet' ||
    lower === 'hegemon-dev' ||
    lower.startsWith('hegemon native ')
  ) {
    return hegemonNetworkName;
  }
  return trimmed;
};

const makeId = () => {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return `conn-${Math.random().toString(36).slice(2, 10)}`;
};

const clampAutoLockMinutes = (value: number) => Math.min(Math.max(value, 1), 120);

type LogLevel = 'info' | 'warn' | 'error' | 'debug';

type LogCategory = 'mining' | 'sync' | 'network' | 'consensus' | 'storage' | 'rpc' | 'other';

type LogEntry = {
  id: string;
  timestamp: string | null;
  level: LogLevel;
  category: LogCategory;
  message: string;
  raw: string;
  highlight?: string;
};

type ActivityStatus = 'processing' | 'pending' | 'confirmed' | 'failed';

type SendAttempt = {
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

type ActivityStep = {
  id: string;
  label: string;
  status: ActivityStatus;
  txId?: string;
  confirmations?: number;
};

type ActivityEntry = {
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

type DisclosureGroup = {
  txId: string;
  createdAt: string;
  outputs: WalletDisclosureRecord[];
};

type NodeTransitionAction = 'starting' | 'stopping';

const isWalletSessionClosedError = (message: string) => {
  const normalized = message.toLowerCase();
  return (
    normalized.includes('walletd process not running') ||
    normalized.includes('walletd stopped') ||
    normalized.includes('walletd stdin not available') ||
    normalized.includes('wallet is locked') ||
    normalized.includes('wallet unlock token') ||
    normalized.includes('expired')
  );
};

type NodeTransition = {
  action: NodeTransitionAction;
  connectionId: string;
  startedAt: number;
};

type UiTone = 'ok' | 'warn' | 'error' | 'neutral';
type BlockAlertTone = 'self' | 'other';
type BlockAlertStep = { frequency: number; duration: number; gap?: number };
type EmptyStateIconName = 'terminal' | 'transactions' | 'contacts' | 'disclosure';
type AppIconName =
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

const logCategoryOrder: LogCategory[] = ['mining', 'sync', 'network', 'consensus', 'storage', 'rpc', 'other'];

const logCategoryLabels: Record<LogCategory, string> = {
  mining: 'Mining',
  sync: 'Sync',
  network: 'Network',
  consensus: 'Consensus',
  storage: 'Storage',
  rpc: 'RPC',
  other: 'Other'
};

const toBaseUnits = (value: string) => {
  const parsed = Number.parseFloat(value);
  if (Number.isNaN(parsed) || !Number.isFinite(parsed)) {
    return null;
  }
  return Math.round(parsed * 100_000_000);
};

const formatNumber = (value: number | null | undefined) => {
  if (value === null || value === undefined) {
    return 'N/A';
  }
  return value.toLocaleString();
};

const formatHgm = (value: number) => `${(value / 100_000_000).toFixed(8)} HGM`;

const formatBlockCount = (value: number) => `${formatNumber(value)} ${value === 1 ? 'block' : 'blocks'}`;

const AppIcon = ({ name }: { name: AppIconName }) => {
  const sharedProps = {
    viewBox: '0 0 24 24',
    fill: 'none',
    'aria-hidden': true
  };

  const paths: Record<AppIconName, JSX.Element> = {
    overview: (
      <>
        <path d="M3.5 11.5 12 4l8.5 7.5" />
        <path d="M5.5 10.5v8h13v-8" />
        <path d="M9.5 18.5v-5h5v5" />
      </>
    ),
    node: (
      <>
        <path d="M12 4.5v5" />
        <path d="M6.5 14.5h11" />
        <path d="M6.5 14.5v5" />
        <path d="M17.5 14.5v5" />
        <path d="M9.5 9.5h5v5h-5z" />
        <path d="M4.5 19.5h4" />
        <path d="M15.5 19.5h4" />
      </>
    ),
    wallet: (
      <>
        <path d="M4 7.5h14.5a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5.5A2.5 2.5 0 0 1 3 17V8.5a1 1 0 0 1 1-1Z" />
        <path d="M4.5 7.5 16 4.5" />
        <path d="M16.5 13.5h4" />
      </>
    ),
    send: (
      <>
        <path d="M4 5.5 20 12 4 18.5l3-6.5-3-6.5Z" />
        <path d="M7 12h7" />
      </>
    ),
    disclosure: (
      <>
        <path d="M6.5 3.5h8l4 4v13h-12z" />
        <path d="M14.5 3.5v4h4" />
        <path d="M8.5 14c1.2-1.7 2.4-2.5 3.5-2.5s2.3.8 3.5 2.5c-1.2 1.7-2.4 2.5-3.5 2.5S9.7 15.7 8.5 14Z" />
        <path d="M11.25 14a.75.75 0 1 0 1.5 0 .75.75 0 0 0-1.5 0Z" />
      </>
    ),
    console: (
      <>
        <path d="M4.5 6.5h15v11h-15z" />
        <path d="m7 10 2.5 2L7 14" />
        <path d="M12 14h4" />
      </>
    ),
    height: (
      <>
        <path d="M4 16.5 8.5 12l3 3 8-8" />
        <path d="M15.5 7.5h4v4" />
      </>
    ),
    target: (
      <>
        <path d="M12 4v3" />
        <path d="M12 17v3" />
        <path d="M4 12h3" />
        <path d="M17 12h3" />
        <path d="M7.5 12a4.5 4.5 0 1 0 9 0 4.5 4.5 0 0 0-9 0Z" />
      </>
    ),
    sync: (
      <>
        <path d="M18.5 8.5A7 7 0 0 0 6 7l-1.5 2.5" />
        <path d="M4.5 7.5v2h2" />
        <path d="M5.5 15.5A7 7 0 0 0 18 17l1.5-2.5" />
        <path d="M19.5 16.5v-2h-2" />
      </>
    ),
    key: (
      <>
        <path d="M4.5 14.5a4 4 0 1 0 3-3.9" />
        <path d="M11.5 12.5 20 4" />
        <path d="M16.5 7.5 18 9" />
        <path d="M14.5 9.5 16 11" />
      </>
    ),
    peers: (
      <>
        <path d="M8 10a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z" />
        <path d="M16 10a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z" />
        <path d="M4.5 19c.7-3.4 2-5 3.5-5s2.8 1.6 3.5 5" />
        <path d="M12.5 19c.7-3.4 2-5 3.5-5s2.8 1.6 3.5 5" />
      </>
    ),
    mining: (
      <>
        <path d="m5 19 9.5-9.5" />
        <path d="M12 7.5 16.5 3 21 7.5l-4.5 4.5" />
        <path d="M8.5 15.5 10 17" />
      </>
    ),
    endpoint: (
      <>
        <path d="M6.5 7.5h11v9h-11z" />
        <path d="M9 20h6" />
        <path d="M12 16.5V20" />
        <path d="M4 10h2.5" />
        <path d="M17.5 10H20" />
      </>
    )
  };

  return (
    <svg className={`app-icon app-icon-${name}`} {...sharedProps}>
      {paths[name]}
    </svg>
  );
};

const EmptyStateIcon = ({ name }: { name: EmptyStateIconName }) => {
  const sharedProps = {
    className: `empty-state-glyph ${name}`,
    viewBox: '0 0 48 48',
    fill: 'none',
    'aria-hidden': true
  };

  if (name === 'terminal') {
    return (
      <svg {...sharedProps}>
        <path d="M11 14.5h26a3 3 0 0 1 3 3v17a3 3 0 0 1-3 3H11a3 3 0 0 1-3-3v-17a3 3 0 0 1 3-3Z" />
        <path d="M15 22.5 20 27l-5 4.5" />
        <path d="M24 31.5h9" />
      </svg>
    );
  }

  if (name === 'contacts') {
    return (
      <svg {...sharedProps}>
        <path d="M13 10.5h18a4 4 0 0 1 4 4v19a4 4 0 0 1-4 4H13a3 3 0 0 1-3-3v-21a3 3 0 0 1 3-3Z" />
        <path d="M35 17h4M35 24h4M35 31h4" />
        <path d="M18 22.5a4 4 0 1 0 8 0 4 4 0 0 0-8 0Z" />
        <path d="M15.5 32.5c1.7-3.1 4.1-4.7 6.5-4.7s4.8 1.6 6.5 4.7" />
      </svg>
    );
  }

  if (name === 'disclosure') {
    return (
      <svg {...sharedProps}>
        <path d="M14 8.5h14l8 8v20a3 3 0 0 1-3 3H14a3 3 0 0 1-3-3v-25a3 3 0 0 1 3-3Z" />
        <path d="M28 8.5v8h8" />
        <path d="M16.5 27c2.3-3.1 4.8-4.7 7.5-4.7s5.2 1.6 7.5 4.7c-2.3 3.1-4.8 4.7-7.5 4.7s-5.2-1.6-7.5-4.7Z" />
        <path d="M22 27a2 2 0 1 0 4 0 2 2 0 0 0-4 0Z" />
      </svg>
    );
  }

  return (
    <svg {...sharedProps}>
      <path d="M12 18.5h20" />
      <path d="m30 13.5 5 5-5 5" />
      <path d="M36 29.5H16" />
      <path d="m18 24.5-5 5 5 5" />
      <path d="M13 11.5h9" opacity="0.55" />
      <path d="M26 36.5h9" opacity="0.55" />
    </svg>
  );
};

const normalizeShieldedAddressInput = (value: string) =>
  value.replace(shieldedAddressSeparatorPattern, '').trim().toLowerCase();

const validateShieldedAddressInput = (value: string, label = 'Address') => {
  const normalized = normalizeShieldedAddressInput(value);
  if (!normalized) {
    return `${label} is required.`;
  }
  if (!normalized.startsWith(shieldedAddressPrefix)) {
    return `${label} must start with ${shieldedAddressPrefix}.`;
  }
  if (normalized.length !== shieldedAddressLength) {
    return `${label} looks truncated or corrupt. Expected ${shieldedAddressLength} chars, got ${normalized.length}.`;
  }
  const payload = normalized.slice(shieldedAddressPrefix.length);
  if (!shieldedAddressDataCharset.test(payload)) {
    return `${label} contains unsupported bech32 characters.`;
  }
  return null;
};

const formatAddress = (address: string) => {
  const normalized = normalizeShieldedAddressInput(address);
  if (normalized.length <= 28) {
    return normalized || address;
  }
  const middleStart = Math.max(0, Math.floor(normalized.length / 2) - 4);
  return `${normalized.slice(0, 10)}...${normalized.slice(middleStart, middleStart + 8)}...${normalized.slice(-8)}`;
};

const formatCompactPath = (value: string | null | undefined) => {
  const trimmed = value?.trim();
  if (!trimmed) {
    return 'N/A';
  }
  if (trimmed.length <= 48) {
    return trimmed;
  }
  const normalized = trimmed.replace(/\\/g, '/');
  const parts = normalized.split('/').filter(Boolean);
  if (parts.length <= 2) {
    return `${trimmed.slice(0, 20)}...${trimmed.slice(-20)}`;
  }
  const prefix = normalized.startsWith('/') ? '/' : '';
  return `${prefix}${parts[0]}/.../${parts.slice(-2).join('/')}`;
};

const formatEndpoint = (value: string | null | undefined) => {
  const trimmed = value?.trim();
  if (!trimmed) {
    return 'N/A';
  }
  if (trimmed.length <= 40) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`;
  } catch {
    return `${trimmed.slice(0, 18)}...${trimmed.slice(-18)}`;
  }
};

const formatSeedList = (value: string[] | string | null | undefined) => {
  const seeds = Array.isArray(value) ? value : (value ?? '').split(',');
  const normalized = seeds.map((seed) => seed.trim()).filter(Boolean);
  return normalized.length ? normalized.join(', ') : 'N/A';
};

const humanizeWalletAddressError = (error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  if (message.toLowerCase().includes('invalid address encoding')) {
    const lengthMatch = message.match(/invalid address length: expected (\d+) bytes, got (\d+)/i);
    if (lengthMatch) {
      const [, expectedBytes, actualBytes] = lengthMatch;
      return `Recipient address is malformed or truncated. Expected ${expectedBytes} address bytes, got ${actualBytes}. Ask your contact to re-copy their full shielded address.`;
    }
    return 'Recipient address is malformed or truncated. Ask your contact to re-copy their full shielded address.';
  }
  return message;
};

const formatBytes = (value: number | null | undefined) => {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 'N/A';
  }
  if (value < 1024) {
    return `${value} B`;
  }
  const units = ['KB', 'MB', 'GB', 'TB'];
  let remaining = value;
  let unitIndex = -1;
  while (remaining >= 1024 && unitIndex < units.length - 1) {
    remaining /= 1024;
    unitIndex += 1;
  }
  return `${remaining.toFixed(2)} ${units[unitIndex]}`;
};

const formatHashRate = (value: number | null | undefined) => {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 'N/A';
  }
  const units = ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s'];
  let remaining = value;
  let unitIndex = 0;
  while (remaining >= 1000 && unitIndex < units.length - 1) {
    remaining /= 1000;
    unitIndex += 1;
  }
  const decimals = remaining >= 100 ? 0 : remaining >= 10 ? 1 : 2;
  return `${remaining.toFixed(decimals)} ${units[unitIndex]}`;
};

const formatDuration = (seconds: number | null | undefined) => {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) {
    return 'N/A';
  }
  const safeSeconds = Math.max(0, Math.floor(seconds));
  const days = Math.floor(safeSeconds / 86400);
  const hours = Math.floor((safeSeconds % 86400) / 3600);
  const minutes = Math.floor((safeSeconds % 3600) / 60);
  const secs = safeSeconds % 60;
  const parts: string[] = [];
  if (days) {
    parts.push(`${days}d`);
  }
  if (hours || days) {
    parts.push(`${hours}h`);
  }
  if (minutes || hours || days) {
    parts.push(`${minutes}m`);
  }
  parts.push(`${secs}s`);
  return parts.join(' ');
};

const formatHash = (value: string | null | undefined) => {
  if (!value) {
    return 'N/A';
  }
  if (value.length <= 20) {
    return value;
  }
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
};

const buildBlockAlertPattern = (tone: BlockAlertTone): BlockAlertStep[] => {
  if (tone === 'self') {
    return [
      { frequency: 1480, duration: 0.08, gap: 0.05 },
      { frequency: 1760, duration: 0.08, gap: 0.05 },
      { frequency: 2090, duration: 0.12 }
    ];
  }
  return [
    { frequency: 330, duration: 0.22, gap: 0.08 },
    { frequency: 220, duration: 0.26 }
  ];
};

const ScrollToTop = () => {
  const location = useLocation();

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
  }, [location.pathname]);

  return null;
};

const parseDisclosureInput = (input: string) => {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error('Disclosure JSON is required.');
  }
  const parseJson = (value: string) => JSON.parse(value);
  try {
    const parsed = parseJson(trimmed);
    if (typeof parsed === 'string') {
      return parseJson(parsed);
    }
    return parsed;
  } catch (error) {
    const firstBrace = trimmed.indexOf('{');
    const lastBrace = trimmed.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      const candidate = trimmed.slice(firstBrace, lastBrace + 1);
      try {
        return parseJson(candidate);
      } catch {
      }
    }
    const message = error instanceof Error ? error.message : 'Invalid disclosure JSON.';
    throw new Error(`Disclosure JSON is invalid. Paste the full package JSON. ${message}`);
  }
};

const parseTimestamp = (value?: string | null) => {
  if (!value) {
    return 0;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
};

const formatTimestamp = (value?: string | null) => {
  if (!value) {
    return 'N/A';
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return value;
  }
  return new Date(parsed).toLocaleString();
};

const activityStatusSymbols: Record<ActivityStatus, string> = {
  processing: '...',
  pending: '...',
  confirmed: '✓',
  failed: 'X'
};

const activityStatusLabels: Record<ActivityStatus, string> = {
  processing: 'Processing',
  pending: 'Pending',
  confirmed: 'Confirmed',
  failed: 'Failed'
};

const activityStatusClasses: Record<ActivityStatus, string> = {
  processing: 'border-ionosphere/40 text-ionosphere bg-ionosphere/10',
  pending: 'border-ionosphere/30 text-ionosphere/80 bg-ionosphere/5',
  confirmed: 'border-ionosphere/40 text-ionosphere bg-ionosphere/15',
  failed: 'border-guard/40 text-guard bg-guard/10'
};

const deriveHttpUrl = (wsUrl: string, httpUrl?: string) => {
  const trimmedWsUrl = wsUrl.trim();
  const wsAsHttp =
    trimmedWsUrl.startsWith('ws://')
      ? `http://${trimmedWsUrl.slice('ws://'.length)}`
      : trimmedWsUrl.startsWith('wss://')
        ? `https://${trimmedWsUrl.slice('wss://'.length)}`
        : trimmedWsUrl;

  const parseEndpoint = (value: string) => {
    try {
      return new URL(value);
    } catch {
      return null;
    }
  };
  const isLoopbackHost = (host: string) => host === '127.0.0.1' || host === 'localhost' || host === '::1';
  const wsEndpoint = parseEndpoint(trimmedWsUrl);

  if (httpUrl && httpUrl.trim()) {
    const trimmedHttpUrl = httpUrl.trim();
    const httpEndpoint = parseEndpoint(trimmedHttpUrl);

    // Local profiles frequently drift when only one endpoint is edited.
    if (
      wsEndpoint &&
      httpEndpoint &&
      isLoopbackHost(wsEndpoint.hostname) &&
      isLoopbackHost(httpEndpoint.hostname) &&
      wsEndpoint.port &&
      httpEndpoint.port &&
      wsEndpoint.port !== httpEndpoint.port
    ) {
      return wsAsHttp;
    }

    return trimmedHttpUrl;
  }

  return wsAsHttp;
};

const parsePortFromUrl = (value?: string | null): number | undefined => {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  try {
    const parsed = new URL(trimmed);
    if (!parsed.port) {
      return undefined;
    }
    const port = Number.parseInt(parsed.port, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return undefined;
    }
    return port;
  } catch {
    return undefined;
  }
};

const normalizeRpcPort = (value?: number): number | undefined => {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    return undefined;
  }
  if (value < 1 || value > 65535) {
    return undefined;
  }
  return value;
};

const parseListenAddrPort = (value?: string | null): number | undefined => {
  if (!value) {
    return undefined;
  }
  const parts = value.trim().split('/');
  for (let index = 0; index < parts.length - 1; index += 1) {
    if (parts[index] !== 'tcp') {
      continue;
    }
    const port = Number.parseInt(parts[index + 1], 10);
    if (Number.isInteger(port) && port >= 1 && port <= 65535) {
      return port;
    }
  }
  return undefined;
};

const rewriteListenAddrPort = (value: string, port: number): string => {
  const parts = value.trim().split('/');
  for (let index = 0; index < parts.length - 1; index += 1) {
    if (parts[index] === 'tcp') {
      parts[index + 1] = String(port);
      return parts.join('/');
    }
  }
  return value;
};

const isLoopbackWsEndpoint = (value: string): boolean =>
  value.startsWith('ws://127.0.0.1:') || value.startsWith('ws://localhost:') || value.startsWith('ws://[::1]:');

const isLoopbackHttpEndpoint = (value?: string): boolean =>
  Boolean(
    value &&
      (value.startsWith('http://127.0.0.1:') ||
        value.startsWith('http://localhost:') ||
        value.startsWith('http://[::1]:') ||
        value.startsWith('https://127.0.0.1:') ||
        value.startsWith('https://localhost:') ||
        value.startsWith('https://[::1]:'))
  );

const rewriteLoopbackWsEndpoint = (value: string, port: number): string => {
  if (value.startsWith('ws://localhost:')) {
    return `ws://localhost:${port}`;
  }
  if (value.startsWith('ws://[::1]:')) {
    return `ws://[::1]:${port}`;
  }
  return `ws://127.0.0.1:${port}`;
};

const rewriteLoopbackHttpEndpoint = (value: string | undefined, port: number): string => {
  if (!value) {
    return `http://127.0.0.1:${port}`;
  }
  if (value.startsWith('http://localhost:')) {
    return `http://localhost:${port}`;
  }
  if (value.startsWith('http://[::1]:')) {
    return `http://[::1]:${port}`;
  }
  if (value.startsWith('https://localhost:')) {
    return `https://localhost:${port}`;
  }
  if (value.startsWith('https://[::1]:')) {
    return `https://[::1]:${port}`;
  }
  return `http://127.0.0.1:${port}`;
};

const inferRpcPort = (connection: NodeConnection): number =>
  normalizeRpcPort(connection.rpcPort) ??
  parsePortFromUrl(connection.wsUrl) ??
  parsePortFromUrl(connection.httpUrl) ??
  defaultRpcPort;

const normalizeLocalConnectionEndpoints = (connection: NodeConnection): NodeConnection => {
  if (connection.mode !== 'local') {
    return connection;
  }

  const rpcPort = inferRpcPort(connection);
  const updates: Partial<NodeConnection> = {};

  if (normalizeRpcPort(connection.rpcPort) !== rpcPort) {
    updates.rpcPort = rpcPort;
  }

  if (!connection.wsUrl?.trim()) {
    updates.wsUrl = `ws://127.0.0.1:${rpcPort}`;
  } else if (isLoopbackWsEndpoint(connection.wsUrl) && parsePortFromUrl(connection.wsUrl) !== rpcPort) {
    updates.wsUrl = rewriteLoopbackWsEndpoint(connection.wsUrl, rpcPort);
  }

  const effectiveWsUrl = updates.wsUrl ?? connection.wsUrl;
  const derivedHttpUrl = deriveHttpUrl(effectiveWsUrl, connection.httpUrl);
  if (!connection.httpUrl?.trim()) {
    updates.httpUrl = derivedHttpUrl;
  } else if (isLoopbackHttpEndpoint(connection.httpUrl) && parsePortFromUrl(connection.httpUrl) !== rpcPort) {
    updates.httpUrl = rewriteLoopbackHttpEndpoint(connection.httpUrl, rpcPort);
  }

  if (Object.keys(updates).length === 0) {
    return connection;
  }
  return { ...connection, ...updates };
};

const isRoutineNetworkRetryLog = (line: string) =>
  /failed to connect to peer|handshake failed|rate-limited peer address announcement/i.test(line);

const classifyLogLevel = (line: string): LogLevel => {
  if (/\bWARN\b|\bWarning\b/i.test(line)) {
    return 'warn';
  }
  if (isRoutineNetworkRetryLog(line)) {
    return 'warn';
  }
  if (/\bERROR\b|\bpanic\b/i.test(line)) {
    return 'error';
  }
  if (/\bDEBUG\b/i.test(line)) {
    return 'debug';
  }
  return 'info';
};

const classifyLogCategory = (line: string): LogCategory => {
  if (/mining|nonce|hashrate|POW|coinbase/i.test(line)) {
    return 'mining';
  }
  if (/imported block|block imported|sync|syncing/i.test(line)) {
    return 'sync';
  }
  if (/peer|network|p2p|seed|broadcast/i.test(line)) {
    return 'network';
  }
  if (/storage|state_root|nullifier_root|da_root/i.test(line)) {
    return 'storage';
  }
  if (/rpc|jsonrpc|http/i.test(line)) {
    return 'rpc';
  }
  if (/consensus|execute_extrinsics|block builder|block built/i.test(line)) {
    return 'consensus';
  }
  return 'other';
};

const highlightLog = (line: string) => {
  const routineNetworkRetry = isRoutineNetworkRetryLog(line);
  if (/Block mined/i.test(line)) {
    return 'Block mined';
  }
  if (/Block imported successfully|Block imported/i.test(line)) {
    return 'Block imported';
  }
  if (/sync complete/i.test(line)) {
    return 'Sync complete';
  }
  if ((/\bWARN\b|\bWarning\b/i.test(line)) && !routineNetworkRetry) {
    return 'Warning';
  }
  if ((/\bERROR\b|\bpanic\b/i.test(line)) && !routineNetworkRetry) {
    return 'Error';
  }
  return undefined;
};

const formatLogTimestamp = (value: string) => {
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
  return value;
};

const parseLogLine = (line: string, index: number): LogEntry => {
  const timestampMatch =
    line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(.*)$/) ??
    line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.*)$/);
  const timestamp = timestampMatch ? formatLogTimestamp(timestampMatch[1]) : null;
  const message = (timestampMatch ? timestampMatch[2] : line).replace(/^(TRACE|DEBUG|INFO|WARN|ERROR)\s+/, '');
  return {
    id: `${index}-${message.slice(0, 12)}`,
    timestamp,
    level: classifyLogLevel(line),
    category: classifyLogCategory(line),
    message,
    raw: line,
    highlight: highlightLog(line)
  };
};

const buildDefaultConnection = (): NodeConnection => ({
  id: makeId(),
  label: defaultDevConnectionLabel,
  mode: 'local',
  participationRole: 'full_node',
  wsUrl: `ws://127.0.0.1:${defaultRpcPort}`,
  httpUrl: `http://127.0.0.1:${defaultRpcPort}`,
  dev: true,
  tmp: false,
  basePath: defaultDevBasePath,
  rpcPort: defaultRpcPort,
  p2pPort: defaultP2pPort,
  mineThreads: defaultMineThreads,
  miningIntent: false,
  ciphertextDaRetentionBlocks: 0,
  proofDaRetentionBlocks: 0,
  daStoreCapacity: 1024,
  rpcMethods: 'unsafe',
  rpcCorsAll: false,
  seeds: approvedSeeds,
  maxPeers: 50
});

const buildDefaultConnections = () => [buildDefaultConnection()];

const normalizeRpcControlPlane = (connection: NodeConnection): NodeConnection => {
  if (connection.mode !== 'local') {
    return connection.rpcMethods === 'safe' ? connection : { ...connection, rpcMethods: 'safe' };
  }
  if (connection.rpcExternal) {
    return connection.rpcMethods === 'safe' ? connection : { ...connection, rpcMethods: 'safe' };
  }
  return connection.rpcMethods === 'unsafe' ? connection : { ...connection, rpcMethods: 'unsafe' };
};

const normalizeConnection = (connection: NodeConnection): NodeConnection => {
  const {
    operatorEndpoint: _operatorEndpoint,
    workerName: _workerName,
    payoutAddress: _payoutAddress,
    poolAuthToken: _poolAuthToken,
    poolShareBits: _poolShareBits,
    ...sanitizedConnection
  } = connection as NodeConnection & {
    operatorEndpoint?: string;
    workerName?: string;
    payoutAddress?: string;
    poolAuthToken?: string;
    poolShareBits?: number;
  };
  const hasDefaultLocalLabel = legacyDefaultConnectionLabels.has(sanitizedConnection.label);
  const hasLegacyHegemonLabel = legacyHegemonConnectionLabels.has(sanitizedConnection.label?.trim());
  const isDefaultLocal =
    sanitizedConnection.mode === 'local' &&
    hasDefaultLocalLabel &&
    (!sanitizedConnection.basePath ||
      sanitizedConnection.basePath === '~/.hegemon-node' ||
      sanitizedConnection.basePath === defaultDevBasePath);
  const isDefaultTestnet =
    sanitizedConnection.mode === 'local' &&
    sanitizedConnection.label === 'Testnet node' &&
    (!sanitizedConnection.basePath || sanitizedConnection.basePath === '~/.hegemon-node-testnet');

  let next = normalizeLocalConnectionEndpoints(sanitizedConnection);
  const isLegacyHegemonLocalProfile =
    sanitizedConnection.mode === 'local' &&
    hasLegacyHegemonLabel &&
    Boolean(sanitizedConnection.dev) &&
    inferRpcPort(next) === defaultRpcPort &&
    isLoopbackWsEndpoint(next.wsUrl) &&
    (!next.httpUrl || isLoopbackHttpEndpoint(next.httpUrl));
  if ((isDefaultLocal || isLegacyHegemonLocalProfile) && next.label !== defaultDevConnectionLabel) {
    next = { ...next, label: defaultDevConnectionLabel };
  }
  if (isDefaultLocal && (!next.basePath || next.basePath === '~/.hegemon-node')) {
    next = { ...next, basePath: defaultDevBasePath };
  }
  if ((isDefaultLocal || isDefaultTestnet) && (next.mineThreads ?? defaultMineThreads) > maxDesktopMineThreads) {
    next = { ...next, mineThreads: maxDesktopMineThreads };
  }
  if (
    isDefaultLocal &&
    inferRpcPort(next) === legacyDesktopRpcPort &&
    isLoopbackWsEndpoint(next.wsUrl) &&
    (!next.httpUrl || isLoopbackHttpEndpoint(next.httpUrl))
  ) {
    next = {
      ...next,
      rpcPort: defaultRpcPort,
      wsUrl: rewriteLoopbackWsEndpoint(next.wsUrl, defaultRpcPort),
      httpUrl: rewriteLoopbackHttpEndpoint(next.httpUrl, defaultRpcPort)
    };
  }
  const inferredParticipationRole = inferParticipationRole(next);
  if (next.participationRole !== inferredParticipationRole) {
    next = { ...next, participationRole: inferredParticipationRole };
  }
  if (next.mode === 'remote' && !next.httpUrl?.trim()) {
    next = { ...next, httpUrl: deriveHttpUrl(next.wsUrl) };
  }
  next = normalizeRpcControlPlane(next);

  const currentSeeds = (next.seeds ?? '').trim();
  const normalizedSeeds = normalizeSeedsValue(next.seeds);
  if (currentSeeds && normalizedSeeds !== currentSeeds.toLowerCase()) {
    next = { ...next, seeds: normalizedSeeds };
  }
  if (isDefaultLocal || isDefaultTestnet) {
    if (normalizedSeeds !== approvedSeeds) {
      next = { ...next, seeds: approvedSeeds };
    }
  }

  if (next.mode === 'local') {
    if (next.p2pPort === 31333) {
      next = { ...next, p2pPort: canonicalTestnetP2pPort };
    }
    const listenAddrPort = parseListenAddrPort(next.listenAddr);
    if (listenAddrPort === 31333 && next.listenAddr) {
      next = {
        ...next,
        listenAddr: rewriteListenAddrPort(next.listenAddr, canonicalTestnetP2pPort)
      };
    }
  }

  if ((isDefaultLocal || isDefaultTestnet) && (!next.mineThreads || next.mineThreads === 1)) {
    next = { ...next, mineThreads: defaultMineThreads };
  }

  if (inferredParticipationRole !== 'authoring_pool' && next.miningIntent) {
    next = { ...next, miningIntent: false };
  }

  return next;
};

const shouldAutoStartDefaultProfile = (connection: NodeConnection): boolean => {
  const normalized = normalizeLocalConnectionEndpoints(connection);
  const role = inferParticipationRole(normalized);
  const miningProfileAllowed =
    role === 'authoring_pool' &&
    Boolean(normalized.miningIntent) &&
    !validateShieldedAddressInput(normalized.minerAddress ?? '', 'Miner address');
  const relayProfileAllowed = role === 'full_node' && !normalized.miningIntent;
  return (
    normalized.mode === 'local' &&
    normalized.label === defaultDevConnectionLabel &&
    Boolean(normalized.dev) &&
    !normalized.tmp &&
    !normalized.rpcExternal &&
    (relayProfileAllowed || miningProfileAllowed) &&
    inferRpcPort(normalized) === defaultRpcPort &&
    normalized.basePath === defaultDevBasePath &&
    isLoopbackWsEndpoint(normalized.wsUrl) &&
    (!normalized.httpUrl || isLoopbackHttpEndpoint(normalized.httpUrl)) &&
    normalizeSeedsValue(normalized.seeds) === approvedSeeds
  );
};

const findDefaultManagedConnection = (connections: NodeConnection[]) =>
  connections.find((connection) => shouldAutoStartDefaultProfile(connection)) ?? null;

export default function App() {
  const [connections, setConnections] = useState<NodeConnection[]>([]);
  const [activeConnectionId, setActiveConnectionId] = useState('');
  const [walletConnectionId, setWalletConnectionId] = useState('');
  const [nodeSummaries, setNodeSummaries] = useState<Record<string, NodeSummary>>({});
  const [nodeLogs, setNodeLogs] = useState<string[]>([]);
  const [nodeManagedStatus, setNodeManagedStatus] = useState<NodeManagedStatus | null>(null);
  const [nodeBusy, setNodeBusy] = useState(false);
  const [nodeTransition, setNodeTransition] = useState<NodeTransition | null>(null);
  const [nodeError, setNodeError] = useState<string | null>(null);
  const [logFilterInfo, setLogFilterInfo] = useState(true);
  const [logFilterWarn, setLogFilterWarn] = useState(true);
  const [logFilterError, setLogFilterError] = useState(true);
  const [logFilterDebug, setLogFilterDebug] = useState(false);
  const [logSearch, setLogSearch] = useState('');
  const [logNewestFirst, setLogNewestFirst] = useState(true);

  const [walletStatus, setWalletStatus] = useState<WalletStatus | null>(null);
  const [walletDisclosureOutput, setWalletDisclosureOutput] = useState<string>('');
  const [walletDisclosureVerifyOutput, setWalletDisclosureVerifyOutput] = useState<string>('');
  const [walletBusy, setWalletBusy] = useState(false);
  const [walletSyncQueued, setWalletSyncQueued] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);
  const [addressCopied, setAddressCopied] = useState(false);
  const [addressCopyError, setAddressCopyError] = useState<string | null>(null);
  const [miningPayoutNotice, setMiningPayoutNotice] = useState<string | null>(null);
  const [disclosureCopied, setDisclosureCopied] = useState(false);
  const [disclosureCopyError, setDisclosureCopyError] = useState<string | null>(null);

  const [storePath, setStorePath] = useState(defaultStorePath);
  const [createPassphrase, setCreatePassphrase] = useState('');
  const [createPassphraseConfirm, setCreatePassphraseConfirm] = useState('');
  const [openPassphrase, setOpenPassphrase] = useState('');
  const [activeUnlockToken, setActiveUnlockToken] = useState<string | null>(null);
  const [wsUrl, setWsUrl] = useState(`ws://127.0.0.1:${defaultRpcPort}`);
  const [forceRescan, setForceRescan] = useState(false);
  const [autoLockEnabled, setAutoLockEnabled] = useState(true);
  const [autoLockMinutes, setAutoLockMinutes] = useState(15);
  const lastActivityRef = useRef(Date.now());
  const [blockAlertEnabled, setBlockAlertEnabled] = useState(false);
  const audioContextRef = useRef<AudioContext | null>(null);
  const blockMinedAudioRef = useRef<HTMLAudioElement | null>(null);
  const blockReceivedAudioRef = useRef<HTMLAudioElement | null>(null);
  const blockAlertRef = useRef<{
    connectionId: string | null;
    blocksMined: number | null;
    blocksImported: number | null;
  }>({ connectionId: null, blocksMined: null, blocksImported: null });
  const autoStartAttemptedRef = useRef<Set<string>>(new Set());
  const manuallyStoppedRef = useRef<Set<string>>(new Set());

  const [recipientAddress, setRecipientAddress] = useState('');
  const [sendAmount, setSendAmount] = useState('');
  const [sendMemo, setSendMemo] = useState('');
  const [sendFee, setSendFee] = useState('0');
  const [autoConsolidate, setAutoConsolidate] = useState(true);

  const [contacts, setContacts] = useState<Contact[]>([]);
  const [contactsLoaded, setContactsLoaded] = useState(false);
  const [contactsSaving, setContactsSaving] = useState(false);
  const [contactsError, setContactsError] = useState<string | null>(null);
  const [newContactName, setNewContactName] = useState('');
  const [newContactAddress, setNewContactAddress] = useState('');
  const [newContactNotes, setNewContactNotes] = useState('');
  const [newContactVerified, setNewContactVerified] = useState(false);

  const [disclosureTxId, setDisclosureTxId] = useState('');
  const [disclosureOutput, setDisclosureOutput] = useState('0');
  const [disclosureInput, setDisclosureInput] = useState('');
  const [disclosureRecords, setDisclosureRecords] = useState<WalletDisclosureRecord[]>([]);
  const [disclosureListBusy, setDisclosureListBusy] = useState(false);
  const [selectedDisclosureKey, setSelectedDisclosureKey] = useState<string | null>(null);

  const [sendAttempts, setSendAttempts] = useState<SendAttempt[]>([]);

  useEffect(() => {
    const storedConnections = window.localStorage.getItem(connectionsKey);
    if (storedConnections) {
      try {
        const parsed = JSON.parse(storedConnections) as NodeConnection[];
        if (parsed.length) {
          const normalizedStored = parsed.map(normalizeConnection);
          const normalized = findDefaultManagedConnection(normalizedStored)
            ? normalizedStored
            : [buildDefaultConnection(), ...normalizedStored];
          setConnections(normalized);
          const storedActive = window.localStorage.getItem(activeConnectionKey);
          const storedWallet = window.localStorage.getItem(walletConnectionKey);
          setActiveConnectionId(
            storedActive && normalized.find((conn) => conn.id === storedActive) ? storedActive : normalized[0].id
          );
          setWalletConnectionId(
            storedWallet && normalized.find((conn) => conn.id === storedWallet) ? storedWallet : normalized[0].id
          );
          return;
        }
      } catch (error) {
        setConnections([buildDefaultConnection()]);
        return;
      }
    }
    const fallback = buildDefaultConnections();
    setConnections(fallback);
    const defaultId = fallback[0]?.id ?? '';
    setActiveConnectionId(defaultId);
    setWalletConnectionId(defaultId);
  }, []);

  useEffect(() => {
    const storedEnabled = window.localStorage.getItem(walletAutoLockEnabledKey);
    if (storedEnabled !== null) {
      setAutoLockEnabled(storedEnabled === 'true');
    }
    const storedMinutes = window.localStorage.getItem(walletAutoLockMinutesKey);
    if (storedMinutes) {
      const parsed = Number.parseInt(storedMinutes, 10);
      if (!Number.isNaN(parsed)) {
        setAutoLockMinutes(clampAutoLockMinutes(parsed));
      }
    }
  }, []);

  useEffect(() => {
    const storedEnabled = window.localStorage.getItem(blockAlertEnabledKey);
    if (storedEnabled !== null) {
      setBlockAlertEnabled(storedEnabled === 'true');
    }
  }, []);

  useEffect(() => {
    window.localStorage.setItem(walletAutoLockEnabledKey, String(autoLockEnabled));
  }, [autoLockEnabled]);

  useEffect(() => {
    window.localStorage.setItem(walletAutoLockMinutesKey, String(clampAutoLockMinutes(autoLockMinutes)));
  }, [autoLockMinutes]);

  useEffect(() => {
    window.localStorage.setItem(blockAlertEnabledKey, String(blockAlertEnabled));
  }, [blockAlertEnabled]);

  useEffect(() => {
    if (connections.length === 0) {
      return;
    }
    window.localStorage.setItem(connectionsKey, JSON.stringify(connections));
  }, [connections]);

  useEffect(() => {
    if (!activeConnectionId) {
      return;
    }
    window.localStorage.setItem(activeConnectionKey, activeConnectionId);
  }, [activeConnectionId]);

  useEffect(() => {
    if (!walletConnectionId) {
      return;
    }
    window.localStorage.setItem(walletConnectionKey, walletConnectionId);
  }, [walletConnectionId]);

  useEffect(() => {
    let cancelled = false;
    const loadContacts = async () => {
      setContactsError(null);
      try {
        const stored = await window.hegemon.contacts.list();
        if (cancelled) {
          return;
        }
        if (stored !== null) {
          setContacts(stored);
          return;
        }
      } catch {
        if (!cancelled) {
          setContactsError('Failed to load contacts.');
        }
      } finally {
        if (!cancelled) {
          setContactsLoaded(true);
        }
      }
    };
    loadContacts();
    return () => {
      cancelled = true;
    };
  }, []);

  const playBlockTone = useCallback((tone: BlockAlertTone) => {
    if (typeof window.AudioContext === 'undefined') {
      return;
    }
    const context = audioContextRef.current ?? new window.AudioContext();
    if (context.state === 'suspended') {
      void context.resume();
    }
    audioContextRef.current = context;
    const pattern = buildBlockAlertPattern(tone);
    let cursor = context.currentTime + 0.02;
    pattern.forEach((step) => {
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.type = 'sine';
      oscillator.frequency.value = step.frequency;
      gain.gain.setValueAtTime(0.0001, cursor);
      gain.gain.exponentialRampToValueAtTime(0.18, cursor + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, cursor + step.duration);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start(cursor);
      oscillator.stop(cursor + step.duration);
      cursor += step.duration + (step.gap ?? 0.06);
    });
  }, []);

  const playBlockAlert = useCallback(
    (tone: BlockAlertTone) => {
      if (!blockAlertEnabled) {
        return;
      }
      const audioRef = tone === 'self' ? blockMinedAudioRef : blockReceivedAudioRef;
      const audioSrc = tone === 'self' ? blockMinedAudio : blockReceivedAudio;
      try {
        if (!audioRef.current) {
          audioRef.current = new Audio(audioSrc);
          audioRef.current.preload = 'auto';
        }
        audioRef.current.currentTime = 0;
        const playPromise = audioRef.current.play();
        if (playPromise && typeof playPromise.catch === 'function') {
          playPromise.catch(() => {
            playBlockTone(tone);
          });
        }
        return;
      } catch {
        playBlockTone(tone);
      }
    },
    [blockAlertEnabled, playBlockTone]
  );

  useEffect(() => {
    if (!walletStatus) {
      setDisclosureRecords([]);
      setSelectedDisclosureKey(null);
    }
  }, [walletStatus]);

  const activeConnection = useMemo(
    () => connections.find((connection) => connection.id === activeConnectionId) ?? null,
    [connections, activeConnectionId]
  );

  const walletConnection = useMemo(
    () => connections.find((connection) => connection.id === walletConnectionId) ?? null,
    [connections, walletConnectionId]
  );

  useEffect(() => {
    if (walletConnection) {
      setWsUrl(walletConnection.wsUrl);
    }
  }, [walletConnection]);

  const updateActiveConnection = (update: Partial<NodeConnection> | ((conn: NodeConnection) => Partial<NodeConnection>)) => {
    if (!activeConnection) {
      return;
    }
    setConnections((prev) =>
      prev.map((conn) => {
        if (conn.id !== activeConnection.id) {
          return conn;
        }
        const patch = typeof update === 'function' ? update(conn) : update;
        return normalizeConnection({ ...conn, ...patch });
      })
    );
  };

  const openDialogPath = useCallback(async (options: DialogOpenOptions) => {
    try {
      return await window.hegemon.dialog.openPath(options);
    } catch (error) {
      console.warn('Failed to open file dialog.', error);
      return null;
    }
  }, []);

  const handlePickBasePath = useCallback(async () => {
    if (!activeConnection) {
      return;
    }
    const selection = await openDialogPath({
      title: 'Select base path',
      defaultPath: activeConnection.basePath?.trim() || undefined,
      properties: ['openDirectory', 'createDirectory']
    });
    if (selection) {
      updateActiveConnection({ basePath: selection });
    }
  }, [activeConnection, openDialogPath, updateActiveConnection]);

  const handlePickWalletStorePath = useCallback(async () => {
    const selection = await openDialogPath({
      title: 'Select wallet store',
      baseDirectory: 'walletStore',
      defaultPath: storePath.trim() || undefined,
      properties: ['openFile', 'showHiddenFiles', 'promptToCreate']
    });
    if (selection) {
      setStorePath(selection);
    }
  }, [openDialogPath, storePath]);

  const activeSummary = activeConnection ? nodeSummaries[activeConnection.id] : null;
  const activeParticipationRole = activeConnection ? inferParticipationRole(activeConnection) : 'full_node';
  const activeParticipationMeta = participationRoleMeta[activeParticipationRole];
  const roleAllowsLocalMining = activeParticipationRole === 'authoring_pool';
  const activeDisplayState = computeNodeDisplayState(activeSummary);
  const activeSummaryPeerCount = activeDisplayState.peerCount;
  const activeDisplaySyncTargetHeight = activeDisplayState.syncTargetHeight;
  const activeDisplayIsSyncing = activeDisplayState.isSyncing;
  const activeHeightDelta = activeDisplayState.heightDelta;
  const activeHeightRelation = activeDisplayState.heightRelation;
  const activeCanonicalStatus = activeDisplayState.canonicalStatus;
  const healthLabel = activeDisplayState.healthLabel;
  const healthTone = activeDisplayState.healthTone;

  const updatedAtLabel = activeSummary?.updatedAt
    ? new Date(activeSummary.updatedAt).toLocaleTimeString()
    : 'N/A';

  const logEntries = useMemo(() => nodeLogs.map((line, index) => parseLogLine(line, index)), [nodeLogs]);

  const logHighlights = useMemo(() => {
    const highlights = logEntries.filter((entry) => entry.highlight);
    return highlights.slice(-6).reverse();
  }, [logEntries]);

  const overviewHighlights = useMemo(
    () => logHighlights.filter((entry) => entry.level === 'error' || entry.highlight !== 'Warning').slice(0, 4),
    [logHighlights]
  );
  const overviewSuppressesRetryNoise = Boolean(
    activeSummary?.reachable && !activeDisplayIsSyncing && (activeSummary.peerList?.length ?? 0) > 0
  );
  const overviewWarningCount = overviewSuppressesRetryNoise
    ? 0
    : logHighlights.filter((entry) => entry.level === 'warn').length;

  const logCategoryStats = useMemo(() => {
    return logEntries.reduce<Record<LogCategory, number>>(
      (acc, entry) => {
        acc[entry.category] += 1;
        return acc;
      },
      {
        mining: 0,
        sync: 0,
        network: 0,
        consensus: 0,
        storage: 0,
        rpc: 0,
        other: 0
      }
    );
  }, [logEntries]);

  const filteredLogEntries = useMemo(() => {
    const search = logSearch.trim().toLowerCase();
    return logEntries.filter((entry) => {
      if (entry.level === 'debug' && !logFilterDebug) {
        return false;
      }
      if (entry.level === 'info' && !logFilterInfo) {
        return false;
      }
      if (entry.level === 'warn' && !logFilterWarn) {
        return false;
      }
      if (entry.level === 'error' && !logFilterError) {
        return false;
      }
      if (search && !entry.raw.toLowerCase().includes(search)) {
        return false;
      }
      return true;
    });
  }, [logEntries, logFilterDebug, logFilterInfo, logFilterWarn, logFilterError, logSearch]);

  const displayedLogEntries = useMemo(
    () => (logNewestFirst ? [...filteredLogEntries].reverse() : filteredLogEntries),
    [filteredLogEntries, logNewestFirst]
  );

  const refreshNode = async () => {
    if (!connections.length) {
      return;
    }

    const summaries: Record<string, NodeSummary> = {};

    await Promise.all(
      connections.map(async (connection) => {
        const httpUrl = deriveHttpUrl(connection.wsUrl, connection.httpUrl);
        try {
          const summary = await window.hegemon.node.summary({
            connectionId: connection.id,
            label: connection.label,
            isLocal: connection.mode === 'local',
            httpUrl
          });
          summaries[connection.id] = summary;
        } catch (error) {
          summaries[connection.id] = {
            connectionId: connection.id,
            label: connection.label,
            reachable: false,
            isLocal: connection.mode === 'local',
            nodeVersion: null,
            peers: null,
            isSyncing: null,
            bestBlock: null,
            bestNumber: null,
            genesisHash: null,
            mining: null,
            minerAddress: null,
            miningThreads: null,
            miningSyncGateOpen: null,
            bootstrapAuthoring: null,
            hashRate: null,
            blocksFound: null,
            difficulty: null,
            nextDifficulty: null,
            blockHeight: null,
            syncTargetHeight: null,
            pendingExtrinsics: null,
            peerList: null,
            canonicalCheckpoint: null,
            supplyDigest: null,
            storage: null,
            telemetry: null,
            config: null,
            updatedAt: new Date().toISOString(),
            error: error instanceof Error ? error.message : 'Summary failed'
          };
        }
      })
    );

    setNodeSummaries(summaries);
    const current = activeConnection ? summaries[activeConnection.id] : null;
    if (current?.error) {
      setNodeError(current.error);
    } else {
      setNodeError(null);
    }

    if (activeConnection?.mode === 'local') {
      try {
        const logs = await window.hegemon.node.logs();
        setNodeLogs(logs);
      } catch (error) {
        setNodeLogs((prev) => prev);
      }
      try {
        const managed = await window.hegemon.node.managedStatus();
        setNodeManagedStatus(managed);
      } catch {
        setNodeManagedStatus(null);
      }
    } else {
      setNodeLogs([]);
      setNodeManagedStatus(null);
    }
  };

  useEffect(() => {
    refreshNode();
    const interval = window.setInterval(refreshNode, 5000);
    return () => window.clearInterval(interval);
  }, [connections, activeConnectionId]);

  useEffect(() => {
    const currentMined = activeSummary?.telemetry?.blocksMined ?? null;
    const currentImported = activeSummary?.telemetry?.blocksImported ?? null;
    if (!activeConnectionId) {
      blockAlertRef.current = { connectionId: null, blocksMined: currentMined, blocksImported: currentImported };
      return;
    }
    const previous = blockAlertRef.current;
    if (
      previous.connectionId !== activeConnectionId ||
      previous.blocksMined === null ||
      previous.blocksImported === null ||
      currentMined === null ||
      currentImported === null
    ) {
      blockAlertRef.current = { connectionId: activeConnectionId, blocksMined: currentMined, blocksImported: currentImported };
      return;
    }
    const minedDelta = currentMined - previous.blocksMined;
    const importedDelta = currentImported - previous.blocksImported;
    if (minedDelta < 0 || importedDelta < 0) {
      blockAlertRef.current = { connectionId: activeConnectionId, blocksMined: currentMined, blocksImported: currentImported };
      return;
    }
    if (blockAlertEnabled) {
      if (minedDelta > 0) {
        playBlockAlert('self');
      } else if (importedDelta > 0) {
        playBlockAlert('other');
      }
    }
    blockAlertRef.current = { connectionId: activeConnectionId, blocksMined: currentMined, blocksImported: currentImported };
  }, [
    activeConnectionId,
    activeSummary?.telemetry?.blocksImported,
    activeSummary?.telemetry?.blocksMined,
    blockAlertEnabled,
    playBlockAlert
  ]);

  const transitionReachable = nodeTransition ? nodeSummaries[nodeTransition.connectionId]?.reachable : undefined;

  useEffect(() => {
    if (!nodeTransition) {
      return;
    }
    if (nodeTransition.action === 'starting' && transitionReachable) {
      setNodeTransition(null);
      return;
    }
    if (nodeTransition.action === 'stopping' && transitionReachable === false) {
      setNodeTransition(null);
    }
  }, [nodeTransition, transitionReachable]);

  useEffect(() => {
    if (!nodeTransition) {
      return;
    }
    const timeoutMs = nodeTransition.action === 'starting' ? 30_000 : 15_000;
    const timer = window.setTimeout(() => {
      setNodeTransition((prev) => {
        if (!prev) {
          return prev;
        }
        if (prev.action !== nodeTransition.action || prev.connectionId !== nodeTransition.connectionId) {
          return prev;
        }
        return null;
      });
    }, timeoutMs);
    return () => window.clearTimeout(timer);
  }, [nodeTransition]);

  const handleNodeStart = async (options: { automatic?: boolean } = {}) => {
    if (!activeConnection || activeConnection.mode !== 'local') {
      setNodeError('Select a local connection to start a node.');
      return;
    }
    const normalizedConnection = normalizeLocalConnectionEndpoints(activeConnection);
    const normalizedRole = inferParticipationRole(normalizedConnection);
    const rpcPort = inferRpcPort(normalizedConnection);
    const normalizedMinerAddress =
      normalizedRole === 'authoring_pool'
        ? normalizeShieldedAddressInput(normalizedConnection.minerAddress ?? '')
        : '';
    if (normalizedConnection !== activeConnection) {
      updateActiveConnection({
        wsUrl: normalizedConnection.wsUrl,
        httpUrl: normalizedConnection.httpUrl,
        rpcPort: rpcPort
      });
    }
    if (normalizedRole !== 'authoring_pool' && normalizedConnection.miningIntent) {
      setNodeError('Local mining is reserved for the Mining node role. Switch roles or disable Auto-start mining.');
      return;
    }
    if (normalizedRole === 'authoring_pool' && normalizedConnection.miningIntent && !normalizedMinerAddress) {
      setNodeError('Set a miner address before enabling mining.');
      return;
    }
    if (normalizedRole === 'authoring_pool' && normalizedMinerAddress) {
      const validationError = validateShieldedAddressInput(normalizedMinerAddress, 'Miner address');
      if (validationError) {
        setNodeError(validationError);
        return;
      }
    }
    if (normalizedConnection.maxPeers !== undefined && normalizedConnection.maxPeers < 1) {
      setNodeError('Max peers must be at least 1.');
      return;
    }
    if (normalizedConnection.tmp) {
      if (options.automatic) {
        return;
      }
      const confirmed = window.confirm('Temp storage deletes node data on shutdown. Continue?');
      if (!confirmed) {
        return;
      }
    } else if (!normalizedConnection.basePath) {
      if (options.automatic) {
        return;
      }
      const confirmed = window.confirm('No base path set. The node will use its default data directory. Continue?');
      if (!confirmed) {
        return;
      }
    }
    setNodeTransition({ action: 'starting', connectionId: normalizedConnection.id, startedAt: Date.now() });
    setNodeBusy(true);
    setNodeError(null);
    try {
      if (!options.automatic) {
        manuallyStoppedRef.current.delete(normalizedConnection.id);
      }
      await window.hegemon.node.start({
        connectionId: normalizedConnection.id,
        basePath: normalizedConnection.basePath || undefined,
        dev: normalizedConnection.dev,
        tmp: normalizedConnection.tmp,
        rpcPort,
        p2pPort: normalizedConnection.p2pPort,
        listenAddr: normalizedConnection.listenAddr || undefined,
        minerAddress: normalizedRole === 'authoring_pool' ? normalizedMinerAddress || undefined : undefined,
        mineThreads: normalizedRole === 'authoring_pool' ? normalizedConnection.mineThreads : undefined,
        mineOnStart: normalizedRole === 'authoring_pool' ? normalizedConnection.miningIntent : false,
        seeds: normalizedConnection.seeds || undefined,
        maxPeers: normalizedConnection.maxPeers,
        rpcExternal: normalizedConnection.rpcExternal,
        rpcMethods: normalizedConnection.rpcMethods,
        rpcCorsAll: normalizedConnection.rpcCorsAll,
        nodeName: normalizedConnection.nodeName || undefined,
        ciphertextDaRetentionBlocks: normalizedConnection.ciphertextDaRetentionBlocks,
        proofDaRetentionBlocks: normalizedConnection.proofDaRetentionBlocks,
        daStoreCapacity: normalizedConnection.daStoreCapacity
      });
      await refreshNode();
    } catch (error) {
      setNodeTransition(null);
      setNodeError(error instanceof Error ? error.message : 'Failed to start node.');
    } finally {
      setNodeBusy(false);
    }
  };

  useEffect(() => {
    if (!activeConnection || activeSummary?.reachable !== false) {
      return;
    }
    if (!shouldAutoStartDefaultProfile(activeConnection)) {
      return;
    }
    if (nodeBusy || nodeTransition || nodeManagedStatus?.managed) {
      return;
    }
    if (manuallyStoppedRef.current.has(activeConnection.id)) {
      return;
    }
    if (autoStartAttemptedRef.current.has(activeConnection.id)) {
      return;
    }
    autoStartAttemptedRef.current.add(activeConnection.id);
    void handleNodeStart({ automatic: true });
  }, [activeConnection, activeSummary?.reachable, nodeBusy, nodeTransition, nodeManagedStatus?.managed]);

  useEffect(() => {
    if (!activeConnection || activeSummary?.reachable !== false) {
      return;
    }
    if (shouldAutoStartDefaultProfile(activeConnection)) {
      return;
    }
    if (nodeBusy || nodeTransition || nodeManagedStatus?.managed) {
      return;
    }

    const defaultManagedConnection = findDefaultManagedConnection(connections);
    if (defaultManagedConnection) {
      setActiveConnectionId(defaultManagedConnection.id);
      if (!walletConnection || walletConnection.id === activeConnection.id) {
        setWalletConnectionId(defaultManagedConnection.id);
      }
      return;
    }

    const fallback = buildDefaultConnection();
    setConnections((prev) => [fallback, ...prev]);
    setActiveConnectionId(fallback.id);
    if (!walletConnectionId || walletConnectionId === activeConnection.id) {
      setWalletConnectionId(fallback.id);
    }
  }, [
    activeConnection,
    activeSummary?.reachable,
    connections,
    nodeBusy,
    nodeTransition,
    nodeManagedStatus?.managed,
    walletConnection,
    walletConnectionId
  ]);

  const handleNodeStop = async () => {
    if (!activeConnection || activeConnection.mode !== 'local') {
      setNodeError('Select a local connection to stop a node.');
      return;
    }
    if (!nodeManagedStatus?.managed) {
      setNodeError('This app is not managing a node process. Stop the node (or port-forward) outside of Hegemon Core.');
      return;
    }
    if (nodeManagedStatus.connectionId && nodeManagedStatus.connectionId !== activeConnection.id) {
      setNodeError('The running node was started from a different local connection profile. Switch to that profile to stop it.');
      return;
    }
    setNodeTransition({ action: 'stopping', connectionId: activeConnection.id, startedAt: Date.now() });
    setNodeBusy(true);
    try {
      await window.hegemon.node.stop();
      manuallyStoppedRef.current.add(activeConnection.id);
      await refreshNode();
    } catch (error) {
      setNodeTransition(null);
      setNodeError(error instanceof Error ? error.message : 'Failed to stop node.');
    } finally {
      setNodeBusy(false);
    }
  };

  const resolveStorePath = () => {
    const trimmed = storePath.trim();
    if (!trimmed) {
      throw new Error('Wallet store path is required.');
    }
    return trimmed;
  };

  const invalidateWalletSession = useCallback(
    (_message: string, _storePathOverride?: string) => {
      setWalletStatus(null);
      setWalletError(null);
      setActiveUnlockToken(null);
      setWalletSyncQueued(false);
      setDisclosureRecords([]);
    },
    []
  );

  const requireActiveUnlockToken = () => {
    if (!activeUnlockToken) {
      throw new Error('Wallet is locked. Open or init the store first.');
    }
    return activeUnlockToken;
  };

  const refreshWalletStatus = useCallback(
    async (overrideUnlockToken?: string) => {
      const unlockToken = overrideUnlockToken ?? activeUnlockToken;
      if (!unlockToken) {
        setWalletStatus(null);
        return;
      }
      let resolvedStorePath = '';
      try {
        resolvedStorePath = resolveStorePath();
        const status = await window.hegemon.wallet.status(resolvedStorePath, unlockToken, true);
        setWalletStatus(status);
        setWalletError(null);
        return true;
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Wallet status failed.';
        if (isWalletSessionClosedError(message)) {
          invalidateWalletSession(message, resolvedStorePath || storePath);
          return false;
        }
        setWalletStatus(null);
        setWalletError(message);
        return false;
      }
    },
    [activeUnlockToken, invalidateWalletSession, storePath]
  );

  const refreshDisclosureRecords = useCallback(
    async (overrideUnlockToken?: string) => {
      const unlockToken = overrideUnlockToken ?? activeUnlockToken;
      if (!unlockToken) {
        setDisclosureRecords([]);
        return;
      }
      setDisclosureListBusy(true);
      try {
        const resolvedStorePath = resolveStorePath();
        const records = await window.hegemon.wallet.disclosureList(resolvedStorePath, unlockToken);
        setDisclosureRecords(records);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Disclosure list failed.';
        const code = (error as { code?: string }).code;
        if (isWalletSessionClosedError(message)) {
          invalidateWalletSession(message, storePath);
          return;
        }
        if (code === 'unknown_method' || message.includes('unknown method disclosure.list')) {
          setDisclosureRecords([]);
          return;
        }
        setWalletError(message);
      } finally {
        setDisclosureListBusy(false);
      }
    },
    [activeUnlockToken, invalidateWalletSession, storePath]
  );

  const handleWalletInit = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const resolvedStorePath = resolveStorePath();
      if (createPassphrase.length < minWalletPassphraseLength) {
        throw new Error(`Passphrase must be at least ${minWalletPassphraseLength} characters.`);
      }
      if (createPassphrase !== createPassphraseConfirm) {
        throw new Error('Passphrases do not match.');
      }
      const session: WalletUnlockSession = await window.hegemon.wallet.init(
        resolvedStorePath,
        createPassphrase
      );
      setWalletStatus(session.status);
      setActiveUnlockToken(session.unlockToken);
      setCreatePassphrase('');
      setCreatePassphraseConfirm('');
      setOpenPassphrase('');
      await refreshDisclosureRecords(session.unlockToken);
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet init failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleWalletRestore = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const resolvedStorePath = resolveStorePath();
      if (!openPassphrase.trim()) {
        throw new Error('Enter the wallet passphrase to open the store.');
      }
      const session: WalletUnlockSession = await window.hegemon.wallet.restore(
        resolvedStorePath,
        openPassphrase
      );
      setWalletStatus(session.status);
      setActiveUnlockToken(session.unlockToken);
      setOpenPassphrase('');
      setCreatePassphrase('');
      setCreatePassphraseConfirm('');
      await refreshDisclosureRecords(session.unlockToken);
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet open failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleWalletLock = useCallback(async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      await window.hegemon.wallet.lock();
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet lock failed.');
    } finally {
      setWalletBusy(false);
      setWalletStatus(null);
      setActiveUnlockToken(null);
      setCreatePassphrase('');
      setCreatePassphraseConfirm('');
      setOpenPassphrase('');
      setWalletDisclosureOutput('');
      setWalletDisclosureVerifyOutput('');
      setDisclosureRecords([]);
      setSelectedDisclosureKey(null);
    }
  }, []);

  useEffect(() => {
    if (!autoLockEnabled || !activeUnlockToken) {
      return;
    }
    const updateActivity = () => {
      lastActivityRef.current = Date.now();
    };
    const events: Array<keyof WindowEventMap> = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'focus'];
    events.forEach((event) => window.addEventListener(event, updateActivity, { passive: true }));
    updateActivity();

    const timeoutMs = clampAutoLockMinutes(autoLockMinutes) * 60_000;
    const interval = window.setInterval(() => {
      if (walletBusy) {
        lastActivityRef.current = Date.now();
        return;
      }
      if (Date.now() - lastActivityRef.current >= timeoutMs) {
        void handleWalletLock();
      }
    }, 30_000);

    return () => {
      events.forEach((event) => window.removeEventListener(event, updateActivity));
      window.clearInterval(interval);
    };
  }, [autoLockEnabled, activeUnlockToken, autoLockMinutes, handleWalletLock, walletBusy]);

  useEffect(() => {
    if (!activeUnlockToken) {
      return;
    }
    if (!walletBusy) {
      void refreshWalletStatus();
    }
    const interval = window.setInterval(() => {
      if (!walletBusy) {
        void refreshWalletStatus();
      }
    }, 10_000);
    return () => window.clearInterval(interval);
  }, [activeUnlockToken, refreshWalletStatus, walletBusy]);

  const handleCopyAddress = async () => {
    setAddressCopyError(null);
    if (!walletStatus?.primaryAddress) {
      setAddressCopyError('Open or sync a wallet before copying the address.');
      return;
    }
    try {
      await window.hegemon.clipboard.writeText(walletStatus.primaryAddress);
      setAddressCopied(true);
      window.setTimeout(() => setAddressCopied(false), 2000);
    } catch {
      setAddressCopyError('Failed to copy address.');
    }
  };

  const handleCopyDisclosureOutput = async () => {
    setDisclosureCopyError(null);
    if (!walletDisclosureOutput) {
      setDisclosureCopyError('Generate a disclosure package first.');
      return;
    }
    try {
      await window.hegemon.clipboard.writeText(walletDisclosureOutput);
      setDisclosureCopied(true);
      window.setTimeout(() => setDisclosureCopied(false), 2000);
    } catch {
      setDisclosureCopyError('Failed to copy disclosure package.');
    }
  };

  const handleUseWalletAddressForMining = () => {
    if (!activeConnection || !walletStatus?.primaryAddress) {
      return;
    }
    const payoutAddress = normalizeShieldedAddressInput(walletStatus.primaryAddress);
    updateActiveConnection((connection) => ({
      participationRole: 'authoring_pool',
      minerAddress: payoutAddress,
      mineThreads: connection.mineThreads || defaultMineThreads,
      miningIntent: connection.miningIntent || activeSummary?.mining === true
    }));
    setMiningPayoutNotice(
      activeSummary?.reachable
        ? 'Saved. Restart the node to apply this mining payout address.'
        : 'Saved for the next node start.'
    );
  };

  const handleWalletSync = async (forceOverride?: boolean) => {
    setWalletError(null);
    const targetWs = wsUrl.trim();
    if (!targetWs) {
      setWalletError('Wallet RPC URL is required.');
      return;
    }
    const walletRpcUrl = deriveHttpUrl(targetWs, walletConnection?.httpUrl ?? activeConnection?.httpUrl);
    try {
      const summary = await window.hegemon.node.summary({
        connectionId: 'wallet-sync',
        label: 'Wallet sync target',
        isLocal: false,
        httpUrl: walletRpcUrl
      });
      if (!summary.reachable) {
        setWalletError('Wallet connection is offline. Check the wallet RPC URL.');
        return;
      }
    } catch {
      setWalletError('Wallet connection is offline. Check the wallet RPC URL.');
      return;
    }
    setWalletBusy(true);
    try {
      const rescan = forceOverride ?? forceRescan;
      if (forceOverride) {
        setForceRescan(true);
      }
      const unlockToken = requireActiveUnlockToken();
      const resolvedStorePath = resolveStorePath();
      const syncPromise = window.hegemon.wallet.sync(
        resolvedStorePath,
        unlockToken,
        walletRpcUrl,
        rescan
      );
      // Full rescans on long-running chains can take minutes; keep the shorter guardrail for normal syncs.
      const timeoutMs = rescan ? 15 * 60_000 : 90_000;
      const result = await new Promise<WalletSyncResult>((resolve, reject) => {
        const timeout = window.setTimeout(async () => {
          try {
            await window.hegemon.wallet.lock();
            setActiveUnlockToken(null);
            setWalletStatus(null);
          } catch {
            // Ignore lock failures; we'll surface a timeout error.
          }
          const modeLabel = rescan ? 'force-rescan' : 'sync';
          reject(
            new Error(
              `Wallet ${modeLabel} timed out after ${Math.round(timeoutMs / 1000)}s. Check the wallet RPC URL and try again.`
            )
          );
        }, timeoutMs);
        syncPromise
          .then((value) => {
            window.clearTimeout(timeout);
            resolve(value);
          })
          .catch((error) => {
            window.clearTimeout(timeout);
            reject(error);
          });
      });
      const refreshed = await refreshWalletStatus();
      if (refreshed) {
        await refreshDisclosureRecords();
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Wallet sync failed.';
      if (isWalletSessionClosedError(message)) {
        invalidateWalletSession(message, storePath);
      } else {
        setWalletError(message);
      }
    } finally {
      setWalletBusy(false);
    }
  };

  const handleWalletCancel = async () => {
    try {
      await window.hegemon.wallet.lock();
    } catch {
      // Ignore lock errors; we still want to clear the busy flag.
    } finally {
      setActiveUnlockToken(null);
      setWalletStatus(null);
      setWalletBusy(false);
      setWalletSyncQueued(false);
      setWalletError('Wallet sync canceled.');
    }
  };

  useEffect(() => {
    if (!walletBusy && walletSyncQueued) {
      setWalletSyncQueued(false);
      void handleWalletSync();
    }
  }, [walletBusy, walletSyncQueued]);

  const handleWalletSend = async () => {
    let attemptId: string | null = null;
    setWalletError(null);
    try {
      const normalizedRecipientAddress = normalizeShieldedAddressInput(recipientAddress);
      const recipientAddressError = validateShieldedAddressInput(normalizedRecipientAddress, 'Recipient address');
      if (recipientAddressError) {
        throw new Error(recipientAddressError);
      }
      const amount = toBaseUnits(sendAmount);
      const fee = toBaseUnits(sendFee);
      if (amount === null || fee === null) {
        throw new Error('Amount and miner tip must be valid numbers.');
      }
      if (amount <= 0) {
        throw new Error('Amount must be greater than 0.');
      }
      if (fee < 0) {
        throw new Error('Miner tip cannot be negative.');
      }
      if (genesisMismatch) {
        throw new Error('Genesis mismatch between wallet and node. Switch nodes or force a rescan before sending.');
      }
      const liveHttpUrl = deriveHttpUrl(wsUrl, activeConnection?.httpUrl);
      if (liveHttpUrl) {
        const liveSummary = await window.hegemon.node.summary({
          connectionId: 'wallet-send',
          label: 'Wallet send target',
          isLocal: false,
          httpUrl: liveHttpUrl
        });
        if (!liveSummary.reachable) {
          throw new Error('Wallet connection is offline. Select a reachable node or fix the RPC endpoint.');
        }
      } else if (walletSummary?.reachable === false) {
        throw new Error('Wallet connection is offline. Select a reachable node or fix the RPC endpoint.');
      }

      setWalletBusy(true);
      const unlockToken = requireActiveUnlockToken();
      const resolvedStorePath = resolveStorePath();
      const recipients = [
        {
          address: normalizedRecipientAddress,
          value: amount,
          asset_id: 0,
          memo: sendMemo || null
        }
      ];

      const plan = await window.hegemon.wallet.sendPlan({
        storePath: resolvedStorePath,
        unlockToken,
        recipients,
        fee
      });

      if (!plan.sufficientFunds) {
        throw new Error(`Insufficient funds: have ${formatHgm(plan.availableValue)}, need ${formatHgm(plan.totalNeeded)}.`);
      }

      let autoConsolidateForSend = autoConsolidate;
      const consolidationEstimate = plan.needsConsolidation ? plan.plan?.txsNeeded : undefined;
      const consolidationBlocksEstimate = plan.needsConsolidation ? plan.plan?.blocksNeeded : undefined;

      if (plan.needsConsolidation && !autoConsolidateForSend) {
        const noteContext = `This send needs ${plan.selectedNoteCount} notes (wallet has ${plan.walletNoteCount}, max ${plan.maxInputs} inputs/tx).`;
        const estimateLine = consolidationEstimate
          ? `\n\nEstimated consolidation: ~${consolidationEstimate} tx${
              consolidationBlocksEstimate
                ? ` across ~${consolidationBlocksEstimate} blocks`
                : ''
            }${
              consolidationBlocksEstimate && consolidationBlocksEstimate > 0
                ? ` (~${(consolidationEstimate / consolidationBlocksEstimate).toFixed(1)} tx/block)`
                : ''
            }.`
          : '';
        const confirmed = window.confirm(
          `Note consolidation is required before sending.\n\n${noteContext}${estimateLine}\n\nEnable auto-consolidate and proceed?`
        );
        if (!confirmed) {
          return;
        }
        autoConsolidateForSend = true;
        setAutoConsolidate(true);
      }

      if (autoConsolidateForSend && consolidationEstimate && consolidationEstimate > 25) {
        const noteContext = `This send needs ${plan.selectedNoteCount} notes (wallet has ${plan.walletNoteCount}, max ${plan.maxInputs} inputs/tx).`;
        const estimateLine =
          consolidationBlocksEstimate && consolidationBlocksEstimate > 0
            ? `Estimated consolidation: ~${consolidationEstimate} tx across ~${consolidationBlocksEstimate} blocks (~${(
                consolidationEstimate / consolidationBlocksEstimate
              ).toFixed(1)} tx/block).`
            : `Estimated consolidation: ~${consolidationEstimate} tx.`;
        const confirmed = window.confirm(
          `This send will trigger note consolidation.\n\n${noteContext}\n\n${estimateLine}\n\nProceed?`
        );
        if (!confirmed) {
          return;
        }
      }

      const consolidationExpected = autoConsolidateForSend ? consolidationEstimate : undefined;
      attemptId = makeId();
      const createdAt = new Date().toISOString();
      const attempt: SendAttempt = {
        id: attemptId,
        storePath: resolvedStorePath,
        createdAt,
        recipient: normalizedRecipientAddress,
        amount,
        fee,
        memo: sendMemo || undefined,
        status: 'processing',
        notesNeeded: plan.selectedNoteCount,
        walletNoteCount: plan.walletNoteCount,
        maxInputs: plan.maxInputs,
        consolidationExpected,
        consolidationExpectedBlocks: autoConsolidateForSend ? consolidationBlocksEstimate : undefined
      };
      setSendAttempts((prev) => [attempt, ...prev].slice(0, 50));

      const request = {
        storePath: resolvedStorePath,
        unlockToken,
        wsUrl: deriveHttpUrl(wsUrl, activeConnection?.httpUrl),
        recipients,
        fee,
        autoConsolidate: autoConsolidateForSend
      };
      const result = await window.hegemon.wallet.send(request);
      const normalizedTxId = normalizeTxId(result.txHash) ?? result.txHash;
      setSendAttempts((prev) =>
        prev.map((entry) =>
          entry.id === attemptId ? { ...entry, status: 'pending', txId: normalizedTxId } : entry
        )
      );
      setRecipientAddress('');
      setSendAmount('');
      setSendMemo('');
      const refreshed = await refreshWalletStatus();
      if (refreshed) {
        await refreshDisclosureRecords();
      }
    } catch (error) {
      if (attemptId) {
        const message = humanizeWalletAddressError(error);
        setSendAttempts((prev) =>
          prev.map((entry) =>
            entry.id === attemptId ? { ...entry, status: 'failed', error: message } : entry
          )
        );
      }
      setWalletError(humanizeWalletAddressError(error));
    } finally {
      setWalletBusy(false);
    }
  };

  const handleAddContact = async () => {
    if (!contactsLoaded || contactsSaving || !newContactName || !newContactAddress) {
      return;
    }
    const normalizedContactAddress = normalizeShieldedAddressInput(newContactAddress);
    const contactAddressError = validateShieldedAddressInput(normalizedContactAddress, 'Contact address');
    if (contactAddressError) {
      setContactsError(contactAddressError);
      return;
    }
    const newEntry: Contact = {
      id: makeId(),
      name: newContactName,
      address: normalizedContactAddress,
      verified: newContactVerified,
      notes: newContactNotes || undefined,
      lastUsed: undefined,
      chainSpecId: activeSummary?.config?.chainSpecId,
      chainSpecName: activeSummary?.config?.chainSpecName,
      protocolVersion: '0.10'
    };
    const nextContacts = [newEntry, ...contacts];

    setContactsSaving(true);
    try {
      await window.hegemon.contacts.save(nextContacts);
      setContacts(nextContacts);
      setContactsError(null);
      setNewContactName('');
      setNewContactAddress('');
      setNewContactNotes('');
      setNewContactVerified(false);
    } catch {
      setContactsError('Failed to save contacts.');
    } finally {
      setContactsSaving(false);
    }
  };

  const handleRemoveContact = async (id: string) => {
    if (!contactsLoaded || contactsSaving) {
      return;
    }
    const nextContacts = contacts.filter((entry) => entry.id !== id);

    setContactsSaving(true);
    try {
      await window.hegemon.contacts.save(nextContacts);
      setContacts(nextContacts);
      setContactsError(null);
    } catch {
      setContactsError('Failed to save contacts.');
    } finally {
      setContactsSaving(false);
    }
  };

  const handleSelectDisclosure = (record: WalletDisclosureRecord) => {
    const key = `${record.txId}:${record.outputIndex}`;
    setSelectedDisclosureKey(key);
    setDisclosureTxId(record.txId);
    setDisclosureOutput(String(record.outputIndex));
  };

  const handleDisclosureCreate = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      if (!disclosureTxId.trim()) {
        throw new Error('Transaction hash is required.');
      }
      const unlockToken = requireActiveUnlockToken();
      const outputIndex = Number.parseInt(disclosureOutput, 10);
      if (Number.isNaN(outputIndex)) {
        throw new Error('Output index must be a number.');
      }
      const result: WalletDisclosureCreateResult = await window.hegemon.wallet.disclosureCreate(
        resolveStorePath(),
        unlockToken,
        deriveHttpUrl(wsUrl, activeConnection?.httpUrl),
        disclosureTxId,
        outputIndex
      );
      setWalletDisclosureOutput(JSON.stringify(result, null, 2));
      setDisclosureCopied(false);
      setDisclosureCopyError(null);
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Disclosure create failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleDisclosureVerify = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const unlockToken = requireActiveUnlockToken();
      const parsed = parseDisclosureInput(disclosureInput);
      const result: WalletDisclosureVerifyResult = await window.hegemon.wallet.disclosureVerify(
        resolveStorePath(),
        unlockToken,
        deriveHttpUrl(wsUrl, activeConnection?.httpUrl),
        parsed
      );
      setWalletDisclosureVerifyOutput(JSON.stringify(result, null, 2));
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Disclosure verify failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleAddConnection = () => {
    const next: NodeConnection = {
      id: makeId(),
      label: 'Local RPC endpoint',
      mode: 'remote',
      wsUrl: `ws://127.0.0.1:${defaultRpcPort}`,
      httpUrl: `http://127.0.0.1:${defaultRpcPort}`,
      allowRemoteMining: false
    };
    setConnections((prev) => [next, ...prev]);
    setActiveConnectionId(next.id);
  };

  const handleRemoveConnection = () => {
    if (!activeConnection || connections.length <= 1) {
      return;
    }
    const remaining = connections.filter((conn) => conn.id !== activeConnection.id);
    setConnections(remaining);
    const nextId = remaining[0]?.id ?? '';
    setActiveConnectionId(nextId);
    if (!remaining.find((conn) => conn.id === walletConnectionId)) {
      setWalletConnectionId(nextId);
    }
  };

  const createPassphraseTooShort =
    createPassphrase.length > 0 && createPassphrase.length < minWalletPassphraseLength;
  const createPassphraseMismatch =
    createPassphraseConfirm.length > 0 && createPassphrase !== createPassphraseConfirm;
  const canInitWallet =
    !walletBusy &&
    createPassphrase.length >= minWalletPassphraseLength &&
    createPassphraseConfirm.length > 0 &&
    !createPassphraseTooShort &&
    !createPassphraseMismatch;
  const canOpenWallet = !walletBusy && Boolean(openPassphrase.trim());

  const walletSummary = walletConnection ? nodeSummaries[walletConnection.id] : null;
  const walletReady = Boolean(walletStatus && activeUnlockToken);
  const walletUnlocked = Boolean(activeUnlockToken);
  const walletGenesis = walletStatus?.genesisHash ?? null;
  const walletNodeGenesis = walletSummary?.genesisHash ?? null;
  const activeNodeGenesis = activeSummary?.genesisHash ?? null;
  const nodeIsLocal = activeConnection?.mode === 'local';
  const nodeTransitionAction =
    nodeTransition && activeConnection && nodeTransition.connectionId === activeConnection.id ? nodeTransition.action : null;
  const defaultProfileLaunchable = activeConnection ? shouldAutoStartDefaultProfile(activeConnection) : false;
  const nodeStartupPending = Boolean(
    activeConnection &&
      defaultProfileLaunchable &&
      !manuallyStoppedRef.current.has(activeConnection.id) &&
      (nodeTransitionAction === 'starting' || (!activeSummary && !nodeError) || (activeSummary?.reachable === false && nodeBusy))
  );
  const displayedNodeGenesis = activeNodeGenesis ?? walletNodeGenesis;
  const activeNodeLive = Boolean(activeSummary?.reachable && displayedNodeGenesis);
  const activeSeedList = activeSummary?.config?.bootstrapNodes?.length
    ? formatSeedList(activeSummary.config.bootstrapNodes)
    : formatSeedList(activeConnection?.seeds);
  const activeHeightDeltaAbsLabel =
    typeof activeHeightDelta === 'number' ? formatBlockCount(Math.abs(activeHeightDelta)) : null;
  const rpcPolicyLabel = activeSummary?.config
    ? `${activeSummary.config.rpcMethods} / ${activeSummary.config.rpcExternal ? 'network' : 'loopback'}`
    : 'N/A';
  const activePeerList = activeSummary?.peerList ?? [];
  const firstActivePeer = activePeerList[0] ?? null;
  const activePeerCount = activeSummaryPeerCount;
  const peerEvidenceLabel =
    firstActivePeer
      ? `${formatNumber(activePeerList.length)} ${activePeerList.length === 1 ? 'peer' : 'peers'} listed`
      : activePeerCount === null
      ? 'Peer count unavailable'
      : activePeerCount === 0
        ? 'No peers reported'
        : `${formatNumber(activePeerCount)} ${activePeerCount === 1 ? 'peer' : 'peers'} reported`;
  const peerDetailLabel = firstActivePeer
    ? `${firstActivePeer.addr} · ${formatHash(firstActivePeer.peerId)}`
    : activePeerCount && activePeerCount > 0
      ? `${peerEvidenceLabel}; peer details unavailable from RPC`
      : peerEvidenceLabel;
  const activeHeightLabel = formatNumber(activeSummary?.bestNumber);
  const syncAlignmentLabel =
    nodeStartupPending
      ? 'Starting'
      : activeCanonicalStatus === 'mismatch'
        ? 'Fork mismatch'
        : activeCanonicalStatus === 'pending'
          ? 'Checkpoint pending'
          : activeCanonicalStatus === 'unavailable'
            ? 'Checkpoint unknown'
      : activeHeightRelation === 'syncing'
        ? `Syncing to ${formatNumber(activeDisplaySyncTargetHeight)}`
        : activeHeightRelation === 'aligned'
          ? 'In sync'
          : activeHeightRelation === 'local_ahead'
            ? `Local tip +${activeHeightDeltaAbsLabel}`
            : activeHeightRelation === 'network_ahead'
              ? `Network ahead ${activeHeightDeltaAbsLabel}`
              : 'No live height';
  const genesisMismatch = Boolean(walletGenesis && walletNodeGenesis && walletGenesis !== walletNodeGenesis);
  const nodeIsRunning = nodeIsLocal && Boolean(activeSummary?.reachable);
  const nodeIsManaged =
    Boolean(nodeManagedStatus?.managed) &&
    (!nodeManagedStatus?.connectionId || nodeManagedStatus.connectionId === activeConnection?.id);
  const nodeToggleDisabled = nodeBusy || !nodeIsLocal || nodeTransitionAction !== null || (nodeIsRunning && !nodeIsManaged);
  const nodeToggleClass = nodeIsRunning || nodeTransitionAction === 'stopping' ? 'secondary' : 'primary';
  const nodeToggleLabel = nodeTransitionAction ? (
    <span className="inline-flex items-center gap-1">
      {nodeTransitionAction === 'starting' ? 'Starting' : 'Stopping'}
      <span className="loading-dots" aria-hidden="true">
        ...
      </span>
    </span>
  ) : nodeIsRunning ? (
    nodeIsManaged ? 'Stop node' : 'Stop unavailable (unmanaged node)'
  ) : (
    'Start node'
  );
  const handleNodeToggle = () => {
    if (nodeToggleDisabled) {
      return;
    }
    if (nodeIsRunning) {
      void handleNodeStop();
      return;
    }
    void handleNodeStart();
  };
  const effectiveMiningHashRate = activeSummary?.hashRate;
  const miningGateBlocked = activeDisplayState.miningGateBlocked;
  const miningStatusLabel =
    activeSummary?.mining === null || activeSummary?.mining === undefined
      ? 'N/A'
      : activeSummary.mining
        ? miningGateBlocked
          ? 'Gated'
          : 'Active'
        : 'Idle';
  const miningHashRateLabel =
    activeSummary?.mining && (!effectiveMiningHashRate || effectiveMiningHashRate <= 0)
      ? 'Measuring'
      : formatHashRate(effectiveMiningHashRate);
  const miningHint = miningGateBlocked
    ? 'Mining is enabled, but this node is waiting for sync before it is allowed to mine.'
    : activeParticipationRole === 'authoring_pool' && !activeSummary?.mining
      ? 'Auto-start mining is off.'
      : null;
  const walletConnectionTone =
    walletSummary?.reachable === true ? 'ok' : walletSummary?.reachable === false ? 'error' : 'neutral';
  const walletConnectionLabel =
    walletSummary?.reachable === true ? 'Online' : walletSummary?.reachable === false ? 'Offline' : 'Unknown';
  const walletTone = walletError ? 'error' : walletReady ? 'ok' : 'warn';
  const walletStateLabel = walletError ? 'Error' : walletReady ? 'Ready' : walletUnlocked ? 'Unlocked' : 'Locked';
  const chainTone = genesisMismatch
    ? 'error'
    : activeNodeLive
      ? 'ok'
      : walletGenesis
        ? 'warn'
        : 'neutral';
  const chainLabel = genesisMismatch
    ? 'Mismatch'
    : activeNodeLive
      ? 'Live'
      : walletGenesis
        ? 'Wallet set'
        : 'Unknown';
  const displayedChainTone = nodeStartupPending ? 'warn' : chainTone;
  const displayedChainLabel = nodeStartupPending ? 'Starting' : chainLabel;
  const displayedHealthTone = nodeStartupPending ? 'warn' : healthTone;
  const displayedHealthLabel = nodeStartupPending ? 'Starting' : healthLabel;
  const displayedWalletConnectionLabel = nodeStartupPending ? 'Starting' : walletConnectionLabel;
  const hgmBalance = walletStatus?.balances?.find((balance) => balance.assetId === 0) ?? null;
  const hgmBalanceLabel = hgmBalance ? formatHgm(hgmBalance.total) : 'N/A';
  const walletSyncLag =
    typeof walletSummary?.bestNumber === 'number' && typeof walletStatus?.lastSyncedHeight === 'number'
      ? Math.max(0, walletSummary.bestNumber - walletStatus.lastSyncedHeight)
      : null;
  const walletBalanceDisplay = walletReady ? hgmBalanceLabel : 'Locked';
  const walletSyncDisplay = walletReady ? formatNumber(walletStatus?.lastSyncedHeight) : 'Locked';
  const walletLagDisplay = walletReady ? (walletSyncLag === null ? 'N/A' : formatNumber(walletSyncLag)) : 'Open wallet';
  const walletSyncActionLabel = walletBusy ? 'Syncing...' : walletSyncLag && walletSyncLag > 0 ? 'Sync wallet' : 'Sync now';
  const spendableNotesDisplay = walletReady ? formatNumber(walletStatus?.notes?.spendableCount) : 'Locked';
  const walletGenesisDisplay = walletGenesis ? formatHash(walletGenesis) : walletReady ? 'N/A' : 'Locked';
  const maxInputsLine = walletReady
    ? `Max ${formatNumber(walletStatus?.notes?.maxInputs)} inputs/tx`
    : 'Open wallet to inspect inputs';
  const primaryAddress = walletStatus?.primaryAddress ?? '';
  const primaryAddressLabel = primaryAddress ? formatAddress(primaryAddress) : walletReady ? 'N/A' : 'Locked';
  const normalizedPrimaryAddress = normalizeShieldedAddressInput(primaryAddress);
  const runningMinerAddress = normalizeShieldedAddressInput(activeSummary?.minerAddress ?? '');
  const savedMinerAddress = normalizeShieldedAddressInput(activeConnection?.minerAddress ?? '');
  const effectiveMinerPayoutAddress = runningMinerAddress || savedMinerAddress;
  const effectiveMinerPayoutLabel = effectiveMinerPayoutAddress
    ? formatAddress(effectiveMinerPayoutAddress)
    : activeSummary?.mining
      ? 'No payout address'
      : 'Not mining';
  const savedMinerPayoutLabel = savedMinerAddress ? formatAddress(savedMinerAddress) : 'Not set';
  const miningPayoutMatchesWallet = Boolean(
    walletReady &&
      normalizedPrimaryAddress &&
      effectiveMinerPayoutAddress &&
      normalizedPrimaryAddress === effectiveMinerPayoutAddress
  );
  const savedMiningPayoutMatchesWallet = Boolean(
    walletReady && normalizedPrimaryAddress && savedMinerAddress && normalizedPrimaryAddress === savedMinerAddress
  );
  const miningPayoutPendingRestart = Boolean(
    runningMinerAddress && savedMinerAddress && runningMinerAddress !== savedMinerAddress
  );
  const miningPayoutMismatch = Boolean(
    walletReady &&
      activeSummary?.mining === true &&
      effectiveMinerPayoutAddress &&
      !miningPayoutMatchesWallet
  );
  const miningPayoutMissing = activeSummary?.mining === true && !effectiveMinerPayoutAddress;
  const miningPayoutTone: UiTone =
    miningPayoutMissing || miningPayoutMismatch
      ? 'error'
      : activeSummary?.mining === true && miningPayoutMatchesWallet
        ? 'ok'
        : savedMinerAddress
          ? 'warn'
          : 'neutral';
  const miningPayoutLabel = miningPayoutMissing
    ? 'No payout'
    : miningPayoutMismatch
      ? 'Different address'
      : activeSummary?.mining === true && miningPayoutMatchesWallet
        ? 'To this wallet'
        : activeSummary?.mining === true && effectiveMinerPayoutAddress
          ? 'Payout set'
        : savedMinerAddress
          ? 'Configured'
          : 'Not set';
  const miningPayoutDetail = miningPayoutMissing
    ? 'Mining is active, but the app cannot see a payout address.'
    : miningPayoutMismatch
      ? 'Local block rewards are not going to the displayed receiving address.'
      : activeSummary?.mining === true && miningPayoutMatchesWallet
        ? 'Local block rewards pay the wallet address shown above.'
        : activeSummary?.mining === true && effectiveMinerPayoutAddress
          ? 'Mining is active. Unlock the wallet to compare this payout with the receiving address.'
        : savedMinerAddress
          ? 'This address will be used when local mining starts.'
          : 'Set this wallet address before enabling local mining.';
  const recipientAddressError = recipientAddress
    ? validateShieldedAddressInput(recipientAddress, 'Recipient address')
    : null;
  const normalizedRecipientAddress = normalizeShieldedAddressInput(recipientAddress);
  const recipientAddressLengthLabel = `${normalizedRecipientAddress.length}/${shieldedAddressLength}`;
  const recipientAddressTone = recipientAddressError
    ? 'text-guard'
    : normalizedRecipientAddress
      ? 'text-proof'
      : 'text-surfaceMuted/70';
  const newContactAddressError = newContactAddress
    ? validateShieldedAddressInput(newContactAddress, 'Contact address')
    : null;
  const minerAddressError =
    roleAllowsLocalMining && activeConnection?.minerAddress
      ? validateShieldedAddressInput(activeConnection.minerAddress, 'Miner address')
      : null;
  const contactAddressErrors = useMemo(() => {
    const errors = new Map<string, string>();
    contacts.forEach((contact) => {
      const error = validateShieldedAddressInput(contact.address, 'Contact address');
      if (error) {
        errors.set(contact.id, error);
      }
    });
    return errors;
  }, [contacts]);
  const contactWarnings = useMemo(() => {
    const warnings = new Map<string, string>();
    contacts.forEach((contact) => {
      const warning = legacyContactWarning(contact);
      if (warning) {
        warnings.set(contact.id, warning);
      }
    });
    return warnings;
  }, [contacts]);
  const contactsByAddress = useMemo(() => {
    const map = new Map<string, Contact>();
    contacts.forEach((contact) => {
      const normalized = normalizeShieldedAddressInput(contact.address);
      if (normalized) {
        map.set(normalized, contact);
      }
    });
    return map;
  }, [contacts]);
  const getContactForAddress = useCallback(
    (address: string | null | undefined) => {
      const normalized = normalizeShieldedAddressInput(address ?? '');
      return normalized ? contactsByAddress.get(normalized) ?? null : null;
    },
    [contactsByAddress]
  );
  const primaryAddressContact = getContactForAddress(primaryAddress);
  const effectiveMinerPayoutContact = getContactForAddress(effectiveMinerPayoutAddress);
  const savedMinerAddressContact = getContactForAddress(savedMinerAddress);
  const configuredMinerAddressContact = getContactForAddress(activeConnection?.minerAddress);
  const configuredMinerAddressNormalized = normalizeShieldedAddressInput(activeConnection?.minerAddress ?? '');
  const sendBlockedReason = !walletReady
    ? 'Open or init a wallet to send funds.'
    : walletSummary?.reachable === false
      ? 'Wallet connection is offline. Select a reachable node or fix the RPC endpoint.'
      : genesisMismatch
        ? 'Genesis mismatch between the wallet store and the selected node.'
        : recipientAddressError
          ? recipientAddressError
        : null;
  const canSend = !walletBusy && !sendBlockedReason;

  const normalizedStorePath = storePath.trim();
  const pendingTransactions = walletStatus?.pending ?? [];
  const recentTransactions = walletStatus?.recent ?? [];
  const walletActivity = useMemo(
    () => [...pendingTransactions, ...recentTransactions],
    [pendingTransactions, recentTransactions]
  );
  const walletNoteDetails = walletStatus?.noteDetails ?? [];
  const activityByTxId = useMemo(() => {
    const map = new Map<string, typeof walletActivity[number]>();
    walletActivity.forEach((entry) => {
      const normalized = normalizeTxId(entry.txId);
      if (normalized) {
        map.set(normalized, entry);
      }
    });
    return map;
  }, [walletActivity]);

  const attemptsForStore = useMemo(
    () => sendAttempts.filter((attempt) => attempt.storePath === normalizedStorePath),
    [sendAttempts, normalizedStorePath]
  );

  const activityEntries = useMemo(() => {
    const consolidationEntries = walletActivity.filter(
      (entry) => entry.memo?.toLowerCase() === 'consolidation'
    );
    const pendingEntries: ActivityEntry[] = walletActivity.map((entry) => ({
      id: entry.txId,
      source: 'wallet',
      createdAt: entry.createdAt,
      recipient: entry.address,
      amount: entry.amount,
      fee: entry.fee,
      memo: entry.memo ?? undefined,
      status: entry.status === 'confirmed' ? 'confirmed' : 'pending',
      txId: normalizeTxId(entry.txId) ?? entry.txId,
      confirmations: entry.confirmations
    }));

    const sortedAttempts = [...attemptsForStore].sort(
      (a, b) => parseTimestamp(b.createdAt) - parseTimestamp(a.createdAt)
    );
    const consolidationTxIds = new Set<string>();
    const attemptEntries: ActivityEntry[] = sortedAttempts.map((attempt, index) => {
      const windowEnd = index > 0 ? sortedAttempts[index - 1]?.createdAt : null;
      const pending = attempt.txId ? activityByTxId.get(attempt.txId) : null;
      const txId = attempt.txId ? normalizeTxId(attempt.txId) ?? attempt.txId : undefined;
      const walletSessionClosedForKnownTx = Boolean(
        txId && attempt.status === 'failed' && attempt.error && isWalletSessionClosedError(attempt.error)
      );
      const missingWalletPending =
        attempt.status === 'pending' && !pending && walletUnlocked && !walletError;
      const status = pending
        ? pending.status === 'confirmed'
          ? 'confirmed'
          : 'pending'
        : walletSessionClosedForKnownTx
          ? 'pending'
        : missingWalletPending
          ? 'failed'
          : attempt.status;
      const expectedSteps = attempt.consolidationExpected ?? 0;
      const matchingSteps = consolidationEntries
        .filter((entry) => parseTimestamp(entry.createdAt) >= parseTimestamp(attempt.createdAt))
        .filter((entry) =>
          windowEnd ? parseTimestamp(entry.createdAt) < parseTimestamp(windowEnd) : true
        )
        .sort((a, b) => parseTimestamp(a.createdAt) - parseTimestamp(b.createdAt));

      matchingSteps.forEach((match) => {
        const normalized = normalizeTxId(match.txId);
        if (normalized) {
          consolidationTxIds.add(normalized);
        }
      });

      const consolidationSubmitted = matchingSteps.length;
      const consolidationConfirmed = matchingSteps.filter((match) => match.status === 'confirmed').length;

      const displayLimit = 3;
      const displaySteps = matchingSteps.slice(-displayLimit);
      const displayOffset = matchingSteps.length - displaySteps.length;
      const steps: ActivityStep[] = displaySteps.map((match, displayIndex) => {
        const stepIndex = displayOffset + displayIndex + 1;
        const label = expectedSteps
          ? `Consolidation tx ${stepIndex} of ~${expectedSteps}`
          : `Consolidation tx ${stepIndex}`;
        return {
          id: `${attempt.id}-step-${stepIndex}`,
          label,
          status: match.status === 'confirmed' ? 'confirmed' : 'pending',
          txId: normalizeTxId(match.txId) ?? match.txId,
          confirmations: match.confirmations
        };
      });

      return {
        id: attempt.id,
        source: 'attempt',
        createdAt: attempt.createdAt,
        recipient: attempt.recipient,
        amount: attempt.amount,
        fee: attempt.fee,
        memo: attempt.memo,
        status,
        txId: normalizeTxId(pending?.txId) ?? txId,
        confirmations: pending?.confirmations,
        error: missingWalletPending
          ? attempt.error ?? 'Submission never appeared in wallet pending state.'
          : walletSessionClosedForKnownTx
            ? undefined
            : attempt.error,
        notesNeeded: attempt.notesNeeded,
        walletNoteCount: attempt.walletNoteCount,
        maxInputs: attempt.maxInputs,
        consolidationExpected: expectedSteps || undefined,
        consolidationExpectedBlocks: attempt.consolidationExpectedBlocks,
        consolidationSubmitted: consolidationSubmitted || undefined,
        consolidationConfirmed: consolidationSubmitted ? consolidationConfirmed : undefined,
        steps: steps.length ? steps : undefined
      };
    });

    const attemptTxIds = new Set(
      attemptEntries
        .map((entry) => entry.txId)
        .filter((entry): entry is string => Boolean(entry))
    );
    const coveredTxIds = new Set([...attemptTxIds, ...consolidationTxIds]);
    const merged = [
      ...attemptEntries,
      ...pendingEntries.filter((entry) => !entry.txId || !coveredTxIds.has(entry.txId))
    ];
    merged.sort((a, b) => parseTimestamp(b.createdAt) - parseTimestamp(a.createdAt));
    return merged;
  }, [attemptsForStore, walletActivity, activityByTxId, walletError, walletUnlocked]);

  const sendInFlight = attemptsForStore.some((attempt) => attempt.status === 'processing');

  const disclosureGroups = useMemo(() => {
    const grouped = new Map<string, WalletDisclosureRecord[]>();
    disclosureRecords.forEach((record) => {
      const existing = grouped.get(record.txId) ?? [];
      existing.push(record);
      grouped.set(record.txId, existing);
    });
    const groups: DisclosureGroup[] = Array.from(grouped.entries()).map(([txId, outputs]) => {
      const sorted = [...outputs].sort(
        (a, b) => parseTimestamp(b.createdAt) - parseTimestamp(a.createdAt)
      );
      return {
        txId,
        createdAt: sorted[0]?.createdAt ?? '',
        outputs: sorted
      };
    });
    return groups.sort((a, b) => parseTimestamp(b.createdAt) - parseTimestamp(a.createdAt));
  }, [disclosureRecords]);

  const selectedDisclosure = useMemo(() => {
    if (!selectedDisclosureKey) {
      return null;
    }
    const [txId, outputIndex] = selectedDisclosureKey.split(':');
    const output = Number.parseInt(outputIndex, 10);
    return disclosureRecords.find(
      (record) => record.txId === txId && record.outputIndex === output
    ) ?? null;
  }, [disclosureRecords, selectedDisclosureKey]);

  const pendingActivityCount = activityEntries.filter(
    (entry) => entry.status === 'processing' || entry.status === 'pending'
  ).length;
  const sendNavTone: UiTone = pendingActivityCount > 0 ? 'warn' : 'neutral';
  const sendNavLabel = pendingActivityCount > 0 ? `${pendingActivityCount} pending` : 'Idle';
  const sendNavDescription =
    pendingActivityCount > 0
      ? 'Outgoing pending'
      : walletReady
        ? 'Ready to send'
        : 'Open wallet first';
  const nodeNavLabel =
    nodeStartupPending
      ? 'Starting'
      : activeNodeLive && (activeHeightRelation === 'aligned' || activeHeightRelation === 'local_ahead')
        ? 'Synced'
        : displayedHealthLabel;
  const nodeNavDescription =
    nodeStartupPending
      ? 'Starting local node'
      : activeNodeLive
        ? activeHeightRelation === 'aligned' || activeHeightRelation === 'local_ahead'
          ? `${activeHeightLabel} synced`
          : syncAlignmentLabel
        : 'Start local node';
  const walletNavDescription = miningPayoutMismatch
    ? 'Mining payout mismatch'
    : walletReady
      ? hgmBalanceLabel
      : `${displayedWalletConnectionLabel} · loopback`;
  const walletNavLabel = miningPayoutMismatch ? 'Payout' : walletStateLabel;
  const walletNavTone = miningPayoutMismatch ? 'error' : walletTone;
  const consoleErrorCount = logEntries.filter((entry) => entry.level === 'error').length;

  const navItems: Array<{
    path: string;
    icon: AppIconName;
    label: string;
    description: string;
    statusLabel?: string;
    statusTone?: UiTone;
  }> = [
    {
      path: '/overview',
      icon: 'overview',
      label: 'Overview',
      description: activeNodeLive ? `${activeHeightLabel} · ${peerEvidenceLabel}` : 'Live status',
      statusLabel: displayedChainLabel,
      statusTone: displayedChainTone
    },
    {
      path: '/node',
      icon: 'node',
      label: 'Node',
      description: nodeNavDescription,
      statusLabel: nodeNavLabel,
      statusTone: displayedHealthTone
    },
    {
      path: '/wallet',
      icon: 'wallet',
      label: 'Wallet',
      description: walletNavDescription,
      statusLabel: walletNavLabel,
      statusTone: walletNavTone
    },
    {
      path: '/send',
      icon: 'send',
      label: 'Send',
      description: sendNavDescription,
      statusLabel: sendNavLabel,
      statusTone: sendNavTone
    },
    {
      path: '/disclosure',
      icon: 'disclosure',
      label: 'Disclosure',
      description: disclosureRecords.length > 0 ? 'Records saved' : 'Proofs',
      statusLabel: disclosureRecords.length > 0 ? `${formatNumber(disclosureRecords.length)}` : undefined,
      statusTone: disclosureRecords.length > 0 ? 'ok' : undefined
    },
    {
      path: '/console',
      icon: 'console',
      label: 'Console',
      description: consoleErrorCount > 0 ? `${formatNumber(consoleErrorCount)} errors` : 'Logs',
      statusLabel: consoleErrorCount > 0 ? `${formatNumber(consoleErrorCount)}` : undefined,
      statusTone: consoleErrorCount > 0 ? 'error' : undefined
    }
  ];

  const GenesisMismatchBanner = genesisMismatch ? (
    <div className="rounded-lg border border-amber/40 bg-amber/10 p-4 space-y-2">
      <p className="text-sm text-surface">
        Genesis mismatch between the wallet store and the selected node. Choose the correct node or force a rescan.
      </p>
      <p className="text-sm text-surfaceMuted mono">
        Wallet: {formatHash(walletGenesis)} | Node: {formatHash(walletNodeGenesis)}
      </p>
      <button className="secondary" onClick={() => handleWalletSync(true)} disabled={walletBusy}>
        Force rescan
      </button>
    </div>
  ) : null;

  const WalletErrorBanner = walletError ? <p className="text-guard">{walletError}</p> : null;
  const ContactsErrorBanner = contactsError ? <p className="text-guard text-sm">{contactsError}</p> : null;

  const OverviewWorkspace = (
    <div className="overview-shell">
      {GenesisMismatchBanner}

      <section className="control-panel">
        <div className="control-rail" aria-label="Live status">
          <div className="control-rail-item">
            <span>Height</span>
            <strong>{activeHeightLabel}</strong>
          </div>
          <div className="control-rail-item">
            <span>Sync</span>
            <strong>{syncAlignmentLabel}</strong>
          </div>
          <div className="control-rail-item">
            <span>Peers</span>
            <strong>{formatNumber(activePeerCount)}</strong>
          </div>
          <div className="control-rail-item">
            <span>Mining</span>
            <strong>{miningStatusLabel}</strong>
          </div>
          <div className="control-rail-item">
            <span>Wallet</span>
            <strong>{walletStateLabel}</strong>
          </div>
        </div>

        <div className="command-surface">
          <div className="command-focus">
            <span className={`status-dot ${displayedChainTone}`} />
            <div className="min-w-0">
              <h1>{activeNodeLive ? (overviewWarningCount ? 'Review needed' : 'Ready') : 'Offline'}</h1>
              <p>
                Height {activeHeightLabel}
                {activeDisplaySyncTargetHeight ? ` / ${formatNumber(activeDisplaySyncTargetHeight)}` : ''} · {peerEvidenceLabel}
              </p>
            </div>
          </div>

          <div className="command-actions">
            {walletReady ? (
              <button className="primary" onClick={() => handleWalletSync()} disabled={walletBusy}>
                <AppIcon name="sync" />
                {walletSyncActionLabel}
              </button>
            ) : (
              <Link className="action-link primary" to="/wallet">
                <AppIcon name="wallet" />
                Open wallet
              </Link>
            )}
            <Link className="action-link secondary" to="/send">
              <AppIcon name="send" />
              Send
            </Link>
            <button className={nodeToggleClass} onClick={handleNodeToggle} disabled={nodeToggleDisabled}>
              <AppIcon name="node" />
              {nodeToggleLabel}
            </button>
          </div>
        </div>

        <div className="control-rows">
          <div className="control-row">
            <AppIcon name="height" />
            <span>Latest block</span>
            <strong className="mono" title={activeSummary?.bestBlock ?? ''}>{formatHash(activeSummary?.bestBlock)}</strong>
            <em>{updatedAtLabel}</em>
          </div>
          <div className="control-row">
            <AppIcon name="wallet" />
            <span>Wallet</span>
            <strong>{walletBalanceDisplay}</strong>
            <em>{walletReady ? `${walletLagDisplay} behind` : walletConnectionLabel}</em>
          </div>
          <div className="control-row">
            <AppIcon name="key" />
            <span>Payout</span>
            <strong title={effectiveMinerPayoutAddress}>{effectiveMinerPayoutLabel}</strong>
            <em>{miningPayoutLabel}</em>
          </div>
          <div className="control-row">
            <AppIcon name="console" />
            <span>Latest event</span>
            <strong>{overviewHighlights[0]?.highlight ?? 'Quiet'}</strong>
            <em>{overviewHighlights[0]?.timestamp ?? 'No alerts'}</em>
          </div>
        </div>

        <details className="control-details">
          <summary>
            <strong>
              {activeCanonicalStatus === 'verified'
                ? 'Checkpoint verified'
                : activeCanonicalStatus === 'mismatch'
                  ? 'Fork mismatch'
                  : firstActivePeer
                    ? 'Peer connected'
                    : 'Seed configured'}
            </strong>
            <span>{overviewWarningCount ? `${overviewWarningCount} warnings` : 'Details'}</span>
          </summary>
          <div className="proof-stack" aria-label="Connection details">
            <div className="proof-row">
              <span>RPC</span>
              <strong className="mono" title={activeConnection?.wsUrl ?? ''}>{formatEndpoint(activeConnection?.wsUrl)}</strong>
              <em>{rpcPolicyLabel}</em>
            </div>
            <div className="proof-row">
              <span>Seed</span>
              <strong className="mono" title={activeSeedList}>{activeSeedList || 'N/A'}</strong>
              <em>approved seed</em>
            </div>
            <div className="proof-row">
              <span>Checkpoint</span>
              <strong className="mono" title={activeSummary?.canonicalCheckpoint?.actualHash ?? ''}>
                {activeSummary?.canonicalCheckpoint?.height
                  ? `${formatNumber(activeSummary.canonicalCheckpoint.height)} · ${activeCanonicalStatus}`
                  : activeCanonicalStatus}
              </strong>
              <em>{activeSummary?.canonicalCheckpoint?.detail ?? 'No checkpoint data yet'}</em>
            </div>
            <div className="proof-row">
              <span>Peer</span>
              <strong className="mono" title={peerDetailLabel}>{peerDetailLabel}</strong>
              <em>{peerEvidenceLabel}</em>
            </div>
            <div className="proof-row">
              <span>Genesis</span>
              <strong className="mono" title={displayedNodeGenesis ?? ''}>{formatHash(displayedNodeGenesis)}</strong>
              <em>0.10 identity</em>
            </div>
          </div>
        </details>
      </section>
    </div>
  );

  const NodeConnectionsSection = (
    <details className="card diagnostic-details">
      <summary>
        <div>
          <h2 className="text-title font-semibold">Configuration</h2>
        </div>
        <span className="badge">
          {activeConnection ? `${connectionModeLabels[activeConnection.mode]} · ${participationRoleLabels[activeParticipationRole]}` : 'Configure'}
        </span>
      </summary>

      <div className="space-y-8">
        <div className="flex justify-end gap-2">
          <button className="secondary text-sm" onClick={handleAddConnection}>Add connection</button>
          <button className="danger text-sm" onClick={handleRemoveConnection} disabled={connections.length <= 1}>Remove</button>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
        <label className="space-y-2">
          <span className="label">Active connection</span>
          <select
            value={activeConnectionId}
            onChange={(event) => setActiveConnectionId(event.target.value)}
          >
            {connections.map((connection) => (
              <option key={connection.id} value={connection.id}>
                {connection.label} ({connectionModeLabels[connection.mode]} · {participationRoleLabels[inferParticipationRole(connection)]})
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-2">
          <span className="label">Label</span>
          <input
            value={activeConnection?.label ?? ''}
            onChange={(event) => updateActiveConnection({ label: event.target.value })}
          />
        </label>
        <label className="space-y-2">
          <span className="label">Mode</span>
          <select
            value={activeConnection?.mode ?? 'local'}
            onChange={(event) => updateActiveConnection({ mode: event.target.value as NodeConnection['mode'] })}
          >
            <option value="local">Managed local</option>
            <option value="remote">Local RPC endpoint</option>
          </select>
        </label>
        <label className="space-y-2">
          <span className="label">Node role</span>
          <select
            value={activeParticipationRole}
            onChange={(event) => {
              const nextRole = event.target.value as NodeParticipationRole;
              updateActiveConnection((connection) => ({
                participationRole: nextRole,
                miningIntent: nextRole === 'authoring_pool' ? connection.miningIntent : false
              }));
            }}
          >
            <option value="full_node">Relay node</option>
            <option value="authoring_pool">Mining node</option>
          </select>
        </label>
        <label className="space-y-2">
          <span className="label">WebSocket URL</span>
          <input
            value={activeConnection?.wsUrl ?? ''}
            onChange={(event) => updateActiveConnection({ wsUrl: event.target.value })}
          />
        </label>
        <label className="space-y-2">
          <span className="label">HTTP URL</span>
          <input
            value={activeConnection?.httpUrl ?? ''}
            onChange={(event) => updateActiveConnection({ httpUrl: event.target.value })}
            placeholder={`http://127.0.0.1:${defaultRpcPort}`}
          />
        </label>
      {activeConnection?.mode === 'remote' && activeParticipationRole === 'authoring_pool' ? (
          <p className="text-xs text-surfaceMuted md:col-span-2">
            Local RPC endpoint mining profiles are read-only in the desktop app. Start/stop and mining control stay on the operator host.
          </p>
        ) : null}
        </div>
      {activeConnection ? (
        <div className="panel space-y-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="label">Node role</p>
              <h3 className="text-base font-semibold">{participationRoleLabels[activeParticipationRole]}</h3>
            </div>
            {activeParticipationMeta.statusLabel ? (
              <span className={`status-pill ${activeParticipationMeta.statusTone}`}>{activeParticipationMeta.statusLabel}</span>
            ) : null}
          </div>
          <p className="text-sm text-surfaceMuted">{activeParticipationMeta.summary}</p>
          <p className="text-xs text-surfaceMuted/80">{activeParticipationMeta.guidance}</p>
        </div>
      ) : null}
      {activeConnection?.mode === 'remote' ? (
        <p className="text-sm text-surfaceMuted">
          Desktop RPC must stay on localhost. Run a local Hegemon P2P relay node for remote network access; direct public RPC is rejected.
        </p>
      ) : null}

      {activeConnection?.mode === 'local' && (
        <details className="diagnostic-details node-advanced">
          <summary>
            <div>
              <p className="label">Local node settings</p>
              <p className="text-sm text-surfaceMuted/80">Storage, networking, mining, and retention controls.</p>
            </div>
            <span className="badge">Advanced</span>
          </summary>
          <div className="space-y-6">
          <div className="panel space-y-4">
            <div>
              <p className="label">Paths</p>
              <p className="text-sm text-surfaceMuted/80">Native node storage locations.</p>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <label className="space-y-2 md:col-span-2">
                <span className="label">Base path</span>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs text-surfaceMuted/70">Choose the folder that holds node data.</span>
                  <button className="secondary text-xs px-3" type="button" onClick={handlePickBasePath}>
                    Browse
                  </button>
                </div>
                <input
                  className="mono"
                  value={activeConnection.basePath ?? ''}
                  onChange={(event) => updateActiveConnection({ basePath: event.target.value })}
                  placeholder="~/.hegemon-node"
                  spellCheck={false}
                  title={activeConnection.basePath ?? ''}
                />
              </label>
              <label className="space-y-2">
                <span className="label">Node name</span>
                <input
                  value={activeConnection.nodeName ?? ''}
                  onChange={(event) => updateActiveConnection({ nodeName: event.target.value })}
                  placeholder="AliceBootNode"
                />
              </label>
            </div>
          </div>

          <div className="panel space-y-4">
            <div>
              <p className="label">Networking</p>
              <p className="text-sm text-surfaceMuted/80">RPC, P2P, and peer discovery.</p>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <label className="space-y-2">
                <span className="label">RPC port</span>
                <input
                  value={activeConnection.rpcPort?.toString() ?? ''}
                  onChange={(event) => {
                    const nextPort = Number.parseInt(event.target.value, 10);
                    updateActiveConnection((conn) => {
                      const port = Number.isNaN(nextPort) ? undefined : nextPort;
                      const updates: Partial<NodeConnection> = { rpcPort: port };
                      if (conn.wsUrl.startsWith('ws://127.0.0.1:') || conn.wsUrl.startsWith('ws://localhost:')) {
                        const host = conn.wsUrl.includes('localhost') ? 'localhost' : '127.0.0.1';
                        if (port) {
                          updates.wsUrl = `ws://${host}:${port}`;
                          updates.httpUrl = `http://${host}:${port}`;
                        }
                      }
                      return updates;
                    });
                  }}
                />
              </label>
              <label className="space-y-2">
                <span className="label">P2P port</span>
                <input
                  value={activeConnection.p2pPort?.toString() ?? ''}
                  onChange={(event) => {
                    const nextPort = Number.parseInt(event.target.value, 10);
                    updateActiveConnection({ p2pPort: Number.isNaN(nextPort) ? undefined : nextPort });
                  }}
                />
              </label>
              <label className="space-y-2 md:col-span-2">
                <span className="label">Listen address</span>
                <input
                  value={activeConnection.listenAddr ?? ''}
                  onChange={(event) => updateActiveConnection({ listenAddr: event.target.value })}
                  placeholder="/ip4/0.0.0.0/tcp/30333"
                />
              </label>
              <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                <input
                  type="checkbox"
                  checked={Boolean(activeConnection.rpcExternal)}
                  onChange={(event) => updateActiveConnection({ rpcExternal: event.target.checked })}
                />
                RPC external (exposes HTTP to network)
              </label>
              <label className="space-y-2">
                <span className="label">RPC methods</span>
                <select
                  value={activeConnection.rpcMethods ?? 'safe'}
                  onChange={(event) => updateActiveConnection({ rpcMethods: event.target.value as NodeConnection['rpcMethods'] })}
                >
                  <option value="safe">safe</option>
                  <option value="unsafe">unsafe</option>
                </select>
              </label>
              <label className="space-y-2 md:col-span-2">
                <span className="label">Seeds (HEGEMON_SEEDS)</span>
                <input
                  value={activeConnection.seeds ?? ''}
                  onChange={(event) => updateActiveConnection({ seeds: event.target.value })}
                  placeholder="1.2.3.4:30333,5.6.7.8:30333"
                />
              </label>
              <label className="space-y-2">
                <span className="label">Max peers (HEGEMON_MAX_PEERS)</span>
                <input
                  type="number"
                  min={1}
                  step={1}
                  value={activeConnection.maxPeers?.toString() ?? ''}
                  onChange={(event) => {
                    const nextValue = Number.parseInt(event.target.value, 10);
                    updateActiveConnection({ maxPeers: Number.isNaN(nextValue) ? undefined : nextValue });
                  }}
                  placeholder="50"
                />
              </label>
              <p className="text-xs text-surfaceMuted md:col-span-2">
                Applied when the node starts. Restart the node after changing this value.
              </p>
            </div>
          </div>

          <div className="panel space-y-4">
            <div>
              <p className="label">Mining + retention</p>
              <p className="text-sm text-surfaceMuted/80">
                {roleAllowsLocalMining
                  ? 'Local mining controls and DA retention policies.'
                  : 'Relay-node notes and DA retention policies.'}
              </p>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              {roleAllowsLocalMining ? (
                <>
                  <label className="space-y-2 md:col-span-2">
                    <span className="label">Miner address</span>
                    <textarea
                      className="mono min-h-28 text-xs"
                      rows={5}
                      value={activeConnection.minerAddress ?? ''}
                      onChange={(event) => updateActiveConnection({ minerAddress: event.target.value })}
                      placeholder="shca1..."
                      spellCheck={false}
                    />
                    {minerAddressError ? <p className="text-xs text-guard">{minerAddressError}</p> : null}
                    {!minerAddressError && configuredMinerAddressNormalized ? (
                      <p className={`text-xs ${configuredMinerAddressContact ? 'text-proof' : 'text-amber'}`}>
                        {configuredMinerAddressContact
                          ? `Saved contact: ${configuredMinerAddressContact.name}${configuredMinerAddressContact.verified ? ' · verified' : ''}`
                          : 'No saved contact match for this mining payout address.'}
                      </p>
                    ) : null}
                  </label>
                  <label className="space-y-2">
                    <span className="label">Mine threads</span>
                    <input
                      value={activeConnection.mineThreads?.toString() ?? ''}
                      onChange={(event) => {
                        const nextValue = Number.parseInt(event.target.value, 10);
                        updateActiveConnection({ mineThreads: Number.isNaN(nextValue) ? undefined : nextValue });
                      }}
                    />
                  </label>
                </>
              ) : (
                <p className="text-xs text-surfaceMuted md:col-span-2">
                  Relay node mode keeps local mining disabled. Switch the node role to Mining node to reveal local mining controls.
                </p>
              )}
              <label className="space-y-2">
                <span className="label">Ciphertext retention (blocks)</span>
                <input
                  value={activeConnection.ciphertextDaRetentionBlocks?.toString() ?? ''}
                  onChange={(event) => {
                    const nextValue = Number.parseInt(event.target.value, 10);
                    updateActiveConnection({
                      ciphertextDaRetentionBlocks: Number.isNaN(nextValue) ? undefined : nextValue
                    });
                  }}
                  placeholder="0 (infinite)"
                />
              </label>
              <label className="space-y-2">
                <span className="label">Proof DA retention (blocks)</span>
                <input
                  value={activeConnection.proofDaRetentionBlocks?.toString() ?? ''}
                  onChange={(event) => {
                    const nextValue = Number.parseInt(event.target.value, 10);
                    updateActiveConnection({
                      proofDaRetentionBlocks: Number.isNaN(nextValue) ? undefined : nextValue
                    });
                  }}
                  placeholder="0"
                />
              </label>
              <label className="space-y-2">
                <span className="label">DA store capacity</span>
                <input
                  value={activeConnection.daStoreCapacity?.toString() ?? ''}
                  onChange={(event) => {
                    const nextValue = Number.parseInt(event.target.value, 10);
                    updateActiveConnection({ daStoreCapacity: Number.isNaN(nextValue) ? undefined : nextValue });
                  }}
                  placeholder="1024"
                />
              </label>
              <div className="grid gap-3 sm:grid-cols-2 md:col-span-2">
                <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                  <input
                    type="checkbox"
                    checked={Boolean(activeConnection.dev)}
                    onChange={(event) => updateActiveConnection({ dev: event.target.checked })}
                  />
                  Dev mode
                </label>
                <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                  <input
                    type="checkbox"
                    checked={Boolean(activeConnection.tmp)}
                    onChange={(event) => updateActiveConnection({ tmp: event.target.checked })}
                  />
                  Temp storage
                </label>
                {roleAllowsLocalMining ? (
                  <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                    <input
                      type="checkbox"
                      checked={Boolean(activeConnection.miningIntent)}
                      onChange={(event) => updateActiveConnection({ miningIntent: event.target.checked })}
                    />
                    Auto-start mining
                  </label>
                ) : null}
                <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                  <input
                    type="checkbox"
                    checked={Boolean(activeConnection.rpcCorsAll)}
                    onChange={(event) => updateActiveConnection({ rpcCorsAll: event.target.checked })}
                  />
                  Enable RPC CORS
                </label>
                <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                  <input
                    type="checkbox"
                    checked={activeConnection.rpcMethods === 'unsafe'}
                    onChange={(event) =>
                      updateActiveConnection({ rpcMethods: event.target.checked ? 'unsafe' : 'safe' })
                    }
                  />
                  Enable local control RPC
                </label>
                <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                  <input
                    type="checkbox"
                    checked={blockAlertEnabled}
                    onChange={(event) => setBlockAlertEnabled(event.target.checked)}
                  />
                  Play block alerts
                </label>
              </div>
              <p className="text-xs text-surfaceMuted md:col-span-2">
                Alerts play a short tone when you mine a block or when the node imports a block from someone else.
              </p>
            </div>
          </div>

          <div className="space-y-2">
            {activeConnection.listenAddr ? (
              <p className="text-sm text-surfaceMuted">
                Listen address overrides the P2P port setting.
              </p>
            ) : null}
            {activeConnection.rpcExternal || activeConnection.rpcMethods === 'unsafe' ? (
              <p className="text-sm text-guard">
                Unsafe controls stay local-only. If RPC is exposed externally, the managed node forces safe methods.
              </p>
            ) : null}
            {activeConnection.tmp ? (
              <p className="text-sm text-guard">
                Temp storage deletes chain data on shutdown. Use a base path for persistence.
              </p>
            ) : null}
          </div>
          </div>
        </details>
      )}
      </div>
    </details>
  );

  const NodeOperationsSection = (
    <section className="node-control-card">
      <div className="node-control-header">
        <div>
          <h2 className="text-title font-semibold">Controls</h2>
        </div>
        <div className="node-control-actions">
          <button
            className={nodeToggleClass}
            onClick={handleNodeToggle}
            disabled={nodeToggleDisabled}
          >
            {nodeToggleLabel}
          </button>
        </div>
      </div>

      {miningHint ? <p className="node-hint">{miningHint}</p> : null}

      <div className="node-control-summary">
        <p>
          <span>Role</span>
          <strong>{participationRoleLabels[activeParticipationRole]}</strong>
        </p>
        <p>
          <span>Mining</span>
          <strong>{miningStatusLabel}</strong>
          <em>{miningHashRateLabel}</em>
        </p>
        <p>
          <span>Payout</span>
          <strong title={effectiveMinerPayoutAddress}>{effectiveMinerPayoutLabel}</strong>
        </p>
        <p>
          <span>Storage</span>
          <strong>{formatBytes(activeSummary?.storage?.totalBytes)}</strong>
        </p>
      </div>

      <details className="diagnostic-details node-advanced">
        <summary>
          <div>
            <p className="label">Diagnostics</p>
          </div>
          <span className="badge">Details</span>
        </summary>
        <div className="node-metric-grid">
          <div className="panel">
          <p className="label">Role</p>
          <p className="text-lg font-medium">{participationRoleLabels[activeParticipationRole]}</p>
          {activeParticipationMeta.statusLabel ? (
            <p className="text-xs text-surfaceMuted">{activeParticipationMeta.statusLabel}</p>
          ) : null}
        </div>
        <div className="panel">
          <p className="label">Health</p>
          <div className="flex items-center gap-2">
            <span className={`status-dot ${healthTone}`} />
            <p className="text-lg font-medium">{healthLabel}</p>
          </div>
          <p className="text-xs text-surfaceMuted">Updated {updatedAtLabel}</p>
        </div>
        <div className="panel">
          <p className="label">Height</p>
          <p className="text-lg font-medium">{formatNumber(activeSummary?.bestNumber)}</p>
          <p className="text-xs text-surfaceMuted">{syncAlignmentLabel}</p>
          <p className="text-xs text-surfaceMuted mono truncate" title={activeSummary?.bestBlock ?? ''}>
            {activeSummary?.bestBlock ?? 'N/A'}
          </p>
        </div>
        <div className="panel">
          <p className="label">Peers</p>
          <p className="text-lg font-medium">{formatNumber(activeSummary?.peers)}</p>
          <p className="text-xs text-surfaceMuted">
            Syncing: {activeDisplayIsSyncing === null || activeDisplayIsSyncing === undefined
              ? 'N/A'
              : activeDisplayIsSyncing
                ? 'Yes'
                : 'No'}
          </p>
          <p className="text-xs text-surfaceMuted">Peer target: {formatNumber(activeDisplaySyncTargetHeight)}</p>
          {firstActivePeer ? (
            <p className="text-xs text-surfaceMuted mono truncate" title={`${firstActivePeer.addr} ${firstActivePeer.peerId}`}>
              {firstActivePeer.addr}
            </p>
          ) : null}
        </div>
        <div className="panel">
          <p className="label">Mining</p>
          <p className="text-lg font-medium">{miningStatusLabel}</p>
          <p className="text-xs text-surfaceMuted">Hash rate: {miningHashRateLabel}</p>
          <p className="text-xs text-surfaceMuted mono truncate" title={effectiveMinerPayoutAddress}>
            {effectiveMinerPayoutLabel}
          </p>
        </div>
        <div className="panel">
          <p className="label">Storage</p>
          <p className="text-lg font-medium">{formatBytes(activeSummary?.storage?.totalBytes)}</p>
          <p className="text-xs text-surfaceMuted">State: {formatBytes(activeSummary?.storage?.stateBytes)}</p>
        </div>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div className="panel">
          <p className="label">Mining details</p>
          <p className="text-sm text-surfaceMuted">Threads: {activeSummary?.miningThreads ?? 'N/A'}</p>
          <p className="text-sm text-surfaceMuted">
            Sync gate:{' '}
            {activeSummary?.miningSyncGateOpen === null || activeSummary?.miningSyncGateOpen === undefined
              ? 'N/A'
              : activeSummary.miningSyncGateOpen
                ? 'Open'
                : 'Closed'}
          </p>
          <p className="text-sm text-surfaceMuted">Hash rate: {miningHashRateLabel}</p>
          <p className="text-sm text-surfaceMuted">Blocks found: {formatNumber(activeSummary?.blocksFound)}</p>
          <p className="text-sm text-surfaceMuted">Difficulty: {formatNumber(activeSummary?.difficulty)}</p>
          <p className="text-sm text-surfaceMuted">Next difficulty: {formatNumber(activeSummary?.nextDifficulty)}</p>
          <p className="text-sm text-surfaceMuted">Block height: {formatNumber(activeSummary?.blockHeight)}</p>
          <p className="text-sm text-surfaceMuted">Pending pool: {formatNumber(activeSummary?.pendingExtrinsics)}</p>
        </div>
        <div className="panel">
          <p className="label">Storage breakdown</p>
          <p className="text-sm text-surfaceMuted">Blocks: {formatBytes(activeSummary?.storage?.blocksBytes)}</p>
          <p className="text-sm text-surfaceMuted">State: {formatBytes(activeSummary?.storage?.stateBytes)}</p>
          <p className="text-sm text-surfaceMuted">Txs: {formatBytes(activeSummary?.storage?.transactionsBytes)}</p>
          <p className="text-sm text-surfaceMuted">Nullifiers: {formatBytes(activeSummary?.storage?.nullifiersBytes)}</p>
        </div>
        <div className="panel">
          <p className="label">Consensus</p>
          <p className="text-sm text-surfaceMuted">
            Genesis: <span className="mono" title={activeSummary?.genesisHash ?? ''}>{formatHash(activeSummary?.genesisHash)}</span>
          </p>
          <p className="text-sm text-surfaceMuted">
            Supply digest: <span className="mono" title={activeSummary?.supplyDigest ?? ''}>{formatHash(activeSummary?.supplyDigest)}</span>
          </p>
        </div>
        <div className="panel">
          <p className="label">Telemetry</p>
          <p className="text-lg font-medium">{formatDuration(activeSummary?.telemetry?.uptimeSecs)}</p>
          <p className="text-sm text-surfaceMuted">Blocks imported: {formatNumber(activeSummary?.telemetry?.blocksImported)}</p>
          <p className="text-sm text-surfaceMuted">Blocks mined: {formatNumber(activeSummary?.telemetry?.blocksMined)}</p>
          <p className="text-sm text-surfaceMuted">Transactions: {formatNumber(activeSummary?.telemetry?.txCount)}</p>
          <p className="text-sm text-surfaceMuted">
            Net: {formatBytes(activeSummary?.telemetry?.networkRxBytes)} / {formatBytes(activeSummary?.telemetry?.networkTxBytes)}
          </p>
          <p className="text-sm text-surfaceMuted">Memory: {formatBytes(activeSummary?.telemetry?.memoryBytes)}</p>
        </div>
        <div className="panel md:col-span-2 space-y-1">
          <p className="label">Config</p>
          <p className="text-sm text-surfaceMuted">Node: {activeSummary?.config?.nodeName || 'N/A'}</p>
          <p className="text-sm text-surfaceMuted">
            Chain:{' '}
            {activeSummary?.config?.chainSpecName
              ? `${normalizeNetworkDisplayName(activeSummary.config.chainSpecName)} (${activeSummary.config.chainSpecId})`
              : 'N/A'}
          </p>
          <p className="text-sm text-surfaceMuted">Chain type: {activeSummary?.config?.chainType || 'N/A'}</p>
          <p className="text-sm text-surfaceMuted">
            Base path:{' '}
            <span className="mono break-all" title={activeSummary?.config?.basePath || ''}>
              {activeSummary?.config?.basePath || 'N/A'}
            </span>
          </p>
          <p className="text-sm text-surfaceMuted">
            P2P listen:{' '}
            <span className="mono break-all" title={activeSummary?.config?.p2pListenAddr || ''}>
              {activeSummary?.config?.p2pListenAddr || 'N/A'}
            </span>
          </p>
          <p className="text-sm text-surfaceMuted">
            RPC listen:{' '}
            <span className="mono break-all" title={activeSummary?.config?.rpcListenAddr || ''}>
              {activeSummary?.config?.rpcListenAddr || 'N/A'}
            </span>
          </p>
          <p className="text-sm text-surfaceMuted">
            RPC methods:{' '}
            {activeSummary?.config?.rpcMethods
              ? `${activeSummary.config.rpcMethods} (${activeSummary.config.rpcExternal ? 'external' : 'local'})`
              : 'N/A'}
          </p>
          <p className="text-sm text-surfaceMuted">
            PQ: {activeSummary?.config ? 'Enabled (PQ-only)' : 'N/A'}{' '}
            {activeSummary?.config?.pqVerbose ? '(verbose)' : ''}
          </p>
          <p className="text-sm text-surfaceMuted">Max peers: {formatNumber(activeSummary?.config?.maxPeers)}</p>
          <p className="text-sm text-surfaceMuted">
            Bootstraps:{' '}
            <span className="mono break-all" title={(activeSummary?.config?.bootstrapNodes ?? []).join(', ')}>
              {activeSummary?.config?.bootstrapNodes?.length
                ? activeSummary.config.bootstrapNodes.join(', ')
                : 'N/A'}
            </span>
          </p>
        </div>
      </div>
      </details>

      {nodeError && <p className="text-guard">{nodeError}</p>}
    </section>
  );

  const ConnectionHealthSection = (
    <section className="card space-y-6">
      <div>
        <p className="label">Node</p>
        <h2 className="text-title font-semibold">Connection health</h2>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        {connections.map((connection) => {
          const summary = nodeSummaries[connection.id];
          const isOnline = Boolean(summary?.reachable);
          const role = inferParticipationRole(connection);
          return (
            <div key={connection.id} className="panel">
              <div className="flex items-center justify-between gap-3">
                <p className="label">{summary?.label ?? connection.label}</p>
                <span className={`status-pill ${isOnline ? 'ok' : 'error'}`}>
                  {isOnline ? 'Online' : 'Offline'}
                </span>
              </div>
              <p className="text-sm text-surfaceMuted">Mode: {connection.mode}</p>
              <p className="text-sm text-surfaceMuted">Role: {participationRoleLabels[role]}</p>
              <p className="text-sm text-surfaceMuted">Height: {formatNumber(summary?.bestNumber)}</p>
              <p className="text-sm text-surfaceMuted">Peers: {formatNumber(summary?.peers)}</p>
            </div>
          );
        })}
      </div>
    </section>
  );

  const NodeConsoleSection = (
    <section className="card space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-title font-semibold">Logs</h2>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button className="chip" type="button" aria-pressed={logFilterInfo} onClick={() => setLogFilterInfo((prev) => !prev)}>
            Info
          </button>
          <button className="chip" type="button" aria-pressed={logFilterWarn} onClick={() => setLogFilterWarn((prev) => !prev)}>
            Warn
          </button>
          <button className="chip" type="button" aria-pressed={logFilterError} onClick={() => setLogFilterError((prev) => !prev)}>
            Error
          </button>
          <button className="chip" type="button" aria-pressed={logFilterDebug} onClick={() => setLogFilterDebug((prev) => !prev)}>
            Debug
          </button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="panel space-y-3">
          <div className="flex items-center justify-between">
            <p className="label">Key events</p>
            <span className="text-xs text-surfaceMuted">{logHighlights.length} recent</span>
          </div>
          {activeConnection?.mode !== 'local' ? (
            <p className="text-sm text-surfaceMuted">Connect to a local node to stream logs.</p>
          ) : logHighlights.length ? (
            <div className="space-y-2">
              {logHighlights.map((entry) => (
                <div key={entry.id} className="key-event-row">
                  <div className="key-event-meta">
                    <span className="mono text-surfaceMuted/60 text-xs">{entry.timestamp ?? '--:--:--'}</span>
                    <span className={`badge badge-highlight level-${entry.level}`}>{entry.highlight}</span>
                  </div>
                  <span className="key-event-message">{entry.message}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-6">
              <p className="text-sm text-surfaceMuted/60">No highlight events yet.</p>
            </div>
          )}
        </div>
        <div className="panel space-y-4 lg:col-span-2">
          <div>
            <p className="label">Channels</p>
            <div className="flex flex-wrap gap-1.5 mt-2">
              {logCategoryOrder.map((category) => (
                <span key={category} className="chip-static">
                  {logCategoryLabels[category]} {formatNumber(logCategoryStats[category])}
                </span>
              ))}
            </div>
          </div>
          <label className="space-y-2">
            <span className="label">Search logs</span>
            <input
              type="search"
              value={logSearch}
              onChange={(event) => setLogSearch(event.target.value)}
              placeholder="Filter by phrase or module"
            />
          </label>
          <div className="flex items-center justify-between gap-3">
            <p className="text-[11px] text-surfaceMuted/60">
              Showing {formatNumber(nodeLogs.length)} lines (newest {logNewestFirst ? 'first' : 'last'}).
            </p>
            <button
              className="chip"
              type="button"
              aria-pressed={logNewestFirst}
              onClick={() => setLogNewestFirst((prev) => !prev)}
            >
              Newest first
            </button>
          </div>
        </div>
      </div>

      <div className="panel h-80 overflow-auto">
        {activeConnection?.mode !== 'local' && (
          <div className="empty-state py-10">
            <div className="empty-state-icon">
              <EmptyStateIcon name="terminal" />
            </div>
            <p className="empty-state-description">Logs are only available for local nodes started from this app.</p>
          </div>
        )}
        {activeConnection?.mode === 'local' && (
          <div className="space-y-1">
            {displayedLogEntries.length === 0 && (
              <div className="text-center py-10">
                <p className="text-sm text-surfaceMuted/60">No matching logs.</p>
              </div>
            )}
            {displayedLogEntries.map((entry) => (
              <div key={entry.id} className="console-log-row">
                <span className="mono text-surfaceMuted/50 text-xs">{entry.timestamp ?? '--:--:--'}</span>
                <span className={`badge level-${entry.level}`}>{entry.level}</span>
                <span className="badge badge-category">{logCategoryLabels[entry.category]}</span>
                <span className="log-message mono">{entry.message}</span>
                {entry.highlight ? (
                  <span className={`badge badge-highlight level-${entry.level}`}>{entry.highlight}</span>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );

  const WalletStoreSection = (
    <section className={`card wallet-main-card ${walletReady ? 'wallet-ready' : 'wallet-locked'}`}>
      <details className="wallet-access-details" open={!walletReady}>
        <summary>
          <div>
            <h2 className="text-title font-semibold">Access</h2>
          </div>
          <span className={`status-pill ${walletTone}`}>{walletStateLabel}</span>
        </summary>

        <div className="grid gap-6">
        <label className="space-y-2">
          <div className="flex items-center justify-between gap-3">
            <span className="label">Store path</span>
            <button className="secondary text-xs px-3" type="button" onClick={handlePickWalletStorePath}>
              Browse
            </button>
          </div>
          <input
            className="mono"
            value={storePath}
            onChange={(event) => setStorePath(event.target.value)}
            spellCheck={false}
            title={storePath}
          />
        </label>
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="panel space-y-4">
            <div>
              <p className="label">Create</p>
              <p className="text-xs text-surfaceMuted">Passphrases cannot be recovered. Store it securely.</p>
            </div>
            <label className="space-y-2">
              <span className="label">Passphrase</span>
              <input
                type="password"
                value={createPassphrase}
                onChange={(event) => setCreatePassphrase(event.target.value)}
                placeholder={`Minimum ${minWalletPassphraseLength} characters`}
              />
            </label>
            <label className="space-y-2">
              <span className="label">Confirm passphrase</span>
              <input
                type="password"
                value={createPassphraseConfirm}
                onChange={(event) => setCreatePassphraseConfirm(event.target.value)}
              />
            </label>
            {createPassphraseTooShort ? (
              <p className="text-xs text-guard">
                Passphrase must be at least {minWalletPassphraseLength} characters.
              </p>
            ) : null}
            {createPassphraseMismatch ? (
              <p className="text-xs text-guard">Passphrases do not match.</p>
            ) : null}
            <button className="primary" onClick={handleWalletInit} disabled={!canInitWallet}>
              Create wallet
            </button>
          </div>

          <div className="panel space-y-4">
            <div>
              <p className="label">Open</p>
            </div>
            <label className="space-y-2">
              <span className="label">Passphrase</span>
              <input
                type="password"
                value={openPassphrase}
                onChange={(event) => setOpenPassphrase(event.target.value)}
              />
            </label>
            <button className="secondary" onClick={handleWalletRestore} disabled={!canOpenWallet}>
              Open wallet
            </button>
          </div>
        </div>

        <details className="diagnostic-details wallet-advanced-settings">
          <summary>
            <div>
              <p className="label">Advanced</p>
            </div>
            <span className="badge">{walletConnectionLabel}</span>
          </summary>
          <div className="grid gap-4 md:grid-cols-2">
          <label className="space-y-2">
            <span className="label">Wallet connection</span>
            <select value={walletConnectionId} onChange={(event) => setWalletConnectionId(event.target.value)}>
              {connections.map((connection) => (
                <option key={connection.id} value={connection.id}>
                  {connection.label}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-2">
            <span className="label">Wallet RPC URL</span>
            <input value={wsUrl} onChange={(event) => setWsUrl(event.target.value)} />
          </label>
        </div>
        {walletConnection?.wsUrl && wsUrl.trim() && wsUrl.trim() !== walletConnection.wsUrl.trim() ? (
          <div className="flex flex-wrap items-center gap-2 text-xs text-amber">
            <span>Wallet sync URL does not match the selected connection.</span>
            <button
              className="action-link secondary"
              type="button"
              onClick={() => setWsUrl(walletConnection.wsUrl)}
            >
              Use selected node
            </button>
          </div>
        ) : null}
        <label className="flex items-center gap-2 text-sm text-surfaceMuted">
          <input type="checkbox" checked={forceRescan} onChange={(event) => setForceRescan(event.target.checked)} />
          Force rescan on next sync
        </label>

        <div className="panel space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="label">Session</p>
              <p className="text-sm text-surfaceMuted">Status {walletStateLabel.toLowerCase()}.</p>
            </div>
            <span className={`status-pill ${walletTone}`}>{walletStateLabel}</span>
          </div>
          <div className="flex flex-wrap gap-3">
            <button className="secondary" onClick={() => handleWalletSync()} disabled={walletBusy || !walletReady}>
              Sync
            </button>
            <button className="secondary" onClick={handleWalletLock} disabled={walletBusy || !activeUnlockToken}>
              Lock wallet
            </button>
            {walletBusy ? (
              <button className="secondary" onClick={handleWalletCancel}>
                Cancel
              </button>
            ) : null}
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="flex items-center gap-2 text-sm text-surfaceMuted">
              <input
                type="checkbox"
                checked={autoLockEnabled}
                onChange={(event) => setAutoLockEnabled(event.target.checked)}
              />
              Auto-lock after inactivity
            </label>
            <label className="space-y-2">
              <span className="label">Timeout (minutes)</span>
              <input
                type="number"
                min={1}
                max={120}
                value={autoLockMinutes}
                onChange={(event) => {
                  const nextValue = Number.parseInt(event.target.value, 10);
                  if (!Number.isNaN(nextValue)) {
                    setAutoLockMinutes(clampAutoLockMinutes(nextValue));
                  }
                }}
                disabled={!autoLockEnabled}
              />
            </label>
          </div>
          <p className="text-xs text-surfaceMuted">Auto-lock stops walletd and clears the unlock token.</p>
        </div>
        </details>
        </div>
      </details>
      {GenesisMismatchBanner}

      {walletReady ? (
      <div className="wallet-surface">
        <div className="wallet-identity">
          <div className="wallet-identity-header">
            <div className="min-w-0">
              <p className="label">Balance</p>
              <h2>{walletBalanceDisplay}</h2>
              <p>
                {walletReady
                  ? `Synced to ${walletSyncDisplay}; lag ${walletLagDisplay} blocks`
                  : 'Open wallet to load funds and notes'}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button
                className="secondary px-3 py-1 text-xs"
                type="button"
                onClick={() => handleWalletSync()}
                disabled={walletBusy || !walletReady}
              >
                {walletSyncActionLabel}
              </button>
              <button
                className="secondary px-3 py-1 text-xs"
                onClick={handleCopyAddress}
                disabled={!primaryAddress}
              >
                {addressCopied ? 'Copied' : 'Copy address'}
              </button>
              <button
                className="secondary px-3 py-1 text-xs"
                onClick={handleWalletLock}
                disabled={walletBusy || !activeUnlockToken}
              >
                Lock
              </button>
            </div>
          </div>
          <div className="wallet-address-row">
            <span>Receiving address</span>
            <p className="address-display" title={primaryAddress}>
              {primaryAddressLabel}
            </p>
          </div>
          {primaryAddress ? (
            <details className="wallet-details">
              <summary>
                <span>Full address</span>
                <span>{normalizedStorePath ? formatCompactPath(normalizedStorePath) : 'Wallet store'}</span>
              </summary>
              <div className="address-full">{primaryAddress}</div>
            </details>
          ) : null}
          {addressCopyError ? <p className="wallet-inline-error">{addressCopyError}</p> : null}
        </div>

        <div className={`mining-payout-panel ${miningPayoutTone}`}>
          <div className="mining-payout-header">
            <div>
              <p className="label">Mining rewards</p>
              <h3>{miningPayoutLabel}</h3>
              <p>{miningPayoutDetail}</p>
            </div>
          </div>
          <div className="mining-payout-current">
            <div className="mining-payout-current-header">
              <span>Current payout</span>
              {effectiveMinerPayoutContact ? (
                <span className="contact-match ok">
                  {effectiveMinerPayoutContact.name}
                  {effectiveMinerPayoutContact.verified ? ' · verified' : ''}
                </span>
              ) : effectiveMinerPayoutAddress ? (
                <span className="contact-match warn">Not in contacts</span>
              ) : null}
            </div>
            {effectiveMinerPayoutAddress ? (
              <div className="address-full mining-payout-full" title={effectiveMinerPayoutAddress}>
                {effectiveMinerPayoutAddress}
              </div>
            ) : (
              <strong>{effectiveMinerPayoutLabel}</strong>
            )}
          </div>
          {miningPayoutTone !== 'ok' || miningPayoutPendingRestart ? (
            <div className="mining-payout-grid">
              <div>
                <span>Wallet address</span>
                <strong title={primaryAddress}>{primaryAddressLabel}</strong>
                {primaryAddressContact ? (
                  <em>
                    {primaryAddressContact.name}
                    {primaryAddressContact.verified ? ' · verified' : ''}
                  </em>
                ) : primaryAddress ? (
                  <em>Not in contacts</em>
                ) : null}
              </div>
              {miningPayoutPendingRestart ? (
              <div>
                <span>Saved next start</span>
                <strong title={savedMinerAddress}>{savedMinerPayoutLabel}</strong>
                {savedMinerAddressContact ? (
                  <em>
                    {savedMinerAddressContact.name}
                    {savedMinerAddressContact.verified ? ' · verified' : ''}
                  </em>
                ) : savedMinerAddress ? (
                  <em>Not in contacts</em>
                ) : null}
              </div>
              ) : null}
            </div>
          ) : null}
          <div className="mining-payout-actions">
            <button
              className="secondary"
              type="button"
              onClick={handleUseWalletAddressForMining}
              disabled={!primaryAddress || savedMiningPayoutMatchesWallet}
            >
              Use wallet address
            </button>
            <span>
              {miningPayoutPendingRestart
                ? 'Restart the node to apply the saved address.'
                : activeSummary?.reachable
                  ? 'Payout changes apply when the node restarts.'
                  : 'Saved payout is used on node start.'}
            </span>
          </div>
          {miningPayoutNotice ? <p className="mining-payout-notice">{miningPayoutNotice}</p> : null}
        </div>

        <div className="wallet-notes-panel">
          <details className="wallet-notes-details rounded-lg border border-surfaceMuted/10 bg-midnight/30 p-3">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-2 text-sm text-surfaceMuted">
              <span className="label">Assets and notes</span>
              <span className="text-xs text-surfaceMuted/80">
                {walletStatus?.balances?.length ?? 0} assets · {spendableNotesDisplay} spendable
              </span>
            </summary>
            <div className="mt-3 space-y-3">
            <div className="detail-grid">
              {walletStatus?.balances?.length ? (
                walletStatus.balances.map((balance) => (
                  <div key={balance.assetId} className="detail-row">
                    <span>{balance.label}</span>
                    <span className="mono">
                      {balance.assetId === 0 ? formatHgm(balance.total) : balance.total.toLocaleString()}
                    </span>
                  </div>
                ))
              ) : (
                <p className="p-3 text-sm text-surfaceMuted">
                  {walletReady ? 'No balances yet.' : 'Open wallet to load balances.'}
                </p>
              )}
            </div>
            {walletStatus?.notes ? (
              <p className="text-sm text-surfaceMuted">
                {walletStatus.notes.spendableCount} spendable notes, max {walletStatus.notes.maxInputs} inputs.
                {walletStatus.notes.needsConsolidation ? (
                  <span className="text-amber"> Some sends may require consolidation.</span>
                ) : null}
              </p>
            ) : null}
            {walletNoteDetails.length ? (
                walletNoteDetails.map((note) => (
                  <div key={note.commitment} className="note-card">
                    <div className="note-card-header">
                      <div className="min-w-0">
                        <p className="text-sm font-medium">Note {formatNumber(note.position)}</p>
                        <p className="mono technical-value" title={note.commitment}>
                          {formatHash(note.commitment)}
                        </p>
                      </div>
                      <span className={`badge ${note.status === 'spendable' ? 'level-info' : 'level-debug'}`}>
                        {note.status}
                      </span>
                    </div>
                    <div className="detail-grid">
                      <div className="detail-row">
                        <span>Balance</span>
                        <span className="mono">
                          {note.assetId === 0 ? formatHgm(note.value) : note.value.toLocaleString()}
                        </span>
                      </div>
                      <div className="detail-row">
                        <span>Asset</span>
                        <span className="mono">{note.assetId}</span>
                      </div>
                      <div className="detail-row">
                        <span>Address</span>
                        <span className="mono technical-value" title={note.address}>{formatAddress(note.address)}</span>
                      </div>
                      <div className="detail-row">
                        <span>Memo</span>
                        <span className="mono technical-value" title={note.memo ?? ''}>{note.memo ?? '—'}</span>
                      </div>
                      <div className="detail-row">
                        <span>Diversifier</span>
                        <span className="mono">{note.diversifierIndex}</span>
                      </div>
                      <div className="detail-row">
                        <span>Position</span>
                        <span className="mono">{formatNumber(note.position)}</span>
                      </div>
                      <div className="detail-row">
                        <span>Ciphertext index</span>
                        <span className="mono">{formatNumber(note.ciphertextIndex)}</span>
                      </div>
                      <div className="detail-row">
                        <span>Commitment</span>
                        <span className="mono technical-value" title={note.commitment}>{formatHash(note.commitment)}</span>
                      </div>
                      <div className="detail-row">
                        <span>Nullifier</span>
                        <span className="mono technical-value" title={note.nullifier ?? ''}>
                          {note.nullifier ? formatHash(note.nullifier) : '—'}
                        </span>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-sm text-surfaceMuted">No notes recorded yet.</p>
              )}
            </div>
          </details>
        </div>
      </div>
      ) : null}

      {WalletErrorBanner}
    </section>
  );

  const SendSection = (
    <section className="card space-y-6">
      <div>
        <h2 className="text-title font-semibold">Send</h2>
      </div>
      <div className="send-sync-strip">
        <div>
          <p className="label">Wallet sync</p>
          <strong>{walletReady ? walletSyncDisplay : walletStateLabel}</strong>
          <span>
            {walletReady
              ? `Lag ${walletLagDisplay} blocks · ${walletConnectionLabel}`
              : `${walletConnectionLabel} · open wallet first`}
          </span>
        </div>
        <button
          className="secondary px-3 py-1 text-xs"
          type="button"
          onClick={() => handleWalletSync()}
          disabled={walletBusy || !walletReady}
        >
          {walletSyncActionLabel}
        </button>
      </div>
      <div className="grid gap-4">
        <label className="space-y-2">
          <span className="flex items-center justify-between gap-3">
            <span className="label">Recipient address</span>
            <span className={`text-xs ${recipientAddressTone}`}>
              {normalizedRecipientAddress
                ? recipientAddressError
                  ? `Invalid ${recipientAddressLengthLabel}`
                  : `Valid ${recipientAddressLengthLabel}`
                : `0/${shieldedAddressLength}`}
            </span>
          </span>
          <textarea
            className="mono min-h-32 text-xs"
            rows={5}
            value={recipientAddress}
            onChange={(event) => setRecipientAddress(event.target.value)}
            placeholder="shca1..."
            spellCheck={false}
          />
          {recipientAddressError ? <p className="text-xs text-guard">{recipientAddressError}</p> : null}
        </label>
        {contacts.length > 0 && (
          <label className="space-y-2">
            <span className="label">Address book</span>
            <select
              value=""
              onChange={(event) => {
                const contact = contacts.find((entry) => entry.id === event.target.value);
                if (contact) {
                  setRecipientAddress(contact.address);
                }
              }}
            >
              <option value="">Select a contact</option>
              {contacts.map((contact) => {
                const contactAddressError = contactAddressErrors.get(contact.id);
                const contactWarning = contactWarnings.get(contact.id);
                return (
                  <option key={contact.id} value={contact.id} disabled={Boolean(contactAddressError || contactWarning)}>
                    {contact.name} - {formatAddress(contact.address)}
                    {contactAddressError ? ' (invalid)' : contactWarning ? ' (legacy; recreate for 0.10)' : ''}
                  </option>
                );
              })}
            </select>
          </label>
        )}
        <div className="grid gap-4 md:grid-cols-2">
          <label className="space-y-2">
            <span className="label">Amount (HGM)</span>
            <input value={sendAmount} onChange={(event) => setSendAmount(event.target.value)} placeholder="0.50" />
          </label>
          <label className="space-y-2">
            <span className="label">Miner tip (optional, HGM)</span>
            <input value={sendFee} onChange={(event) => setSendFee(event.target.value)} placeholder="0" />
          </label>
        </div>
        <label className="space-y-2">
          <span className="label">Memo</span>
          <textarea rows={2} value={sendMemo} onChange={(event) => setSendMemo(event.target.value)} />
        </label>
        <label className="flex items-center gap-2 text-sm text-surfaceMuted">
          <input type="checkbox" checked={autoConsolidate} onChange={(event) => setAutoConsolidate(event.target.checked)} />
          Auto-consolidate notes if needed (can take many txs)
        </label>
      </div>
      <button className="primary" onClick={handleWalletSend} disabled={!canSend}>
        {sendInFlight ? 'Sending...' : 'Send shielded transaction'}
      </button>
      {sendBlockedReason ? <p className="text-sm text-guard">{sendBlockedReason}</p> : null}
      {WalletErrorBanner}
    </section>
  );

  const handleActivitySync = () => {
    if (!walletReady) {
      return;
    }
    if (walletBusy) {
      setWalletSyncQueued(true);
      return;
    }
    void handleWalletSync();
  };

  const activitySyncDisabled = !walletReady || (walletBusy && !sendInFlight) || walletSyncQueued;
  const activitySyncLabel = !walletBusy
    ? 'Sync now'
    : sendInFlight
      ? walletSyncQueued
        ? 'Sync queued'
        : 'Queue sync'
      : 'Syncing...';

  const TransactionActivitySection = (
    <section className="card space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-title font-semibold">Activity</h2>
          {sendInFlight ? (
            <p className="text-xs text-surfaceMuted/70 mt-1">
              Sending is in progress. Sync requests run after submission finishes.
            </p>
          ) : walletSyncQueued ? (
            <p className="text-xs text-surfaceMuted/70 mt-1">Sync is queued and will start when the wallet is ready.</p>
          ) : null}
        </div>
        <button
          className="secondary px-3 py-1 text-xs"
          onClick={handleActivitySync}
          disabled={activitySyncDisabled}
        >
          {activitySyncLabel}
        </button>
      </div>
      {activityEntries.length === 0 ? (
        <div className="empty-state py-8">
          <div className="empty-state-icon">
            <EmptyStateIcon name="transactions" />
          </div>
          <p className="empty-state-description">No outgoing transactions yet.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {activityEntries.map((entry) => {
            const recipientContact = getContactForAddress(entry.recipient);
            const recipientAddressLabel = entry.recipient ? formatAddress(entry.recipient) : 'Unknown';
            return (
              <div key={entry.id} className="rounded-lg border border-surfaceMuted/10 bg-midnight/40 p-4 space-y-3">
                <div className="flex items-start gap-3">
                  <div
                    className={`flex h-10 w-10 items-center justify-center rounded-full border text-[11px] font-semibold ${activityStatusClasses[entry.status]} ${entry.status === 'processing' ? 'animate-pulse-slow' : ''}`}
                  >
                    {activityStatusSymbols[entry.status]}
                  </div>
                  <div className="flex-1 space-y-2">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="text-sm font-medium">
                          Sent {formatHgm(entry.amount)} to {recipientContact ? recipientContact.name : recipientAddressLabel}
                        </p>
                        {recipientContact ? (
                          <p className="text-xs text-surfaceMuted">
                            Contact match · <span className="mono">{recipientAddressLabel}</span>
                            {recipientContact.verified ? ' · verified' : ''}
                          </p>
                        ) : null}
                        <p className="text-xs text-surfaceMuted">
                          Miner tip {formatHgm(entry.fee)}
                          {entry.memo ? ` · Memo: ${entry.memo}` : ''}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-surfaceMuted">{formatTimestamp(entry.createdAt)}</p>
                        <p className="text-xs text-surfaceMuted">{activityStatusLabels[entry.status]}</p>
                      </div>
                    </div>
                    {entry.txId ? (
                      <div className="flex flex-wrap items-center gap-2 text-xs text-surfaceMuted">
                        <span className="mono">Tx {formatHash(entry.txId)}</span>
                        {entry.confirmations !== undefined ? (
                          <span>{entry.confirmations} confirmations</span>
                        ) : null}
                      </div>
                    ) : null}
                    {entry.error ? <p className="text-xs text-guard">{entry.error}</p> : null}
                    {entry.consolidationExpected || entry.consolidationSubmitted ? (
                      <div className="mt-3 space-y-2 border-l border-surfaceMuted/15 pl-4">
                        <p className="text-[10px] uppercase tracking-normal text-surfaceMuted/70">
                          Note consolidation
                        </p>
                        {entry.notesNeeded !== undefined &&
                        entry.walletNoteCount !== undefined &&
                        entry.maxInputs !== undefined ? (
                          <p className="text-xs text-surfaceMuted">
                            Needs {entry.notesNeeded} notes (wallet has {entry.walletNoteCount}, max {entry.maxInputs} inputs/tx).
                          </p>
                        ) : null}
                        <p className="text-xs text-surfaceMuted">
                          {entry.consolidationSubmitted
                            ? `${entry.consolidationConfirmed ?? 0}/${entry.consolidationSubmitted} confirmed`
                            : 'Preparing consolidation…'}
                          {entry.consolidationExpected ? ` · ~${entry.consolidationExpected} txs expected` : ''}
                          {entry.consolidationExpectedBlocks ? ` · ~${entry.consolidationExpectedBlocks} blocks` : ''}
                          {entry.consolidationExpected &&
                          entry.consolidationExpectedBlocks &&
                          entry.consolidationExpectedBlocks > 0
                            ? ` (~${(entry.consolidationExpected / entry.consolidationExpectedBlocks).toFixed(1)} tx/block)`
                            : ''}
                        </p>
                        {entry.steps ? (
                          <div className="space-y-2 pt-1">
                            {entry.steps.map((step) => (
                              <div key={step.id} className="flex items-center justify-between gap-3 text-xs">
                                <div className="flex items-center gap-2">
                                  <span
                                    className={`flex h-6 w-6 items-center justify-center rounded-full border text-[9px] font-semibold ${activityStatusClasses[step.status]} ${step.status === 'processing' ? 'animate-pulse-slow' : ''}`}
                                  >
                                    {activityStatusSymbols[step.status]}
                                  </span>
                                  <span className="text-surfaceMuted">{step.label}</span>
                                </div>
                                <div className="text-surfaceMuted">
                                  {step.txId ? `Tx ${formatHash(step.txId)}` : activityStatusLabels[step.status]}
                                  {step.confirmations !== undefined ? ` · ${step.confirmations} conf` : ''}
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );

  const ContactsSection = (
    <details className="card diagnostic-details">
      <summary>
        <div>
          <h2 className="text-title font-semibold">Recipients</h2>
        </div>
        <span className="badge">{contacts.length} saved</span>
      </summary>
      <div className="space-y-6">
      <div className="grid gap-3">
        <label className="space-y-2">
          <span className="label">Name</span>
          <input value={newContactName} onChange={(event) => setNewContactName(event.target.value)} />
        </label>
        <label className="space-y-2">
          <span className="label">Address</span>
          <input value={newContactAddress} onChange={(event) => setNewContactAddress(event.target.value)} placeholder="shca1..." />
          {newContactAddressError ? <p className="text-xs text-guard">{newContactAddressError}</p> : null}
        </label>
        <label className="space-y-2">
          <span className="label">Notes</span>
          <input value={newContactNotes} onChange={(event) => setNewContactNotes(event.target.value)} placeholder="How verified, context, etc." />
        </label>
        <label className="flex items-center gap-2 text-sm text-surfaceMuted">
          <input type="checkbox" checked={newContactVerified} onChange={(event) => setNewContactVerified(event.target.checked)} />
          Verified out of band
        </label>
        <button
          className="secondary"
          onClick={handleAddContact}
          disabled={
            !contactsLoaded ||
            contactsSaving ||
            !newContactName.trim() ||
            !newContactAddress.trim() ||
            Boolean(newContactAddressError)
          }
        >
          {!contactsLoaded ? 'Loading…' : contactsSaving ? 'Saving…' : 'Add contact'}
        </button>
      </div>

      <div className="space-y-3">
        {contacts.length === 0 && (
          <div className="empty-state py-8">
            <div className="empty-state-icon">
              <EmptyStateIcon name="contacts" />
            </div>
            <p className="empty-state-description">No contacts saved yet. Add your first recipient above.</p>
          </div>
        )}
        {contacts.map((contact) => {
          const contactAddressError = contactAddressErrors.get(contact.id);
          const contactWarning = contactWarnings.get(contact.id);
          return (
            <div
              key={contact.id}
              className={`rounded-lg border p-4 transition-colors ${
                contactWarning
                  ? 'border-amber/30 bg-amber/10'
                  : 'border-surfaceMuted/10 bg-midnight/50 hover:bg-midnight/60'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-lg font-medium">{contact.name}</p>
                    {contact.protocolVersion ? <span className="badge">v{contact.protocolVersion}</span> : null}
                    {contact.chainSpecName ? <span className="badge">{normalizeNetworkDisplayName(contact.chainSpecName)}</span> : null}
                    {contactWarning ? <span className="badge level-warn">Legacy</span> : null}
                  </div>
                  <p className="mono text-sm text-surfaceMuted truncate" title={contact.address}>
                    {formatAddress(contact.address)}
                  </p>
                </div>
                <button className="danger" onClick={() => handleRemoveContact(contact.id)} disabled={contactsSaving}>
                  Remove
                </button>
              </div>
              {contactWarning ? <p className="mt-3 text-sm text-amber">{contactWarning}</p> : null}
              {contactAddressError ? <p className="mt-3 text-sm text-guard">{contactAddressError}</p> : null}
              <p className="mt-2 text-sm text-surfaceMuted">Verified: {contact.verified ? 'Yes' : 'No'}</p>
              {contact.notes ? <p className="text-sm text-surfaceMuted">Notes: {contact.notes}</p> : null}
              {contact.lastUsed ? (
                <p className="text-sm text-surfaceMuted">Last used: {new Date(contact.lastUsed).toLocaleString()}</p>
              ) : null}
            </div>
          );
        })}
      </div>
      {ContactsErrorBanner}
      </div>
    </details>
  );

  const DisclosureRecordsSection = (
    <section className="card flex flex-col gap-4 min-h-0">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-title font-semibold">Outputs</h2>
          <p className="text-sm text-surfaceMuted/80">
            Select one to disclose.
          </p>
        </div>
        <button
          className="secondary px-3 py-1 text-xs"
          onClick={() => void refreshDisclosureRecords()}
          disabled={!walletReady || walletBusy || disclosureListBusy}
        >
          {disclosureListBusy ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>
      {disclosureGroups.length === 0 ? (
        <div className="empty-state py-8 flex-1 flex flex-col items-center justify-center">
          <div className="empty-state-icon">
            <EmptyStateIcon name="disclosure" />
          </div>
          <p className="empty-state-description">No outgoing disclosure records yet.</p>
        </div>
      ) : (
        <div className="space-y-3 flex-1 min-h-0 overflow-y-auto pr-1">
          {disclosureGroups.map((group) => (
            <div key={group.txId} className="rounded-lg border border-surfaceMuted/10 bg-midnight/40 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">Tx {formatHash(group.txId)}</p>
                  <p className="text-xs text-surfaceMuted">
                    {formatTimestamp(group.createdAt)} · {group.outputs.length} outputs
                  </p>
                </div>
              </div>
              <div className="space-y-2">
                {group.outputs.map((record) => {
                  const key = `${record.txId}:${record.outputIndex}`;
                  const selected = key === selectedDisclosureKey;
                  return (
                    <button
                      key={key}
                      className={`w-full text-left rounded-lg border px-3 py-2 transition-colors ${
                        selected
                          ? 'border-ionosphere/40 bg-ionosphere/10 text-surface'
                          : 'border-surfaceMuted/10 bg-midnight/50 text-surfaceMuted'
                      }`}
                      onClick={() => handleSelectDisclosure(record)}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <p className="text-sm font-medium">
                            Output {record.outputIndex} · {formatAddress(record.recipientAddress)}
                          </p>
                          <p className="text-xs text-surfaceMuted">
                            {record.memo ? `Memo: ${record.memo}` : 'No memo'}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm font-medium">{formatHgm(record.value)}</p>
                          <p className="text-xs text-surfaceMuted">
                            {record.assetId === 0 ? 'HGM' : `Asset ${record.assetId}`}
                          </p>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );

  const DisclosureGenerateSection = (
    <section className="card space-y-6">
      <div>
        <h2 className="text-title font-semibold">Create</h2>
      </div>
      <div className="grid gap-4">
        {selectedDisclosure ? (
          <div className="rounded-lg border border-ionosphere/20 bg-ionosphere/10 p-3 text-sm">
            <p className="font-medium text-surface">Selected output</p>
            <p className="text-xs text-surfaceMuted">
              Tx {formatHash(selectedDisclosure.txId)} · Output {selectedDisclosure.outputIndex}
            </p>
            <p className="text-xs text-surfaceMuted">
              {formatHgm(selectedDisclosure.value)} to {formatAddress(selectedDisclosure.recipientAddress)}
            </p>
          </div>
        ) : null}
        <label className="space-y-2">
          <span className="label">Transaction hash</span>
          <input
            value={disclosureTxId}
            onChange={(event) => {
              setDisclosureTxId(event.target.value);
              setSelectedDisclosureKey(null);
            }}
            placeholder="0x..."
          />
        </label>
        <label className="space-y-2">
          <span className="label">Output index</span>
          <input
            value={disclosureOutput}
            onChange={(event) => {
              setDisclosureOutput(event.target.value);
              setSelectedDisclosureKey(null);
            }}
          />
        </label>
      </div>
      <button className="secondary" onClick={handleDisclosureCreate} disabled={walletBusy || !walletReady}>
        Create disclosure package
      </button>
      <div className="flex items-center justify-between">
        <span className="label">Disclosure package</span>
        <button
          className="secondary px-3 py-1 text-xs"
          onClick={handleCopyDisclosureOutput}
          disabled={!walletDisclosureOutput}
        >
          {disclosureCopied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-lg p-4 min-h-48 max-h-[40vh] overflow-y-auto">
        {walletDisclosureOutput || 'N/A'}
      </pre>
      {disclosureCopyError ? <p className="text-guard text-sm">{disclosureCopyError}</p> : null}
      {WalletErrorBanner}
    </section>
  );

  const DisclosureVerifySection = (
    <section className="card space-y-6">
      <div>
        <h2 className="text-title font-semibold">Verify</h2>
      </div>
      <label className="space-y-2">
        <span className="label">Disclosure JSON</span>
        <textarea rows={8} value={disclosureInput} onChange={(event) => setDisclosureInput(event.target.value)} />
      </label>
      <button className="secondary" onClick={handleDisclosureVerify} disabled={walletBusy || !walletReady}>
        Verify disclosure package
      </button>
      <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-lg p-4">
        {walletDisclosureVerifyOutput || 'N/A'}
      </pre>
      {WalletErrorBanner}
    </section>
  );

  const NodeWorkspace = (
    <div className="workspace-view max-w-7xl">
      {NodeOperationsSection}
      {NodeConnectionsSection}
    </div>
  );

  const WalletWorkspace = (
    <div className="workspace-view max-w-7xl">
      {WalletStoreSection}
    </div>
  );

  const showActivityPanel = walletReady || activityEntries.length > 0 || sendInFlight || walletSyncQueued;

  const SendWorkspace = (
    <div className="workspace-view max-w-7xl">
      <div className={showActivityPanel ? 'grid gap-5 xl:grid-cols-[minmax(0,1.08fr)_minmax(24rem,0.92fr)]' : 'grid gap-5 max-w-3xl'}>
        {SendSection}
        {showActivityPanel ? TransactionActivitySection : null}
      </div>
      {ContactsSection}
    </div>
  );

  const DisclosureWorkspace = (
    <div className="workspace-view max-w-7xl">
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.08fr)_minmax(24rem,0.92fr)] items-start">
        {DisclosureRecordsSection}
        <div className="space-y-5">
          {DisclosureGenerateSection}
          {DisclosureVerifySection}
        </div>
      </div>
    </div>
  );

  const ConsoleWorkspace = (
    <div className="workspace-view max-w-7xl">
      {NodeConsoleSection}
    </div>
  );

  return (
    <HashRouter>
      <ScrollToTop />
      <div className="app-shell">
        <aside className="app-sidebar relative">
          <div className="flex items-center gap-3">
            <svg width="40" height="40" viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Hegemon emblem">
              <path d="M100 40 L45 160 L155 160 Z" fill="none" stroke="#F5A623" strokeWidth="12"/>
              <path d="M100 40 L45 160 L155 160 Z" fill="#F5A623" opacity="0.15"/>
              <circle cx="100" cy="100" r="48" fill="none" stroke="#F5A623" strokeWidth="8"/>
              <circle cx="100" cy="100" r="38" fill="#F5A623" opacity="0.08"/>
              <line x1="70" y1="70" x2="130" y2="130" stroke="#F5A623" strokeWidth="2" opacity="0.4"/>
              <line x1="70" y1="130" x2="130" y2="70" stroke="#F5A623" strokeWidth="2" opacity="0.4"/>
            </svg>
            <div>
              <h1 className="text-lg font-semibold tracking-normal">Hegemon</h1>
              <p className="text-[10px] text-surfaceMuted/70 uppercase tracking-normal">Desktop node</p>
            </div>
          </div>
          <nav className="space-y-1 pt-4">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) => `nav-link${isActive ? ' nav-link-active' : ''}`}
              >
                <span className="nav-link-icon">
                  <AppIcon name={item.icon} />
                </span>
                <div className="nav-link-copy">
                  <p className="nav-link-label">{item.label}</p>
                  <p className="nav-link-description">{item.description}</p>
                </div>
                {item.statusLabel && item.statusTone ? (
                  <span className={`nav-status ${item.statusTone}`}>{item.statusLabel}</span>
                ) : null}
              </NavLink>
            ))}
          </nav>
          <div className="sidebar-footer">
            <span>v0.10.0</span>
          </div>
        </aside>
        <div className="app-body">
          <main className="app-main">
            <Routes>
              <Route path="/" element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={OverviewWorkspace} />
              <Route path="/node" element={NodeWorkspace} />
              <Route path="/wallet" element={WalletWorkspace} />
              <Route path="/send" element={SendWorkspace} />
              <Route path="/disclosure" element={DisclosureWorkspace} />
              <Route path="/console" element={ConsoleWorkspace} />
              <Route path="*" element={<Navigate to="/overview" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </HashRouter>
  );
}
