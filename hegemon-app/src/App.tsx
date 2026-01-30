import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { HashRouter, Link, NavLink, Navigate, Route, Routes } from 'react-router-dom';
import type {
  Contact,
  NodeConnection,
  NodeSummary,
  WalletDisclosureCreateResult,
  WalletDisclosureRecord,
  WalletDisclosureVerifyResult,
  WalletStatus
} from './types';

const defaultStorePath = '~/.hegemon-wallet';
const contactsKey = 'hegemon.contacts';
const connectionsKey = 'hegemon.nodeConnections';
const activeConnectionKey = 'hegemon.activeConnection';
const walletConnectionKey = 'hegemon.walletConnection';
const walletAutoLockEnabledKey = 'hegemon.walletAutoLockEnabled';
const walletAutoLockMinutesKey = 'hegemon.walletAutoLockMinutes';
const blockAlertEnabledKey = 'hegemon.blockAlertEnabled';
const minWalletPassphraseLength = 12;

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

type NodeTransition = {
  action: NodeTransitionAction;
  connectionId: string;
  startedAt: number;
};

type BlockAlertTone = 'self' | 'other';
type BlockAlertStep = { frequency: number; duration: number; gap?: number };

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

const formatAddress = (address: string) => {
  if (address.length <= 16) {
    return address;
  }
  return `${address.slice(0, 8)}...${address.slice(-8)}`;
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
      { frequency: 880, duration: 0.12, gap: 0.05 },
      { frequency: 1175, duration: 0.12 }
    ];
  }
  return [
    { frequency: 520, duration: 0.14, gap: 0.04 },
    { frequency: 420, duration: 0.16 }
  ];
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
  if (httpUrl && httpUrl.trim()) {
    return httpUrl.trim();
  }
  if (wsUrl.startsWith('ws://')) {
    return `http://${wsUrl.slice('ws://'.length)}`;
  }
  if (wsUrl.startsWith('wss://')) {
    return `https://${wsUrl.slice('wss://'.length)}`;
  }
  return wsUrl;
};

const classifyLogLevel = (line: string): LogLevel => {
  if (/\bERROR\b|\bError\b|\bpanic\b/i.test(line)) {
    return 'error';
  }
  if (/\bWARN\b|\bWarning\b/i.test(line)) {
    return 'warn';
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
  if (/Block mined/i.test(line)) {
    return 'Block mined';
  }
  if (/Block imported successfully|Block imported/i.test(line)) {
    return 'Block imported';
  }
  if (/sync complete/i.test(line)) {
    return 'Sync complete';
  }
  if (/error|panic/i.test(line)) {
    return 'Error';
  }
  return undefined;
};

const parseLogLine = (line: string, index: number): LogEntry => {
  const timestampMatch = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.*)$/);
  const timestamp = timestampMatch ? timestampMatch[1] : null;
  const message = timestampMatch ? timestampMatch[2] : line;
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
  label: 'Local node',
  mode: 'local',
  wsUrl: 'ws://127.0.0.1:9944',
  httpUrl: 'http://127.0.0.1:9944',
  dev: true,
  chainSpecPath: 'config/dev-chainspec.json',
  tmp: false,
  basePath: '~/.hegemon-node',
  rpcPort: 9944,
  p2pPort: 30333,
  mineThreads: 1,
  miningIntent: false,
  rpcMethods: 'safe',
  seeds: 'hegemon.pauli.group'
});

const buildTestnetConnection = (): NodeConnection => ({
  id: makeId(),
  label: 'Testnet node',
  mode: 'local',
  wsUrl: 'ws://127.0.0.1:9944',
  httpUrl: 'http://127.0.0.1:9944',
  dev: false,
  tmp: false,
  basePath: '~/.hegemon-node-testnet',
  rpcPort: 9944,
  p2pPort: 30333,
  mineThreads: 1,
  miningIntent: false,
  rpcMethods: 'safe',
  chainSpecPath: 'testnet',
  seeds: 'hegemon.pauli.group'
});

const buildDefaultConnections = () => [buildDefaultConnection(), buildTestnetConnection()];

const normalizeConnection = (connection: NodeConnection): NodeConnection => {
  const isDefaultLocal =
    connection.mode === 'local' &&
    connection.label === 'Local node' &&
    (!connection.basePath || connection.basePath === '~/.hegemon-node');
  const isDefaultTestnet =
    connection.mode === 'local' &&
    connection.label === 'Testnet node' &&
    (!connection.basePath || connection.basePath === '~/.hegemon-node-testnet');

  let next = connection;

  if (isDefaultLocal && connection.dev && !connection.chainSpecPath) {
    next = { ...next, chainSpecPath: 'config/dev-chainspec.json' };
  }

  if ((isDefaultLocal || isDefaultTestnet) && connection.seeds === 'hegemon.pauli.group:30333') {
    next = { ...next, seeds: 'hegemon.pauli.group' };
  }

  return next;
};

export default function App() {
  const [connections, setConnections] = useState<NodeConnection[]>([]);
  const [activeConnectionId, setActiveConnectionId] = useState('');
  const [walletConnectionId, setWalletConnectionId] = useState('');
  const [nodeSummaries, setNodeSummaries] = useState<Record<string, NodeSummary>>({});
  const [nodeLogs, setNodeLogs] = useState<string[]>([]);
  const [nodeBusy, setNodeBusy] = useState(false);
  const [nodeTransition, setNodeTransition] = useState<NodeTransition | null>(null);
  const [nodeError, setNodeError] = useState<string | null>(null);
  const [showAdvancedNode, setShowAdvancedNode] = useState(false);
  const [logFilterInfo, setLogFilterInfo] = useState(true);
  const [logFilterWarn, setLogFilterWarn] = useState(true);
  const [logFilterError, setLogFilterError] = useState(true);
  const [logFilterDebug, setLogFilterDebug] = useState(false);
  const [logSearch, setLogSearch] = useState('');
  const [logNewestFirst, setLogNewestFirst] = useState(true);

  const [walletStatus, setWalletStatus] = useState<WalletStatus | null>(null);
  const [walletSyncOutput, setWalletSyncOutput] = useState<string>('');
  const [walletSendOutput, setWalletSendOutput] = useState<string>('');
  const [walletDisclosureOutput, setWalletDisclosureOutput] = useState<string>('');
  const [walletDisclosureVerifyOutput, setWalletDisclosureVerifyOutput] = useState<string>('');
  const [walletBusy, setWalletBusy] = useState(false);
  const [walletSyncQueued, setWalletSyncQueued] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);
  const [addressCopied, setAddressCopied] = useState(false);
  const [disclosureCopied, setDisclosureCopied] = useState(false);
  const [disclosureCopyError, setDisclosureCopyError] = useState<string | null>(null);

  const [storePath, setStorePath] = useState(defaultStorePath);
  const [createPassphrase, setCreatePassphrase] = useState('');
  const [createPassphraseConfirm, setCreatePassphraseConfirm] = useState('');
  const [openPassphrase, setOpenPassphrase] = useState('');
  const [activePassphrase, setActivePassphrase] = useState<string | null>(null);
  const [wsUrl, setWsUrl] = useState('ws://127.0.0.1:9944');
  const [forceRescan, setForceRescan] = useState(false);
  const [autoLockEnabled, setAutoLockEnabled] = useState(true);
  const [autoLockMinutes, setAutoLockMinutes] = useState(15);
  const lastActivityRef = useRef(Date.now());
  const [blockAlertEnabled, setBlockAlertEnabled] = useState(false);
  const audioContextRef = useRef<AudioContext | null>(null);
  const blockAlertRef = useRef<{
    connectionId: string | null;
    blocksMined: number | null;
    blocksImported: number | null;
  }>({ connectionId: null, blocksMined: null, blocksImported: null });

  const [recipientAddress, setRecipientAddress] = useState('');
  const [sendAmount, setSendAmount] = useState('');
  const [sendMemo, setSendMemo] = useState('');
  const [sendFee, setSendFee] = useState('0.01');
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
          const normalized = parsed.map(normalizeConnection);
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
        const legacy = window.localStorage.getItem(contactsKey);
        if (!legacy) {
          return;
        }
        try {
          const parsed = JSON.parse(legacy);
          if (Array.isArray(parsed)) {
            setContacts(parsed);
            await window.hegemon.contacts.save(parsed);
            window.localStorage.removeItem(contactsKey);
          }
        } catch {
          if (!cancelled) {
            setContactsError('Failed to migrate legacy contacts.');
          }
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

  const playBlockAlert = useCallback(
    (tone: BlockAlertTone) => {
      if (!blockAlertEnabled || typeof window.AudioContext === 'undefined') {
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
    },
    [blockAlertEnabled]
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
        return { ...conn, ...patch };
      })
    );
  };

  const activeSummary = activeConnection ? nodeSummaries[activeConnection.id] : null;

  const healthLabel = useMemo(() => {
    if (!activeSummary) {
      return 'Unknown';
    }
    if (!activeSummary.reachable) {
      return 'Offline';
    }
    return activeSummary.isSyncing ? 'Syncing' : 'Healthy';
  }, [activeSummary]);

  const healthTone = !activeSummary
    ? 'neutral'
    : !activeSummary.reachable
      ? 'error'
      : activeSummary.isSyncing
        ? 'warn'
        : 'ok';

  const updatedAtLabel = activeSummary?.updatedAt
    ? new Date(activeSummary.updatedAt).toLocaleTimeString()
    : 'N/A';

  const logEntries = useMemo(() => nodeLogs.map((line, index) => parseLogLine(line, index)), [nodeLogs]);

  const logHighlights = useMemo(() => {
    const highlights = logEntries.filter((entry) => entry.highlight);
    return highlights.slice(-6).reverse();
  }, [logEntries]);

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
            peers: null,
            isSyncing: null,
            bestBlock: null,
            bestNumber: null,
            genesisHash: null,
            mining: null,
            miningThreads: null,
            hashRate: null,
            blocksFound: null,
            difficulty: null,
            blockHeight: null,
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
    } else {
      setNodeLogs([]);
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

  const handleNodeStart = async () => {
    if (!activeConnection || activeConnection.mode !== 'local') {
      setNodeError('Select a local connection to start a node.');
      return;
    }
    if (activeConnection.miningIntent && !activeConnection.minerAddress) {
      setNodeError('Set a miner address before enabling mining.');
      return;
    }
    if (activeConnection.tmp) {
      const confirmed = window.confirm('Temp storage deletes node data on shutdown. Continue?');
      if (!confirmed) {
        return;
      }
    } else if (!activeConnection.basePath) {
      const confirmed = window.confirm('No base path set. The node will use its default data directory. Continue?');
      if (!confirmed) {
        return;
      }
    }
    setNodeTransition({ action: 'starting', connectionId: activeConnection.id, startedAt: Date.now() });
    setNodeBusy(true);
    setNodeError(null);
    try {
      await window.hegemon.node.start({
        connectionId: activeConnection.id,
        chainSpecPath: activeConnection.chainSpecPath || undefined,
        basePath: activeConnection.basePath || undefined,
        dev: activeConnection.dev,
        tmp: activeConnection.tmp,
        rpcPort: activeConnection.rpcPort,
        p2pPort: activeConnection.p2pPort,
        listenAddr: activeConnection.listenAddr || undefined,
        minerAddress: activeConnection.minerAddress || undefined,
        mineThreads: activeConnection.mineThreads,
        mineOnStart: activeConnection.miningIntent,
        seeds: activeConnection.seeds || undefined,
        rpcExternal: activeConnection.rpcExternal,
        rpcMethods: activeConnection.rpcMethods,
        nodeName: activeConnection.nodeName || undefined
      });
      await refreshNode();
    } catch (error) {
      setNodeTransition(null);
      setNodeError(error instanceof Error ? error.message : 'Failed to start node.');
    } finally {
      setNodeBusy(false);
    }
  };

  const handleNodeStop = async () => {
    if (!activeConnection || activeConnection.mode !== 'local') {
      setNodeError('Select a local connection to stop a node.');
      return;
    }
    setNodeTransition({ action: 'stopping', connectionId: activeConnection.id, startedAt: Date.now() });
    setNodeBusy(true);
    try {
      await window.hegemon.node.stop();
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

  const requireActivePassphrase = () => {
    if (!activePassphrase) {
      throw new Error('Wallet is locked. Open or init the store first.');
    }
    return activePassphrase;
  };

  const refreshWalletStatus = async (overridePassphrase?: string) => {
    const passphrase = overridePassphrase ?? activePassphrase;
    if (!passphrase) {
      setWalletStatus(null);
      return;
    }
    try {
      const resolvedStorePath = resolveStorePath();
      const status = await window.hegemon.wallet.status(resolvedStorePath, passphrase, true);
      setWalletStatus(status);
      setWalletError(null);
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet status failed.');
    }
  };

  const refreshDisclosureRecords = async (overridePassphrase?: string) => {
    const passphrase = overridePassphrase ?? activePassphrase;
    if (!passphrase) {
      setDisclosureRecords([]);
      return;
    }
    setDisclosureListBusy(true);
    try {
      const resolvedStorePath = resolveStorePath();
      const records = await window.hegemon.wallet.disclosureList(resolvedStorePath, passphrase);
      setDisclosureRecords(records);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Disclosure list failed.';
      const code = (error as { code?: string }).code;
      if (code === 'unknown_method' || message.includes('unknown method disclosure.list')) {
        setDisclosureRecords([]);
        return;
      }
      setWalletError(message);
    } finally {
      setDisclosureListBusy(false);
    }
  };

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
      const status = await window.hegemon.wallet.init(resolvedStorePath, createPassphrase);
      setWalletStatus(status);
      setActivePassphrase(createPassphrase);
      setCreatePassphrase('');
      setCreatePassphraseConfirm('');
      setOpenPassphrase('');
      await refreshDisclosureRecords(createPassphrase);
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
      const status = await window.hegemon.wallet.restore(resolvedStorePath, openPassphrase);
      setWalletStatus(status);
      setActivePassphrase(openPassphrase);
      setOpenPassphrase('');
      setCreatePassphrase('');
      setCreatePassphraseConfirm('');
      await refreshDisclosureRecords(openPassphrase);
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
      setActivePassphrase(null);
      setCreatePassphrase('');
      setCreatePassphraseConfirm('');
      setOpenPassphrase('');
      setWalletSyncOutput('');
      setWalletSendOutput('');
      setWalletDisclosureOutput('');
      setWalletDisclosureVerifyOutput('');
      setDisclosureRecords([]);
      setSelectedDisclosureKey(null);
    }
  }, []);

  useEffect(() => {
    if (!autoLockEnabled || !activePassphrase) {
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
  }, [autoLockEnabled, activePassphrase, autoLockMinutes, handleWalletLock, walletBusy]);

  const handleCopyAddress = async () => {
    if (!walletStatus?.primaryAddress) {
      return;
    }
    try {
      await navigator.clipboard.writeText(walletStatus.primaryAddress);
      setAddressCopied(true);
      window.setTimeout(() => setAddressCopied(false), 2000);
    } catch {
      setWalletError('Failed to copy address.');
    }
  };

  const handleCopyDisclosureOutput = async () => {
    setDisclosureCopyError(null);
    if (!walletDisclosureOutput) {
      setDisclosureCopyError('Generate a disclosure package first.');
      return;
    }
    try {
      await navigator.clipboard.writeText(walletDisclosureOutput);
      setDisclosureCopied(true);
      window.setTimeout(() => setDisclosureCopied(false), 2000);
    } catch {
      setDisclosureCopyError('Failed to copy disclosure package.');
    }
  };

  const handleWalletSync = async (forceOverride?: boolean) => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const rescan = forceOverride ?? forceRescan;
      if (forceOverride) {
        setForceRescan(true);
      }
      const passphrase = requireActivePassphrase();
      const resolvedStorePath = resolveStorePath();
      const result = await window.hegemon.wallet.sync(resolvedStorePath, passphrase, wsUrl, rescan);
      setWalletSyncOutput(JSON.stringify(result, null, 2));
      await refreshWalletStatus();
      await refreshDisclosureRecords();
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet sync failed.');
    } finally {
      setWalletBusy(false);
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
      const amount = toBaseUnits(sendAmount);
      const fee = toBaseUnits(sendFee);
      if (!amount || !fee) {
        throw new Error('Amount and fee must be valid numbers.');
      }
      if (genesisMismatch) {
        throw new Error('Genesis mismatch between wallet and node. Switch nodes or force a rescan before sending.');
      }
      if (walletSummary?.reachable === false) {
        throw new Error('Wallet connection is offline. Select a reachable node or fix the RPC endpoint.');
      }

      setWalletBusy(true);
      const passphrase = requireActivePassphrase();
      const resolvedStorePath = resolveStorePath();
      const recipients = [
        {
          address: recipientAddress,
          value: amount,
          asset_id: 0,
          memo: sendMemo || null
        }
      ];

      const plan = await window.hegemon.wallet.sendPlan({
        storePath: resolvedStorePath,
        passphrase,
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
        recipient: recipientAddress.trim(),
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
        passphrase,
        wsUrl,
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
      setWalletSendOutput(JSON.stringify(result, null, 2));
      setRecipientAddress('');
      setSendAmount('');
      setSendMemo('');
      await refreshWalletStatus();
      await refreshDisclosureRecords();
    } catch (error) {
      if (attemptId) {
        const message = error instanceof Error ? error.message : 'Wallet send failed.';
        setSendAttempts((prev) =>
          prev.map((entry) =>
            entry.id === attemptId ? { ...entry, status: 'failed', error: message } : entry
          )
        );
      }
      setWalletError(error instanceof Error ? error.message : 'Wallet send failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleAddContact = async () => {
    if (!contactsLoaded || contactsSaving || !newContactName || !newContactAddress) {
      return;
    }
    const newEntry: Contact = {
      id: makeId(),
      name: newContactName,
      address: newContactAddress,
      verified: newContactVerified,
      notes: newContactNotes || undefined,
      lastUsed: undefined
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
      const passphrase = requireActivePassphrase();
      const outputIndex = Number.parseInt(disclosureOutput, 10);
      if (Number.isNaN(outputIndex)) {
        throw new Error('Output index must be a number.');
      }
      const result: WalletDisclosureCreateResult = await window.hegemon.wallet.disclosureCreate(
        resolveStorePath(),
        passphrase,
        wsUrl,
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
      const passphrase = requireActivePassphrase();
      const parsed = parseDisclosureInput(disclosureInput);
      const result: WalletDisclosureVerifyResult = await window.hegemon.wallet.disclosureVerify(
        resolveStorePath(),
        passphrase,
        wsUrl,
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
      label: 'Remote node',
      mode: 'remote',
      wsUrl: 'ws://127.0.0.1:9944',
      httpUrl: 'http://127.0.0.1:9944',
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
  const walletReady = Boolean(walletStatus && activePassphrase);
  const walletUnlocked = Boolean(activePassphrase);
  const walletGenesis = walletStatus?.genesisHash ?? null;
  const walletNodeGenesis = walletSummary?.genesisHash ?? null;
  const genesisMismatch = Boolean(walletGenesis && walletNodeGenesis && walletGenesis !== walletNodeGenesis);
  const nodeIsLocal = activeConnection?.mode === 'local';
  const nodeTransitionAction =
    nodeTransition && activeConnection && nodeTransition.connectionId === activeConnection.id ? nodeTransition.action : null;
  const nodeIsRunning = nodeIsLocal && Boolean(activeSummary?.reachable);
  const nodeToggleDisabled = nodeBusy || !nodeIsLocal || nodeTransitionAction !== null;
  const nodeToggleClass = nodeIsRunning || nodeTransitionAction === 'stopping' ? 'secondary' : 'primary';
  const nodeToggleLabel = nodeTransitionAction ? (
    <span className="inline-flex items-center gap-1">
      {nodeTransitionAction === 'starting' ? 'Starting' : 'Stopping'}
      <span className="loading-dots" aria-hidden="true">
        ...
      </span>
    </span>
  ) : nodeIsRunning ? (
    'Stop node'
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
  const miningHint = activeSummary?.mining
    ? 'Mining is active. To change mining settings, stop the node, update Auto-start mining under Advanced settings, then restart.'
    : 'Mining is configured at launch. Enable Auto-start mining under Advanced settings and restart the node to mine.';
  const walletConnectionTone =
    walletSummary?.reachable === true ? 'ok' : walletSummary?.reachable === false ? 'error' : 'neutral';
  const walletConnectionLabel =
    walletSummary?.reachable === true ? 'Online' : walletSummary?.reachable === false ? 'Offline' : 'Unknown';
  const walletTone = walletError ? 'error' : walletReady ? 'ok' : 'warn';
  const walletStateLabel = walletError ? 'Error' : walletReady ? 'Ready' : walletUnlocked ? 'Unlocked' : 'Locked';
  const chainTone = genesisMismatch ? 'error' : walletGenesis && walletNodeGenesis ? 'ok' : 'neutral';
  const chainLabel = genesisMismatch ? 'Mismatch' : walletGenesis && walletNodeGenesis ? 'Match' : 'Unknown';
  const hgmBalance = walletStatus?.balances?.find((balance) => balance.assetId === 0) ?? null;
  const sendBlockedReason = !walletReady
    ? 'Open or init a wallet to send funds.'
    : walletSummary?.reachable === false
      ? 'Wallet connection is offline. Select a reachable node or fix the RPC endpoint.'
      : genesisMismatch
        ? 'Genesis mismatch between the wallet store and the selected node.'
        : null;
  const canSend = !walletBusy && !sendBlockedReason;

  const normalizedStorePath = storePath.trim();
  const pendingTransactions = walletStatus?.pending ?? [];
  const pendingByTxId = useMemo(() => {
    const map = new Map<string, typeof pendingTransactions[number]>();
    pendingTransactions.forEach((entry) => {
      const normalized = normalizeTxId(entry.txId);
      if (normalized) {
        map.set(normalized, entry);
      }
    });
    return map;
  }, [pendingTransactions]);

  const attemptsForStore = useMemo(
    () => sendAttempts.filter((attempt) => attempt.storePath === normalizedStorePath),
    [sendAttempts, normalizedStorePath]
  );

  const activityEntries = useMemo(() => {
    const consolidationEntries = pendingTransactions.filter(
      (entry) => entry.memo?.toLowerCase() === 'consolidation'
    );
    const pendingEntries: ActivityEntry[] = pendingTransactions.map((entry) => ({
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
      const pending = attempt.txId ? pendingByTxId.get(attempt.txId) : null;
      const status = pending ? (pending.status === 'confirmed' ? 'confirmed' : 'pending') : attempt.status;
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
        txId: normalizeTxId(pending?.txId) ?? attempt.txId,
        confirmations: pending?.confirmations,
        error: attempt.error,
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
  }, [attemptsForStore, pendingTransactions, pendingByTxId]);

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

  const navItems = [
    { path: '/overview', label: 'Overview', description: 'Command center' },
    { path: '/node', label: 'Node', description: 'Operate + observe' },
    { path: '/wallet', label: 'Wallet', description: 'Store + sync' },
    { path: '/send', label: 'Send', description: 'Shielded transfers' },
    { path: '/disclosure', label: 'Disclosure', description: 'Audit proofs' },
    { path: '/console', label: 'Console', description: 'Diagnostics' }
  ];

  const GenesisMismatchBanner = genesisMismatch ? (
    <div className="rounded-xl border border-amber/40 bg-amber/10 p-4 space-y-2">
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

  const StatusBar = (
    <div className="status-bar">
      <div className="status-grid">
        <div className="status-group">
          <p className="label">Node</p>
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`status-pill ${healthTone}`}>{healthLabel}</span>
            <span className="text-sm font-medium text-surface">{activeConnection?.label ?? 'No connection'}</span>
            <span className="badge">{activeConnection?.mode ?? 'n/a'}</span>
          </div>
          <p className="text-xs text-surfaceMuted/80 mono break-all mt-1" title={activeConnection?.wsUrl ?? ''}>
            {activeConnection?.wsUrl ?? 'N/A'}
          </p>
          <p className="text-xs text-surfaceMuted/70 mt-0.5">
            Height {formatNumber(activeSummary?.bestNumber)} · Peers {formatNumber(activeSummary?.peers)}
          </p>
        </div>
        <div className="status-group">
          <p className="label">Wallet</p>
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`status-pill ${walletTone}`}>{walletStateLabel}</span>
            <span className="text-sm font-medium text-surface">{walletConnection?.label ?? 'No connection'}</span>
            <span className={`status-pill ${walletConnectionTone}`}>{walletConnectionLabel}</span>
          </div>
          <p className="text-xs text-surfaceMuted/80 mt-1">
            Store:{' '}
            <span className="mono break-all" title={storePath}>
              {storePath}
            </span>
          </p>
          <p className="text-xs text-surfaceMuted/70 mt-0.5">
            Height {formatNumber(walletSummary?.bestNumber)} · Last synced {formatNumber(walletStatus?.lastSyncedHeight)}
          </p>
        </div>
        <div className="status-group">
          <p className="label">Chain</p>
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`status-pill ${chainTone}`}>{chainLabel}</span>
            <span className="text-xs text-surfaceMuted/80 mono">Genesis {formatHash(walletNodeGenesis ?? walletGenesis)}</span>
          </div>
          <p className="text-xs text-surfaceMuted/70 mt-1">
            Mining {activeSummary?.mining ? 'Active' : 'Idle'} · Supply {formatHash(activeSummary?.supplyDigest)}
          </p>
          <p className="text-xs text-surfaceMuted/70 mt-0.5">Hash rate {formatHashRate(activeSummary?.hashRate)}</p>
        </div>
      </div>
    </div>
  );

  const OverviewWorkspace = (
    <div className="mx-auto w-full max-w-6xl space-y-8">
      <header className="space-y-3">
        <p className="label">Overview</p>
        <h1 className="text-headline font-semibold tracking-tight">Command Center</h1>
        <p className="text-surfaceMuted max-w-2xl">
          Keep the node, wallet, and chain context visible while you decide your next move.
        </p>
      </header>

      {GenesisMismatchBanner}

      <div className="grid gap-6 xl:grid-cols-3">
        <section className="card space-y-4">
          <div>
            <p className="label">Node</p>
            <h2 className="text-title font-semibold">Status</h2>
            <p className="text-sm text-surfaceMuted/80 mt-1">
              Active: {activeConnection?.label ?? 'No connection'} ({activeConnection?.mode ?? 'n/a'})
            </p>
          </div>
          <div className="space-y-2 text-sm text-surfaceMuted">
            <div className="flex items-center gap-2">
              <span className={`status-pill ${healthTone}`}>{healthLabel}</span>
              <span className="text-surfaceMuted/70">Updated {updatedAtLabel}</span>
            </div>
            <p>Height {formatNumber(activeSummary?.bestNumber)} · Peers {formatNumber(activeSummary?.peers)}</p>
            <p>
              Mining {activeSummary?.mining ? 'Active' : 'Idle'} · Hash rate {formatHashRate(activeSummary?.hashRate)}
            </p>
            <p className="mono text-xs">Supply digest {formatHash(activeSummary?.supplyDigest)}</p>
          </div>
        </section>

        <section className="card space-y-4">
          <div>
            <p className="label">Wallet</p>
            <h2 className="text-title font-semibold">Readiness</h2>
            <p className="text-sm text-surfaceMuted/80 mono mt-1">{storePath}</p>
          </div>
          <div className="space-y-2 text-sm text-surfaceMuted">
            <div className="flex items-center gap-2">
              <span className={`status-pill ${walletTone}`}>{walletStateLabel}</span>
              <span className="text-surfaceMuted/70">{walletConnectionLabel}</span>
            </div>
            <p className="font-medium text-surface">
              Balance {hgmBalance ? formatHgm(hgmBalance.total) : 'N/A'}
            </p>
            <p>Last synced height {formatNumber(walletStatus?.lastSyncedHeight)}</p>
            {walletStatus?.notes?.needsConsolidation ? (
              <p className="text-amber">
                Wallet has {walletStatus.notes.spendableCount} notes (max {walletStatus.notes.maxInputs} inputs/tx). Some sends may require consolidation.
              </p>
            ) : null}
          </div>
        </section>

        <section className="card space-y-4">
          <div>
            <p className="label">Chain</p>
            <h2 className="text-title font-semibold">Context</h2>
          </div>
          <div className="space-y-2 text-sm text-surfaceMuted">
            <p>
              Node genesis <span className="mono text-xs">{formatHash(walletNodeGenesis)}</span>
            </p>
            <p>
              Wallet genesis <span className="mono text-xs">{formatHash(walletGenesis)}</span>
            </p>
            <p>
              Chain spec{' '}
              <span className="mono text-xs">
                {activeSummary?.config?.chainSpecName
                  ? `${activeSummary.config.chainSpecName} (${activeSummary.config.chainSpecId})`
                  : 'N/A'}
              </span>
            </p>
            <p>Mining {activeSummary?.mining ? 'Active' : 'Idle'}</p>
          </div>
        </section>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <section className="card space-y-4">
          <div>
            <p className="label">Actions</p>
            <h2 className="text-title font-semibold">Quick moves</h2>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <button
              className={nodeToggleClass}
              onClick={handleNodeToggle}
              disabled={nodeToggleDisabled}
            >
              {nodeToggleLabel}
            </button>
            <button className="secondary" onClick={() => handleWalletSync()} disabled={walletBusy || !walletReady}>
              Sync wallet
            </button>
            <Link className="action-link secondary" to="/send">
              Send transfer
            </Link>
            <Link className="action-link secondary" to="/node">
              Node operations
            </Link>
            <Link className="action-link secondary" to="/console">
              Open console
            </Link>
          </div>
          {sendBlockedReason ? <p className="text-xs text-amber">{sendBlockedReason}</p> : null}
        </section>

        <section className="card space-y-4">
          <div>
            <p className="label">Events</p>
            <h2 className="text-title font-semibold">Recent activity</h2>
          </div>
          {logHighlights.length ? (
            <div className="space-y-3">
              {logHighlights.slice(0, 5).map((entry) => (
                <div key={entry.id} className="flex items-start gap-3 text-sm">
                  <span className="mono text-surfaceMuted/60 text-xs">{entry.timestamp ?? '--:--:--'}</span>
                  <span className={`badge badge-highlight level-${entry.level}`}>{entry.highlight}</span>
                  <span className="text-surfaceMuted/80 text-xs truncate">{entry.message}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state py-8">
              <div className="empty-state-icon">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <p className="empty-state-description">No highlight events yet. Start a node to see activity.</p>
            </div>
          )}
        </section>
      </div>
    </div>
  );

  const NodeConnectionsSection = (
    <section className="card space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="label">Node</p>
          <h2 className="text-title font-semibold">Connections</h2>
        </div>
        <div className="flex gap-2">
          <button className="secondary text-sm" onClick={handleAddConnection}>Add connection</button>
          <button className="danger text-sm" onClick={handleRemoveConnection} disabled={connections.length <= 1}>Remove</button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <label className="space-y-2">
          <span className="label">Active connection</span>
          <select
            value={activeConnectionId}
            onChange={(event) => setActiveConnectionId(event.target.value)}
          >
            {connections.map((connection) => (
              <option key={connection.id} value={connection.id}>
                {connection.label} ({connection.mode})
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
            <option value="local">Local</option>
            <option value="remote">Remote</option>
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
            placeholder="http://127.0.0.1:9944"
          />
        </label>
        {activeConnection?.mode === 'remote' ? (
          <label className="flex items-center gap-2 text-sm text-surfaceMuted">
            <input
              type="checkbox"
              checked={Boolean(activeConnection.allowRemoteMining)}
              onChange={(event) => updateActiveConnection({ allowRemoteMining: event.target.checked })}
            />
            Allow remote mining control
          </label>
        ) : null}
      </div>
      {activeConnection?.mode === 'remote' ? (
        <p className="text-sm text-surfaceMuted">
          Remote RPC should be restricted and authenticated. Review runbooks/two_person_testnet.md before exposing RPC.
        </p>
      ) : null}

      {activeConnection?.mode === 'local' && (
        <div className="space-y-4">
          <button
            className="secondary"
            onClick={() => setShowAdvancedNode((prev) => !prev)}
          >
            {showAdvancedNode ? 'Hide advanced settings' : 'Show advanced settings'}
          </button>

          {showAdvancedNode && (
            <>
              <div className="grid gap-4 md:grid-cols-2">
                <label className="space-y-2">
                  <span className="label">Chain spec (path or name)</span>
                  <input
                    value={activeConnection.chainSpecPath ?? ''}
                    onChange={(event) => updateActiveConnection({ chainSpecPath: event.target.value })}
                    placeholder="config/dev-chainspec.json"
                  />
                </label>
                <label className="space-y-2">
                  <span className="label">Base path</span>
                  <input
                    value={activeConnection.basePath ?? ''}
                    onChange={(event) => updateActiveConnection({ basePath: event.target.value })}
                    placeholder="~/.hegemon-node"
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
                <label className="space-y-2">
                  <span className="label">Listen address</span>
                  <input
                    value={activeConnection.listenAddr ?? ''}
                    onChange={(event) => updateActiveConnection({ listenAddr: event.target.value })}
                    placeholder="/ip4/0.0.0.0/tcp/30333"
                  />
                </label>
                <label className="space-y-2 md:col-span-2">
                  <span className="label">Seeds (HEGEMON_SEEDS)</span>
                  <input
                    value={activeConnection.seeds ?? ''}
                    onChange={(event) => updateActiveConnection({ seeds: event.target.value })}
                    placeholder="1.2.3.4:30333,5.6.7.8:30333"
                  />
                </label>
                <label className="space-y-2 md:col-span-2">
                  <span className="label">Miner address</span>
                  <input
                    value={activeConnection.minerAddress ?? ''}
                    onChange={(event) => updateActiveConnection({ minerAddress: event.target.value })}
                    placeholder="shca1..."
                  />
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
                <div className="flex items-center gap-3">
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
                  <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                    <input
                      type="checkbox"
                      checked={Boolean(activeConnection.miningIntent)}
                      onChange={(event) => updateActiveConnection({ miningIntent: event.target.checked })}
                    />
                    Auto-start mining
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
              {activeConnection.dev && !activeConnection.chainSpecPath ? (
                <p className="text-sm text-surfaceMuted">
                  Multi-machine networks require a shared chainspec. See runbooks/two_person_testnet.md for details.
                </p>
              ) : null}
              {activeConnection.listenAddr ? (
                <p className="text-sm text-surfaceMuted">
                  Listen address overrides the P2P port setting.
                </p>
              ) : null}
              {activeConnection.rpcExternal || activeConnection.rpcMethods === 'unsafe' ? (
                <p className="text-sm text-guard">
                  External RPC and unsafe methods expose control surfaces. Restrict with firewalls and only use on trusted networks.
                </p>
              ) : null}
              {activeConnection.tmp ? (
                <p className="text-sm text-guard">
                  Temp storage deletes chain data on shutdown. Use a base path for persistence.
                </p>
              ) : null}
            </>
          )}
        </div>
      )}
    </section>
  );

  const NodeOperationsSection = (
    <section className="card space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="label">Node</p>
          <h2 className="text-title font-semibold">Operations</h2>
          <p className="text-sm text-surfaceMuted/80 mt-1">
            Active: {activeConnection?.label ?? 'No connection'} ({activeConnection?.mode ?? 'n/a'}) | Updated {updatedAtLabel}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`status-pill ${healthTone}`}>{healthLabel}</span>
          <span className="text-xs text-surfaceMuted/70">
            Height {formatNumber(activeSummary?.bestNumber)} · Peers {formatNumber(activeSummary?.peers)}
          </span>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        <button
          className={nodeToggleClass}
          onClick={handleNodeToggle}
          disabled={nodeToggleDisabled}
        >
          {nodeToggleLabel}
        </button>
      </div>
      <p className="text-sm text-surfaceMuted">{miningHint}</p>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
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
          <p className="text-xs text-surfaceMuted mono truncate" title={activeSummary?.bestBlock ?? ''}>
            {activeSummary?.bestBlock ?? 'N/A'}
          </p>
        </div>
        <div className="panel">
          <p className="label">Peers</p>
          <p className="text-lg font-medium">{formatNumber(activeSummary?.peers)}</p>
          <p className="text-xs text-surfaceMuted">
            Syncing: {activeSummary?.isSyncing === null || activeSummary?.isSyncing === undefined
              ? 'N/A'
              : activeSummary.isSyncing
                ? 'Yes'
                : 'No'}
          </p>
        </div>
        <div className="panel">
          <p className="label">Mining</p>
          <p className="text-lg font-medium">
            {activeSummary?.mining === null || activeSummary?.mining === undefined
              ? 'N/A'
              : activeSummary.mining
                ? 'Active'
                : 'Idle'}
          </p>
          <p className="text-xs text-surfaceMuted">Hash rate: {formatHashRate(activeSummary?.hashRate)}</p>
        </div>
        <div className="panel">
          <p className="label">Storage</p>
          <p className="text-lg font-medium">{formatBytes(activeSummary?.storage?.totalBytes)}</p>
          <p className="text-xs text-surfaceMuted">State: {formatBytes(activeSummary?.storage?.stateBytes)}</p>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <div className="panel">
          <p className="label">Mining details</p>
          <p className="text-sm text-surfaceMuted">Threads: {activeSummary?.miningThreads ?? 'N/A'}</p>
          <p className="text-sm text-surfaceMuted">Hash rate: {formatHashRate(activeSummary?.hashRate)}</p>
          <p className="text-sm text-surfaceMuted">Blocks found: {formatNumber(activeSummary?.blocksFound)}</p>
          <p className="text-sm text-surfaceMuted">Difficulty: {formatNumber(activeSummary?.difficulty)}</p>
          <p className="text-sm text-surfaceMuted">Block height: {formatNumber(activeSummary?.blockHeight)}</p>
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
              ? `${activeSummary.config.chainSpecName} (${activeSummary.config.chainSpecId})`
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
          return (
            <div key={connection.id} className="panel">
              <div className="flex items-center justify-between gap-3">
                <p className="label">{summary?.label ?? connection.label}</p>
                <span className={`status-pill ${isOnline ? 'ok' : 'error'}`}>
                  {isOnline ? 'Online' : 'Offline'}
                </span>
              </div>
              <p className="text-sm text-surfaceMuted">Mode: {connection.mode}</p>
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
          <p className="label">Console</p>
          <h2 className="text-title font-semibold">Node Console</h2>
          <p className="text-sm text-surfaceMuted/80 mt-1">
            Structured logs and milestone events for the active connection.
          </p>
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
                <div key={entry.id} className="flex items-start gap-3 text-sm px-2 py-1 rounded-lg hover:bg-surfaceMuted/5 transition-colors">
                  <span className="mono text-surfaceMuted/60 text-xs">{entry.timestamp ?? '--:--:--'}</span>
                  <span className={`badge badge-highlight level-${entry.level}`}>{entry.highlight}</span>
                  <span className="text-surfaceMuted/80 text-xs truncate">{entry.message}</span>
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
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
              </svg>
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
              <div key={entry.id} className="flex flex-wrap gap-3 text-sm log-row px-2 py-1.5 rounded-lg">
                <span className="mono text-surfaceMuted/50 text-xs">{entry.timestamp ?? '--:--:--'}</span>
                <span className={`badge level-${entry.level}`}>{entry.level}</span>
                <span className="badge badge-category">{logCategoryLabels[entry.category]}</span>
                <span className="mono flex-1 text-surfaceMuted/90 text-xs">{entry.message}</span>
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
    <section className="card space-y-6">
      <div>
        <p className="label">Wallet</p>
        <h2 className="text-title font-semibold">Shielded Store</h2>
      </div>

      <div className="grid gap-4">
        <label className="space-y-2">
          <span className="label">Store path</span>
          <input value={storePath} onChange={(event) => setStorePath(event.target.value)} />
        </label>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="panel space-y-3">
            <div>
              <p className="label">Create wallet</p>
              <p className="text-sm text-surfaceMuted">New store with a strong passphrase.</p>
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

          <div className="panel space-y-3">
            <div>
              <p className="label">Open wallet</p>
              <p className="text-sm text-surfaceMuted">Unlock an existing store to sync and send.</p>
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
            <span className="label">WebSocket URL</span>
            <input value={wsUrl} onChange={(event) => setWsUrl(event.target.value)} />
          </label>
        </div>
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
            <button className="secondary" onClick={handleWalletLock} disabled={walletBusy || !activePassphrase}>
              Lock wallet
            </button>
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
          <p className="text-xs text-surfaceMuted">
            Auto-lock stops walletd and clears the in-memory passphrase.
          </p>
        </div>
      </div>
      {!walletReady && (
        <p className="text-sm text-surfaceMuted">
          Open or init a wallet to enable sync and transfers.
        </p>
      )}

      {GenesisMismatchBanner}

      <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <p className="label">Primary address</p>
          <button
            className="secondary px-3 py-1 text-xs"
            onClick={handleCopyAddress}
            disabled={!walletStatus?.primaryAddress}
          >
            {addressCopied ? 'Copied' : 'Copy'}
          </button>
        </div>
        <p className="mono break-all">{walletStatus?.primaryAddress ?? 'N/A'}</p>
        <div>
          <p className="label">Balances</p>
          <div className="space-y-1">
            {walletStatus?.balances?.length ? (
              walletStatus.balances.map((balance) => (
                <div key={balance.assetId} className="flex justify-between text-sm">
                  <span>{balance.label}</span>
                  <span className="mono">
                    {balance.assetId === 0 ? formatHgm(balance.total) : balance.total.toLocaleString()}
                  </span>
                </div>
              ))
            ) : (
              <p className="text-sm text-surfaceMuted">No balances yet.</p>
            )}
          </div>
        </div>
        <div>
          <p className="label">Notes</p>
          {walletStatus?.notes ? (
            <p className="text-sm text-surfaceMuted">
              {walletStatus.notes.spendableCount} spendable notes, max {walletStatus.notes.maxInputs} inputs.
              {walletStatus.notes.needsConsolidation ? (
                <span className="text-amber"> Some sends may require consolidation.</span>
              ) : null}
            </p>
          ) : (
            <p className="text-sm text-surfaceMuted">No note summary.</p>
          )}
        </div>
        <div>
          <p className="label">Connected to</p>
          <p className="text-sm text-surfaceMuted">
            {walletConnection?.label ?? 'N/A'} (height {formatNumber(walletSummary?.bestNumber)})
          </p>
        </div>
      </div>

      {WalletErrorBanner}
    </section>
  );

  const WalletOutputSection = (
    <section className="card space-y-6">
      <div>
        <p className="label">Operations</p>
        <h2 className="text-title font-semibold">Wallet Output</h2>
      </div>
      <div className="grid gap-3">
        <div>
          <p className="label">Sync</p>
          <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4">
            {walletSyncOutput || 'N/A'}
          </pre>
        </div>
        <div>
          <p className="label">Send</p>
          <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4">
            {walletSendOutput || 'N/A'}
          </pre>
        </div>
      </div>
    </section>
  );

  const SendPreflightSection = (
    <section className="card space-y-4">
      <div>
        <p className="label">Send</p>
        <h2 className="text-title font-semibold">Preflight check</h2>
        <p className="text-sm text-surfaceMuted/80 mt-1">Confirm wallet + chain context before sending.</p>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <div className="panel space-y-2">
          <p className="label">Wallet</p>
          <div className="flex items-center gap-2">
            <span className={`status-pill ${walletTone}`}>{walletStateLabel}</span>
            <span className="text-sm text-surfaceMuted">{walletConnectionLabel}</span>
          </div>
          <p className="text-sm text-surfaceMuted">Last synced height {formatNumber(walletStatus?.lastSyncedHeight)}</p>
          <p className="text-sm text-surfaceMuted">Balance {hgmBalance ? formatHgm(hgmBalance.total) : 'N/A'}</p>
        </div>
        <div className="panel space-y-2">
          <p className="label">Chain</p>
          <div className="flex items-center gap-2">
            <span className={`status-pill ${chainTone}`}>{chainLabel}</span>
            <span className="text-xs text-surfaceMuted">Genesis {formatHash(walletNodeGenesis ?? walletGenesis)}</span>
          </div>
          <p className="text-sm text-surfaceMuted">RPC {walletConnection?.wsUrl ?? 'N/A'}</p>
          <p className="text-sm text-surfaceMuted">Height {formatNumber(walletSummary?.bestNumber)}</p>
        </div>
      </div>
      {walletStatus?.notes ? (
        <p className="text-sm text-surfaceMuted">
          Notes: {walletStatus.notes.spendableCount} spendable · max {walletStatus.notes.maxInputs} inputs/tx.
          {walletStatus.notes.needsConsolidation ? (
            <span className="text-amber"> Some sends may require consolidation.</span>
          ) : null}
        </p>
      ) : null}
      {sendBlockedReason ? (
        <p className="text-sm text-guard">{sendBlockedReason}</p>
      ) : (
        <p className="text-sm text-proof">Ready to send.</p>
      )}
    </section>
  );

  const SendSection = (
    <section className="card space-y-6">
      <div>
        <p className="label">Send</p>
        <h2 className="text-title font-semibold">Shielded Transfer</h2>
      </div>
      <div className="grid gap-4">
        <label className="space-y-2">
          <span className="label">Recipient address</span>
          <textarea
            rows={3}
            value={recipientAddress}
            onChange={(event) => setRecipientAddress(event.target.value)}
            placeholder="shca1..."
          />
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
              {contacts.map((contact) => (
                <option key={contact.id} value={contact.id}>
                  {contact.name} - {formatAddress(contact.address)}
                </option>
              ))}
            </select>
          </label>
        )}
        <div className="grid gap-4 md:grid-cols-2">
          <label className="space-y-2">
            <span className="label">Amount (HGM)</span>
            <input value={sendAmount} onChange={(event) => setSendAmount(event.target.value)} placeholder="0.50" />
          </label>
          <label className="space-y-2">
            <span className="label">Fee (HGM)</span>
            <input value={sendFee} onChange={(event) => setSendFee(event.target.value)} placeholder="0.01" />
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
          <p className="label">Transactions</p>
          <h2 className="text-title font-semibold">Activity</h2>
          <p className="text-sm text-surfaceMuted/80">
            Outgoing transfers show up immediately. Sync to confirm mined status.
          </p>
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
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6l4 2m6 4a10 10 0 11-20 0 10 10 0 0120 0z" />
            </svg>
          </div>
          <p className="empty-state-description">No outgoing transactions yet.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {activityEntries.map((entry) => (
            <div key={entry.id} className="rounded-xl border border-surfaceMuted/10 bg-midnight/40 p-4 space-y-3">
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
                        Sent {formatHgm(entry.amount)} to {formatAddress(entry.recipient || 'Unknown')}
                      </p>
                      <p className="text-xs text-surfaceMuted">
                        Fee {formatHgm(entry.fee)}
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
                      <p className="text-[10px] uppercase tracking-[0.2em] text-surfaceMuted/70">
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
          ))}
        </div>
      )}
    </section>
  );

  const ContactsSection = (
    <section className="card space-y-6">
      <div>
        <p className="label">Address book</p>
        <h2 className="text-title font-semibold">Contacts</h2>
      </div>
      <div className="grid gap-3">
        <label className="space-y-2">
          <span className="label">Name</span>
          <input value={newContactName} onChange={(event) => setNewContactName(event.target.value)} />
        </label>
        <label className="space-y-2">
          <span className="label">Address</span>
          <input value={newContactAddress} onChange={(event) => setNewContactAddress(event.target.value)} placeholder="shca1..." />
        </label>
        <label className="space-y-2">
          <span className="label">Notes</span>
          <input value={newContactNotes} onChange={(event) => setNewContactNotes(event.target.value)} placeholder="How verified, context, etc." />
        </label>
        <label className="flex items-center gap-2 text-sm text-surfaceMuted">
          <input type="checkbox" checked={newContactVerified} onChange={(event) => setNewContactVerified(event.target.checked)} />
          Verified out of band
        </label>
        <button className="secondary" onClick={handleAddContact} disabled={!contactsLoaded || contactsSaving}>
          {!contactsLoaded ? 'Loading…' : contactsSaving ? 'Saving…' : 'Add contact'}
        </button>
      </div>

      <div className="space-y-3">
        {contacts.length === 0 && (
          <div className="empty-state py-8">
            <div className="empty-state-icon">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
              </svg>
            </div>
            <p className="empty-state-description">No contacts saved yet. Add your first recipient above.</p>
          </div>
        )}
        {contacts.map((contact) => (
          <div key={contact.id} className="border border-surfaceMuted/10 rounded-xl p-4 bg-midnight/50 hover:bg-midnight/60 transition-colors">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-lg font-medium">{contact.name}</p>
                <p className="mono text-sm text-surfaceMuted">{formatAddress(contact.address)}</p>
              </div>
              <button className="danger" onClick={() => handleRemoveContact(contact.id)} disabled={contactsSaving}>
                Remove
              </button>
            </div>
            <p className="text-sm text-surfaceMuted">Verified: {contact.verified ? 'Yes' : 'No'}</p>
            {contact.notes && <p className="text-sm text-surfaceMuted">Notes: {contact.notes}</p>}
            {contact.lastUsed && <p className="text-sm text-surfaceMuted">Last used: {new Date(contact.lastUsed).toLocaleString()}</p>}
          </div>
        ))}
      </div>
      {ContactsErrorBanner}
    </section>
  );

  const DisclosureRecordsSection = (
    <section className="card flex flex-col gap-4 min-h-0 h-full">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="label">Disclosure</p>
          <h2 className="text-title font-semibold">Outgoing outputs</h2>
          <p className="text-sm text-surfaceMuted/80">
            Select a transaction output to generate a disclosure package.
          </p>
        </div>
        <button
          className="secondary px-3 py-1 text-xs"
          onClick={refreshDisclosureRecords}
          disabled={!walletReady || walletBusy || disclosureListBusy}
        >
          {disclosureListBusy ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>
      {disclosureGroups.length === 0 ? (
        <div className="empty-state py-8 flex-1 flex flex-col items-center justify-center">
          <div className="empty-state-icon">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6l4 2m6 4a10 10 0 11-20 0 10 10 0 0120 0z" />
            </svg>
          </div>
          <p className="empty-state-description">No outgoing disclosure records yet.</p>
        </div>
      ) : (
        <div className="space-y-3 flex-1 min-h-0 overflow-y-auto pr-1">
          {disclosureGroups.map((group) => (
            <div key={group.txId} className="rounded-xl border border-surfaceMuted/10 bg-midnight/40 p-4 space-y-3">
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
        <p className="label">Disclosure</p>
        <h2 className="text-title font-semibold">Generate proof</h2>
      </div>
      <div className="grid gap-4">
        {selectedDisclosure ? (
          <div className="rounded-xl border border-ionosphere/20 bg-ionosphere/10 p-3 text-sm">
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
      <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4 min-h-48 max-h-[40vh] overflow-y-auto">
        {walletDisclosureOutput || 'N/A'}
      </pre>
      {disclosureCopyError ? <p className="text-guard text-sm">{disclosureCopyError}</p> : null}
      {WalletErrorBanner}
    </section>
  );

  const DisclosureVerifySection = (
    <section className="card space-y-6">
      <div>
        <p className="label">Disclosure</p>
        <h2 className="text-title font-semibold">Verify proof</h2>
      </div>
      <label className="space-y-2">
        <span className="label">Disclosure JSON</span>
        <textarea rows={8} value={disclosureInput} onChange={(event) => setDisclosureInput(event.target.value)} />
      </label>
      <button className="secondary" onClick={handleDisclosureVerify} disabled={walletBusy || !walletReady}>
        Verify disclosure package
      </button>
      <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4">
        {walletDisclosureVerifyOutput || 'N/A'}
      </pre>
      {WalletErrorBanner}
    </section>
  );

  const NodeWorkspace = (
    <div className="mx-auto w-full max-w-6xl space-y-8">
      <header className="space-y-3">
        <p className="label">Node</p>
        <h1 className="text-headline font-semibold tracking-tight">Operate + Observe</h1>
        <p className="text-surfaceMuted max-w-2xl">Run local nodes, manage connections, and monitor telemetry.</p>
      </header>
      <div className="grid gap-6 xl:grid-cols-3">
        <div className="space-y-6 xl:col-span-1">
          {NodeConnectionsSection}
          {ConnectionHealthSection}
        </div>
        <div className="space-y-6 xl:col-span-2">
          {NodeOperationsSection}
        </div>
      </div>
    </div>
  );

  const WalletWorkspace = (
    <div className="mx-auto w-full max-w-6xl space-y-8">
      <header className="space-y-3">
        <p className="label">Wallet</p>
        <h1 className="text-headline font-semibold tracking-tight">Shielded Store</h1>
        <p className="text-surfaceMuted max-w-2xl">Initialize, unlock, and sync your shielded wallet store.</p>
      </header>
      {WalletStoreSection}
      {WalletOutputSection}
    </div>
  );

  const SendWorkspace = (
    <div className="mx-auto w-full max-w-6xl space-y-8">
      <header className="space-y-3">
        <p className="label">Send</p>
        <h1 className="text-headline font-semibold tracking-tight">Shielded Transfer</h1>
        <p className="text-surfaceMuted max-w-2xl">Prepare, validate, and send a shielded transaction.</p>
      </header>
      {SendPreflightSection}
      <div className="grid gap-6 xl:grid-cols-2">
        {SendSection}
        <div className="space-y-6">
          {TransactionActivitySection}
          {ContactsSection}
        </div>
      </div>
    </div>
  );

  const DisclosureWorkspace = (
    <div className="mx-auto w-full max-w-6xl space-y-8">
      <header className="space-y-3">
        <p className="label">Disclosure</p>
        <h1 className="text-headline font-semibold tracking-tight">Audit Packages</h1>
        <p className="text-surfaceMuted max-w-2xl">Generate and verify disclosure proofs without leaving the desktop app.</p>
      </header>
      <div className="grid gap-6 xl:grid-cols-2 items-stretch">
        {DisclosureRecordsSection}
        <div className="space-y-6">
          {DisclosureGenerateSection}
          {DisclosureVerifySection}
        </div>
      </div>
    </div>
  );

  const ConsoleWorkspace = (
    <div className="mx-auto w-full max-w-6xl space-y-8">
      <header className="space-y-3">
        <p className="label">Console</p>
        <h1 className="text-headline font-semibold tracking-tight">Diagnostics Timeline</h1>
        <p className="text-surfaceMuted max-w-2xl">Track events, search logs, and investigate anomalies.</p>
      </header>
      {NodeConsoleSection}
    </div>
  );

  return (
    <HashRouter>
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
              <h1 className="text-lg font-semibold tracking-tight">Hegemon</h1>
              <p className="text-[10px] text-surfaceMuted/70 uppercase tracking-[0.15em]">Core Console</p>
            </div>
          </div>
          <nav className="space-y-1 pt-4">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) => `nav-link${isActive ? ' nav-link-active' : ''}`}
              >
                <div className="pl-2">
                  <p className="text-sm font-medium text-surface">{item.label}</p>
                  <p className="text-[11px] text-surfaceMuted/70">{item.description}</p>
                </div>
              </NavLink>
            ))}
          </nav>
        </aside>
        <div className="app-body">
          {StatusBar}
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
