import { useEffect, useMemo, useState } from 'react';
import type {
  NodeConnection,
  NodeSummary,
  WalletDisclosureCreateResult,
  WalletDisclosureVerifyResult,
  WalletStatus
} from './types';

const defaultStorePath = '~/hegemon-wallet';
const contactsKey = 'hegemon.contacts';
const connectionsKey = 'hegemon.nodeConnections';
const activeConnectionKey = 'hegemon.activeConnection';
const walletConnectionKey = 'hegemon.walletConnection';

const makeId = () => {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return `conn-${Math.random().toString(36).slice(2, 10)}`;
};

type Contact = {
  id: string;
  name: string;
  address: string;
  verified: boolean;
  notes?: string;
  lastUsed?: string;
};

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
  tmp: false,
  basePath: '~/.hegemon-node',
  rpcPort: 9944,
  p2pPort: 30333,
  mineThreads: 1,
  miningIntent: false,
  rpcMethods: 'safe'
});

export default function App() {
  const [connections, setConnections] = useState<NodeConnection[]>([]);
  const [activeConnectionId, setActiveConnectionId] = useState('');
  const [walletConnectionId, setWalletConnectionId] = useState('');
  const [nodeSummaries, setNodeSummaries] = useState<Record<string, NodeSummary>>({});
  const [nodeLogs, setNodeLogs] = useState<string[]>([]);
  const [nodeBusy, setNodeBusy] = useState(false);
  const [nodeError, setNodeError] = useState<string | null>(null);
  const [showAdvancedNode, setShowAdvancedNode] = useState(false);
  const [logFilterInfo, setLogFilterInfo] = useState(true);
  const [logFilterWarn, setLogFilterWarn] = useState(true);
  const [logFilterError, setLogFilterError] = useState(true);
  const [logFilterDebug, setLogFilterDebug] = useState(false);
  const [logSearch, setLogSearch] = useState('');

  const [walletStatus, setWalletStatus] = useState<WalletStatus | null>(null);
  const [walletSyncOutput, setWalletSyncOutput] = useState<string>('');
  const [walletSendOutput, setWalletSendOutput] = useState<string>('');
  const [walletDisclosureOutput, setWalletDisclosureOutput] = useState<string>('');
  const [walletDisclosureVerifyOutput, setWalletDisclosureVerifyOutput] = useState<string>('');
  const [walletBusy, setWalletBusy] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);

  const [storePath, setStorePath] = useState(defaultStorePath);
  const [passphrase, setPassphrase] = useState('test-pass');
  const [wsUrl, setWsUrl] = useState('ws://127.0.0.1:9944');
  const [forceRescan, setForceRescan] = useState(false);

  const [recipientAddress, setRecipientAddress] = useState('');
  const [sendAmount, setSendAmount] = useState('');
  const [sendMemo, setSendMemo] = useState('');
  const [sendFee, setSendFee] = useState('0.01');
  const [autoConsolidate, setAutoConsolidate] = useState(true);

  const [contacts, setContacts] = useState<Contact[]>([]);
  const [newContactName, setNewContactName] = useState('');
  const [newContactAddress, setNewContactAddress] = useState('');
  const [newContactNotes, setNewContactNotes] = useState('');
  const [newContactVerified, setNewContactVerified] = useState(false);

  const [disclosureTxId, setDisclosureTxId] = useState('');
  const [disclosureOutput, setDisclosureOutput] = useState('0');
  const [disclosureInput, setDisclosureInput] = useState('');

  useEffect(() => {
    const storedConnections = window.localStorage.getItem(connectionsKey);
    if (storedConnections) {
      try {
        const parsed = JSON.parse(storedConnections) as NodeConnection[];
        if (parsed.length) {
          setConnections(parsed);
          const storedActive = window.localStorage.getItem(activeConnectionKey);
          const storedWallet = window.localStorage.getItem(walletConnectionKey);
          setActiveConnectionId(storedActive && parsed.find((conn) => conn.id === storedActive) ? storedActive : parsed[0].id);
          setWalletConnectionId(storedWallet && parsed.find((conn) => conn.id === storedWallet) ? storedWallet : parsed[0].id);
          return;
        }
      } catch (error) {
        setConnections([buildDefaultConnection()]);
        return;
      }
    }
    const fallback = buildDefaultConnection();
    setConnections([fallback]);
    setActiveConnectionId(fallback.id);
    setWalletConnectionId(fallback.id);
  }, []);

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
    const stored = window.localStorage.getItem(contactsKey);
    if (stored) {
      try {
        setContacts(JSON.parse(stored));
      } catch (error) {
        setContacts([]);
      }
    }
  }, []);

  useEffect(() => {
    window.localStorage.setItem(contactsKey, JSON.stringify(contacts));
  }, [contacts]);

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

  const logEntries = useMemo(() => nodeLogs.map((line, index) => parseLogLine(line, index)), [nodeLogs]);

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
    setNodeBusy(true);
    try {
      await window.hegemon.node.stop();
      await refreshNode();
    } catch (error) {
      setNodeError(error instanceof Error ? error.message : 'Failed to stop node.');
    } finally {
      setNodeBusy(false);
    }
  };

  const handleMiningToggle = async () => {
    if (!activeConnection) {
      return;
    }
    if (activeConnection.mode === 'remote' && !activeConnection.allowRemoteMining) {
      setNodeError('Remote mining control is disabled for this connection.');
      return;
    }
    if (!activeSummary) {
      return;
    }
    if (!activeSummary.mining && activeConnection.mode === 'local' && !activeConnection.minerAddress) {
      setNodeError('Set a miner address before enabling mining.');
      return;
    }
    if (activeConnection.mode === 'remote') {
      const confirmed = window.confirm('Toggle mining on the remote node?');
      if (!confirmed) {
        return;
      }
    }
    setNodeBusy(true);
    try {
      const httpUrl = deriveHttpUrl(activeConnection.wsUrl, activeConnection.httpUrl);
      await window.hegemon.node.setMining({
        enabled: !activeSummary.mining,
        threads: activeConnection.mineThreads,
        httpUrl
      });
      await refreshNode();
    } catch (error) {
      setNodeError(error instanceof Error ? error.message : 'Failed to toggle mining.');
    } finally {
      setNodeBusy(false);
    }
  };

  const refreshWalletStatus = async () => {
    try {
      const status = await window.hegemon.wallet.status(storePath, passphrase, true);
      setWalletStatus(status);
      setWalletError(null);
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet status failed.');
    }
  };

  const handleWalletInit = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const status = await window.hegemon.wallet.init(storePath, passphrase);
      setWalletStatus(status);
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
      const status = await window.hegemon.wallet.restore(storePath, passphrase);
      setWalletStatus(status);
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet open failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleWalletStatus = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const status = await window.hegemon.wallet.status(storePath, passphrase, true);
      setWalletStatus(status);
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet status failed.');
    } finally {
      setWalletBusy(false);
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
      const result = await window.hegemon.wallet.sync(storePath, passphrase, wsUrl, rescan);
      setWalletSyncOutput(JSON.stringify(result, null, 2));
      await refreshWalletStatus();
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet sync failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleWalletSend = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const amount = toBaseUnits(sendAmount);
      const fee = toBaseUnits(sendFee);
      if (!amount || !fee) {
        throw new Error('Amount and fee must be valid numbers.');
      }
      const request = {
        storePath,
        passphrase,
        wsUrl,
        recipients: [
          {
            address: recipientAddress,
            value: amount,
            asset_id: 0,
            memo: sendMemo || null
          }
        ],
        fee,
        autoConsolidate
      };
      const result = await window.hegemon.wallet.send(request);
      setWalletSendOutput(JSON.stringify(result, null, 2));
      setRecipientAddress('');
      setSendAmount('');
      setSendMemo('');
      await refreshWalletStatus();
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet send failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleAddContact = () => {
    if (!newContactName || !newContactAddress) {
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
    setContacts((prev) => [newEntry, ...prev]);
    setNewContactName('');
    setNewContactAddress('');
    setNewContactNotes('');
    setNewContactVerified(false);
  };

  const handleRemoveContact = (id: string) => {
    setContacts((prev) => prev.filter((entry) => entry.id !== id));
  };

  const handleDisclosureCreate = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const outputIndex = Number.parseInt(disclosureOutput, 10);
      if (Number.isNaN(outputIndex)) {
        throw new Error('Output index must be a number.');
      }
      const result: WalletDisclosureCreateResult = await window.hegemon.wallet.disclosureCreate(
        storePath,
        passphrase,
        wsUrl,
        disclosureTxId,
        outputIndex
      );
      setWalletDisclosureOutput(JSON.stringify(result, null, 2));
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
      const parsed = JSON.parse(disclosureInput);
      const result: WalletDisclosureVerifyResult = await window.hegemon.wallet.disclosureVerify(
        storePath,
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

  const walletSummary = walletConnection ? nodeSummaries[walletConnection.id] : null;
  const canControlMining = activeConnection?.mode === 'local' || activeConnection?.allowRemoteMining;
  const walletGenesis = walletStatus?.genesisHash ?? null;
  const walletNodeGenesis = walletSummary?.genesisHash ?? null;
  const genesisMismatch = Boolean(walletGenesis && walletNodeGenesis && walletGenesis !== walletNodeGenesis);

  return (
    <div className="min-h-screen bg-midnight text-surface px-6 py-8">
      <header className="max-w-6xl mx-auto space-y-2">
        <p className="label">Hegemon Desktop</p>
        <h1 className="text-3xl font-semibold">Node + Wallet Console</h1>
        <p className="text-surfaceMuted">
          Operate local or remote nodes, manage your shielded wallet, and keep mining and sync operations in one place.
        </p>
      </header>

      <div className="max-w-6xl mx-auto grid gap-8 mt-10">
        <section className="card space-y-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="label">Node</p>
              <h2 className="text-2xl font-semibold">Connections</h2>
            </div>
            <div className="flex gap-2">
              <button className="secondary" onClick={handleAddConnection}>Add connection</button>
              <button className="danger" onClick={handleRemoveConnection} disabled={connections.length <= 1}>Remove</button>
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
                      <span className="label">Chain spec path</span>
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
                    </div>
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

        <section className="card space-y-6">
          <div>
            <p className="label">Node</p>
            <h2 className="text-2xl font-semibold">Operations</h2>
          </div>

          <div className="flex flex-wrap gap-3">
            <button className="primary" onClick={handleNodeStart} disabled={nodeBusy || activeConnection?.mode !== 'local'}>
              Start node
            </button>
            <button className="secondary" onClick={handleNodeStop} disabled={nodeBusy || activeConnection?.mode !== 'local'}>
              Stop node
            </button>
            <button
              className="secondary"
              onClick={handleMiningToggle}
              disabled={nodeBusy || !activeSummary || !activeSummary.reachable || !canControlMining}
            >
              {activeSummary?.mining ? 'Stop mining' : 'Start mining'}
            </button>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
              <p className="label">Status</p>
              <p className="text-lg font-medium">{healthLabel}</p>
              <p className="text-sm text-surfaceMuted">Peers: {formatNumber(activeSummary?.peers)}</p>
              <p className="text-sm text-surfaceMuted">
                Syncing: {activeSummary?.isSyncing === null || activeSummary?.isSyncing === undefined
                  ? 'N/A'
                  : activeSummary.isSyncing
                    ? 'Yes'
                    : 'No'}
              </p>
            </div>
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
              <p className="label">Best block</p>
              <p className="text-lg font-medium">{formatNumber(activeSummary?.bestNumber)}</p>
              <p className="text-sm text-surfaceMuted mono truncate">{activeSummary?.bestBlock ?? 'N/A'}</p>
            </div>
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
              <p className="label">Mining</p>
              <p className="text-lg font-medium">
                {activeSummary?.mining === null || activeSummary?.mining === undefined
                  ? 'N/A'
                  : activeSummary.mining
                    ? 'Active'
                    : 'Idle'}
              </p>
              <p className="text-sm text-surfaceMuted">Threads: {activeSummary?.miningThreads ?? 'N/A'}</p>
              <p className="text-sm text-surfaceMuted">Hash rate: {formatHashRate(activeSummary?.hashRate)}</p>
              <p className="text-sm text-surfaceMuted">Blocks found: {formatNumber(activeSummary?.blocksFound)}</p>
              <p className="text-sm text-surfaceMuted">Difficulty: {formatNumber(activeSummary?.difficulty)}</p>
            </div>
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
              <p className="label">Storage</p>
              <p className="text-lg font-medium">{formatBytes(activeSummary?.storage?.totalBytes)}</p>
              <p className="text-sm text-surfaceMuted">Blocks: {formatBytes(activeSummary?.storage?.blocksBytes)}</p>
              <p className="text-sm text-surfaceMuted">State: {formatBytes(activeSummary?.storage?.stateBytes)}</p>
              <p className="text-sm text-surfaceMuted">Txs: {formatBytes(activeSummary?.storage?.transactionsBytes)}</p>
              <p className="text-sm text-surfaceMuted">Nullifiers: {formatBytes(activeSummary?.storage?.nullifiersBytes)}</p>
            </div>
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
              <p className="label">Consensus</p>
              <p className="text-sm text-surfaceMuted">
                Genesis: <span className="mono" title={activeSummary?.genesisHash ?? ''}>{formatHash(activeSummary?.genesisHash)}</span>
              </p>
              <p className="text-sm text-surfaceMuted">
                Supply digest: <span className="mono" title={activeSummary?.supplyDigest ?? ''}>{formatHash(activeSummary?.supplyDigest)}</span>
              </p>
            </div>
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
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
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4 space-y-1">
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
                PQ: {activeSummary?.config?.requirePq ? 'Required' : activeSummary?.config ? 'Optional' : 'N/A'}{' '}
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

        <section className="card space-y-6">
          <div>
            <p className="label">Node</p>
            <h2 className="text-2xl font-semibold">Connection health</h2>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            {connections.map((connection) => {
              const summary = nodeSummaries[connection.id];
              return (
                <div key={connection.id} className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
                  <p className="label">{summary?.label ?? connection.label}</p>
                  <p className="text-lg font-medium">{summary?.reachable ? 'Online' : 'Offline'}</p>
                  <p className="text-sm text-surfaceMuted">Height: {formatNumber(summary?.bestNumber)}</p>
                  <p className="text-sm text-surfaceMuted">Peers: {formatNumber(summary?.peers)}</p>
                </div>
              );
            })}
          </div>
        </section>

        <section className="card space-y-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="label">Console</p>
              <h2 className="text-2xl font-semibold">Node Console</h2>
            </div>
            <div className="flex flex-wrap gap-2 text-sm text-surfaceMuted">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={logFilterInfo} onChange={(event) => setLogFilterInfo(event.target.checked)} />
                Info
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={logFilterWarn} onChange={(event) => setLogFilterWarn(event.target.checked)} />
                Warn
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={logFilterError} onChange={(event) => setLogFilterError(event.target.checked)} />
                Error
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={logFilterDebug} onChange={(event) => setLogFilterDebug(event.target.checked)} />
                Debug
              </label>
            </div>
          </div>

          <label className="space-y-2">
            <span className="label">Search logs</span>
            <input value={logSearch} onChange={(event) => setLogSearch(event.target.value)} placeholder="Filter by phrase" />
          </label>

          <div className="bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4 h-80 overflow-auto">
            {activeConnection?.mode !== 'local' && (
              <p className="text-sm text-surfaceMuted">Logs are only available for local nodes started from this app.</p>
            )}
            {activeConnection?.mode === 'local' && (
              <div className="space-y-2">
                {filteredLogEntries.length === 0 && <p className="text-sm text-surfaceMuted">No matching logs.</p>}
                {filteredLogEntries.map((entry) => (
                  <div key={entry.id} className="flex gap-3 text-sm">
                    <span className="mono text-surfaceMuted">{entry.timestamp ?? '--:--:--'}</span>
                    <span className="text-xs uppercase tracking-widest text-surfaceMuted">{entry.level}</span>
                    <span className="text-xs uppercase tracking-widest text-surfaceMuted">{entry.category}</span>
                    <span className="mono flex-1">{entry.message}</span>
                    {entry.highlight ? (
                      <span className="text-xs uppercase tracking-widest text-amber">{entry.highlight}</span>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        <section className="card space-y-6">
          <div>
            <p className="label">Wallet</p>
            <h2 className="text-2xl font-semibold">Shielded Store</h2>
          </div>

          <div className="grid gap-4">
            <label className="space-y-2">
              <span className="label">Store path</span>
              <input value={storePath} onChange={(event) => setStorePath(event.target.value)} />
            </label>
            <label className="space-y-2">
              <span className="label">Passphrase</span>
              <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} />
            </label>
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
            <label className="flex items-center gap-2 text-sm text-surfaceMuted">
              <input type="checkbox" checked={forceRescan} onChange={(event) => setForceRescan(event.target.checked)} />
              Force rescan on next sync
            </label>
          </div>

          <div className="flex flex-wrap gap-3">
            <button className="primary" onClick={handleWalletInit} disabled={walletBusy}>
              Init wallet
            </button>
            <button className="secondary" onClick={handleWalletRestore} disabled={walletBusy}>
              Open wallet
            </button>
            <button className="secondary" onClick={handleWalletStatus} disabled={walletBusy}>
              Status
            </button>
            <button className="secondary" onClick={() => handleWalletSync()} disabled={walletBusy}>
              Sync
            </button>
          </div>

          {genesisMismatch ? (
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
          ) : null}

          <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4 space-y-3">
            <div>
              <p className="label">Primary address</p>
              <p className="mono break-all">{walletStatus?.primaryAddress ?? 'N/A'}</p>
            </div>
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
                  {walletStatus.notes.needsConsolidation && walletStatus.notes.plan ? (
                    <span className="text-amber"> Consolidation needed (~{walletStatus.notes.plan.txsNeeded} txs).</span>
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

          {walletError && <p className="text-guard">{walletError}</p>}
        </section>
      </div>

      <div className="max-w-6xl mx-auto grid gap-8 mt-8 xl:grid-cols-2">
        <section className="card space-y-6">
          <div>
            <p className="label">Send</p>
            <h2 className="text-2xl font-semibold">Shielded Transfer</h2>
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
              Auto-consolidate notes if needed
            </label>
          </div>
          <button className="primary" onClick={handleWalletSend} disabled={walletBusy}>
            Send shielded transaction
          </button>
        </section>

        <section className="card space-y-6">
          <div>
            <p className="label">Address book</p>
            <h2 className="text-2xl font-semibold">Contacts</h2>
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
            <button className="secondary" onClick={handleAddContact}>Add contact</button>
          </div>

          <div className="space-y-3">
            {contacts.length === 0 && <p className="text-sm text-surfaceMuted">No contacts saved yet.</p>}
            {contacts.map((contact) => (
              <div key={contact.id} className="border border-surfaceMuted/10 rounded-xl p-4 bg-midnight/40">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-lg font-medium">{contact.name}</p>
                    <p className="mono text-sm text-surfaceMuted">{formatAddress(contact.address)}</p>
                  </div>
                  <button className="danger" onClick={() => handleRemoveContact(contact.id)}>Remove</button>
                </div>
                <p className="text-sm text-surfaceMuted">Verified: {contact.verified ? 'Yes' : 'No'}</p>
                {contact.notes && <p className="text-sm text-surfaceMuted">Notes: {contact.notes}</p>}
                {contact.lastUsed && <p className="text-sm text-surfaceMuted">Last used: {new Date(contact.lastUsed).toLocaleString()}</p>}
              </div>
            ))}
          </div>
        </section>
      </div>

      <div className="max-w-6xl mx-auto grid gap-8 mt-8 xl:grid-cols-2">
        <section className="card space-y-6">
          <div>
            <p className="label">Disclosure</p>
            <h2 className="text-2xl font-semibold">Generate proof</h2>
          </div>
          <div className="grid gap-4">
            <label className="space-y-2">
              <span className="label">Transaction hash</span>
              <input value={disclosureTxId} onChange={(event) => setDisclosureTxId(event.target.value)} placeholder="0x..." />
            </label>
            <label className="space-y-2">
              <span className="label">Output index</span>
              <input value={disclosureOutput} onChange={(event) => setDisclosureOutput(event.target.value)} />
            </label>
          </div>
          <button className="secondary" onClick={handleDisclosureCreate} disabled={walletBusy}>
            Create disclosure package
          </button>
          <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4">
            {walletDisclosureOutput || 'N/A'}
          </pre>
        </section>

        <section className="card space-y-6">
          <div>
            <p className="label">Disclosure</p>
            <h2 className="text-2xl font-semibold">Verify proof</h2>
          </div>
          <label className="space-y-2">
            <span className="label">Disclosure JSON</span>
            <textarea rows={8} value={disclosureInput} onChange={(event) => setDisclosureInput(event.target.value)} />
          </label>
          <button className="secondary" onClick={handleDisclosureVerify} disabled={walletBusy}>
            Verify disclosure package
          </button>
          <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4">
            {walletDisclosureVerifyOutput || 'N/A'}
          </pre>
        </section>
      </div>

      <div className="max-w-6xl mx-auto grid gap-8 mt-8 xl:grid-cols-2">
        <section className="card space-y-6">
          <div>
            <p className="label">Operations</p>
            <h2 className="text-2xl font-semibold">Wallet Output</h2>
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
      </div>
    </div>
  );
}
