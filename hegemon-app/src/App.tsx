import { useEffect, useMemo, useState } from 'react';
import type {
  NodeSummary,
  WalletDisclosureCreateResult,
  WalletDisclosureVerifyResult,
  WalletSendResult,
  WalletStatus,
  WalletSyncResult
} from './types';

const defaultStorePath = '/tmp/hegemon-wallet';
const contactsKey = 'hegemon.contacts';

type Contact = {
  id: string;
  name: string;
  address: string;
  verified: boolean;
  notes?: string;
  lastUsed?: string;
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
    return '—';
  }
  return value.toLocaleString();
};

const formatHgm = (value: number) => `${(value / 100_000_000).toFixed(8)} HGM`;

const formatAddress = (address: string) => {
  if (address.length <= 16) {
    return address;
  }
  return `${address.slice(0, 8)}…${address.slice(-8)}`;
};

export default function App() {
  const [nodeSummary, setNodeSummary] = useState<NodeSummary | null>(null);
  const [nodeLogs, setNodeLogs] = useState<string[]>([]);
  const [nodeBusy, setNodeBusy] = useState(false);
  const [nodeError, setNodeError] = useState<string | null>(null);
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

  const [chainSpecPath, setChainSpecPath] = useState('');
  const [basePath, setBasePath] = useState('');
  const [devMode, setDevMode] = useState(true);
  const [tmpMode, setTmpMode] = useState(true);
  const [rpcPort, setRpcPort] = useState('9944');
  const [p2pPort, setP2pPort] = useState('30333');
  const [minerAddress, setMinerAddress] = useState('');
  const [mineThreads, setMineThreads] = useState('1');
  const [seeds, setSeeds] = useState('');

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

  const healthLabel = useMemo(() => {
    if (!nodeSummary) {
      return 'Unknown';
    }
    return nodeSummary.isSyncing ? 'Syncing' : 'Healthy';
  }, [nodeSummary]);

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

  const refreshNode = async () => {
    try {
      const summary = await window.hegemon.node.summary();
      setNodeSummary(summary);
      setNodeError(null);
    } catch (error) {
      setNodeError(error instanceof Error ? error.message : 'Failed to read node summary.');
    }
    try {
      const logs = await window.hegemon.node.logs();
      setNodeLogs(logs);
    } catch (error) {
      setNodeLogs((prev) => prev);
    }
  };

  useEffect(() => {
    refreshNode();
    const interval = window.setInterval(refreshNode, 5000);
    return () => window.clearInterval(interval);
  }, []);

  const handleNodeStart = async () => {
    setNodeBusy(true);
    setNodeError(null);
    try {
      await window.hegemon.node.start({
        chainSpecPath: chainSpecPath || undefined,
        basePath: basePath || undefined,
        dev: devMode,
        tmp: tmpMode,
        rpcPort: Number.parseInt(rpcPort, 10),
        p2pPort: Number.parseInt(p2pPort, 10),
        minerAddress: minerAddress || undefined,
        mineThreads: Number.parseInt(mineThreads, 10),
        seeds: seeds || undefined
      });
      await refreshNode();
    } catch (error) {
      setNodeError(error instanceof Error ? error.message : 'Failed to start node.');
    } finally {
      setNodeBusy(false);
    }
  };

  const handleNodeStop = async () => {
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
    if (!nodeSummary) {
      return;
    }
    setNodeBusy(true);
    try {
      await window.hegemon.node.setMining(!nodeSummary.mining, Number.parseInt(mineThreads, 10));
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
    await refreshWalletStatus();
    setWalletBusy(false);
  };

  const handleWalletSync = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const result: WalletSyncResult = await window.hegemon.wallet.sync(
        storePath,
        passphrase,
        wsUrl,
        forceRescan
      );
      setWalletSyncOutput(JSON.stringify(result, null, 2));
      await refreshWalletStatus();
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet sync failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleWalletSend = async () => {
    const value = toBaseUnits(sendAmount);
    const feeValue = toBaseUnits(sendFee);
    if (!value || !feeValue || !recipientAddress) {
      setWalletError('Recipient, amount, and fee are required.');
      return;
    }
    setWalletBusy(true);
    setWalletError(null);
    try {
      const result: WalletSendResult = await window.hegemon.wallet.send({
        storePath,
        passphrase,
        wsUrl,
        recipients: [
          {
            address: recipientAddress,
            value,
            asset_id: 0,
            memo: sendMemo || null
          }
        ],
        fee: feeValue,
        autoConsolidate
      });
      setWalletSendOutput(JSON.stringify(result, null, 2));
      await refreshWalletStatus();
      setContacts((prev) =>
        prev.map((contact) =>
          contact.address === recipientAddress
            ? { ...contact, lastUsed: new Date().toISOString() }
            : contact
        )
      );
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet send failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  const handleAddContact = () => {
    if (!newContactName.trim() || !newContactAddress.trim()) {
      setWalletError('Contact name and address are required.');
      return;
    }
    const nextContact: Contact = {
      id: crypto.randomUUID(),
      name: newContactName.trim(),
      address: newContactAddress.trim(),
      notes: newContactNotes.trim() || undefined,
      verified: newContactVerified
    };
    setContacts((prev) => [...prev, nextContact]);
    setNewContactName('');
    setNewContactAddress('');
    setNewContactNotes('');
    setNewContactVerified(false);
  };

  const handleRemoveContact = (id: string) => {
    setContacts((prev) => prev.filter((contact) => contact.id !== id));
  };

  const handleDisclosureCreate = async () => {
    setWalletBusy(true);
    setWalletError(null);
    try {
      const result: WalletDisclosureCreateResult = await window.hegemon.wallet.disclosureCreate(
        storePath,
        passphrase,
        wsUrl,
        disclosureTxId,
        Number.parseInt(disclosureOutput, 10)
      );
      setWalletDisclosureOutput(JSON.stringify(result, null, 2));
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Disclosure creation failed.');
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
      setWalletError(error instanceof Error ? error.message : 'Disclosure verification failed.');
    } finally {
      setWalletBusy(false);
    }
  };

  return (
    <div className="min-h-screen px-10 py-12">
      <header className="mb-10">
        <p className="label">Hegemon Core</p>
        <h1 className="text-4xl font-semibold text-surface">Node + Wallet Control</h1>
        <p className="mt-2 text-surfaceMuted max-w-2xl">
          Run a local Hegemon node, manage a shielded wallet, and send transactions without leaving the GUI.
        </p>
      </header>

      <div className="grid gap-8 xl:grid-cols-2">
        <section className="card space-y-6">
          <div>
            <p className="label">Node</p>
            <h2 className="text-2xl font-semibold">Lifecycle</h2>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="label">Chain spec path</span>
              <input value={chainSpecPath} onChange={(event) => setChainSpecPath(event.target.value)} placeholder="config/dev-chainspec.json" />
            </label>
            <label className="space-y-2">
              <span className="label">Base path</span>
              <input value={basePath} onChange={(event) => setBasePath(event.target.value)} placeholder="~/.hegemon/node" />
            </label>
            <label className="space-y-2">
              <span className="label">RPC port</span>
              <input value={rpcPort} onChange={(event) => setRpcPort(event.target.value)} />
            </label>
            <label className="space-y-2">
              <span className="label">P2P port</span>
              <input value={p2pPort} onChange={(event) => setP2pPort(event.target.value)} />
            </label>
            <label className="space-y-2 md:col-span-2">
              <span className="label">Miner address</span>
              <input value={minerAddress} onChange={(event) => setMinerAddress(event.target.value)} placeholder="shca1..." />
            </label>
            <label className="space-y-2">
              <span className="label">Mine threads</span>
              <input value={mineThreads} onChange={(event) => setMineThreads(event.target.value)} />
            </label>
            <label className="space-y-2">
              <span className="label">Seeds (HEGEMON_SEEDS)</span>
              <input value={seeds} onChange={(event) => setSeeds(event.target.value)} placeholder="1.2.3.4:30333,5.6.7.8:30333" />
            </label>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                <input type="checkbox" checked={devMode} onChange={(event) => setDevMode(event.target.checked)} />
                Dev mode
              </label>
              <label className="flex items-center gap-2 text-sm text-surfaceMuted">
                <input type="checkbox" checked={tmpMode} onChange={(event) => setTmpMode(event.target.checked)} />
                Temp storage
              </label>
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <button className="primary" onClick={handleNodeStart} disabled={nodeBusy}>
              Start node
            </button>
            <button className="secondary" onClick={handleNodeStop} disabled={nodeBusy}>
              Stop node
            </button>
            <button className="secondary" onClick={handleMiningToggle} disabled={nodeBusy || !nodeSummary}>
              {nodeSummary?.mining ? 'Stop mining' : 'Start mining'}
            </button>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
              <p className="label">Status</p>
              <p className="text-lg font-medium">{healthLabel}</p>
              <p className="text-sm text-surfaceMuted">Peers: {formatNumber(nodeSummary?.peers)}</p>
            </div>
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
              <p className="label">Best block</p>
              <p className="text-lg font-medium">{formatNumber(nodeSummary?.bestNumber)}</p>
              <p className="text-sm text-surfaceMuted mono truncate">{nodeSummary?.bestBlock ?? '—'}</p>
            </div>
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
              <p className="label">Mining</p>
              <p className="text-lg font-medium">{nodeSummary?.mining ? 'Active' : 'Idle'}</p>
              <p className="text-sm text-surfaceMuted">Threads: {nodeSummary?.miningThreads ?? '—'}</p>
            </div>
            <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4">
              <p className="label">RPC</p>
              <p className="text-lg font-medium">ws://127.0.0.1:{rpcPort}</p>
              <p className="text-sm text-surfaceMuted">HTTP at :{rpcPort}</p>
            </div>
          </div>

          {nodeError && <p className="text-guard">{nodeError}</p>}
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
            <button className="secondary" onClick={handleWalletSync} disabled={walletBusy}>
              Sync
            </button>
          </div>

          <div className="rounded-xl bg-midnight/40 border border-surfaceMuted/10 p-4 space-y-3">
            <div>
              <p className="label">Primary address</p>
              <p className="mono break-all">{walletStatus?.primaryAddress ?? '—'}</p>
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
          </div>

          {walletError && <p className="text-guard">{walletError}</p>}
        </section>
      </div>

      <div className="grid gap-8 mt-8 xl:grid-cols-2">
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
                      {contact.name} · {formatAddress(contact.address)}
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

      <div className="grid gap-8 mt-8 xl:grid-cols-2">
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
            {walletDisclosureOutput || '—'}
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
            {walletDisclosureVerifyOutput || '—'}
          </pre>
        </section>
      </div>

      <div className="grid gap-8 mt-8 xl:grid-cols-2">
        <section className="card space-y-6">
          <div>
            <p className="label">Telemetry</p>
            <h2 className="text-2xl font-semibold">Recent Logs</h2>
          </div>
          <div className="bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4 h-80 overflow-auto">
            <pre className="mono whitespace-pre-wrap">{nodeLogs.join('\n') || 'No logs yet.'}</pre>
          </div>
        </section>
        <section className="card space-y-6">
          <div>
            <p className="label">Operations</p>
            <h2 className="text-2xl font-semibold">Wallet Output</h2>
          </div>
          <div className="grid gap-3">
            <div>
              <p className="label">Sync</p>
              <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4">
                {walletSyncOutput || '—'}
              </pre>
            </div>
            <div>
              <p className="label">Send</p>
              <pre className="mono whitespace-pre-wrap bg-midnight/40 border border-surfaceMuted/10 rounded-xl p-4">
                {walletSendOutput || '—'}
              </pre>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
