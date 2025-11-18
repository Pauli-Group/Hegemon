import { FormEvent, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import QRCode from 'react-qr-code';
import { PageShell } from '../components/PageShell';
import { MetricTile } from '../components/MetricTile';
import { TransactionTable } from '../components/TransactionTable';
import { useNodeMetrics, useTransferLedger, useWalletNotes, useWalletStatus } from '../hooks/useNodeData';
import { useToasts } from '../components/ToastProvider';
import { ConnectionBadge } from '../components/ConnectionBadge';
import { DataStatusBanner } from '../components/DataStatusBanner';
import { formatCoinsFromAtomic } from '../utils/amounts';
import styles from './WalletPage.module.css';

const VIEW_KEY = import.meta.env.VITE_DEMO_VIEW_KEY || 'view_sapling_demo_1qv9k8';

interface TransferFormState {
  address: string;
  amount: number;
  memo: string;
  fee: number;
}

export function WalletPage() {
  const walletNotes = useWalletNotes();
  const nodeMetrics = useNodeMetrics();
  const walletStatus = useWalletStatus();
  const transfersQuery = useTransferLedger();
  const { pushToast } = useToasts();
  const [form, setForm] = useState<TransferFormState>({ address: '', amount: 0.5, memo: '', fee: 0.001 });

  const wallet = walletStatus.data?.data;
  const walletSource = walletStatus.data?.source ?? 'mock';
  const notes = walletNotes.data?.data;
  const metrics = nodeMetrics.data?.data;
  const notesSource = walletNotes.data?.source ?? 'mock';
  const metricsSource = nodeMetrics.data?.source ?? 'mock';

  const balanceMap = wallet?.balances ?? {};
  const nativeBalance = (() => {
    if (typeof balanceMap['0'] === 'number') return balanceMap['0'];
    if (typeof balanceMap[0] === 'number') return balanceMap[0];
    if (typeof balanceMap['1'] === 'number') return balanceMap['1'];
    if (typeof balanceMap[1] === 'number') return balanceMap[1];
    return 0;
  })();

  const primaryAddress = wallet?.primary_address ?? 'shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq';
  const viewKey = wallet?.incoming_viewing_key || VIEW_KEY;
  const coverage = notes ? `${notes.leaf_count.toLocaleString()} notes` : '—';
  const shieldedBalanceLabel =
    walletSource === 'live'
      ? `Spendable balance (native asset) at height ${wallet?.last_synced_height ?? 0} · 1 HGN = 100,000,000 atomic units`
      : 'Showing placeholder until live wallet data is available';
  const shieldedBalanceValue =
    walletSource === 'live' ? `${formatCoinsFromAtomic(nativeBalance)} HGN` : '—';

  const transfers = useMemo(() => {
    const items = transfersQuery.data?.data?.transfers ?? [];
    return [...items].sort((a, b) => (a.created_at > b.created_at ? -1 : 1));
  }, [transfersQuery.data?.data?.transfers]);

  const isSubmitting = transfersQuery.submitTransfer.isPending;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const response = await transfersQuery.submitTransfer.mutateAsync(form);
      const txId = response.transfer.tx_id || response.transfer.id;
      pushToast({
        kind: 'success',
        title: 'Transfer dispatched',
        description: `Transaction ${txId.slice(0, 12)}… submitted.`,
      });
      setForm((prev) => ({ ...prev, address: '', memo: '' }));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      pushToast({ kind: 'error', title: 'Transfer failed', description: message });
    }
  };

  const copyViewKey = async () => {
    try {
      await navigator.clipboard.writeText(viewKey);
      pushToast({ kind: 'success', title: 'View key copied' });
    } catch (error) {
      pushToast({ kind: 'error', title: 'Copy failed', description: (error as Error).message });
    }
  };

  return (
    <PageShell
      title="Wallet operations"
      intro="Monitor balances, notes, and confirmations while sending or receiving shielded transfers through the node RPC."
    >
      <div className={styles.sectionHeader}>
        <div>
          <p className={styles.kicker}>Wallet telemetry feed</p>
        </div>
        <div className={styles.badgeRow}>
          <ConnectionBadge
            source={walletStatus.data?.source ?? 'mock'}
            error={walletStatus.data?.error}
            label="Wallet status"
          />
          <ConnectionBadge
            source={walletNotes.data?.source ?? 'mock'}
            error={walletNotes.data?.error}
            label="Wallet notes feed"
          />
          <ConnectionBadge
            source={nodeMetrics.data?.source ?? 'mock'}
            error={nodeMetrics.data?.error}
            label="Node metrics feed"
          />
        </div>
      </div>

      <DataStatusBanner
        label="Wallet status"
        result={walletStatus.data}
        isPlaceholder={walletStatus.isPlaceholderData}
        cta={<Link to="/node">Configure a node</Link>}
      />
      <DataStatusBanner
        label="Node metrics feed"
        result={nodeMetrics.data}
        isPlaceholder={nodeMetrics.isPlaceholderData}
        cta={<Link to="/node">Configure a node</Link>}
      />

      <div className={styles.metricsGrid}>
        <MetricTile label="Shielded balance" value={shieldedBalanceValue} helper={shieldedBalanceLabel} />
        <MetricTile label="Notes committed" value={coverage} helper={`Tree depth ${notes?.depth ?? '—'}`} />
        <MetricTile
          label="Mempool depth"
          value={`${metrics?.mempool_depth ?? 0}`}
          helper={
            metricsSource === 'live'
              ? `Difficulty ${metrics?.difficulty_bits ?? 0}`
              : 'Node metrics unavailable – using placeholders'
          }
        />
      </div>

      <section className={styles.panels}>
        <article className={styles.formCard}>
          <header>
            <h3>Send shielded funds</h3>
            <p>Address, memo, and fee inputs forward to the node proxy with immediate logging in history.</p>
          </header>
          <form onSubmit={handleSubmit} className={styles.formFields}>
            <label>
              <span>Recipient address</span>
              <input
                required
                value={form.address}
                onChange={(event) => setForm((prev) => ({ ...prev, address: event.target.value }))}
                placeholder="shield1..."
              />
            </label>
            <div className={styles.inlineFields}>
              <label>
                <span>Amount (HGN)</span>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  value={form.amount}
                  onChange={(event) => setForm((prev) => ({ ...prev, amount: Number(event.target.value) }))}
                />
              </label>
              <label>
                <span>Fee (HGN)</span>
                <input
                  type="number"
                  step="0.0001"
                  min="0"
                  value={form.fee}
                  onChange={(event) => setForm((prev) => ({ ...prev, fee: Number(event.target.value) }))}
                />
              </label>
            </div>
            <label>
              <span>Memo</span>
              <textarea
                rows={2}
                value={form.memo}
                onChange={(event) => setForm((prev) => ({ ...prev, memo: event.target.value }))}
              />
            </label>
            <button type="submit" disabled={isSubmitting} className={styles.primaryButton}>
              {isSubmitting ? 'Submitting…' : 'Send transfer'}
            </button>
          </form>
        </article>
        <article className={styles.receiveCard}>
          <header>
          <h3>Accept incoming payments</h3>
          <p>Share the QR or export your view key to monitor confirmations without revealing spend authority.</p>
        </header>
        <div className={styles.qrRow}>
          <QRCode value={viewKey} size={132} bgColor="transparent" fgColor="var(--color-surface-mid)" />
          <div>
            <p className={styles.kicker}>Primary address</p>
            <p className={styles.viewKey}>{primaryAddress}</p>
            <p className={styles.kicker}>Incoming view key</p>
            <p className={styles.viewKey}>{viewKey}</p>
            <div className={styles.receiveActions}>
              <button type="button" onClick={copyViewKey} className={styles.ghostButton}>
                Copy view key
              </button>
              <a
                className={styles.linkButton}
                download="view-key.txt"
                href={`data:text/plain,${encodeURIComponent(viewKey)}`}
              >
                Export
              </a>
            </div>
          </div>
          </div>
        </article>
      </section>

      <section>
        <header className={`${styles.historyHeader} ${styles.sectionHeader}`}>
          <div>
            <p className={styles.kicker}>Transaction history</p>
            <h3>Transfers & confirmations</h3>
          </div>
          <ConnectionBadge
            source={transfersQuery.data?.source ?? 'mock'}
            error={transfersQuery.data?.error}
            label="Transfer ledger"
          />
        </header>
        <DataStatusBanner
          label="Transfer ledger"
          result={transfersQuery.data}
          isPlaceholder={transfersQuery.isPlaceholderData}
        />
        <TransactionTable records={transfers} />
      </section>
    </PageShell>
  );
}
