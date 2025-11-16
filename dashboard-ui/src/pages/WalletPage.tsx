import { FormEvent, useMemo, useState } from 'react';
import QRCode from 'react-qr-code';
import { PageShell } from '../components/PageShell';
import { MetricTile } from '../components/MetricTile';
import { TransactionTable } from '../components/TransactionTable';
import { useNodeMetrics, useNodeEventStream, useTransferLedger, useWalletNotes } from '../hooks/useNodeData';
import { useToasts } from '../components/ToastProvider';
import type { TransferRecord } from '../types/node';
import styles from './WalletPage.module.css';

const VIEW_KEY = import.meta.env.VITE_DEMO_VIEW_KEY || 'view_sapling_demo_1qv9k8';

interface TransferFormState {
  address: string;
  amount: number;
  memo: string;
  fee: number;
}

export function WalletPage() {
  const { data: notes } = useWalletNotes();
  const { data: metrics } = useNodeMetrics();
  const { events } = useNodeEventStream(24);
  const transfersQuery = useTransferLedger();
  const { pushToast } = useToasts();
  const [form, setForm] = useState<TransferFormState>({ address: '', amount: 0.5, memo: '', fee: 0.001 });

  const estimatedBalance = notes ? notes.leaf_count * 0.0005 : 0;
  const coverage = notes ? `${notes.leaf_count.toLocaleString()} notes` : '—';

  const eventTransfers = useMemo<TransferRecord[]>(() => {
    return events
      .filter((event) => event.type === 'transaction')
      .map((event) => ({
        id: event.tx_id,
        direction: 'incoming',
        address: event.tx_id.slice(0, 16).padEnd(16, '0'),
        memo: 'Network inbound',
        amount: 0,
        fee: 0,
        status: 'pending',
        confirmations: 0,
        created_at: event.timestamp || new Date().toISOString(),
      }));
  }, [events]);

  const transfers = useMemo(() => {
    const seen = new Set<string>();
    const merged: TransferRecord[] = [];
    for (const record of eventTransfers) {
      if (!seen.has(record.id)) {
        merged.push(record);
        seen.add(record.id);
      }
    }
    const persisted = transfersQuery.data?.transfers ?? [];
    for (const record of persisted) {
      if (!seen.has(record.id)) {
        merged.push(record);
      }
    }
    return merged.sort((a, b) => (a.created_at > b.created_at ? -1 : 1));
  }, [eventTransfers, transfersQuery.data?.transfers]);

  const isSubmitting = transfersQuery.submitTransfer.isPending;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    try {
      await transfersQuery.submitTransfer.mutateAsync(form);
      pushToast({ kind: 'success', title: 'Transfer dispatched', description: 'Check the history for confirmation counts.' });
      setForm((prev) => ({ ...prev, address: '', memo: '' }));
    } catch (error) {
      pushToast({ kind: 'error', title: 'Transfer failed', description: (error as Error).message });
    }
  };

  const copyViewKey = async () => {
    try {
      await navigator.clipboard.writeText(VIEW_KEY);
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
      <div className={`grid-12 ${styles.grid}`}>
        <MetricTile label="Shielded balance" value={`${estimatedBalance.toFixed(2)} SHC`} helper="Estimated from note depth" />
        <MetricTile label="Notes committed" value={coverage} helper={`Tree depth ${notes?.depth ?? '—'}`} />
        <MetricTile
          label="Mempool depth"
          value={`${metrics?.mempool_depth ?? 0}`}
          helper={`Difficulty ${metrics?.difficulty_bits ?? 0}`}
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
                <span>Amount (SHC)</span>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  value={form.amount}
                  onChange={(event) => setForm((prev) => ({ ...prev, amount: Number(event.target.value) }))}
                />
              </label>
              <label>
                <span>Fee (SHC)</span>
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
            <QRCode value={VIEW_KEY} size={132} bgColor="transparent" fgColor="var(--color-surface-mid)" />
            <div>
              <p className={styles.viewKey}>{VIEW_KEY}</p>
              <div className={styles.receiveActions}>
                <button type="button" onClick={copyViewKey} className={styles.ghostButton}>
                  Copy view key
                </button>
                <a
                  className={styles.linkButton}
                  download="view-key.txt"
                  href={`data:text/plain,${encodeURIComponent(VIEW_KEY)}`}
                >
                  Export
                </a>
              </div>
            </div>
          </div>
        </article>
      </section>

      <section>
        <header className={styles.historyHeader}>
          <div>
            <p className={styles.kicker}>Transaction history</p>
            <h3>Transfers & confirmations</h3>
          </div>
        </header>
        <TransactionTable records={transfers} />
      </section>
    </PageShell>
  );
}
