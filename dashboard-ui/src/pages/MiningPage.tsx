import { useEffect, useMemo, useState } from 'react';
import { PageShell } from '../components/PageShell';
import { MetricTile } from '../components/MetricTile';
import { Sparkline } from '../components/Sparkline';
import { LogPanel } from '../components/LogPanel';
import { useMinerStatus, useNodeEventStream } from '../hooks/useNodeData';
import { useToasts } from '../components/ToastProvider';
import { ConnectionBadge } from '../components/ConnectionBadge';
import { DataStatusBanner } from '../components/DataStatusBanner';
import type { LogEntry } from '../hooks/useActionRunner';
import styles from './MiningPage.module.css';

export function MiningPage() {
  const miner = useMinerStatus();
  const { events, hashRateSeries, mempoolSeries, difficultySeries, latestTelemetry } = useNodeEventStream(48);
  const { pushToast } = useToasts();
  const minerData = miner.data?.data;
  const [targetRate, setTargetRate] = useState(minerData?.target_hash_rate ?? 0);
  const [threads, setThreads] = useState(minerData?.thread_count ?? 2);

  useEffect(() => {
    if (!minerData) {
      return;
    }
    setTargetRate(minerData.target_hash_rate);
    setThreads(minerData.thread_count);
  }, [minerData]);

  const hashRateValue = minerData?.metrics.hash_rate ?? latestTelemetry?.hash_rate ?? 0;

  const sendControl = async (action: 'start' | 'stop') => {
    try {
      await miner.controlMiner.mutateAsync({ action, target_hash_rate: targetRate, thread_count: threads });
      pushToast({ kind: 'success', title: action === 'start' ? 'Mining resumed' : 'Mining paused' });
    } catch (error) {
      pushToast({ kind: 'error', title: 'Control failed', description: (error as Error).message });
    }
  };

  const logLines: LogEntry[] = useMemo(() => {
    return events.slice(0, 20).map((event, index) => {
      switch (event.type) {
        case 'telemetry':
          return {
            level: 'info',
            text: `Telemetry ▸ hash ${event.hash_rate.toFixed(2)} H/s, mempool ${event.mempool_depth}`,
            commandIndex: index,
          } satisfies LogEntry;
        case 'block':
          return {
            level: 'success',
            text: `Block ▸ height ${event.height}`,
            commandIndex: index,
          } satisfies LogEntry;
        case 'transaction':
          return {
            level: 'success',
            text: `Tx ▸ ${event.tx_id}`,
            commandIndex: index,
          } satisfies LogEntry;
        case 'warning':
          return {
            level: 'error',
            text: `Warning ▸ ${event.message}`,
            commandIndex: index,
          } satisfies LogEntry;
        default:
          return {
            level: 'info',
            text: 'Event',
            commandIndex: index,
          } satisfies LogEntry;
      }
    });
  }, [events]);

  const staleHelper = minerData?.metrics.stale_share_rate
    ? `${(minerData.metrics.stale_share_rate * 100).toFixed(2)}% stale`
    : 'Healthy';

  return (
    <PageShell
      title="Mining telemetry"
      intro="Adjust workers and targets while monitoring live hash rate, mempool depth, and stale share alerts."
      actions={
        <div className={styles.actionRow}>
          <ConnectionBadge
            source={miner.data?.source ?? 'mock'}
            error={miner.data?.error}
            label="Miner status feed"
          />
          <button
            type="button"
            className={styles.primaryButton}
            onClick={() => sendControl(minerData?.is_running ? 'stop' : 'start')}
            disabled={miner.controlMiner.isPending}
          >
            {minerData?.is_running ? 'Pause mining' : 'Resume mining'}
          </button>
        </div>
      }
    >
      <DataStatusBanner
        label="Miner status feed"
        result={miner.data}
        isPlaceholder={miner.isPlaceholderData}
      />

      <div className={`grid-12 ${styles.grid}`}>
        <MetricTile label="Hash rate" value={`${hashRateValue.toFixed(2)} H/s`} helper={`Threads ${minerData?.thread_count ?? 0}`}>
          <Sparkline data={hashRateSeries} label="24 samples" />
        </MetricTile>
        <MetricTile label="Mempool" value={`${minerData?.metrics.mempool_depth ?? 0} tx`} helper="Live backlog">
          <Sparkline data={mempoolSeries} color="var(--color-accent-secondary)" label="Txn depth" />
        </MetricTile>
        <MetricTile label="Difficulty" value={`${minerData?.metrics.difficulty_bits ?? 0}`} helper={staleHelper}>
          <Sparkline data={difficultySeries} color="var(--color-success)" label="Bits" />
        </MetricTile>
      </div>

      <section className={styles.controlGrid}>
        <article className={styles.controlCard}>
          <h3>Target hash rate</h3>
          <p>Guide worker intensity to align with your energy budget.</p>
          <div className={styles.sliderRow}>
            <input
              type="range"
              min={100000}
              max={4000000}
              step={10000}
              value={targetRate}
              onChange={(event) => setTargetRate(Number(event.target.value))}
            />
            <span className={styles.sliderValue}>{targetRate.toLocaleString()} H/s</span>
          </div>
        </article>
        <article className={styles.controlCard}>
          <h3>Worker threads</h3>
          <p>Scale miners up or down without restarting the node service.</p>
          <div className={styles.numberField}>
            <input
              type="number"
              min={1}
              max={32}
              value={threads}
              onChange={(event) => setThreads(Number(event.target.value))}
            />
            <button
              type="button"
              className={styles.primaryButton}
              onClick={() => sendControl('start')}
              disabled={miner.controlMiner.isPending}
            >
              Apply changes
            </button>
          </div>
        </article>
      </section>

      <section className={styles.logSection}>
        <div>
          <p className={styles.kicker}>Realtime feed</p>
          <h3>Telemetry & confirmations</h3>
        </div>
        <LogPanel
          title="Live output"
          lines={logLines}
          isStreaming
          exportFileName="telemetry-feed.txt"
        />
      </section>
    </PageShell>
  );
}
