import { useEffect, useMemo, useState } from 'react';
import { PageShell } from '../components/PageShell';
import { MetricTile } from '../components/MetricTile';
import { Sparkline } from '../components/Sparkline';
import { LogPanel } from '../components/LogPanel';
import { useMinerStatus, useNodeEventStream } from '../hooks/useNodeData';
import { useToasts } from '../components/ToastProvider';
import styles from './MiningPage.module.css';

export function MiningPage() {
  const miner = useMinerStatus();
  const { events, hashRateSeries, mempoolSeries, difficultySeries, latestTelemetry } = useNodeEventStream(48);
  const { pushToast } = useToasts();
  const [targetRate, setTargetRate] = useState(miner.data?.target_hash_rate ?? 0);
  const [threads, setThreads] = useState(miner.data?.thread_count ?? 2);

  useEffect(() => {
    if (!miner.data) {
      return;
    }
    setTargetRate(miner.data.target_hash_rate);
    setThreads(miner.data.thread_count);
  }, [miner.data]);

  const hashRateValue = miner.data?.metrics.hash_rate ?? latestTelemetry?.hash_rate ?? 0;

  const sendControl = async (action: 'start' | 'stop') => {
    try {
      await miner.controlMiner.mutateAsync({ action, target_hash_rate: targetRate, thread_count: threads });
      pushToast({ kind: 'success', title: action === 'start' ? 'Mining resumed' : 'Mining paused' });
    } catch (error) {
      pushToast({ kind: 'error', title: 'Control failed', description: (error as Error).message });
    }
  };

  const logLines = useMemo(() => {
    return events.slice(0, 20).map((event) => {
      switch (event.type) {
        case 'telemetry':
          return `Telemetry ▸ hash ${event.hash_rate.toFixed(2)} H/s, mempool ${event.mempool_depth}`;
        case 'block':
          return `Block ▸ height ${event.height}`;
        case 'transaction':
          return `Tx ▸ ${event.tx_id}`;
        case 'warning':
          return `Warning ▸ ${event.message}`;
        default:
          return 'Event';
      }
    });
  }, [events]);

  const staleHelper = miner.data?.metrics.stale_share_rate
    ? `${(miner.data.metrics.stale_share_rate * 100).toFixed(2)}% stale`
    : 'Healthy';

  return (
    <PageShell
      title="Mining telemetry"
      intro="Adjust workers and targets while monitoring live hash rate, mempool depth, and stale share alerts."
      actions={
        <div className={styles.actionRow}>
          <button
            type="button"
            className={styles.primaryButton}
            onClick={() => sendControl(miner.data?.is_running ? 'stop' : 'start')}
            disabled={miner.controlMiner.isPending}
          >
            {miner.data?.is_running ? 'Pause mining' : 'Resume mining'}
          </button>
        </div>
      }
    >
      <div className={`grid-12 ${styles.grid}`}>
        <MetricTile label="Hash rate" value={`${hashRateValue.toFixed(2)} H/s`} helper={`Threads ${miner.data?.thread_count ?? 0}`}>
          <Sparkline data={hashRateSeries} label="24 samples" />
        </MetricTile>
        <MetricTile label="Mempool" value={`${miner.data?.metrics.mempool_depth ?? 0} tx`} helper="Live backlog">
          <Sparkline data={mempoolSeries} color="var(--color-accent-secondary)" label="Txn depth" />
        </MetricTile>
        <MetricTile label="Difficulty" value={`${miner.data?.metrics.difficulty_bits ?? 0}`} helper={staleHelper}>
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
        <LogPanel lines={logLines} isStreaming />
      </section>
    </PageShell>
  );
}
