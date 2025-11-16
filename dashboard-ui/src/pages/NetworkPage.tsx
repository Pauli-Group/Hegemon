import { PageShell } from '../components/PageShell';
import { MetricTile } from '../components/MetricTile';
import { Sparkline } from '../components/Sparkline';
import { useNodeMetrics, useNodeEventStream } from '../hooks/useNodeData';
import styles from './NetworkPage.module.css';

export function NetworkPage() {
  const metrics = useNodeMetrics();
  const { events, hashRateSeries, mempoolSeries, latestTelemetry } = useNodeEventStream(36);
  const blockEvents = events.filter((event) => event.type === 'block').slice(0, 6);
  const txEvents = events.filter((event) => event.type === 'transaction').slice(0, 6);
  const staleRate = latestTelemetry?.type === 'telemetry' ? latestTelemetry.stale_share_rate : metrics.data?.stale_share_rate ?? 0;
  const showAlert = staleRate > 0.05;

  return (
    <PageShell
      title="Network analytics"
      intro="Surface consensus depth, mempool churn, and block propagation alerts for the synthetic hegemonic currency network."
    >
      {showAlert && (
        <div className={styles.alertBanner}>
          <p>High stale share rate detected ({(staleRate * 100).toFixed(2)}%). Investigate peer connectivity.</p>
        </div>
      )}

      <div className={`grid-12 ${styles.grid}`}>
        <MetricTile label="Best height" value={`${metrics.data?.best_height ?? 0}`} helper="Latest confirmed block" />
        <MetricTile label="Total hashes" value={(metrics.data?.total_hashes ?? 0).toLocaleString()} helper="Since node start" />
        <MetricTile label="Stale rate" value={`${(staleRate * 100).toFixed(2)}%`} helper="Past 5 samples" />
      </div>

      <section className={styles.sparkGrid}>
        <article className={styles.sparkCard}>
          <h3>Hash rate trend</h3>
          <Sparkline data={hashRateSeries} label="Hashes per second" />
        </article>
        <article className={styles.sparkCard}>
          <h3>Mempool depth trend</h3>
          <Sparkline data={mempoolSeries} color="var(--color-accent-secondary)" label="Transactions" />
        </article>
      </section>

      <section className={styles.eventColumns}>
        <div>
          <p className={styles.kicker}>Blocks</p>
          <ul className={styles.eventList}>
            {blockEvents.map((event) => (
              <li key={`block-${event.height}`}>
                <span className={styles.badge}>#{event.height}</span>
                <span>Hash {event.hash?.slice(0, 10) ?? '—'}</span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <p className={styles.kicker}>Transactions</p>
          <ul className={styles.eventList}>
            {txEvents.map((event) => (
              <li key={`tx-${event.tx_id}`}>
                <span className={styles.badge}>Tx</span>
                <span className={styles.mono}>{event.tx_id}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </PageShell>
  );
}
