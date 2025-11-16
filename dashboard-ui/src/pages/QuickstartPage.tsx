import { Link } from 'react-router-dom';
import { PageShell } from '../components/PageShell';
import { LogPanel } from '../components/LogPanel';
import { getActionBySlug, quickstartAction } from '../data/actions';
import styles from './QuickstartPage.module.css';

const dependencySlugs = ['dev-setup', 'check', 'bench-all', 'wallet-demo'];

export function QuickstartPage() {
  const quickstart = quickstartAction;
  const dependencies = dependencySlugs
    .map((slug) => getActionBySlug(slug))
    .filter((action): action is NonNullable<typeof action> => Boolean(action));

  const timeline = quickstart?.commands ?? [];

  return (
    <PageShell
      title="Full workstation quickstart"
      intro="Sequential view of dev setup, CI checks, and demos so a new contributor can mirror the CLI dashboard end-to-end."
      actions={
        <Link className={styles.catalogLink} to="/">
          Catalog ↗
        </Link>
      }
    >
      <div className={styles.summaryGrid}>
        <div className={styles.summaryCard}>
          <p className={styles.label}>Steps</p>
          <p className={styles.value}>{timeline.length}</p>
        </div>
        <div className={styles.summaryCard}>
          <p className={styles.label}>Dependencies</p>
          <p className={styles.value}>{dependencies.length}</p>
        </div>
        <div className={styles.summaryCard}>
          <p className={styles.label}>Action slug</p>
          <p className={styles.value}>{quickstart?.slug ?? 'quickstart'}</p>
        </div>
      </div>
      <section className={styles.timelineSection}>
        <h2>Timeline</h2>
        <ol className={styles.timeline}>
          {timeline.map((command, index) => (
            <li key={command.argv.join('-')}>
              <div className={styles.stepBadge}>{index + 1}</div>
              <div>
                <p className={styles.stepCommand}>{command.argv.join(' ')}</p>
                {command.cwd && <p className={styles.stepMeta}>cwd: {command.cwd}</p>}
              </div>
            </li>
          ))}
        </ol>
      </section>
      <section className={styles.dependencies}>
        <h2>Prep actions</h2>
        <div className={`grid-12 ${styles.depGrid}`}>
          {dependencies.map((action) => (
            <article key={action.slug} className={styles.depCard}>
              <p className={styles.label}>{action.category}</p>
              <h3>{action.title}</h3>
              <p>{action.description}</p>
              <Link to={`/actions/${action.slug}`}>View action</Link>
            </article>
          ))}
        </div>
      </section>
      {quickstart && (
        <LogPanel
          title="CLI playback"
          lines={quickstart.commands.map((cmd, index) => `${index + 1}. ${cmd.argv.join(' ')}`)}
        />
      )}
    </PageShell>
  );
}
