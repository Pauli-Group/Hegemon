import { Link } from 'react-router-dom';
import { useEffect } from 'react';
import { PageShell } from '../components/PageShell';
import { LogPanel } from '../components/LogPanel';
import { getActionBySlug, quickstartAction } from '../data/actions';
import { useActionRunner, type CommandStatus } from '../hooks/useActionRunner';
import { useToasts } from '../components/ToastProvider';
import styles from './QuickstartPage.module.css';

const dependencySlugs = ['dev-setup', 'check', 'bench-all', 'wallet-demo'];

export function QuickstartPage() {
  const quickstart = quickstartAction;
  const dependencies = dependencySlugs
    .map((slug) => getActionBySlug(slug))
    .filter((action): action is NonNullable<typeof action> => Boolean(action));

  const timeline = quickstart?.commands ?? [];
  const {
    status,
    logs,
    error,
    isStreaming,
    lastCompletion,
    runAction,
    reset,
    commandProgress,
  } = useActionRunner(quickstart?.slug);
  const { pushToast } = useToasts();

  useEffect(() => () => reset(), [reset]);

  useEffect(() => {
    if (!lastCompletion || !quickstart) {
      return;
    }
    if (lastCompletion.status === 'success') {
      const duration =
        typeof lastCompletion.duration === 'number'
          ? `${lastCompletion.duration.toFixed(2)}s`
          : 'just now';
      pushToast({
        kind: 'success',
        title: `Completed ${quickstart.title}`,
        description: `Finished in ${duration}.`,
      });
    }
    if (lastCompletion.status === 'error') {
      pushToast({
        kind: 'error',
        title: `Failed to run ${quickstart.title}`,
        description: lastCompletion.error ?? 'See log output for details.',
      });
    }
  }, [lastCompletion, pushToast, quickstart]);

  const defaultLogLines = timeline.map((command, index) => {
    const prefix = command.cwd ? `cd ${command.cwd} && ` : '';
    return `${index + 1}. ${prefix}${command.argv.join(' ')}`;
  });

  const displayLines = logs.length > 0 ? logs : isStreaming ? [] : defaultLogLines;

  const statusLabels: Record<CommandStatus, string> = {
    pending: 'Pending',
    running: 'Running',
    success: 'Complete',
    error: 'Failed',
  };

  const statusTone: Record<CommandStatus, string> = {
    pending: styles.statusPending,
    running: styles.statusRunning,
    success: styles.statusSuccess,
    error: styles.statusError,
  };

  const hasCommandProgress = Object.keys(commandProgress).length > 0;
  const fallbackFirstStatus: CommandStatus | undefined = !hasCommandProgress
    ? status === 'running'
      ? 'running'
      : status === 'error'
        ? 'error'
        : undefined
    : undefined;

  const stepStatuses = timeline.map((_, index) => {
    const progress = commandProgress[index];
    if (progress) {
      return progress;
    }
    if (index === 0 && fallbackFirstStatus) {
      return fallbackFirstStatus;
    }
    return 'pending';
  });

  return (
    <PageShell
      title="Full workstation quickstart"
      intro="Sequential view of dev setup, CI checks, and demos so a new contributor can mirror the CLI dashboard end-to-end."
      actions={
        <div className={styles.headerActions}>
          <Link className={styles.catalogLink} to="/">
            Catalog ↗
          </Link>
          <button
            className={styles.runButton}
            onClick={runAction}
            disabled={status === 'running' || !quickstart}
          >
            {status === 'running' ? 'Running…' : 'Run quickstart'}
          </button>
        </div>
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
          {timeline.map((command, index) => {
            const stepStatus = stepStatuses[index];
            const chipClass = `${styles.statusChip} ${statusTone[stepStatus]}`;
            return (
              <li key={command.argv.join('-')}>
                <div className={styles.stepBadge}>{index + 1}</div>
                <div>
                  <p className={styles.stepCommand}>{command.argv.join(' ')}</p>
                  {command.cwd && <p className={styles.stepMeta}>cwd: {command.cwd}</p>}
                  <span className={chipClass} data-testid={`command-status-${index + 1}`}>
                    {statusLabels[stepStatus]}
                  </span>
                </div>
              </li>
            );
          })}
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
        <>
          {status === 'error' && (
            <p className={styles.guardRailCopy}>
              Guard Rail triggered — {error ?? 'See CLI playback for details.'}
            </p>
          )}
          <LogPanel
            title="Live output"
            lines={displayLines}
            isStreaming={isStreaming}
            shimmerCount={6}
          />
        </>
      )}
    </PageShell>
  );
}
