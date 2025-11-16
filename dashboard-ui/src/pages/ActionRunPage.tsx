import { Link, useParams } from 'react-router-dom';
import { useEffect } from 'react';
import { PageShell } from '../components/PageShell';
import { LogPanel } from '../components/LogPanel';
import { formatCommandLine, getActionBySlug } from '../data/actions';
import { useActionRunner, type LogEntry, type RunStatus } from '../hooks/useActionRunner';
import { useToasts } from '../components/ToastProvider';
import styles from './ActionRunPage.module.css';

export function ActionRunPage() {
  const { slug } = useParams();
  const action = slug ? getActionBySlug(slug) : undefined;
  const { status, logs, error, isStreaming, lastCompletion, runAction, reset } =
    useActionRunner(action?.slug);
  const { pushToast } = useToasts();

  useEffect(() => {
    if (!lastCompletion || !action) {
      return;
    }
    if (lastCompletion.status === 'success') {
      const duration =
        typeof lastCompletion.duration === 'number'
          ? `${lastCompletion.duration.toFixed(2)}s`
          : 'just now';
      pushToast({
        kind: 'success',
        title: `Completed ${action.title}`,
        description: `Finished in ${duration}.`,
      });
    }
    if (lastCompletion.status === 'error') {
      pushToast({
        kind: 'error',
        title: `Failed to run ${action.title}`,
        description: lastCompletion.error ?? 'See log output for details.',
      });
    }
  }, [action, lastCompletion, pushToast]);

  useEffect(() => () => reset(), [reset]);

  if (!action) {
    return (
      <PageShell title="Action not found" intro="Pick any workflow from the catalog to see its CLI representation and recommended notes.">
        <p>
          Return to the <Link to="/">action catalog</Link> to select a known slug.
        </p>
      </PageShell>
    );
  }

  const logLines = action.commands.map((command, index) => {
    const prefix = command.cwd ? `cd ${command.cwd} && ` : '';
    return `${index + 1}. ${prefix}${formatCommandLine(command.argv)}`;
  });

  const placeholderEntries: LogEntry[] = logLines.map((text, index) => ({
    level: 'info',
    text,
    commandIndex: index,
  }));

  const statusLabel: Record<RunStatus, string> = {
    idle: 'Idle',
    running: 'Running',
    success: 'Success',
    error: 'Error',
  };

  const toneClass = {
    idle: styles.statusIdle,
    running: styles.statusRunning,
    success: styles.statusSuccess,
    error: styles.statusError,
  }[status];

  const displayLines = logs.length > 0 ? logs : isStreaming ? [] : placeholderEntries;

  return (
    <PageShell
      title={action.title}
      intro={action.description}
      actions={
        <Link className={styles.backLink} to="/">
          ← Catalog
        </Link>
      }
    >
      <div className={styles.metaGrid}>
        <div className={styles.metaCard}>
          <p className={styles.label}>Slug</p>
          <p className={styles.value}>{action.slug}</p>
        </div>
        <div className={styles.metaCard}>
          <p className={styles.label}>Category</p>
          <p className={styles.value}>{action.category}</p>
        </div>
        <div className={styles.metaCard}>
          <p className={styles.label}>Command count</p>
          <p className={styles.value}>{action.commands.length}</p>
        </div>
      </div>
      {action.notes && <p className={styles.notes}>Notes: {action.notes}</p>}
      <div className={styles.runControls}>
        <div>
          <p className={styles.label}>Status</p>
          <span className={`${styles.statusBadge} ${toneClass}`}>{statusLabel[status]}</span>
        </div>
        <button
          className={styles.runButton}
          onClick={runAction}
          disabled={status === 'running'}
        >
          {status === 'running' ? 'Running…' : 'Run action'}
        </button>
      </div>
      {error && <p className={styles.errorHint}>{error}</p>}
      <LogPanel
        title="Live output"
        lines={displayLines}
        isStreaming={isStreaming}
        shimmerCount={6}
        exportFileName={`action-${action.slug}-logs.txt`}
      />
    </PageShell>
  );
}
