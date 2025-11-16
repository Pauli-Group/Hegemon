import { Link, useParams } from 'react-router-dom';
import { PageShell } from '../components/PageShell';
import { LogPanel } from '../components/LogPanel';
import { formatCommandLine, getActionBySlug } from '../data/actions';
import styles from './ActionRunPage.module.css';

export function ActionRunPage() {
  const { slug } = useParams();
  const action = slug ? getActionBySlug(slug) : undefined;

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
      <LogPanel title="CLI playback" lines={logLines} />
    </PageShell>
  );
}
