import { Link } from 'react-router-dom';
import type { DashboardAction } from '../data/types';
import styles from './ActionCard.module.css';

interface ActionCardProps {
  action: DashboardAction;
}

export function ActionCard({ action }: ActionCardProps) {
  const commandCount = action.commands.length;
  return (
    <article className={styles.card}>
      <p className={styles.slug}>{action.slug}</p>
      <h3>{action.title}</h3>
      <p className={styles.description}>{action.description}</p>
      {action.notes && <p className={styles.notes}>{action.notes}</p>}
      <div className={styles.metaRow}>
        <span className={styles.metaChip}>{action.category}</span>
        <span className={styles.metaChip}>{commandCount} commands</span>
      </div>
      <Link className={styles.cta} to={`/actions/${action.slug}`}>
        Review & run
      </Link>
    </article>
  );
}
