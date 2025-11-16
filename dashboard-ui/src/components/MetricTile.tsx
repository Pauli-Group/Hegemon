import type { ReactNode } from 'react';
import styles from './MetricTile.module.css';

interface MetricTileProps {
  label: string;
  value: string;
  helper?: string;
  accent?: 'primary' | 'success' | 'warning';
  children?: ReactNode;
}

export function MetricTile({ label, value, helper, accent = 'primary', children }: MetricTileProps) {
  return (
    <article className={`${styles.tile} ${styles[accent]}`}>
      <p className={styles.label}>{label}</p>
      <p className={styles.value}>{value}</p>
      {helper && <p className={styles.helper}>{helper}</p>}
      {children && <div className={styles.extra}>{children}</div>}
    </article>
  );
}
