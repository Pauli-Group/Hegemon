import type { ReactNode } from 'react';
import styles from './PageShell.module.css';

interface PageShellProps {
  title: string;
  intro?: string;
  actions?: ReactNode;
  children: ReactNode;
}

export function PageShell({ title, intro, actions, children }: PageShellProps) {
  return (
    <section className={styles.shell}>
      <div className={styles.headerRow}>
        <div>
          <p className={styles.kicker}>HEGEMON · HGN</p>
          <h1>{title}</h1>
          {intro && <p className={styles.intro}>{intro}</p>}
        </div>
        {actions && <div className={styles.headerActions}>{actions}</div>}
      </div>
      <div className={styles.body}>{children}</div>
    </section>
  );
}
