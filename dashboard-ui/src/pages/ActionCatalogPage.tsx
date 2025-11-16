import { useMemo, useState } from 'react';
import { PageShell } from '../components/PageShell';
import { ActionCard } from '../components/ActionCard';
import { groupActionsByCategory, listActions } from '../data/actions';
import styles from './ActionCatalogPage.module.css';

export function ActionCatalogPage() {
  const [query, setQuery] = useState('');
  const allActions = useMemo(() => listActions(), []);

  const filtered = useMemo(() => {
    if (!query.trim()) {
      return allActions;
    }
    const lowered = query.toLowerCase();
    return allActions.filter((action) =>
      [action.slug, action.title, action.description, action.category]
        .filter(Boolean)
        .some((field) => field.toLowerCase().includes(lowered))
    );
  }, [allActions, query]);

  const grouped = useMemo(() => groupActionsByCategory(filtered), [filtered]);

  return (
    <PageShell
      title="Operational action catalog"
      intro="Runbook actions mirrored from scripts/dashboard.py so every workflow feels identical in the CLI and UI. Use the filter to locate install, CI, and benchmark rituals."
      actions={
        <label className={styles.searchField}>
          <span className="visually-hidden">Filter actions</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter by slug, command, or category"
          />
        </label>
      }
    >
      {grouped.map((group) => (
        <section key={group.category} className={styles.section}>
          <div className={styles.sectionHeader}>
            <p className={styles.category}>{group.category}</p>
            <p className={styles.count}>{group.actions.length} actions</p>
          </div>
          <div className={`grid-12 ${styles.grid}`}>
            {group.actions.map((action) => (
              <ActionCard key={action.slug} action={action} />
            ))}
          </div>
        </section>
      ))}
    </PageShell>
  );
}
