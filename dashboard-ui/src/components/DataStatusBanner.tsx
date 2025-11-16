import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import type { FallbackResult } from '../hooks/useNodeData';
import styles from './DataStatusBanner.module.css';

interface DataStatusBannerProps {
  label: string;
  result?: FallbackResult<unknown>;
  isPlaceholder?: boolean;
  className?: string;
  cta?: ReactNode;
}

export function DataStatusBanner({ label, result, isPlaceholder, className, cta }: DataStatusBannerProps) {
  const [dismissed, setDismissed] = useState(false);

  const content = useMemo(() => {
    if (!result || isPlaceholder) {
      return null;
    }

    const isMock = result.source === 'mock';
    const hasError = Boolean(result.error);

    if (!isMock && !hasError) {
      return null;
    }

    const reason = result.error?.message ?? 'Node proxy unavailable – showing deterministic mock payloads.';
    const variant = isMock ? 'mock' : 'error';

    return { isMock, reason, variant } as const;
  }, [isPlaceholder, result]);

  if (dismissed || !content) {
    return null;
  }

  const { isMock, reason, variant } = content;

  return (
    <div
      className={[styles.banner, className].filter(Boolean).join(' ')}
      role="status"
      aria-live="polite"
      aria-label={`${label} status banner`}
      title={`${label}: ${reason}`}
      data-variant={variant}
    >
      <div className={styles.messageRow}>
        <div className={styles.message}>
          <strong>{label}:</strong> {isMock ? 'Mock data in use.' : 'Encountered an error.'} {reason}
          {cta && isMock ? <span className={styles.cta}>{cta}</span> : null}
        </div>
        <button
          type="button"
          className={styles.dismiss}
          onClick={() => setDismissed(true)}
          aria-label={`Dismiss ${label} status banner`}
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}
