import type { FallbackResult } from '../hooks/useNodeData';
import styles from './DataStatusBanner.module.css';

interface DataStatusBannerProps {
  label: string;
  result?: FallbackResult<unknown>;
  isPlaceholder?: boolean;
  className?: string;
}

export function DataStatusBanner({ label, result, isPlaceholder, className }: DataStatusBannerProps) {
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

  return (
    <div
      className={[styles.banner, className].filter(Boolean).join(' ')}
      role="status"
      title={`${label}: ${reason}`}
      data-variant={variant}
    >
      <strong>{label}:</strong> {isMock ? 'Mock data in use.' : 'Encountered an error.'} {reason}
    </div>
  );
}
