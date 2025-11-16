import styles from './ConnectionBadge.module.css';

interface ConnectionBadgeProps {
  source: 'live' | 'mock';
  error?: Error;
  label?: string;
  className?: string;
}

export function ConnectionBadge({ source, error, label, className }: ConnectionBadgeProps) {
  const isLive = source === 'live';
  const reason = error?.message ?? (isLive ? 'Connected to the node proxy.' : 'Node proxy unavailable, showing mock payloads.');
  const tooltip = label ? `${label}: ${reason}` : reason;
  const badgeClass = [styles.badge, isLive ? styles.live : styles.mock, className].filter(Boolean).join(' ');
  const ariaLabel = label
    ? `${label} connection status: ${isLive ? 'live data' : 'mock data'}`
    : `Connection status: ${isLive ? 'live data' : 'mock data'}`;

  return (
    <span className={badgeClass} title={tooltip} aria-label={ariaLabel} role="status">
      <span className={styles.dot} aria-hidden="true" />
      {isLive ? 'Live data' : 'Mock data'}
    </span>
  );
}
