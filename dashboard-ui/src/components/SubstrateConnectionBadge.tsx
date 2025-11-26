/**
 * SubstrateConnectionBadge - Shows WebSocket connection status to Substrate node
 */

import { useSubstrateApi, type ConnectionState } from '../providers/SubstrateApiProvider';
import styles from './ConnectionBadge.module.css';

interface SubstrateConnectionBadgeProps {
  label?: string;
  className?: string;
}

function getStatusInfo(state: ConnectionState, error: string | null): {
  label: string;
  tooltip: string;
  isLive: boolean;
} {
  switch (state) {
    case 'connected':
      return {
        label: 'Live',
        tooltip: 'Connected to Substrate node via WebSocket',
        isLive: true,
      };
    case 'connecting':
      return {
        label: 'Connecting...',
        tooltip: 'Establishing WebSocket connection to Substrate node',
        isLive: false,
      };
    case 'error':
      return {
        label: 'Error',
        tooltip: error || 'Failed to connect to Substrate node',
        isLive: false,
      };
    case 'disconnected':
    default:
      return {
        label: 'Offline',
        tooltip: 'Not connected to Substrate node',
        isLive: false,
      };
  }
}

export function SubstrateConnectionBadge({ label, className }: SubstrateConnectionBadgeProps) {
  const { connectionState, error, blockNumber, peerCount } = useSubstrateApi();
  const statusInfo = getStatusInfo(connectionState, error);

  const fullTooltip = label
    ? `${label}: ${statusInfo.tooltip}${blockNumber > 0 ? ` (Block #${blockNumber}, ${peerCount} peers)` : ''}`
    : statusInfo.tooltip;

  const badgeClass = [
    styles.badge,
    statusInfo.isLive ? styles.live : styles.mock,
    connectionState === 'connecting' ? styles.connecting : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  const ariaLabel = label
    ? `${label} connection status: ${statusInfo.label}`
    : `Connection status: ${statusInfo.label}`;

  return (
    <span className={badgeClass} title={fullTooltip} aria-label={ariaLabel} role="status">
      <span className={styles.dot} aria-hidden="true" />
      {statusInfo.label}
      {blockNumber > 0 && connectionState === 'connected' && (
        <span className={styles.blockInfo}> #{blockNumber}</span>
      )}
    </span>
  );
}
