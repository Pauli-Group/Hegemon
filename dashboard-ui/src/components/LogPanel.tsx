import { useCallback, useEffect, useRef, useState } from 'react';
import type { LogEntry } from '../hooks/useActionRunner';
import { copyLogEntries, downloadLogEntries } from '../utils/logExport';
import styles from './LogPanel.module.css';

interface LogPanelProps {
  title?: string;
  lines: LogEntry[];
  isStreaming?: boolean;
  shimmerCount?: number;
  exportFileName?: string;
}

export function LogPanel({
  title,
  lines,
  isStreaming = false,
  shimmerCount = 4,
  exportFileName = 'dashboard-logs.txt',
}: LogPanelProps) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'error'>('idle');

  useEffect(() => {
    if (viewportRef.current) {
      viewportRef.current.scrollTop = viewportRef.current.scrollHeight;
    }
  }, [lines.length]);

  useEffect(() => {
    if (copyState === 'copied') {
      const timer = globalThis.setTimeout(() => setCopyState('idle'), 2000);
      return () => {
        globalThis.clearTimeout(timer);
      };
    }
    return undefined;
  }, [copyState]);

  const showShimmer = isStreaming && lines.length === 0;
  const disableExport = lines.length === 0;

  const handleCopy = useCallback(async () => {
    try {
      const ok = await copyLogEntries(lines);
      setCopyState(ok ? 'copied' : 'idle');
    } catch (error) {
      console.error('copy failed', error);
      setCopyState('error');
    }
  }, [lines]);

  const handleDownload = useCallback(() => {
    const ok = downloadLogEntries(lines, exportFileName);
    if (!ok) {
      console.warn('Download skipped — no log payload available.');
    }
  }, [exportFileName, lines]);

  const copyLabel = copyState === 'copied' ? 'Copied' : copyState === 'error' ? 'Retry copy' : 'Copy logs';

  return (
    <div className={styles.panel}>
      <div className={styles.header}>
        {title && <p className={styles.title}>{title}</p>}
        <div className={styles.toolbar} role="toolbar" aria-label="Log export controls">
          <button
            type="button"
            className={styles.actionButton}
            onClick={handleCopy}
            disabled={disableExport}
            data-testid="copy-logs-button"
          >
            {copyLabel}
          </button>
          <button
            type="button"
            className={styles.actionButton}
            onClick={handleDownload}
            disabled={disableExport}
          >
            Download .txt
          </button>
        </div>
      </div>
      <div ref={viewportRef} className={styles.log}>
        {showShimmer && (
          <div className={styles.shimmerStack} data-testid="log-shimmer">
            {Array.from({ length: shimmerCount }).map((_, index) => (
              <span key={index} className={styles.shimmer} />
            ))}
          </div>
        )}
        {!showShimmer && (
          <ul className={styles.logList}>
            {lines.map((entry, index) => (
              <li key={`${entry.text}-${index}`} className={`${styles.logLine} ${styles[entry.level]}`}>
                <span className={styles.lineText}>{entry.text}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
