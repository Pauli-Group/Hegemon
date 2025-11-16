import { useEffect, useRef } from 'react';
import styles from './LogPanel.module.css';

interface LogPanelProps {
  title?: string;
  lines: string[];
  isStreaming?: boolean;
  shimmerCount?: number;
}

export function LogPanel({ title, lines, isStreaming = false, shimmerCount = 4 }: LogPanelProps) {
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (preRef.current) {
      preRef.current.scrollTop = preRef.current.scrollHeight;
    }
  }, [lines.length]);

  const showShimmer = isStreaming && lines.length === 0;

  return (
    <div className={styles.panel}>
      {title && <p className={styles.title}>{title}</p>}
      <pre ref={preRef} className={styles.log}>
        <code>
          {showShimmer && (
            <div className={styles.shimmerStack}>
              {Array.from({ length: shimmerCount }).map((_, index) => (
                <span key={index} className={styles.shimmer} />
              ))}
            </div>
          )}
          {!showShimmer &&
            lines.map((line, index) => (
              <span key={`${line}-${index}`}>{line}\n</span>
            ))}
        </code>
      </pre>
    </div>
  );
}
