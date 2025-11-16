import styles from './LogPanel.module.css';

interface LogPanelProps {
  title?: string;
  lines: string[];
}

export function LogPanel({ title, lines }: LogPanelProps) {
  return (
    <div className={styles.panel}>
      {title && <p className={styles.title}>{title}</p>}
      <pre className={styles.log}>
        <code>
          {lines.map((line, index) => (
            <span key={`${line}-${index}`}>{line}\n</span>
          ))}
        </code>
      </pre>
    </div>
  );
}
