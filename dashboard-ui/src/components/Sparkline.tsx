import type { TelemetryPoint } from '../types/node';
import styles from './Sparkline.module.css';

interface SparklineProps {
  data: TelemetryPoint[];
  color?: string;
  height?: number;
  label?: string;
}

export function Sparkline({ data, color = 'var(--color-accent-primary)', height = 56, label }: SparklineProps) {
  if (!data.length) {
    return <div className={styles.placeholder}>Awaiting telemetry…</div>;
  }
  const width = Math.max(data.length - 1, 1) * 12;
  const values = data.map((point) => point.value);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const normalized = data.map((point, index) => {
    const x = (index / Math.max(data.length - 1, 1)) * width;
    const y = height - ((point.value - min) / range) * height;
    return `${x},${y}`;
  });
  const pathData = `M ${normalized.join(' L ')}`;
  const lastPoint = normalized[normalized.length - 1]?.split(',').map(Number) ?? [width, height];
  return (
    <div className={styles.sparkline}>
      {label && <p className={styles.label}>{label}</p>}
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
        <path d={pathData} stroke={color} fill="none" strokeWidth={2.5} strokeLinecap="round" />
        <circle cx={lastPoint[0]} cy={lastPoint[1]} r={3} fill={color} />
      </svg>
    </div>
  );
}
