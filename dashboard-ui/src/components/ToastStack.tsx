import styles from './ToastStack.module.css';
import type { ToastKind } from './ToastProvider';

interface ToastItem {
  id: string;
  kind: ToastKind;
  title: string;
  description?: string;
}

interface ToastStackProps {
  toasts: ToastItem[];
  onDismiss: (id: string) => void;
}

export function ToastStack({ toasts, onDismiss }: ToastStackProps) {
  if (toasts.length === 0) {
    return null;
  }
  return (
    <div className={styles.stack}>
      {toasts.map((toast) => (
        <div key={toast.id} className={`${styles.toast} ${styles[toast.kind]}`}>
          <div>
            <p className={styles.title}>{toast.title}</p>
            {toast.description && <p className={styles.description}>{toast.description}</p>}
          </div>
          <button type="button" className={styles.dismiss} onClick={() => onDismiss(toast.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
