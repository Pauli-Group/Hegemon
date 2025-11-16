import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { ToastStack } from './ToastStack';

export type ToastKind = 'success' | 'error';

export interface ToastPayload {
  kind: ToastKind;
  title: string;
  description?: string;
}

interface Toast extends ToastPayload {
  id: string;
  createdAt: number;
}

interface ToastContextValue {
  pushToast: (toast: ToastPayload) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

function makeId() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).slice(2);
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timeouts = useRef<Record<string, number>>({});

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
    const timeoutId = timeouts.current[id];
    if (timeoutId) {
      window.clearTimeout(timeoutId);
      delete timeouts.current[id];
    }
  }, []);

  const scheduleAutoDismiss = useCallback(
    (id: string) => {
      const timeoutId = window.setTimeout(() => dismissToast(id), 6000);
      timeouts.current[id] = timeoutId;
    },
    [dismissToast]
  );

  const pushToast = useCallback(
    (toast: ToastPayload) => {
      const id = makeId();
      setToasts((prev) => [...prev, { ...toast, id, createdAt: Date.now() }]);
      scheduleAutoDismiss(id);
    },
    [scheduleAutoDismiss]
  );

  const value = useMemo(() => ({ pushToast }), [pushToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastStack toasts={toasts} onDismiss={dismissToast} />
    </ToastContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToasts() {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToasts must be used within a ToastProvider');
  }
  return ctx;
}
