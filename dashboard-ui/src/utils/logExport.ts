import type { LogEntry } from '../hooks/useActionRunner';

export const DEFAULT_EXPORT_LIMIT = 50;

const defaultCopyFn = (text: string) => {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text);
  }
  return Promise.reject(new Error('Clipboard API unavailable'));
};

export const buildLogExportPayload = (entries: LogEntry[], limit: number = DEFAULT_EXPORT_LIMIT): string => {
  if (entries.length === 0) {
    return '';
  }

  const trimmed = limit > 0 ? entries.slice(-limit) : entries;
  return trimmed.map((entry) => entry.text).join('\n');
};

interface CopyOptions {
  limit?: number;
  copyFn?: (text: string) => Promise<void> | void;
}

export async function copyLogEntries(entries: LogEntry[], options: CopyOptions = {}): Promise<boolean> {
  const payload = buildLogExportPayload(entries, options.limit ?? DEFAULT_EXPORT_LIMIT);
  if (!payload) {
    return false;
  }

  const copyFn = options.copyFn ?? defaultCopyFn;
  await copyFn(payload);
  return true;
}

export function downloadLogEntries(
  entries: LogEntry[],
  fileName = 'dashboard-logs.txt',
  limit: number = DEFAULT_EXPORT_LIMIT,
): boolean {
  if (typeof document === 'undefined' || typeof window === 'undefined') {
    return false;
  }

  const payload = buildLogExportPayload(entries, limit);
  if (!payload) {
    return false;
  }

  const blob = new Blob([payload], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  return true;
}
