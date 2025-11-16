import { describe, expect, it, vi } from 'vitest';
import type { LogEntry } from '../hooks/useActionRunner';
import { buildLogExportPayload, copyLogEntries, DEFAULT_EXPORT_LIMIT } from './logExport';

const sampleEntries: LogEntry[] = Array.from({ length: 3 }).map((_, index) => ({
  level: 'info',
  text: `line-${index + 1}`,
  commandIndex: index,
}));

describe('buildLogExportPayload', () => {
  it('returns the last N lines with newline separators', () => {
    const payload = buildLogExportPayload(sampleEntries, 2);
    expect(payload).toBe('line-2\nline-3');
  });

  it('honors empty inputs', () => {
    expect(buildLogExportPayload([], DEFAULT_EXPORT_LIMIT)).toBe('');
  });
});

describe('copyLogEntries', () => {
  it('invokes the provided copy function with the payload', async () => {
    const copyFn = vi.fn();
    const result = await copyLogEntries(sampleEntries, { limit: 2, copyFn });
    expect(result).toBe(true);
    expect(copyFn).toHaveBeenCalledWith('line-2\nline-3');
  });

  it('short-circuits when there is nothing to copy', async () => {
    const copyFn = vi.fn();
    const result = await copyLogEntries([], { copyFn });
    expect(result).toBe(false);
    expect(copyFn).not.toHaveBeenCalled();
  });
});
