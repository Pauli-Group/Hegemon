import { useCallback, useEffect, useRef, useState } from 'react';
import { dashboardServiceUrl } from '../config';

export type RunStatus = 'idle' | 'running' | 'success' | 'error';

const formatDuration = (value?: number) =>
  typeof value === 'number' ? value.toFixed(2) : '0.00';

type Completion = {
  runId: number;
  status: 'success' | 'error';
  duration?: number;
  error?: string;
};

interface RunnerState {
  status: RunStatus;
  logs: string[];
  error?: string;
  isStreaming: boolean;
  lastCompletion?: Completion;
  runAction: () => Promise<void>;
  reset: () => void;
}

interface ActionEvent {
  type: string;
  slug: string;
  command_index?: number;
  line?: string;
  duration?: number;
  exit_code?: number;
  command?: string;
}

function formatLine(event: ActionEvent): string | null {
  switch (event.type) {
    case 'action_start':
      return `▶︎ Starting ${event.slug}`;
    case 'command_start':
      return `→ [${(event.command_index ?? 0) + 1}] ${event.command}`;
    case 'command_end':
      return `✓ Command ${(event.command_index ?? 0) + 1} ${
        event.exit_code === 0 ? 'completed' : 'failed'
      } in ${formatDuration(event.duration)}s`;
    case 'action_complete':
      return `✔︎ Action ${event.slug} completed in ${formatDuration(event.duration)}s`;
    case 'action_error':
      return `✖ Action ${event.slug} failed (command ${(event.command_index ?? 0) + 1})`;
    case 'command_output':
      return event.line ?? '';
    default:
      return null;
  }
}

export function useActionRunner(slug?: string): RunnerState {
  const [status, setStatus] = useState<RunStatus>('idle');
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState<string | undefined>(undefined);
  const [isStreaming, setIsStreaming] = useState(false);
  const [lastCompletion, setLastCompletion] = useState<Completion | undefined>(undefined);
  const runIdRef = useRef(0);
  const abortRef = useRef<AbortController | null>(null);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setStatus('idle');
    setLogs([]);
    setError(undefined);
    setIsStreaming(false);
  }, []);

  useEffect(() => {
    reset();
  }, [reset, slug]);

  const handleEvent = useCallback((event: ActionEvent, currentRunId: number) => {
    const formatted = formatLine(event);
    if (formatted) {
      setLogs((prev) => [...prev, formatted]);
    }
    if (event.type === 'action_complete') {
      setStatus('success');
      setIsStreaming(false);
      setLastCompletion({ runId: currentRunId, status: 'success', duration: event.duration });
    }
    if (event.type === 'action_error') {
      const message = `Command ${(event.command_index ?? 0) + 1} failed with exit code ${
        event.exit_code
      }`;
      setError(message);
      setStatus('error');
      setIsStreaming(false);
      setLastCompletion({
        runId: currentRunId,
        status: 'error',
        duration: event.duration,
        error: message,
      });
    }
  }, []);

  const runAction = useCallback(async () => {
    if (!slug) {
      return;
    }
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    runIdRef.current += 1;
    const currentRunId = runIdRef.current;
    setStatus('running');
    setLogs([]);
    setError(undefined);
    setIsStreaming(true);

    try {
      const response = await fetch(`${dashboardServiceUrl}/run/${slug}`, {
        method: 'POST',
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        throw new Error(`Service responded with ${response.status}`);
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let streamComplete = false;
      while (!streamComplete) {
        const { value, done } = await reader.read();
        streamComplete = Boolean(done);
        if (value) {
          buffer += decoder.decode(value, { stream: !streamComplete });
        }
        let newlineIndex = buffer.indexOf('\n');
        while (newlineIndex >= 0) {
          const chunk = buffer.slice(0, newlineIndex).trim();
          buffer = buffer.slice(newlineIndex + 1);
          if (chunk) {
            try {
              const event = JSON.parse(chunk) as ActionEvent;
              handleEvent(event, currentRunId);
            } catch (parseError) {
              console.error('Failed to parse event', parseError);
            }
          }
          newlineIndex = buffer.indexOf('\n');
        }
      }
      if (buffer.trim()) {
        try {
          const event = JSON.parse(buffer.trim()) as ActionEvent;
          handleEvent(event, currentRunId);
        } catch (parseError) {
          console.error('Failed to parse trailing event', parseError);
        }
      }
    } catch (err) {
      if ((err as { name?: string }).name === 'AbortError') {
        return;
      }
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(message);
      setStatus('error');
      setIsStreaming(false);
      setLastCompletion({
        runId: currentRunId,
        status: 'error',
        error: message,
      });
    }
  }, [handleEvent, slug]);

  return { status, logs, error, isStreaming, lastCompletion, runAction, reset };
}
