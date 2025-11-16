import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { dashboardServiceUrl } from '../config';
import type {
  MinerStatus,
  NoteStatus,
  NodeEvent,
  TelemetryPoint,
  TelemetrySnapshot,
  TransferRecord,
} from '../types/node';
import { mockMinerStatus, mockNotes, mockTelemetry, mockTransfers } from '../mocks/nodeSamples';

const SERVICE_HEADERS: HeadersInit = { 'Content-Type': 'application/json' };

class HttpError extends Error {
  status: number;
  detail?: unknown;

  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${dashboardServiceUrl}${path}`, init);
  if (!response.ok) {
    let message = `Request failed with ${response.status}`;
    let detail: unknown;
    try {
      detail = await response.json();
      if (detail && typeof detail === 'object' && 'error' in detail && typeof (detail as { error: unknown }).error === 'string') {
        message = (detail as { error: string }).error;
      }
    } catch {
      // ignore parse errors
    }
    throw new HttpError(response.status, message, detail);
  }
  return (await response.json()) as T;
}

async function getOrFallback<T>(path: string, fallback: T): Promise<T> {
  try {
    return await fetchJson<T>(path);
  } catch (error) {
    console.warn(`Falling back to mock payload for ${path}`, error);
    return fallback;
  }
}

export function useNodeMetrics() {
  return useQuery<TelemetrySnapshot>({
    queryKey: ['node-metrics'],
    queryFn: () => getOrFallback('/node/metrics', mockTelemetry),
    refetchInterval: 5000,
    placeholderData: mockTelemetry,
  });
}

export function useWalletNotes() {
  return useQuery<NoteStatus>({
    queryKey: ['wallet-notes'],
    queryFn: () => getOrFallback('/node/wallet/notes', mockNotes),
    refetchInterval: 7000,
    placeholderData: mockNotes,
  });
}

export function useMinerStatus() {
  const queryClient = useQueryClient();
  const query = useQuery<MinerStatus>({
    queryKey: ['miner-status'],
    queryFn: () => getOrFallback('/node/miner/status', mockMinerStatus),
    refetchInterval: 4000,
    placeholderData: mockMinerStatus,
  });

  const mutation = useMutation({
    mutationFn: (body: { action: 'start' | 'stop'; target_hash_rate?: number; thread_count?: number }) =>
      fetchJson<{ status: string; state: MinerStatus }>(`/node/miner/control`, {
        method: 'POST',
        headers: SERVICE_HEADERS,
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['miner-status'] });
    },
  });

  return { ...query, controlMiner: mutation };
}

export function useTransferLedger() {
  const queryClient = useQueryClient();
  const query = useQuery<{ transfers: TransferRecord[] }>({
    queryKey: ['wallet-transfers'],
    queryFn: async () => {
      try {
        return await fetchJson<{ transfers: TransferRecord[] }>('/node/wallet/transfers');
      } catch (error) {
        if (error instanceof HttpError) {
          throw error;
        }
        console.warn('Falling back to mock payload for /node/wallet/transfers', error);
        return { transfers: mockTransfers };
      }
    },
    refetchInterval: 8000,
    placeholderData: { transfers: mockTransfers },
  });

  const mutation = useMutation({
    mutationFn: async (payload: { address: string; amount: number; fee: number; memo?: string }) => {
      try {
        return await fetchJson<{ transfer: TransferRecord }>(`/node/wallet/transfers`, {
          method: 'POST',
          headers: SERVICE_HEADERS,
          body: JSON.stringify(payload),
        });
      } catch (error) {
        if (error instanceof HttpError) {
          throw error;
        }
        console.warn('Wallet API unavailable, returning mock transfer record', error);
        const txId = `mock-${Date.now()}`;
        return {
          transfer: {
            id: txId,
            tx_id: txId,
            direction: 'outgoing',
            address: payload.address,
            memo: payload.memo ?? null,
            amount: payload.amount,
            fee: payload.fee,
            status: 'pending',
            confirmations: 0,
            created_at: new Date().toISOString(),
          },
        } satisfies { transfer: TransferRecord };
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['wallet-transfers'] });
    },
  });

  return { ...query, submitTransfer: mutation };
}

function appendPoint(series: TelemetryPoint[], value: number, maxSamples: number): TelemetryPoint[] {
  const next = [...series, { timestamp: Date.now(), value }];
  return next.slice(-maxSamples);
}

export function useNodeEventStream(maxSamples = 32) {
  const [events, setEvents] = useState<NodeEvent[]>([]);
  const [hashRateSeries, setHashRateSeries] = useState<TelemetryPoint[]>([]);
  const [mempoolSeries, setMempoolSeries] = useState<TelemetryPoint[]>([]);
  const [difficultySeries, setDifficultySeries] = useState<TelemetryPoint[]>([]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return () => undefined;
    }
    let source: EventSource | null = null;
    let retryHandle: number | undefined;

    const connect = () => {
      source = new EventSource(`${dashboardServiceUrl}/node/events/stream`);
      source.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data) as NodeEvent;
          setEvents((prev) => [payload, ...prev].slice(0, maxSamples));
          if (payload.type === 'telemetry') {
            setHashRateSeries((prev) => appendPoint(prev, payload.hash_rate, maxSamples));
            setMempoolSeries((prev) => appendPoint(prev, payload.mempool_depth, maxSamples));
            setDifficultySeries((prev) => appendPoint(prev, payload.difficulty_bits, maxSamples));
          }
        } catch (error) {
          console.error('Failed to parse node event', error);
        }
      };
      source.onerror = () => {
        source?.close();
        if (retryHandle) {
          window.clearTimeout(retryHandle);
        }
        retryHandle = window.setTimeout(connect, 2500);
      };
    };

    connect();

    return () => {
      source?.close();
      if (retryHandle) {
        window.clearTimeout(retryHandle);
      }
    };
  }, [maxSamples]);

  const latestTelemetry = useMemo(() => events.find((event) => event.type === 'telemetry'), [events]);

  return { events, hashRateSeries, mempoolSeries, difficultySeries, latestTelemetry };
}
