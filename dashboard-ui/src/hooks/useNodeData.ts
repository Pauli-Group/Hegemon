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

export class HttpError extends Error {
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

export interface FallbackResult<T> {
  data: T;
  source: 'live' | 'mock';
  error?: Error;
}

interface GetOrFallbackOptions {
  detectMockData?: boolean;
}

function normalizeForComparison(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeForComparison(item));
  }
  if (value && typeof value === 'object') {
    return Object.keys(value as Record<string, unknown>)
      .sort()
      .reduce<Record<string, unknown>>((acc, key) => {
        acc[key] = normalizeForComparison((value as Record<string, unknown>)[key]);
        return acc;
      }, {});
  }
  return value;
}

function isDeepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(normalizeForComparison(a)) === JSON.stringify(normalizeForComparison(b));
}

async function getOrFallback<T>(
  path: string,
  fallback: T,
  options: GetOrFallbackOptions = { detectMockData: true },
): Promise<FallbackResult<T>> {
  try {
    const raw = await fetchJson<T & { __mock_source?: boolean }>(path);
    const { __mock_source, ...rest } = raw;
    const data = rest as T;
    const shouldMarkMock = FORCE_MOCK_INDICATOR || (options.detectMockData && ((__mock_source ?? false) || isDeepEqual(data, fallback)));
    return { data, source: shouldMarkMock ? 'mock' : 'live' } satisfies FallbackResult<T>;
  } catch (error) {
    const normalizedError = error instanceof Error ? error : new Error('Unknown error');
    console.warn(`Falling back to mock payload for ${path}`, error);
    return { data: fallback, source: 'mock', error: normalizedError } satisfies FallbackResult<T>;
  }
}

export function useNodeMetrics() {
  return useQuery<FallbackResult<TelemetrySnapshot>>({
    queryKey: ['node-metrics'],
    queryFn: () => getOrFallback('/node/metrics', mockTelemetry),
    refetchInterval: 5000,
    placeholderData: { data: mockTelemetry, source: 'mock' },
  });
}

export function useWalletNotes() {
  return useQuery<FallbackResult<NoteStatus>>({
    queryKey: ['wallet-notes'],
    queryFn: () => getOrFallback('/node/wallet/notes', mockNotes),
    refetchInterval: 7000,
    placeholderData: { data: mockNotes, source: 'mock' },
  });
}

export function useMinerStatus() {
  const queryClient = useQueryClient();
  const query = useQuery<FallbackResult<MinerStatus>>({
    queryKey: ['miner-status'],
    queryFn: () => getOrFallback('/node/miner/status', mockMinerStatus),
    refetchInterval: 4000,
    placeholderData: { data: mockMinerStatus, source: 'mock' },
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
  const query = useQuery<FallbackResult<{ transfers: TransferRecord[] }>>({
    queryKey: ['wallet-transfers'],
    queryFn: () => getOrFallback('/node/wallet/transfers', { transfers: mockTransfers }),
    refetchInterval: 8000,
    placeholderData: { data: { transfers: mockTransfers }, source: 'mock' },
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

export type NodeLifecycleMode = 'genesis' | 'join';

export interface NodeRoutingConfig {
  tls: boolean;
  doh: boolean;
  vpn: boolean;
  tor: boolean;
  mtls: boolean;
  localOnly: boolean;
}

export interface NodeLifecyclePayload {
  mode: NodeLifecycleMode;
  host: string;
  port: number;
  peer_url?: string;
  routing: {
    tls: boolean;
    doh: boolean;
    vpn: boolean;
    tor: boolean;
    mtls: boolean;
    local_only: boolean;
  };
}

export interface NodeLifecycleResponse {
  status: string;
  mode: NodeLifecycleMode;
  node_url: string;
  peer_url?: string | null;
  routing: NodeLifecyclePayload['routing'];
  overlays?: string[];
  local_rpc_only: boolean;
  applied_at?: string;
}

export function useNodeLifecycle() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: NodeLifecyclePayload) =>
      fetchJson<NodeLifecycleResponse>('/node/lifecycle', {
        method: 'POST',
        headers: SERVICE_HEADERS,
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['node-metrics'] });
      queryClient.invalidateQueries({ queryKey: ['miner-status'] });
    },
  });
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
const FORCE_MOCK_INDICATOR = import.meta.env.VITE_FORCE_MOCK_DATA_INDICATOR === 'true';

