import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { defaultDashboardServiceUrl, sanitizeBaseUrl } from '../config';

export type NodeProtocol = 'http' | 'https';

export interface NodeEndpoint {
  protocol: NodeProtocol;
  host: string;
  port: number;
  authToken?: string;
}

interface NodeConnectionContextValue {
  endpoint: NodeEndpoint;
  serviceUrl: string;
  setEndpoint: (endpoint: NodeEndpoint) => void;
  markActiveEndpoint: (endpoint: NodeEndpoint) => void;
  authToken?: string;
}

const STORAGE_KEY = 'shc.dashboard.endpoint';

const DEFAULT_ENDPOINT: NodeEndpoint = (() => {
  try {
    const parsed = new URL(defaultDashboardServiceUrl);
    return {
      protocol: parsed.protocol === 'https:' ? 'https' : 'http',
      host: parsed.hostname,
      port: parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80,
    } satisfies NodeEndpoint;
  } catch {
    return { protocol: 'http', host: 'localhost', port: 8001 } satisfies NodeEndpoint;
  }
})();

function endpointToUrl(endpoint: NodeEndpoint): string {
  return sanitizeBaseUrl(`${endpoint.protocol}://${endpoint.host}:${endpoint.port}`);
}

function readStoredEndpoint(): NodeEndpoint | null {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<NodeEndpoint>;
    if (!parsed.host || !parsed.port || !parsed.protocol) return null;
    return {
      protocol: parsed.protocol === 'https' ? 'https' : 'http',
      host: parsed.host,
      port: Number(parsed.port),
      authToken: parsed.authToken,
    } satisfies NodeEndpoint;
  } catch (error) {
    console.warn('Failed to parse stored endpoint', error);
    return null;
  }
}

const NodeConnectionContext = createContext<NodeConnectionContextValue | undefined>(undefined);

export function NodeConnectionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [endpoint, setEndpointState] = useState<NodeEndpoint>(() => readStoredEndpoint() ?? DEFAULT_ENDPOINT);

  const setEndpoint = (value: NodeEndpoint) => {
    setEndpointState(value);
    if (typeof window !== 'undefined') {
      try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
      } catch (error) {
        console.warn('Failed to persist endpoint selection', error);
      }
    }
  };

  const serviceUrl = useMemo(() => endpointToUrl(endpoint), [endpoint]);

  useEffect(() => {
    queryClient.invalidateQueries();
  }, [queryClient, serviceUrl]);

  const value = useMemo(
    () => ({ endpoint, serviceUrl, setEndpoint, markActiveEndpoint: setEndpoint, authToken: endpoint.authToken }),
    [endpoint, serviceUrl],
  );

  return <NodeConnectionContext.Provider value={value}>{children}</NodeConnectionContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useNodeConnection() {
  const context = useContext(NodeConnectionContext);
  if (!context) {
    throw new Error('useNodeConnection must be used within a NodeConnectionProvider');
  }
  return context;
}
