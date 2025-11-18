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

const NodeConnectionContext = createContext<NodeConnectionContextValue | undefined>(undefined);

export function NodeConnectionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  // Always pin to the service endpoint derived from VITE_DASHBOARD_SERVICE_URL/DEFAULT.
  const [endpoint, setEndpointState] = useState<NodeEndpoint>(DEFAULT_ENDPOINT);

  const setEndpoint = (value: NodeEndpoint) => {
    setEndpointState({ ...DEFAULT_ENDPOINT, authToken: value.authToken });
  };

  const serviceUrl = useMemo(() => endpointToUrl(endpoint), [endpoint]);

  useEffect(() => {
    queryClient.invalidateQueries();
  }, [queryClient, serviceUrl]);

  const value = useMemo(
    () => ({
      endpoint,
      serviceUrl,
      setEndpoint,
      // Only update auth token; keep host/port pinned to the service URL.
      markActiveEndpoint: (value: NodeEndpoint) =>
        setEndpointState((prev) => ({
          ...prev,
          authToken: value.authToken ?? prev.authToken,
        })),
      authToken: endpoint.authToken,
    }),
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
