/**
 * SubstrateApiProvider - React context for Substrate API connection.
 * Replaces the HTTP-based NodeConnectionProvider with WebSocket-based Substrate RPC.
 */

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  useMemo,
  type ReactNode,
} from 'react';
import { ApiPromise, WsProvider } from '@polkadot/api';
import type { Header, Health } from '@polkadot/types/interfaces';
import { hegemonTypesBundle, hegemonRpcMethods } from '../api/types';

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error';

export interface SubstrateApiContextValue {
  /** The Polkadot.js API instance */
  api: ApiPromise | null;
  /** Current connection state */
  connectionState: ConnectionState;
  /** WebSocket endpoint URL */
  endpoint: string;
  /** Set the WebSocket endpoint (will trigger reconnection) */
  setEndpoint: (endpoint: string) => void;
  /** Manually reconnect */
  reconnect: () => Promise<void>;
  /** Disconnect from the node */
  disconnect: () => Promise<void>;
  /** Last error message */
  error: string | null;
  /** Current block number (from subscription) */
  blockNumber: number;
  /** Current block hash */
  blockHash: string;
  /** Node health information */
  health: Health | null;
  /** Connected peer count */
  peerCount: number;
  /** Whether the node is syncing */
  isSyncing: boolean;
}

const SubstrateApiContext = createContext<SubstrateApiContextValue | undefined>(undefined);

// Default WebSocket endpoint from environment or localhost
const DEFAULT_WS_ENDPOINT =
  import.meta.env.VITE_WS_ENDPOINT || 'ws://127.0.0.1:9944';

interface SubstrateApiProviderProps {
  children: ReactNode;
  /** Initial WebSocket endpoint (optional, uses VITE_WS_ENDPOINT or localhost) */
  initialEndpoint?: string;
}

export function SubstrateApiProvider({
  children,
  initialEndpoint = DEFAULT_WS_ENDPOINT,
}: SubstrateApiProviderProps) {
  const [api, setApi] = useState<ApiPromise | null>(null);
  const [provider, setProvider] = useState<WsProvider | null>(null);
  const [connectionState, setConnectionState] = useState<ConnectionState>('disconnected');
  const [endpoint, setEndpointState] = useState(initialEndpoint);
  const [error, setError] = useState<string | null>(null);
  const [blockNumber, setBlockNumber] = useState(0);
  const [blockHash, setBlockHash] = useState('');
  const [health, setHealth] = useState<Health | null>(null);
  const [peerCount, setPeerCount] = useState(0);
  const [isSyncing, setIsSyncing] = useState(false);

  // Connect to the Substrate node
  const connect = useCallback(async (wsEndpoint: string) => {
    setConnectionState('connecting');
    setError(null);

    try {
      const wsProvider = new WsProvider(wsEndpoint);
      setProvider(wsProvider);

      // Handle provider events
      wsProvider.on('connected', () => {
        console.log('WebSocket connected to', wsEndpoint);
      });

      wsProvider.on('disconnected', () => {
        console.log('WebSocket disconnected');
        setConnectionState('disconnected');
      });

      wsProvider.on('error', (err: Error) => {
        console.error('WebSocket error:', err);
        setError(err.message);
        setConnectionState('error');
      });

      // Create API with custom types
      const apiInstance = await ApiPromise.create({
        provider: wsProvider,
        typesBundle: hegemonTypesBundle,
        rpc: hegemonRpcMethods,
      });

      await apiInstance.isReady;
      setApi(apiInstance);
      setConnectionState('connected');

      // Get initial system health
      try {
        const healthResult = await apiInstance.rpc.system.health();
        setHealth(healthResult);
        setIsSyncing(healthResult.isSyncing.isTrue);
        setPeerCount(healthResult.peers.toNumber());
      } catch (err) {
        console.warn('Failed to get system health:', err);
      }

      // Subscribe to new block headers
      const unsubHeads = await apiInstance.rpc.chain.subscribeNewHeads(
        (header: Header) => {
          setBlockNumber(header.number.toNumber());
          setBlockHash(header.hash.toHex());
        }
      );

      // Periodic health check
      const healthInterval = setInterval(async () => {
        if (apiInstance.isConnected) {
          try {
            const h = await apiInstance.rpc.system.health();
            setHealth(h);
            setIsSyncing(h.isSyncing.isTrue);
            setPeerCount(h.peers.toNumber());
          } catch {
            // Ignore transient errors
          }
        }
      }, 10000);

      // Return cleanup function
      return () => {
        unsubHeads();
        clearInterval(healthInterval);
      };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to connect';
      setError(errorMessage);
      setConnectionState('error');
      console.error('Failed to connect to Substrate node:', err);
      throw err;
    }
  }, []);

  // Disconnect from the node
  const disconnect = useCallback(async () => {
    if (api) {
      await api.disconnect();
      setApi(null);
    }
    if (provider) {
      await provider.disconnect();
      setProvider(null);
    }
    setConnectionState('disconnected');
    setBlockNumber(0);
    setBlockHash('');
    setHealth(null);
    setPeerCount(0);
    setIsSyncing(false);
  }, [api, provider]);

  // Reconnect with current endpoint
  const reconnect = useCallback(async () => {
    await disconnect();
    await connect(endpoint);
  }, [connect, disconnect, endpoint]);

  // Update endpoint and reconnect
  const setEndpoint = useCallback(
    (newEndpoint: string) => {
      if (newEndpoint !== endpoint) {
        setEndpointState(newEndpoint);
      }
    },
    [endpoint]
  );

  // Connect on mount and when endpoint changes
  useEffect(() => {
    let cleanup: (() => void) | undefined;

    connect(endpoint)
      .then((cleanupFn) => {
        cleanup = cleanupFn;
      })
      .catch(() => {
        // Error already handled in connect()
      });

    return () => {
      cleanup?.();
      disconnect();
    };
  }, [endpoint]); // eslint-disable-line react-hooks/exhaustive-deps

  const value = useMemo(
    () => ({
      api,
      connectionState,
      endpoint,
      setEndpoint,
      reconnect,
      disconnect,
      error,
      blockNumber,
      blockHash,
      health,
      peerCount,
      isSyncing,
    }),
    [
      api,
      connectionState,
      endpoint,
      setEndpoint,
      reconnect,
      disconnect,
      error,
      blockNumber,
      blockHash,
      health,
      peerCount,
      isSyncing,
    ]
  );

  return (
    <SubstrateApiContext.Provider value={value}>
      {children}
    </SubstrateApiContext.Provider>
  );
}

/**
 * Hook to access the Substrate API context
 */
export function useSubstrateApi(): SubstrateApiContextValue {
  const context = useContext(SubstrateApiContext);
  if (!context) {
    throw new Error('useSubstrateApi must be used within a SubstrateApiProvider');
  }
  return context;
}

/**
 * Hook to get the ready API instance (throws if not connected)
 */
export function useApi(): ApiPromise {
  const { api, connectionState } = useSubstrateApi();
  if (!api || connectionState !== 'connected') {
    throw new Error('Substrate API is not connected');
  }
  return api;
}

/**
 * Hook to check if API is ready
 */
export function useIsApiReady(): boolean {
  const { api, connectionState } = useSubstrateApi();
  return api !== null && connectionState === 'connected';
}
