"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { ApiPromise, WsProvider } from "@polkadot/api";
import { typesBundle } from "@/lib/types";

interface ApiContextValue {
  api: ApiPromise | null;
  isConnected: boolean;
  isConnecting: boolean;
  error: string | null;
  endpoint: string;
}

const ApiContext = createContext<ApiContextValue>({
  api: null,
  isConnected: false,
  isConnecting: true,
  error: null,
  endpoint: "ws://127.0.0.1:9944",
});

export function useApi() {
  return useContext(ApiContext);
}

interface ApiProviderProps {
  children: ReactNode;
  endpoint?: string;
}

export function ApiProvider({ 
  children, 
  endpoint = "ws://127.0.0.1:9944" 
}: ApiProviderProps) {
  const [api, setApi] = useState<ApiPromise | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    let apiInstance: ApiPromise | null = null;

    async function connect() {
      try {
        setIsConnecting(true);
        setError(null);

        const provider = new WsProvider(endpoint);
        apiInstance = await ApiPromise.create({ 
          provider, 
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          typesBundle: typesBundle as any
        });

        if (!mounted) {
          await apiInstance.disconnect();
          return;
        }

        setApi(apiInstance);
        setIsConnected(true);
        setIsConnecting(false);

        // Handle disconnection
        apiInstance.on("disconnected", () => {
          if (mounted) {
            setIsConnected(false);
            setError("Disconnected from node");
          }
        });

        apiInstance.on("connected", () => {
          if (mounted) {
            setIsConnected(true);
            setError(null);
          }
        });

      } catch (err) {
        if (mounted) {
          setError(err instanceof Error ? err.message : "Connection failed");
          setIsConnecting(false);
        }
      }
    }

    connect();

    return () => {
      mounted = false;
      if (apiInstance) {
        apiInstance.disconnect();
      }
    };
  }, [endpoint]);

  return (
    <ApiContext.Provider value={{ api, isConnected, isConnecting, error, endpoint }}>
      {children}
    </ApiContext.Provider>
  );
}
