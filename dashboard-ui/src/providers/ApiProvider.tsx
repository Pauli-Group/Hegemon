"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { ApiPromise, WsProvider } from "@polkadot/api";
import { cryptoWaitReady } from "@polkadot/util-crypto";

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

// Default endpoint from environment or localhost
const DEFAULT_ENDPOINT = process.env.NEXT_PUBLIC_NODE_ENDPOINT || "ws://127.0.0.1:9944";

export function ApiProvider({ 
  children, 
  endpoint = DEFAULT_ENDPOINT 
}: ApiProviderProps) {
  const [api, setApi] = useState<ApiPromise | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    // Timeout wrapper
    function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
      return Promise.race([
        promise,
        new Promise<T>((_, reject) => 
          setTimeout(() => reject(new Error(message)), ms)
        )
      ]);
    }

    async function connect() {
      try {
        setIsConnecting(true);
        setError(null);
        
        console.log("[ApiProvider] Initializing crypto...");
        await withTimeout(cryptoWaitReady(), 10000, "Crypto initialization timeout");
        console.log("[ApiProvider] Crypto ready, connecting to", endpoint);

        const provider = new WsProvider(endpoint);
        
        // Create API with timeout
        console.log("[ApiProvider] Creating API...");
        const apiInstance = await withTimeout(
          ApiPromise.create({ provider, noInitWarn: true }),
          15000,
          "API connection timeout - is the node running?"
        );

        if (!mounted) {
          await apiInstance.disconnect();
          return;
        }
        
        console.log("[ApiProvider] API ready, chain:", apiInstance.runtimeChain.toString());

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
        console.error("[ApiProvider] Connection error:", err);
        if (mounted) {
          setError(err instanceof Error ? err.message : "Connection failed");
          setIsConnecting(false);
        }
      }
    }

    connect();

    return () => {
      mounted = false;
      // Cleanup will happen via api state - component unmounts
    };
  }, [endpoint]);

  // Cleanup api on unmount
  useEffect(() => {
    return () => {
      if (api) {
        api.disconnect();
      }
    };
  }, [api]);

  return (
    <ApiContext.Provider value={{ api, isConnected, isConnecting, error, endpoint }}>
      {children}
    </ApiContext.Provider>
  );
}
