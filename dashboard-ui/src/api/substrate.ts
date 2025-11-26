/**
 * Substrate API client for Hegemon dashboard.
 * Provides WebSocket connection to Substrate node with custom RPC methods.
 */

import { ApiPromise, WsProvider } from '@polkadot/api';
import type { Header } from '@polkadot/types/interfaces';
import { hegemonTypesBundle, hegemonRpcMethods } from './types';

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error';

export interface SubstrateApiConfig {
  endpoint: string;
  autoReconnect?: boolean;
  reconnectDelay?: number;
}

const DEFAULT_CONFIG: SubstrateApiConfig = {
  endpoint: 'ws://127.0.0.1:9944',
  autoReconnect: true,
  reconnectDelay: 2500,
};

/**
 * Singleton API manager for Substrate connection
 */
class SubstrateApiManager {
  private api: ApiPromise | null = null;
  private provider: WsProvider | null = null;
  private config: SubstrateApiConfig = DEFAULT_CONFIG;
  private connectionState: ConnectionState = 'disconnected';
  private listeners: Set<(state: ConnectionState) => void> = new Set();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * Initialize or update the API connection
   */
  async connect(config?: Partial<SubstrateApiConfig>): Promise<ApiPromise> {
    if (config) {
      this.config = { ...this.config, ...config };
    }

    // If already connected to same endpoint, return existing API
    if (this.api && this.provider && this.connectionState === 'connected') {
      const currentEndpoint = this.provider.endpoint;
      if (currentEndpoint === this.config.endpoint) {
        return this.api;
      }
      // Endpoint changed, disconnect first
      await this.disconnect();
    }

    this.setConnectionState('connecting');

    try {
      this.provider = new WsProvider(this.config.endpoint);

      // Set up provider event handlers
      this.provider.on('connected', () => {
        this.setConnectionState('connected');
      });

      this.provider.on('disconnected', () => {
        this.setConnectionState('disconnected');
        if (this.config.autoReconnect) {
          this.scheduleReconnect();
        }
      });

      this.provider.on('error', (error) => {
        console.error('WebSocket error:', error);
        this.setConnectionState('error');
      });

      this.api = await ApiPromise.create({
        provider: this.provider,
        typesBundle: hegemonTypesBundle,
        rpc: hegemonRpcMethods,
      });

      // Wait for the API to be ready
      await this.api.isReady;
      this.setConnectionState('connected');

      return this.api;
    } catch (error) {
      console.error('Failed to connect to Substrate node:', error);
      this.setConnectionState('error');
      if (this.config.autoReconnect) {
        this.scheduleReconnect();
      }
      throw error;
    }
  }

  /**
   * Disconnect from the Substrate node
   */
  async disconnect(): Promise<void> {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.api) {
      await this.api.disconnect();
      this.api = null;
    }

    if (this.provider) {
      await this.provider.disconnect();
      this.provider = null;
    }

    this.setConnectionState('disconnected');
  }

  /**
   * Get the current API instance
   */
  getApi(): ApiPromise | null {
    return this.api;
  }

  /**
   * Get current connection state
   */
  getConnectionState(): ConnectionState {
    return this.connectionState;
  }

  /**
   * Subscribe to connection state changes
   */
  onConnectionStateChange(callback: (state: ConnectionState) => void): () => void {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  private setConnectionState(state: ConnectionState): void {
    this.connectionState = state;
    this.listeners.forEach((listener) => listener(state));
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      try {
        await this.connect();
      } catch {
        // Error handled in connect()
      }
    }, this.config.reconnectDelay);
  }
}

// Export singleton instance
export const substrateApi = new SubstrateApiManager();

/**
 * Create a new API connection (for use in React context)
 */
export async function createApi(endpoint: string): Promise<ApiPromise> {
  return substrateApi.connect({ endpoint });
}

/**
 * Subscribe to new block headers
 */
export function subscribeNewHeads(
  api: ApiPromise,
  callback: (header: Header) => void,
): () => void {
  let unsubscribe: (() => void) | null = null;

  api.rpc.chain.subscribeNewHeads((header) => {
    callback(header);
  }).then((unsub) => {
    unsubscribe = unsub;
  }).catch((error) => {
    console.error('Failed to subscribe to new heads:', error);
  });

  return () => {
    if (unsubscribe) {
      unsubscribe();
    }
  };
}

/**
 * Subscribe to finalized block headers
 */
export function subscribeFinalizedHeads(
  api: ApiPromise,
  callback: (header: Header) => void,
): () => void {
  let unsubscribe: (() => void) | null = null;

  api.rpc.chain.subscribeFinalizedHeads((header) => {
    callback(header);
  }).then((unsub) => {
    unsubscribe = unsub;
  }).catch((error) => {
    console.error('Failed to subscribe to finalized heads:', error);
  });

  return () => {
    if (unsubscribe) {
      unsubscribe();
    }
  };
}

/**
 * Utility: Convert block number from hex string
 */
export function parseBlockNumber(header: Header): number {
  return header.number.toNumber();
}

/**
 * Utility: Get block hash as string
 */
export function getBlockHash(header: Header): string {
  return header.hash.toHex();
}
