import { describe, expect, it } from 'vitest';
import {
  buildDefaultConnection,
  deriveHttpUrl,
  isLoopbackRpcEndpoint,
  normalizeConnection,
  normalizeLocalConnectionEndpoints,
  rewriteLoopbackRpcEndpoint,
  shouldAutoStartDefaultProfile
} from '../src/lib/connections';
import { defaultRpcPort, defaultRpcUrl } from '../src/lib/config';
import type { NodeConnection } from '../src/types';

const local = (overrides: Partial<NodeConnection> = {}): NodeConnection => ({
  ...buildDefaultConnection(),
  ...overrides
});

describe('native desktop HTTP defaults', () => {
  it('creates an HTTP managed profile that can still auto-start', () => {
    const connection = buildDefaultConnection();
    expect(defaultRpcUrl).toBe(`http://127.0.0.1:${defaultRpcPort}`);
    expect(connection.wsUrl).toBe(defaultRpcUrl);
    expect(connection.httpUrl).toBe(defaultRpcUrl);
    expect(shouldAutoStartDefaultProfile(connection)).toBe(true);
  });

  it('fills an omitted endpoint with HTTP on the selected native RPC port', () => {
    const connection = normalizeLocalConnectionEndpoints(local({ wsUrl: '', httpUrl: '', rpcPort: 9966 }));
    expect(connection.wsUrl).toBe('http://127.0.0.1:9966');
    expect(connection.httpUrl).toBe('http://127.0.0.1:9966');
  });

  it('retains explicit saved WebSocket URLs and their default-profile behavior', () => {
    const endpoint = `ws://localhost:${defaultRpcPort}/rpc?client=wallet`;
    const connection = normalizeConnection(local({ wsUrl: endpoint }));
    expect(connection.wsUrl).toBe(endpoint);
    expect(shouldAutoStartDefaultProfile(connection)).toBe(true);
    expect(deriveHttpUrl(endpoint)).toBe(`http://localhost:${defaultRpcPort}/rpc?client=wallet`);
  });

  it('keeps HTTP endpoints aligned when the managed RPC port changes', () => {
    const connection = normalizeLocalConnectionEndpoints(local({
      wsUrl: 'http://127.0.0.1:9955/rpc?client=wallet',
      httpUrl: 'http://127.0.0.1:9955/rpc?client=wallet',
      rpcPort: 9966
    }));
    expect(connection.wsUrl).toBe('http://127.0.0.1:9966/rpc?client=wallet');
    expect(connection.httpUrl).toBe('http://127.0.0.1:9966/rpc?client=wallet');
  });

  it('keeps saved WebSocket protocol and route during legacy default-port migration', () => {
    const connection = normalizeConnection(local({
      wsUrl: 'ws://localhost:9944/rpc?client=wallet',
      httpUrl: 'http://localhost:9944/rpc?client=wallet',
      rpcPort: 9944
    }));
    expect(connection.rpcPort).toBe(defaultRpcPort);
    expect(connection.wsUrl).toBe(`ws://localhost:${defaultRpcPort}/rpc?client=wallet`);
    expect(connection.httpUrl).toBe(`http://localhost:${defaultRpcPort}/rpc?client=wallet`);
  });

  it('derives the matching HTTP port for an IPv6 loopback primary endpoint', () => {
    expect(deriveHttpUrl('http://[::1]:9966/rpc', 'http://[::1]:9955/rpc')).toBe(
      'http://[::1]:9966/rpc'
    );
  });

  it('does not reinterpret an explicit external endpoint as a managed default', () => {
    const connection = local({ wsUrl: 'http://example.com:9955' });
    expect(shouldAutoStartDefaultProfile(connection)).toBe(false);
    expect(normalizeLocalConnectionEndpoints(connection).wsUrl).toBe(connection.wsUrl);
  });

  it('leaves explicit remote profiles unchanged during local endpoint alignment', () => {
    const connection = local({ mode: 'remote', wsUrl: 'wss://localhost:9944/events', rpcPort: 9966 });
    expect(normalizeLocalConnectionEndpoints(connection)).toBe(connection);
  });
});

describe('loopback RPC port changes', () => {
  it.each([
    ['http://127.0.0.1:9955/rpc?client=wallet', 'http://127.0.0.1:9966/rpc?client=wallet'],
    ['https://localhost:9955/rpc', 'https://localhost:9966/rpc'],
    ['http://[::1]:9955/rpc', 'http://[::1]:9966/rpc'],
    ['ws://localhost:9955/events', 'ws://localhost:9966/events'],
    ['wss://[::1]:9955/events?client=wallet', 'wss://[::1]:9966/events?client=wallet']
  ])('preserves protocol, host and route for %s', (endpoint, expected) => {
    expect(isLoopbackRpcEndpoint(endpoint)).toBe(true);
    expect(rewriteLoopbackRpcEndpoint(endpoint, 9966)).toBe(expected);
  });

  it.each([
    'http://example.com:9955',
    'http://127.0.0.1:9955@example.com',
    'http://user:pass@localhost:9955',
    'http://localhost:9955/#fragment',
    'ftp://localhost:9955',
    'not a URL'
  ])('refuses to rewrite an untrusted or malformed endpoint: %s', (endpoint) => {
    expect(isLoopbackRpcEndpoint(endpoint)).toBe(false);
    expect(rewriteLoopbackRpcEndpoint(endpoint, 9966)).toBe(endpoint);
  });

  it('leaves the endpoint unchanged for invalid ports', () => {
    for (const port of [0, -1, 65536, 1.5]) {
      expect(rewriteLoopbackRpcEndpoint(defaultRpcUrl, port)).toBe(defaultRpcUrl);
    }
  });
});
