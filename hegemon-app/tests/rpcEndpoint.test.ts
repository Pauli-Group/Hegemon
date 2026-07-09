import { describe, expect, it } from 'vitest';
import {
  normalizeLoopbackWalletOneShotRpcEndpoint,
  normalizeLoopbackWalletRpcEndpoint
} from '../electron/rpcEndpoint';

describe('normalizeLoopbackWalletRpcEndpoint', () => {
  it('accepts loopback ws/http endpoints', () => {
    expect(normalizeLoopbackWalletRpcEndpoint('ws://127.0.0.1:9944')).toBe('ws://127.0.0.1:9944/');
    expect(normalizeLoopbackWalletRpcEndpoint('http://localhost:9944/rpc')).toBe(
      'http://localhost:9944/rpc'
    );
    expect(normalizeLoopbackWalletRpcEndpoint('ws://[::1]:9944')).toBe('ws://[::1]:9944/');
  });

  it('trims surrounding whitespace', () => {
    expect(normalizeLoopbackWalletRpcEndpoint('  ws://127.0.0.1:9944  ')).toBe(
      'ws://127.0.0.1:9944/'
    );
  });

  it('rejects empty and malformed endpoints', () => {
    expect(() => normalizeLoopbackWalletRpcEndpoint('')).toThrow(/required/);
    expect(() => normalizeLoopbackWalletRpcEndpoint('   ')).toThrow(/required/);
    expect(() => normalizeLoopbackWalletRpcEndpoint('not a url')).toThrow(/valid URL/);
  });

  it('rejects non-loopback hosts', () => {
    expect(() => normalizeLoopbackWalletRpcEndpoint('ws://example.com:9944')).toThrow(/loopback/);
    expect(() => normalizeLoopbackWalletRpcEndpoint('ws://192.168.1.10:9944')).toThrow(/loopback/);
    expect(() => normalizeLoopbackWalletRpcEndpoint('ws://0.0.0.0:9944')).toThrow(/loopback/);
  });

  it('rejects unsupported protocols', () => {
    expect(() => normalizeLoopbackWalletRpcEndpoint('ftp://127.0.0.1:9944')).toThrow(
      /must use ws, wss, http, or https/
    );
    expect(() => normalizeLoopbackWalletRpcEndpoint('file:///etc/passwd')).toThrow(
      /must use ws, wss, http, or https/
    );
  });

  it('rejects credentials and fragments', () => {
    expect(() => normalizeLoopbackWalletRpcEndpoint('ws://user:pass@127.0.0.1:9944')).toThrow(
      /credentials or fragments/
    );
    expect(() => normalizeLoopbackWalletRpcEndpoint('ws://127.0.0.1:9944/#frag')).toThrow(
      /credentials or fragments/
    );
  });

  it('is case-insensitive on hostnames', () => {
    expect(normalizeLoopbackWalletRpcEndpoint('ws://LOCALHOST:9944')).toBe('ws://localhost:9944/');
  });
});

describe('normalizeLoopbackWalletOneShotRpcEndpoint', () => {
  it('maps ws to http and wss to https', () => {
    expect(normalizeLoopbackWalletOneShotRpcEndpoint('ws://127.0.0.1:9944')).toBe(
      'http://127.0.0.1:9944/'
    );
    expect(normalizeLoopbackWalletOneShotRpcEndpoint('wss://127.0.0.1:9944')).toBe(
      'https://127.0.0.1:9944/'
    );
  });

  it('passes through http endpoints', () => {
    expect(normalizeLoopbackWalletOneShotRpcEndpoint('http://127.0.0.1:9944')).toBe(
      'http://127.0.0.1:9944/'
    );
  });

  it('still enforces loopback', () => {
    expect(() => normalizeLoopbackWalletOneShotRpcEndpoint('ws://example.com:9944')).toThrow(
      /loopback/
    );
  });
});
