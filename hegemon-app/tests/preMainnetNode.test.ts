import { EventEmitter } from 'node:events';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { NodeStartOptions } from '../src/types';

const mocks = vi.hoisted(() => ({
  spawn: vi.fn(),
  nodePath: vi.fn(() => '/test/hegemon-node'),
  manifestPath: vi.fn(() => '/test/pinned-manifest.json')
}));
vi.mock('node:child_process', () => ({ spawn: mocks.spawn }));
vi.mock('../electron/binPaths', () => ({
  resolveBinaryPath: mocks.nodePath,
  resolvePreMainnetManifestPath: mocks.manifestPath
}));

import { NodeManager } from '../electron/nodeManager';

const SEEDS = 'hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333';
const options = (overrides: Partial<NodeStartOptions> = {}): NodeStartOptions => ({
  connectionId: 'public-testnet', networkProfile: 'pre-mainnet',
  basePath: '~/.hegemon-node-v0.11', dev: false, tmp: false, seeds: SEEDS,
  rpcExternal: false, rpcCorsAll: false, mineOnStart: false,
  ...overrides
});

function managerWithFakeProcess() {
  const child = Object.assign(new EventEmitter(), {
    stdout: new EventEmitter(), stderr: new EventEmitter(), pid: 12345, exitCode: null
  });
  mocks.spawn.mockReturnValue(child);
  const manager = new NodeManager();
  vi.spyOn(manager as unknown as { ping: () => Promise<boolean> }, 'ping').mockResolvedValue(false);
  return manager;
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.manifestPath.mockImplementation(() => '/test/pinned-manifest.json');
});

describe('managed v0.11 relay launch', () => {
  it('launches the selected profile with the pinned manifest and private RPC', async () => {
    const manager = managerWithFakeProcess();
    await manager.startNode(options());
    expect(mocks.manifestPath).toHaveBeenCalledOnce();
    expect(mocks.spawn).toHaveBeenCalledOnce();
    const [path, args, launch] = mocks.spawn.mock.calls[0] as [string, string[], { env: NodeJS.ProcessEnv }];
    expect(path).toBe('/test/hegemon-node');
    expect(args).toContain('--network');
    expect(args[args.indexOf('--network') + 1]).toBe('pre-mainnet');
    expect(args[args.indexOf('--network-manifest') + 1]).toBe('/test/pinned-manifest.json');
    expect(args[args.indexOf('--rpc-methods') + 1]).toBe('unsafe');
    expect(args).not.toContain('--dev');
    expect(args).not.toContain('--tmp');
    expect(args).not.toContain('--rpc-external');
    expect(args).not.toContain('--rpc-cors=all');
    expect(launch.env.HEGEMON_MINE).toBe('0');
    expect(launch.env.HEGEMON_SEEDS).toBe(SEEDS);
    await expect(manager.setMiningEnabled(true, 1)).rejects.toThrow(/does not enable mining/);
    await expect(manager.startNode(options({ connectionId: 'other' }))).rejects.toThrow(/other connection profile/);
  });

  it.each([
    { dev: true }, { tmp: true }, { rpcExternal: true }, { rpcCorsAll: true },
    { mineOnStart: true }, { basePath: undefined }, { basePath: '~/.hegemon-node-native-010-dev' },
    { basePath: '~/.hegemon-node-testnet' }, { seeds: 'unknown.example:30333' }
  ])('refuses unsafe or incompatible options before starting: %j', async (change) => {
    const manager = managerWithFakeProcess();
    await expect(manager.startNode(options(change))).rejects.toThrow();
    expect(mocks.spawn).not.toHaveBeenCalled();
  });

  it('does not start when the release manifest cannot be verified', async () => {
    mocks.manifestPath.mockImplementation(() => { throw new Error('manifest mismatch'); });
    const manager = managerWithFakeProcess();
    await expect(manager.startNode(options())).rejects.toThrow(/manifest mismatch/);
    expect(mocks.spawn).not.toHaveBeenCalled();
  });
});
