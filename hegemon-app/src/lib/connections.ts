import type { NodeConnection } from '../types';
import {
  approvedSeeds,
  canonicalTestnetP2pPort,
  defaultDevBasePath,
  defaultDevConnectionLabel,
  defaultMineThreads,
  defaultP2pPort,
  defaultRpcPort,
  hegemonNetworkName,
  inferParticipationRole,
  legacyDefaultConnectionLabels,
  legacyDesktopRpcPort,
  legacyHegemonConnectionLabels,
  legacySeedAliases,
  maxDesktopMineThreads
} from './config';
import { makeId, validateShieldedAddressInput } from './format';

export const canonicalizeSeedEntry = (seed: string) => {
  const normalized = seed.trim().toLowerCase();
  if (!normalized) {
    return '';
  }
  return legacySeedAliases[normalized] ?? normalized;
};

export const normalizeSeedsValue = (value: string | null | undefined) => {
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const rawSeed of (value ?? '').split(',')) {
    for (const seed of canonicalizeSeedEntry(rawSeed).split(',')) {
      if (!seed || seen.has(seed)) {
        continue;
      }
      seen.add(seed);
      normalized.push(seed);
    }
  }
  return normalized.join(',');
};

export const normalizeNetworkDisplayName = (value: string | null | undefined) => {
  const trimmed = value?.trim();
  if (!trimmed) {
    return hegemonNetworkName;
  }
  const lower = trimmed.toLowerCase();
  if (
    lower === 'hegemon network' ||
    lower === 'hegemon native' ||
    lower === 'hegemon native dev' ||
    lower === 'native 0.10 devnet' ||
    lower === 'hegemon-dev' ||
    lower.startsWith('hegemon native ')
  ) {
    return hegemonNetworkName;
  }
  return trimmed;
};

export const deriveHttpUrl = (wsUrl: string, httpUrl?: string) => {
  const trimmedWsUrl = wsUrl.trim();
  const wsAsHttp =
    trimmedWsUrl.startsWith('ws://')
      ? `http://${trimmedWsUrl.slice('ws://'.length)}`
      : trimmedWsUrl.startsWith('wss://')
        ? `https://${trimmedWsUrl.slice('wss://'.length)}`
        : trimmedWsUrl;

  const parseEndpoint = (value: string) => {
    try {
      return new URL(value);
    } catch {
      return null;
    }
  };
  const isLoopbackHost = (host: string) => host === '127.0.0.1' || host === 'localhost' || host === '::1';
  const wsEndpoint = parseEndpoint(trimmedWsUrl);

  if (httpUrl && httpUrl.trim()) {
    const trimmedHttpUrl = httpUrl.trim();
    const httpEndpoint = parseEndpoint(trimmedHttpUrl);

    // Local profiles frequently drift when only one endpoint is edited.
    if (
      wsEndpoint &&
      httpEndpoint &&
      isLoopbackHost(wsEndpoint.hostname) &&
      isLoopbackHost(httpEndpoint.hostname) &&
      wsEndpoint.port &&
      httpEndpoint.port &&
      wsEndpoint.port !== httpEndpoint.port
    ) {
      return wsAsHttp;
    }

    return trimmedHttpUrl;
  }

  return wsAsHttp;
};

export const parsePortFromUrl = (value?: string | null): number | undefined => {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  try {
    const parsed = new URL(trimmed);
    if (!parsed.port) {
      return undefined;
    }
    const port = Number.parseInt(parsed.port, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return undefined;
    }
    return port;
  } catch {
    return undefined;
  }
};

export const normalizeRpcPort = (value?: number): number | undefined => {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    return undefined;
  }
  if (value < 1 || value > 65535) {
    return undefined;
  }
  return value;
};

export const parseListenAddrPort = (value?: string | null): number | undefined => {
  if (!value) {
    return undefined;
  }
  const parts = value.trim().split('/');
  for (let index = 0; index < parts.length - 1; index += 1) {
    if (parts[index] !== 'tcp') {
      continue;
    }
    const port = Number.parseInt(parts[index + 1], 10);
    if (Number.isInteger(port) && port >= 1 && port <= 65535) {
      return port;
    }
  }
  return undefined;
};

export const rewriteListenAddrPort = (value: string, port: number): string => {
  const parts = value.trim().split('/');
  for (let index = 0; index < parts.length - 1; index += 1) {
    if (parts[index] === 'tcp') {
      parts[index + 1] = String(port);
      return parts.join('/');
    }
  }
  return value;
};

export const isLoopbackWsEndpoint = (value: string): boolean =>
  value.startsWith('ws://127.0.0.1:') || value.startsWith('ws://localhost:') || value.startsWith('ws://[::1]:');

export const isLoopbackHttpEndpoint = (value?: string): boolean =>
  Boolean(
    value &&
      (value.startsWith('http://127.0.0.1:') ||
        value.startsWith('http://localhost:') ||
        value.startsWith('http://[::1]:') ||
        value.startsWith('https://127.0.0.1:') ||
        value.startsWith('https://localhost:') ||
        value.startsWith('https://[::1]:'))
  );

export const rewriteLoopbackWsEndpoint = (value: string, port: number): string => {
  if (value.startsWith('ws://localhost:')) {
    return `ws://localhost:${port}`;
  }
  if (value.startsWith('ws://[::1]:')) {
    return `ws://[::1]:${port}`;
  }
  return `ws://127.0.0.1:${port}`;
};

export const rewriteLoopbackHttpEndpoint = (value: string | undefined, port: number): string => {
  if (!value) {
    return `http://127.0.0.1:${port}`;
  }
  if (value.startsWith('http://localhost:')) {
    return `http://localhost:${port}`;
  }
  if (value.startsWith('http://[::1]:')) {
    return `http://[::1]:${port}`;
  }
  if (value.startsWith('https://localhost:')) {
    return `https://localhost:${port}`;
  }
  if (value.startsWith('https://[::1]:')) {
    return `https://[::1]:${port}`;
  }
  return `http://127.0.0.1:${port}`;
};

export const inferRpcPort = (connection: NodeConnection): number =>
  normalizeRpcPort(connection.rpcPort) ??
  parsePortFromUrl(connection.wsUrl) ??
  parsePortFromUrl(connection.httpUrl) ??
  defaultRpcPort;

export const normalizeLocalConnectionEndpoints = (connection: NodeConnection): NodeConnection => {
  if (connection.mode !== 'local') {
    return connection;
  }

  const rpcPort = inferRpcPort(connection);
  const updates: Partial<NodeConnection> = {};

  if (normalizeRpcPort(connection.rpcPort) !== rpcPort) {
    updates.rpcPort = rpcPort;
  }

  if (!connection.wsUrl?.trim()) {
    updates.wsUrl = `ws://127.0.0.1:${rpcPort}`;
  } else if (isLoopbackWsEndpoint(connection.wsUrl) && parsePortFromUrl(connection.wsUrl) !== rpcPort) {
    updates.wsUrl = rewriteLoopbackWsEndpoint(connection.wsUrl, rpcPort);
  }

  const effectiveWsUrl = updates.wsUrl ?? connection.wsUrl;
  const derivedHttpUrl = deriveHttpUrl(effectiveWsUrl, connection.httpUrl);
  if (!connection.httpUrl?.trim()) {
    updates.httpUrl = derivedHttpUrl;
  } else if (isLoopbackHttpEndpoint(connection.httpUrl) && parsePortFromUrl(connection.httpUrl) !== rpcPort) {
    updates.httpUrl = rewriteLoopbackHttpEndpoint(connection.httpUrl, rpcPort);
  }

  if (Object.keys(updates).length === 0) {
    return connection;
  }
  return { ...connection, ...updates };
};

export const buildDefaultConnection = (): NodeConnection => ({
  id: makeId(),
  label: defaultDevConnectionLabel,
  mode: 'local',
  participationRole: 'full_node',
  wsUrl: `ws://127.0.0.1:${defaultRpcPort}`,
  httpUrl: `http://127.0.0.1:${defaultRpcPort}`,
  dev: true,
  tmp: false,
  basePath: defaultDevBasePath,
  rpcPort: defaultRpcPort,
  p2pPort: defaultP2pPort,
  mineThreads: defaultMineThreads,
  miningIntent: false,
  ciphertextDaRetentionBlocks: 0,
  proofDaRetentionBlocks: 0,
  daStoreCapacity: 1024,
  rpcMethods: 'unsafe',
  rpcCorsAll: false,
  seeds: approvedSeeds,
  maxPeers: 50
});

export const buildDefaultConnections = () => [buildDefaultConnection()];

export const normalizeRpcControlPlane = (connection: NodeConnection): NodeConnection => {
  if (connection.mode !== 'local') {
    return connection.rpcMethods === 'safe' ? connection : { ...connection, rpcMethods: 'safe' };
  }
  if (connection.rpcExternal) {
    return connection.rpcMethods === 'safe' ? connection : { ...connection, rpcMethods: 'safe' };
  }
  return connection.rpcMethods === 'unsafe' ? connection : { ...connection, rpcMethods: 'unsafe' };
};

export const normalizeConnection = (connection: NodeConnection): NodeConnection => {
  const {
    operatorEndpoint: _operatorEndpoint,
    workerName: _workerName,
    payoutAddress: _payoutAddress,
    poolAuthToken: _poolAuthToken,
    poolShareBits: _poolShareBits,
    ...sanitizedConnection
  } = connection as NodeConnection & {
    operatorEndpoint?: string;
    workerName?: string;
    payoutAddress?: string;
    poolAuthToken?: string;
    poolShareBits?: number;
  };
  const hasDefaultLocalLabel = legacyDefaultConnectionLabels.has(sanitizedConnection.label);
  const hasLegacyHegemonLabel = legacyHegemonConnectionLabels.has(sanitizedConnection.label?.trim());
  const isDefaultLocal =
    sanitizedConnection.mode === 'local' &&
    hasDefaultLocalLabel &&
    (!sanitizedConnection.basePath ||
      sanitizedConnection.basePath === '~/.hegemon-node' ||
      sanitizedConnection.basePath === defaultDevBasePath);
  const isDefaultTestnet =
    sanitizedConnection.mode === 'local' &&
    sanitizedConnection.label === 'Testnet node' &&
    (!sanitizedConnection.basePath || sanitizedConnection.basePath === '~/.hegemon-node-testnet');

  let next = normalizeLocalConnectionEndpoints(sanitizedConnection);
  const isLegacyHegemonLocalProfile =
    sanitizedConnection.mode === 'local' &&
    hasLegacyHegemonLabel &&
    Boolean(sanitizedConnection.dev) &&
    inferRpcPort(next) === defaultRpcPort &&
    isLoopbackWsEndpoint(next.wsUrl) &&
    (!next.httpUrl || isLoopbackHttpEndpoint(next.httpUrl));
  if ((isDefaultLocal || isLegacyHegemonLocalProfile) && next.label !== defaultDevConnectionLabel) {
    next = { ...next, label: defaultDevConnectionLabel };
  }
  if (isDefaultLocal && (!next.basePath || next.basePath === '~/.hegemon-node')) {
    next = { ...next, basePath: defaultDevBasePath };
  }
  if ((isDefaultLocal || isDefaultTestnet) && (next.mineThreads ?? defaultMineThreads) > maxDesktopMineThreads) {
    next = { ...next, mineThreads: maxDesktopMineThreads };
  }
  if (
    isDefaultLocal &&
    inferRpcPort(next) === legacyDesktopRpcPort &&
    isLoopbackWsEndpoint(next.wsUrl) &&
    (!next.httpUrl || isLoopbackHttpEndpoint(next.httpUrl))
  ) {
    next = {
      ...next,
      rpcPort: defaultRpcPort,
      wsUrl: rewriteLoopbackWsEndpoint(next.wsUrl, defaultRpcPort),
      httpUrl: rewriteLoopbackHttpEndpoint(next.httpUrl, defaultRpcPort)
    };
  }
  const inferredParticipationRole = inferParticipationRole(next);
  if (next.participationRole !== inferredParticipationRole) {
    next = { ...next, participationRole: inferredParticipationRole };
  }
  if (next.mode === 'remote' && !next.httpUrl?.trim()) {
    next = { ...next, httpUrl: deriveHttpUrl(next.wsUrl) };
  }
  next = normalizeRpcControlPlane(next);

  const currentSeeds = (next.seeds ?? '').trim();
  const normalizedSeeds = normalizeSeedsValue(next.seeds);
  if (currentSeeds && normalizedSeeds !== currentSeeds.toLowerCase()) {
    next = { ...next, seeds: normalizedSeeds };
  }
  if (isDefaultLocal || isDefaultTestnet) {
    if (normalizedSeeds !== approvedSeeds) {
      next = { ...next, seeds: approvedSeeds };
    }
  }

  if (next.mode === 'local') {
    if (next.p2pPort === 31333) {
      next = { ...next, p2pPort: canonicalTestnetP2pPort };
    }
    const listenAddrPort = parseListenAddrPort(next.listenAddr);
    if (listenAddrPort === 31333 && next.listenAddr) {
      next = {
        ...next,
        listenAddr: rewriteListenAddrPort(next.listenAddr, canonicalTestnetP2pPort)
      };
    }
  }

  if ((isDefaultLocal || isDefaultTestnet) && (!next.mineThreads || next.mineThreads === 1)) {
    next = { ...next, mineThreads: defaultMineThreads };
  }

  if (inferredParticipationRole !== 'authoring_pool' && next.miningIntent) {
    next = { ...next, miningIntent: false };
  }

  return next;
};

export const shouldAutoStartDefaultProfile = (connection: NodeConnection): boolean => {
  const normalized = normalizeLocalConnectionEndpoints(connection);
  const role = inferParticipationRole(normalized);
  const miningProfileAllowed =
    role === 'authoring_pool' &&
    Boolean(normalized.miningIntent) &&
    !validateShieldedAddressInput(normalized.minerAddress ?? '', 'Miner address');
  const relayProfileAllowed = role === 'full_node' && !normalized.miningIntent;
  return (
    normalized.mode === 'local' &&
    normalized.label === defaultDevConnectionLabel &&
    Boolean(normalized.dev) &&
    !normalized.tmp &&
    !normalized.rpcExternal &&
    (relayProfileAllowed || miningProfileAllowed) &&
    inferRpcPort(normalized) === defaultRpcPort &&
    normalized.basePath === defaultDevBasePath &&
    isLoopbackWsEndpoint(normalized.wsUrl) &&
    (!normalized.httpUrl || isLoopbackHttpEndpoint(normalized.httpUrl)) &&
    normalizeSeedsValue(normalized.seeds) === approvedSeeds
  );
};

export const findDefaultManagedConnection = (connections: NodeConnection[]) =>
  connections.find((connection) => shouldAutoStartDefaultProfile(connection)) ?? null;
