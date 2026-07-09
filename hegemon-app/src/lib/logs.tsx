import type { LogCategory, LogEntry, LogLevel } from './appTypes';

export const logCategoryOrder: LogCategory[] = ['mining', 'sync', 'network', 'consensus', 'storage', 'rpc', 'other'];

export const logCategoryLabels: Record<LogCategory, string> = {
  mining: 'Mining',
  sync: 'Sync',
  network: 'Network',
  consensus: 'Consensus',
  storage: 'Storage',
  rpc: 'RPC',
  other: 'Other'
};

export const isRoutineNetworkRetryLog = (line: string) =>
  /failed to connect to peer|handshake failed|rate-limited peer address announcement/i.test(line);

export const classifyLogLevel = (line: string): LogLevel => {
  if (/\bWARN\b|\bWarning\b/i.test(line)) {
    return 'warn';
  }
  if (isRoutineNetworkRetryLog(line)) {
    return 'warn';
  }
  if (/\bERROR\b|\bpanic\b/i.test(line)) {
    return 'error';
  }
  if (/\bDEBUG\b/i.test(line)) {
    return 'debug';
  }
  return 'info';
};

export const classifyLogCategory = (line: string): LogCategory => {
  if (/mining|nonce|hashrate|POW|coinbase/i.test(line)) {
    return 'mining';
  }
  if (/imported block|block imported|sync|syncing/i.test(line)) {
    return 'sync';
  }
  if (/peer|network|p2p|seed|broadcast/i.test(line)) {
    return 'network';
  }
  if (/storage|state_root|nullifier_root|da_root/i.test(line)) {
    return 'storage';
  }
  if (/rpc|jsonrpc|http/i.test(line)) {
    return 'rpc';
  }
  if (/consensus|execute_extrinsics|block builder|block built/i.test(line)) {
    return 'consensus';
  }
  return 'other';
};

export const highlightLog = (line: string) => {
  const routineNetworkRetry = isRoutineNetworkRetryLog(line);
  if (/Block mined/i.test(line)) {
    return 'Block mined';
  }
  if (/Block imported successfully|Block imported/i.test(line)) {
    return 'Block imported';
  }
  if (/sync complete/i.test(line)) {
    return 'Sync complete';
  }
  if ((/\bWARN\b|\bWarning\b/i.test(line)) && !routineNetworkRetry) {
    return 'Warning';
  }
  if ((/\bERROR\b|\bpanic\b/i.test(line)) && !routineNetworkRetry) {
    return 'Error';
  }
  return undefined;
};

export const formatLogTimestamp = (value: string) => {
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
  return value;
};

export const parseLogLine = (line: string, index: number): LogEntry => {
  const timestampMatch =
    line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(.*)$/) ??
    line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.*)$/);
  const timestamp = timestampMatch ? formatLogTimestamp(timestampMatch[1]) : null;
  const message = (timestampMatch ? timestampMatch[2] : line).replace(/^(TRACE|DEBUG|INFO|WARN|ERROR)\s+/, '');
  return {
    id: `${index}-${message.slice(0, 12)}`,
    timestamp,
    level: classifyLogLevel(line),
    category: classifyLogCategory(line),
    message,
    raw: line,
    highlight: highlightLog(line)
  };
};

