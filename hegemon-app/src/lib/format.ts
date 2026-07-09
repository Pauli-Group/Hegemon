import type { ActivityStatus, BlockAlertStep, BlockAlertTone } from './appTypes';
import {
  shieldedAddressDataCharset,
  shieldedAddressLength,
  shieldedAddressPrefix,
  shieldedAddressSeparatorPattern
} from './config';

export const normalizeTxId = (value: string | null | undefined) => {
  if (!value) {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  return trimmed.replace(/^0x/i, '').toLowerCase();
};

export const makeId = () => {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return `conn-${Math.random().toString(36).slice(2, 10)}`;
};

export const clampAutoLockMinutes = (value: number) => Math.min(Math.max(value, 1), 120);

export const isWalletSessionClosedError = (message: string) => {
  const normalized = message.toLowerCase();
  return (
    normalized.includes('walletd process not running') ||
    normalized.includes('walletd stopped') ||
    normalized.includes('walletd stdin not available') ||
    normalized.includes('wallet is locked') ||
    normalized.includes('wallet unlock token') ||
    normalized.includes('expired')
  );
};

export const toBaseUnits = (value: string) => {
  const parsed = Number.parseFloat(value);
  if (Number.isNaN(parsed) || !Number.isFinite(parsed)) {
    return null;
  }
  return Math.round(parsed * 100_000_000);
};

export const formatNumber = (value: number | null | undefined) => {
  if (value === null || value === undefined) {
    return 'N/A';
  }
  return value.toLocaleString();
};

export const formatHgm = (value: number) => `${(value / 100_000_000).toFixed(8)} HGM`;

export const formatBlockCount = (value: number) => `${formatNumber(value)} ${value === 1 ? 'block' : 'blocks'}`;

export const normalizeShieldedAddressInput = (value: string) =>
  value.replace(shieldedAddressSeparatorPattern, '').trim().toLowerCase();

export const validateShieldedAddressInput = (value: string, label = 'Address') => {
  const normalized = normalizeShieldedAddressInput(value);
  if (!normalized) {
    return `${label} is required.`;
  }
  if (!normalized.startsWith(shieldedAddressPrefix)) {
    return `${label} must start with ${shieldedAddressPrefix}.`;
  }
  if (normalized.length !== shieldedAddressLength) {
    return `${label} looks truncated or corrupt. Expected ${shieldedAddressLength} chars, got ${normalized.length}.`;
  }
  const payload = normalized.slice(shieldedAddressPrefix.length);
  if (!shieldedAddressDataCharset.test(payload)) {
    return `${label} contains unsupported bech32 characters.`;
  }
  return null;
};

export const formatAddress = (address: string) => {
  const normalized = normalizeShieldedAddressInput(address);
  if (normalized.length <= 28) {
    return normalized || address;
  }
  const middleStart = Math.max(0, Math.floor(normalized.length / 2) - 4);
  return `${normalized.slice(0, 10)}...${normalized.slice(middleStart, middleStart + 8)}...${normalized.slice(-8)}`;
};

export const formatCompactPath = (value: string | null | undefined) => {
  const trimmed = value?.trim();
  if (!trimmed) {
    return 'N/A';
  }
  if (trimmed.length <= 48) {
    return trimmed;
  }
  const normalized = trimmed.replace(/\\/g, '/');
  const parts = normalized.split('/').filter(Boolean);
  if (parts.length <= 2) {
    return `${trimmed.slice(0, 20)}...${trimmed.slice(-20)}`;
  }
  const prefix = normalized.startsWith('/') ? '/' : '';
  return `${prefix}${parts[0]}/.../${parts.slice(-2).join('/')}`;
};

export const formatEndpoint = (value: string | null | undefined) => {
  const trimmed = value?.trim();
  if (!trimmed) {
    return 'N/A';
  }
  if (trimmed.length <= 40) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`;
  } catch {
    return `${trimmed.slice(0, 18)}...${trimmed.slice(-18)}`;
  }
};

export const formatSeedList = (value: string[] | string | null | undefined) => {
  const seeds = Array.isArray(value) ? value : (value ?? '').split(',');
  const normalized = seeds.map((seed) => seed.trim()).filter(Boolean);
  return normalized.length ? normalized.join(', ') : 'N/A';
};

export const humanizeWalletAddressError = (error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  if (message.toLowerCase().includes('invalid address encoding')) {
    const lengthMatch = message.match(/invalid address length: expected (\d+) bytes, got (\d+)/i);
    if (lengthMatch) {
      const [, expectedBytes, actualBytes] = lengthMatch;
      return `Recipient address is malformed or truncated. Expected ${expectedBytes} address bytes, got ${actualBytes}. Ask your contact to re-copy their full shielded address.`;
    }
    return 'Recipient address is malformed or truncated. Ask your contact to re-copy their full shielded address.';
  }
  return message;
};

export const formatBytes = (value: number | null | undefined) => {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 'N/A';
  }
  if (value < 1024) {
    return `${value} B`;
  }
  const units = ['KB', 'MB', 'GB', 'TB'];
  let remaining = value;
  let unitIndex = -1;
  while (remaining >= 1024 && unitIndex < units.length - 1) {
    remaining /= 1024;
    unitIndex += 1;
  }
  return `${remaining.toFixed(2)} ${units[unitIndex]}`;
};

export const formatHashRate = (value: number | null | undefined) => {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 'N/A';
  }
  const units = ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s'];
  let remaining = value;
  let unitIndex = 0;
  while (remaining >= 1000 && unitIndex < units.length - 1) {
    remaining /= 1000;
    unitIndex += 1;
  }
  const decimals = remaining >= 100 ? 0 : remaining >= 10 ? 1 : 2;
  return `${remaining.toFixed(decimals)} ${units[unitIndex]}`;
};

export const formatDuration = (seconds: number | null | undefined) => {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) {
    return 'N/A';
  }
  const safeSeconds = Math.max(0, Math.floor(seconds));
  const days = Math.floor(safeSeconds / 86400);
  const hours = Math.floor((safeSeconds % 86400) / 3600);
  const minutes = Math.floor((safeSeconds % 3600) / 60);
  const secs = safeSeconds % 60;
  const parts: string[] = [];
  if (days) {
    parts.push(`${days}d`);
  }
  if (hours || days) {
    parts.push(`${hours}h`);
  }
  if (minutes || hours || days) {
    parts.push(`${minutes}m`);
  }
  parts.push(`${secs}s`);
  return parts.join(' ');
};

export const formatHash = (value: string | null | undefined) => {
  if (!value) {
    return 'N/A';
  }
  if (value.length <= 20) {
    return value;
  }
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
};

export const buildBlockAlertPattern = (tone: BlockAlertTone): BlockAlertStep[] => {
  if (tone === 'self') {
    return [
      { frequency: 1480, duration: 0.08, gap: 0.05 },
      { frequency: 1760, duration: 0.08, gap: 0.05 },
      { frequency: 2090, duration: 0.12 }
    ];
  }
  return [
    { frequency: 330, duration: 0.22, gap: 0.08 },
    { frequency: 220, duration: 0.26 }
  ];
};

export const parseDisclosureInput = (input: string) => {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error('Disclosure JSON is required.');
  }
  const parseJson = (value: string) => JSON.parse(value);
  try {
    const parsed = parseJson(trimmed);
    if (typeof parsed === 'string') {
      return parseJson(parsed);
    }
    return parsed;
  } catch (error) {
    const firstBrace = trimmed.indexOf('{');
    const lastBrace = trimmed.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      const candidate = trimmed.slice(firstBrace, lastBrace + 1);
      try {
        return parseJson(candidate);
      } catch {
      }
    }
    const message = error instanceof Error ? error.message : 'Invalid disclosure JSON.';
    throw new Error(`Disclosure JSON is invalid. Paste the full package JSON. ${message}`);
  }
};

export const parseTimestamp = (value?: string | null) => {
  if (!value) {
    return 0;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
};

export const formatTimestamp = (value?: string | null) => {
  if (!value) {
    return 'N/A';
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return value;
  }
  return new Date(parsed).toLocaleString();
};

export const activityStatusSymbols: Record<ActivityStatus, string> = {
  processing: '...',
  pending: '...',
  confirmed: '✓',
  failed: 'X'
};

export const activityStatusLabels: Record<ActivityStatus, string> = {
  processing: 'Processing',
  pending: 'Pending',
  confirmed: 'Confirmed',
  failed: 'Failed'
};

export const activityStatusClasses: Record<ActivityStatus, string> = {
  processing: 'border-ionosphere/40 text-ionosphere bg-ionosphere/10',
  pending: 'border-ionosphere/30 text-ionosphere/80 bg-ionosphere/5',
  confirmed: 'border-ionosphere/40 text-ionosphere bg-ionosphere/15',
  failed: 'border-guard/40 text-guard bg-guard/10'
};
