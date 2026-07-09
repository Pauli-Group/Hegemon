export type WalletdResponse = {
  id: number;
  ok: boolean;
  result?: any;
  error?: string;
  error_code?: string;
};

export const DEFAULT_WALLETD_REQUEST_TIMEOUT_MS = 600_000;
export const MIN_WALLETD_REQUEST_TIMEOUT_MS = 1_000;

/**
 * Resolve the walletd per-request timeout from an environment override.
 * Falls back to the default when unset, unparsable, or below the minimum.
 */
export function resolveWalletdRequestTimeoutMs(raw: string | undefined): number {
  const parsed = raw ? Number.parseInt(raw, 10) : NaN;
  if (!Number.isFinite(parsed) || parsed < MIN_WALLETD_REQUEST_TIMEOUT_MS) {
    return DEFAULT_WALLETD_REQUEST_TIMEOUT_MS;
  }
  return parsed;
}

export function rejectLineDelimitedPassphrase(passphrase: string): void {
  if (passphrase.includes('\n') || passphrase.includes('\r')) {
    throw new Error('Wallet passphrase cannot contain line breaks.');
  }
}

export type ParsedWalletdLine =
  | { kind: 'empty' }
  | { kind: 'noise'; text: string }
  | { kind: 'invalid'; text: string }
  | { kind: 'response'; response: WalletdResponse };

/**
 * Classify one line of walletd stdout. walletd speaks line-delimited JSON;
 * non-JSON lines are operator noise and malformed JSON objects are protocol
 * errors that must never settle a pending request.
 */
export function parseWalletdResponseLine(line: string): ParsedWalletdLine {
  const trimmed = line.trim();
  if (!trimmed) {
    return { kind: 'empty' };
  }
  try {
    return { kind: 'response', response: JSON.parse(trimmed) as WalletdResponse };
  } catch {
    if (!trimmed.startsWith('{')) {
      return { kind: 'noise', text: trimmed };
    }
    return { kind: 'invalid', text: trimmed };
  }
}

/** Build the Error surfaced to callers for a failed walletd response. */
export function walletdResponseError(response: WalletdResponse): Error {
  const message = response.error || 'walletd error';
  const error = new Error(
    response.error_code ? `${message} (${response.error_code})` : message
  );
  if (response.error_code) {
    (error as { code?: string }).code = response.error_code;
  }
  return error;
}

/** Build the Error surfaced when the walletd process exits. */
export function walletdExitError(
  code: number | null,
  signal: NodeJS.Signals | null,
  stderrLines: readonly string[]
): Error {
  const summary = formatWalletdStderrSummary(stderrLines);
  if (summary) {
    const cleaned = summary.replace(/^Error:\s*/, '').trim();
    if (cleaned) {
      return new Error(cleaned);
    }
  }
  const suffix = signal ? ` (signal ${signal})` : '';
  return new Error(`walletd exited with code ${code ?? 'unknown'}${suffix}`);
}

export function formatWalletdStderrSummary(stderrLines: readonly string[]): string {
  const lines = stderrLines.filter(Boolean);
  if (!lines.length) {
    return '';
  }
  const first = lines[0];
  const last = lines[lines.length - 1].replace(/^\d+:\s*/, '');
  if (lines.length > 1 && last && last !== first) {
    return `${first} (${last})`;
  }
  return first;
}
