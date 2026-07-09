import { describe, expect, it } from 'vitest';
import {
  DEFAULT_WALLETD_REQUEST_TIMEOUT_MS,
  MIN_WALLETD_REQUEST_TIMEOUT_MS,
  formatWalletdStderrSummary,
  parseWalletdResponseLine,
  rejectLineDelimitedPassphrase,
  resolveWalletdRequestTimeoutMs,
  walletdExitError,
  walletdResponseError
} from '../electron/walletdProtocol';

describe('resolveWalletdRequestTimeoutMs', () => {
  it('defaults when unset', () => {
    expect(resolveWalletdRequestTimeoutMs(undefined)).toBe(DEFAULT_WALLETD_REQUEST_TIMEOUT_MS);
  });

  it('defaults when unparsable', () => {
    expect(resolveWalletdRequestTimeoutMs('not-a-number')).toBe(
      DEFAULT_WALLETD_REQUEST_TIMEOUT_MS
    );
  });

  it('defaults when below the minimum', () => {
    expect(resolveWalletdRequestTimeoutMs(String(MIN_WALLETD_REQUEST_TIMEOUT_MS - 1))).toBe(
      DEFAULT_WALLETD_REQUEST_TIMEOUT_MS
    );
  });

  it('accepts explicit values at or above the minimum', () => {
    expect(resolveWalletdRequestTimeoutMs('1000')).toBe(1000);
    expect(resolveWalletdRequestTimeoutMs('900000')).toBe(900000);
  });
});

describe('rejectLineDelimitedPassphrase', () => {
  it('rejects newline and carriage return', () => {
    expect(() => rejectLineDelimitedPassphrase('a\nb')).toThrow(/line breaks/);
    expect(() => rejectLineDelimitedPassphrase('a\rb')).toThrow(/line breaks/);
  });

  it('accepts ordinary passphrases', () => {
    expect(() => rejectLineDelimitedPassphrase('correct horse battery staple')).not.toThrow();
  });
});

describe('parseWalletdResponseLine', () => {
  it('classifies blank lines as empty', () => {
    expect(parseWalletdResponseLine('   ').kind).toBe('empty');
  });

  it('classifies non-JSON lines as noise', () => {
    const parsed = parseWalletdResponseLine('starting sync...');
    expect(parsed).toEqual({ kind: 'noise', text: 'starting sync...' });
  });

  it('classifies malformed JSON objects as invalid', () => {
    const parsed = parseWalletdResponseLine('{"id": 1, "ok": tru');
    expect(parsed.kind).toBe('invalid');
  });

  it('parses well-formed responses', () => {
    const parsed = parseWalletdResponseLine('{"id": 3, "ok": true, "result": {"height": 7}}');
    expect(parsed).toEqual({
      kind: 'response',
      response: { id: 3, ok: true, result: { height: 7 } }
    });
  });
});

describe('walletdResponseError', () => {
  it('includes the error code as suffix and code property', () => {
    const error = walletdResponseError({
      id: 1,
      ok: false,
      error: 'store locked',
      error_code: 'WALLET_LOCKED'
    });
    expect(error.message).toBe('store locked (WALLET_LOCKED)');
    expect((error as { code?: string }).code).toBe('WALLET_LOCKED');
  });

  it('falls back to a generic message', () => {
    const error = walletdResponseError({ id: 1, ok: false });
    expect(error.message).toBe('walletd error');
  });
});

describe('walletdExitError', () => {
  it('prefers a cleaned stderr summary', () => {
    const error = walletdExitError(1, null, ['Error: bad passphrase']);
    expect(error.message).toBe('bad passphrase');
  });

  it('combines first and last stderr lines', () => {
    const error = walletdExitError(1, null, ['first failure', '2: last failure']);
    expect(error.message).toBe('first failure (last failure)');
  });

  it('reports exit code and signal without stderr', () => {
    expect(walletdExitError(137, 'SIGKILL', []).message).toBe(
      'walletd exited with code 137 (signal SIGKILL)'
    );
    expect(walletdExitError(null, null, []).message).toBe('walletd exited with code unknown');
  });
});

describe('formatWalletdStderrSummary', () => {
  it('returns empty for no lines', () => {
    expect(formatWalletdStderrSummary([])).toBe('');
  });

  it('returns the single line as-is', () => {
    expect(formatWalletdStderrSummary(['only line'])).toBe('only line');
  });
});
