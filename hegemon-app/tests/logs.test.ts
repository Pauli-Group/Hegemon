import { describe, expect, it } from 'vitest';
import { classifyLogLevel, parseLogLine } from '../src/lib/logs';

describe('node log classification', () => {
  it('treats ordinary remote socket closure as retry noise', () => {
    const line =
      '2026-07-12T20:35:40Z ERROR network::service: failed to send to 42.116.135.181:14428: io error: Broken pipe (os error 32)';

    expect(classifyLogLevel(line)).toBe('warn');
    expect(parseLogLine(line, 0).highlight).toBeUndefined();
  });

  it('recognizes the standard unexpected-EOF wording from older nodes', () => {
    const line =
      '2026-07-12T20:35:40Z ERROR network::service: error receiving from 42.116.135.181:14428: io error: unexpected end of file';

    expect(classifyLogLevel(line)).toBe('warn');
    expect(parseLogLine(line, 0).highlight).toBeUndefined();
  });

  it('preserves error severity for non-routine transport failures', () => {
    const line =
      '2026-07-12T20:35:40Z ERROR network::service: failed to send to 42.116.135.181:14428: encryption error';

    expect(classifyLogLevel(line)).toBe('error');
    expect(parseLogLine(line, 0).highlight).toBe('Error');
  });
});
