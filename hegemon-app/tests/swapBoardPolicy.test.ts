import { describe, expect, it } from 'vitest';
import { allowSwapBoardNavigation, allowSwapBoardRequest } from '../electron/swapBoardPolicy';

describe('isolated swap board window', () => {
  it('allows only the fixed local board as a top-level page', () => {
    expect(allowSwapBoardNavigation('http://127.0.0.1:8787/#offer')).toBe(true);
    for (const value of ['http://127.0.0.1:8788/', 'http://127.0.0.1:8787/app.js', 'http://localhost:8787/', 'https://127.0.0.1:8787/', 'http://127.0.0.1:8787@evil.invalid/', 'file:///tmp/x']) {
      expect(allowSwapBoardNavigation(value)).toBe(false);
    }
  });
  it('allows requests only to the fixed loopback board and companion', () => {
    expect(allowSwapBoardRequest('http://127.0.0.1:8787/app.js')).toBe(true);
    expect(allowSwapBoardRequest('http://127.0.0.1:8788/bitcoin/verify')).toBe(true);
    for (const value of ['https://example.com/', 'http://127.0.0.1:9999/', 'file:///etc/passwd', 'data:text/html,hello']) {
      expect(allowSwapBoardRequest(value)).toBe(false);
    }
  });
});
