/** Only the loopback offer board and its read-only companion are reachable. */
export const SWAP_BOARD_ORIGIN = 'http://127.0.0.1:8787';
export const SWAP_COMPANION_ORIGIN = 'http://127.0.0.1:8788';

export function allowSwapBoardNavigation(value: string): boolean {
  try {
    const url = new URL(value);
    return url.origin === SWAP_BOARD_ORIGIN && url.pathname === '/' && !url.username && !url.password;
  } catch {
    return false;
  }
}

export function allowSwapBoardRequest(value: string): boolean {
  try {
    const url = new URL(value);
    return !url.username && !url.password && (url.origin === SWAP_BOARD_ORIGIN || url.origin === SWAP_COMPANION_ORIGIN);
  } catch {
    return false;
  }
}
