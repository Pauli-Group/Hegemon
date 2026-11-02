import { useState } from 'react';

/** The offer board runs in an isolated window without the desktop wallet API. */
export function SwapWorkspace() {
  const [status, setStatus] = useState('');
  const [opening, setOpening] = useState(false);
  async function openBoard() {
    setOpening(true);
    setStatus('');
    try {
      if (!window.hegemon?.swap) throw new Error('The local board is available in the desktop application.');
      await window.hegemon.swap.openBoard();
      setStatus('Local offer board opened.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'The local offer board could not be opened.');
    } finally {
      setOpening(false);
    }
  }
  return (
    <div className="workspace-view max-w-7xl">
      <section className="rounded-lg border border-surfaceMuted/30 bg-midnight/40 p-6 space-y-4">
        <p className="text-xs uppercase tracking-wide text-ionosphere">Local prototype</p>
        <h1 className="text-2xl font-semibold text-surface">Swap offers</h1>
        <p className="text-sm text-surfaceMuted max-w-2xl">
          Open the local offer board in an isolated window. Start the local relay separately first.
          The board can display offers and check configured local escrows; it cannot yet execute swaps.
        </p>
        <p className="text-sm text-surfaceMuted max-w-2xl">
          The board window cannot access this desktop wallet. For browser wallet extensions, open the
          board in a regular browser. The local companion handles read-only Bitcoin, Cardano and Hegemon checks.
        </p>
        <button type="button" className="primary" onClick={openBoard} disabled={opening}>
          {opening ? 'Opening…' : 'Open local offer board'}
        </button>
        {status ? <p role="status" className="text-sm text-surface">{status}</p> : null}
      </section>
    </div>
  );
}
