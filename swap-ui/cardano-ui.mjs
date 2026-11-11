/* Page glue for the Cardano preview wallet actions. Everything it needs from the page is passed in, so it can be
 * driven by a test page with a mock CIP-30 wallet. It never handles keys; the wallet signs. */
import {cardanoWalletAction, WalletError} from './cardano-wallet.mjs';
import {loadPinnedScript, pinnedScript} from './cardano-tx.mjs';
import {toHex} from './cbor.mjs';

const FIELDS = ['outref', 'lovelace', 'assets', 'hashlock', 'claimant', 'refundee', 'expiry_ms'];

export function initCardanoWalletActions(d) {
  const {$, msg} = d, form = $('cardano-wallet-form');
  let busy = false, scriptLoaded;
  const buttons = () => form.querySelectorAll('button');
  const lock = on => { busy = on; for (const b of buttons()) b.disabled = on; };

  /** Show what the checked bytes do and wait for an explicit choice. The wallet is not contacted until Approve. */
  function confirmPanel(summary, warning) {
    const panel = $('cardano-confirm');
    $('cardano-confirm-text').textContent = summary.lines.join('\n') + (warning ? '\n\n' + warning : '');
    panel.hidden = false;
    $('cardano-confirm-yes').focus();
    return new Promise(resolve => {
      const done = value => { panel.hidden = true; $('cardano-confirm-yes').onclick = $('cardano-confirm-no').onclick = null; resolve(value); };
      $('cardano-confirm-yes').onclick = () => done(true);
      $('cardano-confirm-no').onclick = () => done(false);
    });
  }

  async function run(op) {
    if (busy) return;
    let secret;
    try {
      if (!form.reportValidity()) return;
      const api = d.getApi();
      if (!api) throw Error('Connect a Cardano test-network wallet first.');
      const data = new FormData(form), terms = {};
      for (const name of FIELDS) terms[name] = String(data.get(name) || '').trim();
      if (op !== 'fund' && !/^[0-9a-f]{64}#(0|[1-9][0-9]{0,9})$/.test(terms.outref)) throw Error('Enter the escrow output reference.');
      if (op === 'fund') delete terms.outref;
      lock(true);
      $('cardano-wallet-result').textContent = '';
      msg($('cardano-wallet-status'), 'Checking the wallet, the escrow and the transaction.');
      scriptLoaded ??= loadPinnedScript();
      await scriptLoaded;
      const config = await d.loadTiming(), requirements = d.legRequirements(config, 'cardano'), expirySeconds = Number(terms.expiry_ms) / 1000;
      let preimage;
      if (op === 'claim') {
        const selected = $('cardano-claim-backup').value, phrase = $('cardano-claim-passphrase').value;
        $('cardano-claim-passphrase').value = '';
        if (!selected || !phrase) throw Error('Select an encrypted backup and enter its passphrase.');
        const entry = (await d.listVault()).find(item => item.envelope.hashlock === selected);
        if (!entry) throw Error('Encrypted backup not found.');
        if (selected !== terms.hashlock) throw Error('The selected backup is for a different hashlock.');
        secret = await d.unlockRecovery(entry.envelope, phrase);
        preimage = toHex(secret);
      }
      const verifyEscrow = t => d.verifyEscrow({...t, expiry_ms: Number(t.expiry_ms)}, op === 'refund' ? {confirmations: requirements.confirmations, allowExpired: true} : requirements);
      const warning = op === 'claim' ? 'A claim reveals the swap secret on chain. Claim only the escrow you are owed, and only after verifying the other leg and its deadlines. This action does not recheck the other leg, even when opened from the guided review.' : op === 'fund' ? 'Fund only after the other party has verified terms you both agreed to. This action does not recheck the other leg, even when opened from the guided review.' : '';
      const journal = {
        begin: async (chain, operation, request) => { const id = await d.journal.begin(chain, operation, request); d.refresh(); return id; },
        finish: async (id, receipt) => { await d.journal.finish(id, receipt); d.refresh(); },
        uncertain: async id => { await d.journal.uncertain(id); d.refresh(); },
        remove: async id => { await d.journal.remove(id); d.refresh(); },
      };
      const result = await cardanoWalletAction({
        op, terms, preimage, api, journal, verifyEscrow, budget: pinnedScript().executionUnits, read: d.read, confirm: summary => confirmPanel(summary, warning),
        cutoffSeconds: op === 'claim' ? expirySeconds - d.actionSeconds(config.chains.cardano) : undefined,
      });
      $('cardano-wallet-result').textContent = JSON.stringify({state: result.state, txid: result.txid, fee_lovelace: String(result.fee), note: result.message}, null, 2);
      msg($('cardano-wallet-status'), result.state === 'submitted' ? 'Transaction submitted. Check its inclusion and confirmations on a Cardano preview explorer.' : result.message, result.state !== 'submitted');
    } catch (error) {
      msg($('cardano-wallet-status'), error instanceof WalletError || error instanceof Error ? error.message : 'Cardano action failed.', true);
    } finally {
      secret?.fill(0);
      lock(false);
    }
  }

  for (const op of ['fund', 'claim', 'refund']) $('cardano-' + op).addEventListener('click', () => run(op));
  return {run};
}
