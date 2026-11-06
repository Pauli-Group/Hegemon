/* Page glue for Bitcoin testnet4 PSBT actions. All page dependencies are passed in so a test page can drive it.
 * The page never holds a wallet key; the user's PSBT signer signs the exported PSBT. */
import {prepareBitcoinPsbt, finishBitcoinPsbt, BitcoinWalletError} from './bitcoin-wallet.mjs';
import {toHex} from './cbor.mjs';

const TERM_FIELDS = ['txid', 'vout', 'amount_sats', 'hashlock', 'claimant_key', 'refund_key', 'refund_height'];

export function initBitcoinWalletActions(d) {
  const {$, msg} = d, form = $('bitcoin-wallet-form');
  let session = null, busy = false;
  const operation = () => form.elements.operation.value;

  function syncFields() {
    const spend = operation() !== 'fund';
    for (const label of form.querySelectorAll('[data-spend]')) {
      label.hidden = !spend;
      for (const input of label.querySelectorAll('input')) input.disabled = !spend;
    }
    $('bitcoin-claim-fields').hidden = operation() !== 'claim';
    $('bitcoin-address-label').textContent = spend ? 'Destination testnet4 address' : 'Your testnet4 address (funding coins and change)';
  }
  form.elements.operation.addEventListener('change', () => { session = null; $('bitcoin-psbt-section').hidden = true; syncFields(); });
  syncFields();

  const journal = {
    begin: async (chain, op, request) => { const id = await d.journal.begin(chain, op, request); d.refresh(); return id; },
    finish: async (id, receipt) => { await d.journal.finish(id, receipt); d.refresh(); },
    uncertain: async id => { await d.journal.uncertain(id); d.refresh(); },
    remove: async id => { await d.journal.remove(id); d.refresh(); },
  };
  const termsFromForm = () => {
    const data = new FormData(form), terms = {};
    for (const name of TERM_FIELDS) if (data.has(name)) terms[name] = String(data.get(name) || '').trim();
    return terms;
  };
  const verifyEscrow = async (terms, {op}) => {
    const config = await d.loadTiming(), requirements = d.legRequirements(config, 'bitcoin');
    const limits = op === 'refund' ? {confirmations: requirements.confirmations, allowExpired: true} : requirements;
    return d.verifyEscrow({...terms, vout: Number(terms.vout), amount_sats: Number(terms.amount_sats), refund_height: Number(terms.refund_height)}, limits);
  };

  async function build() {
    if (busy) return;
    try {
      if (!form.reportValidity()) return;
      busy = true;
      session = null;
      $('bitcoin-psbt-section').hidden = true;
      $('bitcoin-wallet-result').textContent = '';
      msg($('bitcoin-wallet-status'), 'Checking the chain and building the transaction.');
      const op = operation(), data = new FormData(form);
      session = await prepareBitcoinPsbt({op, terms: termsFromForm(), address: String(data.get('address')).trim(), feeRate: Number(data.get('feerate')),
        read: d.read, verifyEscrow, journal});
      $('bitcoin-psbt-summary').textContent = session.lines.join('\n') + `\n\nFee: ${session.fee} sats\nTransaction ID once signed: ${session.txid}\nChain height when built: ${session.tip}`;
      $('bitcoin-psbt-out').value = session.psbt;
      const link = $('bitcoin-psbt-download');
      if (link.dataset.url) URL.revokeObjectURL(link.dataset.url);
      link.dataset.url = link.href = URL.createObjectURL(new Blob([Uint8Array.from(atob(session.psbt), c => c.charCodeAt(0))], {type: 'application/octet-stream'}));
      link.download = `hegemon-${op}-${session.txid.slice(0, 12)}.psbt`;
      $('bitcoin-psbt-in').value = '';
      $('bitcoin-psbt-section').hidden = false;
      msg($('bitcoin-wallet-status'), 'Review the summary, then sign this PSBT in your wallet and paste the signed result below. An action record was saved.');
    } catch (error) {
      msg($('bitcoin-wallet-status'), error.message || 'Bitcoin action failed.', true);
    } finally {
      busy = false;
    }
  }

  async function finish(broadcast) {
    if (busy || !session) return;
    let secret;
    try {
      busy = true;
      const signedPsbt = $('bitcoin-psbt-in').value;
      if (!signedPsbt.trim()) throw Error('Paste the signed PSBT first.');
      let preimage;
      if (session.op === 'claim') {
        const selected = $('bitcoin-claim-backup').value, phrase = $('bitcoin-claim-passphrase').value;
        $('bitcoin-claim-passphrase').value = '';
        if (!selected || !phrase) throw Error('Select an encrypted backup and enter its passphrase.');
        if (selected !== session.terms.hashlock) throw Error('The selected backup is for a different hashlock.');
        const entry = (await d.listVault()).find(item => item.envelope.hashlock === selected);
        if (!entry) throw Error('Encrypted backup not found.');
        secret = await d.unlockRecovery(entry.envelope, phrase);
        preimage = toHex(secret);
      }
      msg($('bitcoin-wallet-status'), 'Re-checking the chain and the signature.');
      const result = await finishBitcoinPsbt({session, signedPsbt, preimage, read: d.read, verifyEscrow, journal, broadcast});
      $('bitcoin-wallet-result').textContent = JSON.stringify({state: result.state, txid: result.txid, fee_sats: String(result.fee), vsize: result.vsize,
        ...(result.state === 'finalized' ? {raw_transaction: result.txHex} : {})}, null, 2);
      msg($('bitcoin-wallet-status'), result.message);
      session = null;
      $('bitcoin-psbt-section').hidden = true;
    } catch (error) {
      msg($('bitcoin-wallet-status'), error instanceof BitcoinWalletError || error instanceof Error ? error.message : 'Bitcoin action failed.', true);
    } finally {
      secret?.fill(0);
      busy = false;
    }
  }

  $('bitcoin-build').addEventListener('click', build);
  $('bitcoin-broadcast').addEventListener('click', () => finish(true));
  $('bitcoin-finalize').addEventListener('click', () => finish(false));
  return {build, finish};
}
