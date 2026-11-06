/* Page glue for observing the counterparty's claim. The preimage it finds is held only in memory until the user saves it
 * under a passphrase, and then only as an encrypted backup. */
import {observe, saveLearnedPreimage} from './observers.mjs';
import {fromHex} from './cbor.mjs';

export function initObserver(d) {
  const {$, msg} = d, form = $('observer-form');
  let learned = null;   // {preimage: Uint8Array, hashlock}
  const forget = () => { learned?.preimage.fill(0); learned = null; $('observer-save-panel').hidden = true; };
  const chain = () => form.elements.chain.value;
  function sync() {
    for (const group of form.querySelectorAll('[data-chain]')) {
      const on = group.dataset.chain === chain();
      group.hidden = !on;
      for (const input of group.querySelectorAll('input')) input.disabled = !on;
    }
    forget();
  }
  form.elements.chain.addEventListener('change', sync);
  sync();

  const value = name => String(form.elements[name].value).trim();
  function termsFor(name) {
    const hashlock = value('hashlock');
    if (name === 'bitcoin') return {hashlock, txid: value('txid'), vout: Number(value('vout')), claimant_key: value('claimant_key'), refund_key: value('refund_key'), refund_height: Number(value('refund_height')), amount_sats: 546};
    if (name === 'ethereum') return {hashlock, contract: value('contract'), from_block: Number(value('from_block') || 0)};
    return {hashlock, outref: value('outref')};
  }

  async function look() {
    forget();
    try {
      if (!form.reportValidity()) return;
      $('observer-look').disabled = true;
      $('observer-result').textContent = '';
      msg($('observer-status'), 'Reading the chain.');
      const name = chain(), config = await d.loadTiming(), need = d.legRequirements(config, name).confirmations;
      const terms = termsFor(name), seen = await observe[name](terms, d.read[name], {confirmations: need});
      const shown = {...seen};
      delete shown.preimage;
      $('observer-result').textContent = JSON.stringify({...shown, preimage_hash_matches: seen.preimage ? true : undefined}, null, 2);
      if (seen.state === 'claimed') {
        learned = {preimage: fromHex(seen.preimage), hashlock: terms.hashlock};
        $('observer-save-panel').hidden = false;
        msg($('observer-status'), seen.enough ? 'Claim found and it hashes to the agreed hashlock. Save it as an encrypted backup.'
          : `Claim found and it hashes to the hashlock, but it has ${seen.confirmations} of ${need} required confirmations. You can save the secret, but check the other leg's policy before relying on this claim.`);
      } else if (seen.state === 'pending') {
        msg($('observer-status'), seen.note + ' Try again shortly; this is not evidence that nothing happened.');
      } else if (seen.state === 'refunded') {
        msg($('observer-status'), 'The escrow was refunded. There is no preimage to learn.');
      } else {
        msg($('observer-status'), 'No spend of this escrow is visible yet.');
      }
    } catch (error) {
      msg($('observer-status'), error.message || 'Observation failed.', true);
    } finally {
      $('observer-look').disabled = false;
    }
  }

  async function save() {
    if (!learned) return;
    const phrase = $('observer-passphrase').value, repeat = $('observer-confirm').value;
    $('observer-passphrase').value = $('observer-confirm').value = '';
    try {
      const out = await saveLearnedPreimage({preimage: Array.from(learned.preimage, b => b.toString(16).padStart(2, '0')).join(''), hashlock: learned.hashlock,
        label: d.vaultLabel($('observer-label').value || 'Learned from counterparty claim'), passphrase: phrase, confirm: repeat},
      {encryptRecovery: d.encryptRecovery, addVault: d.addVault, listVault: d.listVault});
      if (out.saved) { d.notifyVault(); $('vault-backup').value = JSON.stringify({label: d.vaultLabel($('observer-label').value || 'Learned from counterparty claim'), envelope: out.envelope}); await d.renderVault(); forget(); msg($('observer-status'), 'Encrypted backup saved. Copy it from the backup section and keep its passphrase separate.'); }
      else msg($('observer-status'), out.reason, false);
    } catch (error) {
      msg($('observer-status'), error.message || 'Could not save the backup.', true);
    }
  }
  $('observer-look').addEventListener('click', look);
  $('observer-save').addEventListener('click', save);
  return {look, save};
}
