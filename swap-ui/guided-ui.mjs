/* Page glue for the guided swap view. Read-only: it fills wallet forms the user then submits themselves, and shows
 * engine commands to copy. It writes nothing the engine treats as an action. */
import {review, SIDE_STATES} from './guided.mjs';

const LABEL = {
  terms_saved: 'Terms saved', long_fund_submitted: 'Long leg funding submitted', long_funded: 'Long leg funded', short_verified: 'Short leg verified',
  short_claim_submitted: 'Short leg claim submitted', long_verified: 'Long leg verified', short_fund_submitted: 'Short leg funding submitted', short_funded: 'Short leg funded',
  preimage_known: 'Secret learned', long_claim_submitted: 'Long leg claim submitted', done: 'Done', refund_submitted: 'Refund submitted', refunded: 'Refunded', aborted: 'Aborted', failed: 'Failed',
};

export function initGuided(d) {
  const {$, msg} = d;
  let last = null;
  const clock = d.now ?? (() => Math.floor(Date.now() / 1000));

  function render(out) {
    const list = $('guided-sequence');
    list.replaceChildren();
    out.sequence.path.forEach((state, index) => {
      const item = document.createElement('li');
      item.textContent = LABEL[state] ?? state;
      if (index === out.sequence.index) item.setAttribute('aria-current', 'step');
      list.append(item);
    });
    $('guided-side').textContent = out.sequence.side ? `This swap is in a side state: ${LABEL[out.sequence.side]}.` : (out.sequence.index < 0 ? `Current state: ${LABEL[out.record.state] ?? out.record.state}.` : '');
    $('guided-headline').textContent = out.view.headline;
    const notes = $('guided-notes');
    notes.replaceChildren(...out.view.notes.map(text => { const li = document.createElement('li'); li.textContent = text; return li; }));
    const lines = [];
    if (out.policy) {
      lines.push(`Timelock policy: ${out.policy.ok ? 'allows these terms' : 'rejects these terms'}`);
      for (const reason of out.policy.reasons ?? []) lines.push(`  ${reason.code}: ${reason.message ?? ''}`);
      const m = out.policy.metrics ?? {};
      if (m.gapSeconds !== undefined) lines.push(`  gap between the legs ${m.gapSeconds}s (needs ${m.gapRequiredSeconds}s); short claim window ${m.shortClaimWindowSeconds}s (needs ${m.shortClaimRequiredSeconds}s)`);
    } else lines.push('Timelock policy: not evaluated; a chain head is unavailable.');
    if (out.view.claimGate) lines.push(out.view.claimGate.submitBySeconds !== null ? `Submit the claim within ${Math.max(0, Math.floor(out.view.claimGate.submitBySeconds))}s of this reading.` : '');
    for (const leg of ['long', 'short']) {
      const o = out.obs.legs[leg];
      lines.push(`${leg} leg (${out.terms.legs[leg].chain}): ${o === null ? 'not readable' : o.problem ? 'MISMATCH ' + o.problem : !o.found ? 'not seen' : `${o.verified ? 'verified' : 'unverified'}, ${o.confirmations} confirmations${o.spent ? ', ' + o.spent : ''}`}`);
    }
    $('guided-detail').textContent = lines.filter(Boolean).join('\n');
    $('guided-command').textContent = out.view.cli;
    $('guided-next').textContent = out.view.next?.text ?? '';
    const button = $('guided-fill');
    button.hidden = !out.view.prefill;
    last = out;
  }

  async function check() {
    $('guided-check').disabled = true;
    try {
      msg($('guided-status'), 'Reading the chains.');
      const config = await d.loadTiming(), template = await d.template();
      const out = await review({termsText: $('guided-terms').value, statusText: $('guided-swap-status').value, config, now: clock(), readers: d.readers, template,
        hasSecret: async hashlock => (await d.listVault()).some(item => item.envelope.hashlock === hashlock), records: await d.listActions()});
      render(out);
      msg($('guided-status'), 'Checked. This is advice from public reads; the engine remains the source of truth.');
    } catch (error) {
      msg($('guided-status'), error.message || 'Could not check this swap.', true);
    } finally {
      $('guided-check').disabled = false;
    }
  }

  /** Fill the matching wallet form with the agreed terms. Nothing is submitted and no wallet is contacted. */
  function fill() {
    const plan = last?.view.prefill;
    if (!plan) return;
    const section = $(plan.section), form = $(plan.form);
    section.hidden = false;
    const op = form.elements.operation;
    if (op && plan.operation) { op.value = plan.operation; op.dispatchEvent(new Event('change', {bubbles: true})); }
    for (const [name, value] of Object.entries(plan.fields)) {
      const field = form.elements[name];
      if (!field) continue;
      field.value = String(value);
      field.dispatchEvent(new Event('input', {bubbles: true}));
    }
    section.scrollIntoView({block: 'start'});
    msg($('guided-status'), `The ${plan.operation} form is filled with the agreed terms. Review it and press its own button; this page asks no wallet for anything.`);
  }

  $('guided-check').addEventListener('click', check);
  $('guided-fill').addEventListener('click', fill);
  return {check, fill, SIDE_STATES};
}
