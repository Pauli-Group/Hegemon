/* Guided view of one two-party swap. It reads, checks and explains; it never signs and never writes engine state.
 *
 * Inputs are the swap's terms and the output of `swap_engine_cli.py status <id>`. The page rebuilds the engine's
 * observations from public chain reads it can verify itself, runs the display port of the engine's `decide`
 * (swap-flow.mjs, held equal to Python by shared vectors) and shows the same verdict a CLI `advance` would reach,
 * the P1 timelock verdict behind it, and which hosted action, if any, is next. Actions stay in the wallet sections,
 * each of which writes the action journal before it asks a wallet for anything.
 *
 * Limits, stated rather than hidden: the page cannot see engine-side files, so "preimage available" means an
 * encrypted backup for the hashlock exists in this browser; it does not know the engine's `submitted` timestamps, so
 * it cannot report a stalled submission (the CLI does); and the Hegemon leg is observed only through
 * a local companion (`readers.hegemon`) because the hosted page cannot reach a loopback node.
 */
import {LONG, SHORT, TERMINAL, TRANSITIONS, claimGate, decide, otherLeg, ownLeg, policyLegs, swapId, termsDigest, validateTerms} from './swap-flow.mjs';
import {checkOrdered} from './timelock-policy.mjs';
import {expectedBitcoinScript} from './bitcoin-testnet-verifier.mjs';
import {PREVIEW_HTLC_ADDRESS} from './cardano-preview-verifier.mjs';
import {expectedEtherRuntime} from './ethereum-escrow.mjs';
import {observeBitcoin, observeCardano, observeEthereum} from './observers.mjs';

export const SEQUENCE = {
  initiator: ['terms_saved', 'long_fund_submitted', 'long_funded', 'short_verified', 'short_claim_submitted', 'done'],
  responder: ['terms_saved', 'long_verified', 'short_fund_submitted', 'short_funded', 'preimage_known', 'long_claim_submitted', 'done'],
};
export const SIDE_STATES = ['refund_submitted', 'refunded', 'aborted', 'failed'];
const STATES = new Set([...TRANSITIONS.flatMap(([, from, to]) => [from, to])]);
const HEX64 = /^[0-9a-f]{64}$/;
const fail = message => { throw Error(message); };

export const emptyObservation = () => ({found: false, verified: false, confirmations: 0, problem: null, spent: null, spend_confirmations: 0, spend_txid: null, preimage: null});

// ---------------------------------------------------------------- inputs

/** Check the pasted terms and engine status against each other. Everything later trusts only what passes here. */
export async function parseSwap({termsText, statusText}) {
  let terms, status;
  try { terms = JSON.parse(termsText); } catch { fail('The terms are not valid JSON.'); }
  try { status = JSON.parse(statusText); } catch { fail('The status is not valid JSON.'); }
  validateTerms(terms);
  if (!status || typeof status !== 'object' || Array.isArray(status)) fail('The status must be the JSON printed by the engine status command for one swap.');
  if (!['initiator', 'responder'].includes(status.role)) fail('The status has no valid role.');
  if (!STATES.has(status.state)) fail('The status names an unknown state.');
  const id = await swapId(terms);
  if (status.swap_id !== id) fail('The status belongs to a different swap than these terms.');
  if (status.terms_digest !== undefined && status.terms_digest !== await termsDigest(terms)) fail('The status was written for different terms.');
  const escrows = status.escrows ?? {};
  for (const name of [LONG, SHORT]) {
    const ref = escrows[name];
    if (ref == null) continue;
    const chain = terms.legs[name].chain;
    if (chain === 'bitcoin' && !(HEX64.test(ref.txid) && Number.isSafeInteger(ref.vout) && ref.vout >= 0)) fail(`The ${name} escrow reference is not a Bitcoin output.`);
    if (chain === 'cardano' && !(HEX64.test(ref.txid) && Number.isSafeInteger(ref.vout) && ref.vout >= 0)) fail(`The ${name} escrow reference is not a Cardano output.`);
    if (chain === 'ethereum' && !HEX64.test(String(ref.txid ?? ''))) fail(`The ${name} escrow reference is not an Ethereum transaction.`);
  }
  const record = {role: status.role, state: status.state, needs_human: status.needs_human ?? null, inflight: status.inflight ?? null,
    escrows: {long: escrows.long ?? null, short: escrows.short ?? null}, txids: status.txids ?? {}, submitted: {}};
  return {terms, record, id};
}

export function sequenceView(record) {
  const path = SEQUENCE[record.role], index = path.indexOf(record.state);
  return {path, index, side: SIDE_STATES.includes(record.state) ? record.state : null};
}

/** A human-readable owner of the next step. Chain reads are snapshots: absence of a
 * recorded reference cannot prove that the other person has not already acted. */
export function waitingView({record, decision, obs}) {
  if (decision.kind === 'terminal') return {actor: 'No one', title: 'This swap is finished'};
  if (decision.kind === 'halt' || decision.kind === 'abort') return {actor: 'You', title: 'Review the problem before continuing'};
  if (decision.kind === 'act') return {actor: 'You', title: decision.action === 'fund' ? 'Lock your side of the swap' : decision.action === 'claim' ? 'Claim the escrow you are owed' : 'Refund your escrow'};
  if (decision.kind === 'move') return {actor: 'You', title: 'Update the local swap record'};
  if (Object.keys(obs.errors ?? {}).length) return {actor: 'Unknown', title: 'A chain could not be checked'};
  if (record.state === 'long_fund_submitted' || record.state === 'short_fund_submitted' || record.state === 'short_claim_submitted' || record.state === 'long_claim_submitted' || record.state === 'refund_submitted') {
    return {actor: 'The network', title: 'Waiting for transaction confirmation'};
  }
  if ((record.role === 'initiator' && record.state === 'long_funded') || (record.role === 'responder' && (record.state === 'terms_saved' || record.state === 'short_funded'))) {
    const ref = record.escrows[record.role === 'initiator' ? 'short' : record.state === 'terms_saved' ? 'long' : 'short'];
    if (ref && record.state !== 'short_funded') return {actor: 'The network', title: 'Checking the other escrow'};
    return {actor: 'The other person', title: record.state === 'short_funded' ? 'Waiting for their claim' : 'Waiting for their escrow details'};
  }
  return {actor: 'Unknown', title: 'Check the latest swap state'};
}

// ---------------------------------------------------------------- observations

const unreadable = (errors, name, error) => { errors[name] = String(error?.message ?? error).slice(0, 200); return null; };

/** A spent escrow whose spend the provider has not indexed is unreadable, never "unspent": the engine raises the same way. */
function settle(observation, seen) {
  if (seen.state !== 'claimed' && seen.state !== 'refunded') fail('the escrow is spent but the spending transaction is not indexed yet');
  Object.assign(observation, {spent: seen.state, spend_txid: seen.txid, spend_confirmations: seen.confirmations, preimage: seen.preimage ?? null});
}

async function bitcoinLeg(leg, ref, terms, readers, config) {
  const t = {txid: ref.txid, vout: ref.vout, amount_sats: leg.amount, hashlock: terms.hashlock, claimant_key: leg.claimant, refund_key: leg.refundee, refund_height: leg.expiry};
  const snapshot = await readers.bitcoin.escrow(ref.txid, ref.vout), observation = emptyObservation();
  observation.found = true;
  observation.confirmations = snapshot.confirmed === true ? snapshot.confirmations : 0;
  const problems = [];
  if (snapshot.script !== await expectedBitcoinScript(t)) problems.push('script');
  if (snapshot.amount_sats !== leg.amount) problems.push('amount');
  if (problems.length) return {...observation, problem: 'escrow differs from the terms in ' + problems.join(', ')};
  observation.verified = true;
  if (snapshot.spent) {
    const seen = await observeBitcoin(t, readers.bitcoin.spend, {confirmations: 0});
    settle(observation, seen);
  }
  return observation;
}

async function cardanoLeg(leg, ref, terms, readers) {
  const outref = `${ref.txid}#${ref.vout}`, snapshot = await readers.cardano.escrow(outref), row = snapshot?.output, observation = emptyObservation();
  if (!row) return observation;
  observation.found = true;
  observation.confirmations = snapshot.confirmations;
  const datum = row.inline_datum?.value?.fields, problems = [];
  if (row.address !== PREVIEW_HTLC_ADDRESS) problems.push('script address');
  if (row.value !== String(leg.amount) || (row.asset_list ?? []).length) problems.push('value');
  if (!Array.isArray(datum) || datum[0]?.bytes !== terms.hashlock || datum[1]?.bytes !== leg.claimant || datum[2]?.bytes !== leg.refundee || datum[3]?.int !== leg.expiry * 1000) problems.push('datum terms');
  if (problems.length) return {...observation, problem: 'escrow differs from the terms in ' + problems.join(', ')};
  observation.verified = true;
  if (row.is_spent === true) {
    const seen = await observeCardano({outref, hashlock: terms.hashlock}, readers.cardano.spend, {confirmations: 0});
    settle(observation, seen);
  }
  return observation;
}

async function ethereumLeg(leg, ref, terms, readers, template) {
  const provider = readers.ethereum.provider, request = (method, params = []) => provider.request({method, params}), observation = emptyObservation();
  const receipt = await request('eth_getTransactionReceipt', ['0x' + ref.txid]);
  if (!receipt) return observation;
  const tx = await request('eth_getTransactionByHash', ['0x' + ref.txid]);
  if (!tx || String(tx.hash).toLowerCase() !== '0x' + ref.txid) fail('the provider returned a different transaction');
  const tip = BigInt(await request('eth_blockNumber')), mined = BigInt(receipt.blockNumber);
  observation.found = true;
  observation.confirmations = Number(tip >= mined ? tip - mined + 1n : 0n);
  const contract = String(receipt.contractAddress ?? '').toLowerCase(), problems = [];
  if (receipt.status !== '0x1' || !/^0x[0-9a-f]{40}$/.test(contract)) problems.push('creation');
  if (tx.to !== null) problems.push('creation');
  if (String(tx.from).toLowerCase() !== leg.refundee) problems.push('funder');
  if (BigInt(tx.value) !== BigInt(leg.amount)) problems.push('amount');
  if (!problems.length) {
    const expected = expectedEtherRuntime(template, {hashlock: '0x' + terms.hashlock, claimant: leg.claimant, refundee: leg.refundee, expiry: String(leg.expiry), amount: String(leg.amount)});
    if (String(await request('eth_getCode', [contract, 'latest'])).toLowerCase() !== expected) problems.push('runtime code');
  }
  if (problems.length) return {...observation, problem: 'escrow differs from the terms in ' + [...new Set(problems)].join(', ')};
  observation.verified = true;
  observation.contract = contract;
  const seen = await observeEthereum({contract, hashlock: terms.hashlock, from_block: Number(mined)}, readers.ethereum.events, {confirmations: 0});
  if (seen.state !== 'unspent') settle(observation, seen);
  return observation;
}

async function hegemonLeg(leg, ref, terms, readers) {
  const snapshot = await readers.hegemon.escrow(ref, terms);
  return snapshot || null;
}

async function head(chain, readers, now) {
  if (chain === 'bitcoin') return {observedAt: now, height: (await readers.bitcoin.head()).tip};
  if (chain === 'cardano') { const p = await readers.cardano.params(); return {observedAt: now, timestamp: p.system_start + p.slot}; }
  if (chain === 'ethereum') {
    const block = await readers.ethereum.provider.request({method: 'eth_getBlockByNumber', params: ['latest', false]});
    const timestamp = Number(BigInt(block?.timestamp));
    if (!Number.isSafeInteger(timestamp)) fail('the provider returned an invalid block');
    return {observedAt: now, timestamp};
  }
  if (chain === 'hegemon') {
    const h = await readers.hegemon.head();
    if (!Number.isSafeInteger(h?.height)) fail('the Hegemon companion returned an invalid head');
    return {observedAt: now, height: h.height};
  }
  fail('no public testnet head for ' + chain);
}

/** The engine's observation structure from public reads. A leg that cannot be read is `null` with a note in `errors`. */
export async function buildObservation({terms, record, now, readers, template, hasSecret}) {
  const heads = {long: null, short: null}, legs = {long: null, short: null}, errors = {};
  for (const name of [LONG, SHORT]) {
    const leg = terms.legs[name], ref = record.escrows[name];
    if (leg.chain === 'hegemon' && !readers.hegemon) {
      errors[name] = 'Hegemon requires a local companion on this machine; the hosted page cannot reach a loopback node.';
      continue;
    }
    try { heads[name] = await head(leg.chain, readers, now); } catch (error) { unreadable(errors, name, error); }
    if (ref == null) continue;
    try {
      legs[name] = leg.chain === 'bitcoin' ? await bitcoinLeg(leg, ref, terms, readers)
        : leg.chain === 'cardano' ? await cardanoLeg(leg, ref, terms, readers)
          : leg.chain === 'hegemon' ? await hegemonLeg(leg, ref, terms, readers)
            : await ethereumLeg(leg, ref, terms, readers, template);
    } catch (error) { unreadable(errors, name, error); }
  }
  return {now, heads, legs, errors, preimage_available: hasSecret};
}

// ---------------------------------------------------------------- explanation

const SECTIONS = {bitcoin: 'bitcoin-wallet-section', cardano: 'cardano-wallet-section', ethereum: 'sepolia-action-section'};
const ACTION_FORM = {fund: 'fund', claim: 'claim', refund: 'refund'};

/** Which hosted form to fill for an `act` decision, and with what. Pure; the page does the filling. */
export function prefillFor(decision, terms, record, obs = null) {
  const leg = terms.legs[decision.leg], chain = leg.chain, ref = record.escrows[decision.leg];
  const section = SECTIONS[chain];
  if (!section) return null;
  const operation = ACTION_FORM[decision.action];
  if (chain === 'bitcoin') {
    return {section, form: 'bitcoin-wallet-form', operation, fields: {amount_sats: leg.amount, hashlock: terms.hashlock, claimant_key: leg.claimant, refund_key: leg.refundee, refund_height: leg.expiry, ...(operation !== 'fund' && ref ? {txid: ref.txid, vout: ref.vout} : {})}};
  }
  if (chain === 'cardano') {
    return {section, form: 'cardano-wallet-form', operation, fields: {lovelace: leg.amount, hashlock: terms.hashlock, claimant: leg.claimant, refundee: leg.refundee, expiry_ms: leg.expiry * 1000, ...(operation !== 'fund' && ref ? {outref: `${ref.txid}#${ref.vout}`} : {})}};
  }
  return {section, form: 'sepolia-action-form', operation, fields: {kind: 'eth', amount: leg.amount, hashlock: '0x' + terms.hashlock, claimant: leg.claimant, refundee: leg.refundee, expiry: leg.expiry, ...(obs?.legs?.[decision.leg]?.contract ? {contract: obs.legs[decision.leg].contract} : {})}};
}

/** The headline, reasons and next step for a decision. `claim` also reports the last safe submission time. */
export function explainDecision({decision, record, terms, obs, config, id}) {
  const cli = `python3 scripts/swap_engine_cli.py advance ${id}`;
  const notes = [];
  if (record.inflight) notes.push('An action is in flight: the engine submitted something whose outcome it has not settled. Do not act from this page until it is resolved (CLI: resolve --adopt or --abandon after checking the chain).');
  if (record.needs_human) notes.push(`The engine stopped for a human: ${record.needs_human}. Inspect the chain, then use the CLI clear command.`);
  for (const [name, text] of Object.entries(obs.errors)) notes.push(`${name} leg: ${text}`);
  const base = {notes, cli, decision};
  if (decision.kind === 'terminal') return {...base, headline: `Finished: ${decision.why}.`, next: null};
  if (decision.kind === 'halt') return {...base, headline: `Stopped: ${decision.why}`, next: {type: 'human', text: 'Check the chains, then use resolve or clear in the CLI. The page will not act.'}};
  if (decision.kind === 'wait') return {...base, headline: `Wait: ${decision.why}.`, next: {type: 'wait'}};
  if (decision.kind === 'abort') return {...base, headline: `Do not fund: ${decision.why}.`, next: {type: 'abort', text: `Nothing is funded. Abort in the CLI: swap_engine_cli.py abort ${id}.`}};
  if (decision.kind === 'move') return {...base, headline: `The engine would record: ${decision.why}.`, next: {type: 'cli', text: `Run ${cli} to record it.`}};
  // act
  const leg = terms.legs[decision.leg], gate = decision.action === 'claim' ? claimGate(record.role, terms, obs.heads, config, obs.now) : null;
  if (gate && !gate.ok) return {...base, headline: `Do not claim now: ${gate.reasons.join(', ')}.`, claimGate: gate, next: {type: 'wait'}};
  const prefill = leg.chain === 'hegemon' ? null : prefillFor(decision, terms, record, obs);
  return {...base, claimGate: gate, prefill,
    headline: `Next: ${decision.action} the ${decision.leg} leg on ${leg.chain}: ${decision.why}.`,
    next: prefill ? {type: 'wallet', section: prefill.section, text: `Use the ${leg.chain} wallet section below, or run ${cli}.`}
      : {type: 'cli', text: leg.chain === 'hegemon' ? 'The Hegemon leg requires a local companion (the hosted page cannot reach loopback). Use the CLI or scripts/local_swap_companion.py --hegemon-public.' : `Run ${cli}.`}};
}

/** Saved action records that concern this swap and are not settled. */
export function openActions(records, terms) {
  const chains = new Set([terms.legs.long.chain, terms.legs.short.chain]);
  return records.filter(r => chains.has(r.chain) && r.state !== 'completed' && (r.request.hashlock === undefined || r.request.hashlock === terms.hashlock || r.request.hashlock === '0x' + terms.hashlock));
}

/** One full pass: observe, decide, explain. */
export async function review({termsText, statusText, config, now, readers, template, hasSecret, records = []}) {
  const {terms, record, id} = await parseSwap({termsText, statusText});
  const secret = typeof hasSecret === 'function' ? await hasSecret(terms.hashlock) : hasSecret;
  const obs = await buildObservation({terms, record, now, readers, template, hasSecret: secret});
  const open = openActions(records, terms);
  const decision = open.length ? {kind: 'halt', why: 'a saved action is pending or uncertain; check its outcome before continuing'} : decide(record, terms, obs, config, now);
  const view = explainDecision({decision, record, terms, obs, config, id});
  if (open.length) view.notes.push(`${open.length} saved action record${open.length > 1 ? 's' : ''} for these chains ${open.length > 1 ? 'are' : 'is'} pending or uncertain. Check the chain and the local action journal before acting.`);
  const policy = obs.heads.long && obs.heads.short ? checkOrdered(config, {...policyLegs(terms), heads: obs.heads, now}) : null;
  return {id, terms, record, obs, sequence: sequenceView(record), view, open, policy};
}

export {TERMINAL, otherLeg, ownLeg};
