#!/usr/bin/env node
/* Qualification run: the hosted page's wallet flows on the real public testnets with disposable funds.
 *
 * It spends real (worthless) testnet coins, so it never runs from `node --test`. Run it deliberately:
 *
 *   HEGEMON_QUALIFY=1 HEGEMON_WALLETS=~/.local/share/hegemon-testnet-wallets-20261104/testnet-wallets \
 *   CHROMIUM_PATH=/snap/bin/chromium PYTHONPATH=$HOME/.local/opt/hegemon-swap-python \
 *   node swap-service/qualify/hosted-ui.mjs [--out results.json] [--only sepolia,cardano,bitcoin]
 *
 * `--sweep-cardano TXID#INDEX` instead refunds one leftover Cardano escrow of the pinned validator that belongs to Alice,
 * through the page, reading its terms from the on-chain datum (clean-up after aborted runs).
 *
 * What is real: the hosted Worker (swap-service/cloudflare/worker.mjs, hosted in Node with an in-memory D1 and
 * an identity HTMLRewriter), the page's own modules in Chromium, the public providers behind the Worker, and the
 * chains. What stands in for a wallet product: an EIP-1193 provider backed by eth_account (Python), a CIP-30
 * software wallet signing with an ed25519 key (swap-service/tools/cardano-bridge.mjs), and an embit PSBT signer
 * (Python). No browser-extension wallet is involved. Key files are named by HEGEMON_WALLETS only; key material
 * is never printed and only public identifiers go to the results file.
 */
import http from 'node:http';
import net from 'node:net';
import {DatabaseSync} from 'node:sqlite';
import {spawn} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {extname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright-core';
import {secp256k1} from '../../swap-ui/vendor/btc-signer.mjs';
import {toHex, fromHex} from '../../swap-ui/cbor.mjs';
import {softwareWallet} from '../tools/cardano-bridge.mjs';
import {blake2b, ed25519} from '../../swap-ui/vendor/hash.mjs';

// Node's default 250 ms per-address connect attempt is shorter than a normal TLS-less TCP connect to a busy CDN edge from here,
// so unrelated reads (the Worker's own provider calls included) failed with ETIMEDOUT. Give each attempt a realistic budget.
net.setDefaultAutoSelectFamilyAttemptTimeout(5000);
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const args = process.argv.slice(2);
const option = (name, fallback) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : fallback; };
if (process.env.HEGEMON_QUALIFY !== '1') { console.error('Set HEGEMON_QUALIFY=1 to spend testnet funds.'); process.exit(2); }
const WALLETS = resolve(process.env.HEGEMON_WALLETS ?? '');
if (!process.env.HEGEMON_WALLETS || !existsSync(WALLETS)) { console.error('Set HEGEMON_WALLETS to the testnet wallet directory.'); process.exit(2); }
const ONLY = new Set((option('--only', 'sepolia,cardano,bitcoin')).split(','));
const OUT = option('--out', `/tmp/hegemon-qualify-${Date.now()}.json`);
const PASSPHRASE = 'qualification run passphrase';
const results = {started: new Date().toISOString(), host: 'local Node host of swap-service/cloudflare/worker.mjs', wallets: {}, sepolia: {}, cardano: {}, bitcoin: {}, notes: []};
const save = () => writeFileSync(OUT, JSON.stringify(results, null, 2));
const log = (chain, text) => console.log(`[${new Date().toISOString().slice(11, 19)}] ${chain}: ${text}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const addresses = JSON.parse(readFileSync(join(WALLETS, 'addresses.json'), 'utf8'));
const keyFile = (who, name) => join(WALLETS, who, name);
const unixNow = () => Math.floor(Date.now() / 1000);

/** Public providers drop connections now and then; a read may be repeated, a spend never is. */
async function retry(fn, tries = 8) {
  for (let i = 1; ; i++) {
    try { return await fn(); } catch (error) { console.error(`  (read failed, try ${i}: ${error.cause?.code ?? error.cause?.message ?? error.message})`); if (i >= tries) throw error; await sleep(2000 * i); }
  }
}

async function until(what, fn, {timeoutMs = 3_600_000, everyMs = 15_000} = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn().catch(() => null);
    if (value) return value;
    if (Date.now() > end) throw Error(`timed out waiting for ${what}`);
    await sleep(everyMs);
  }
}

// ---- the hosted Worker, in Node
globalThis.HTMLRewriter = class { on() { return this; } transform(response) { return response; } };
const {default: worker} = await import('../cloudflare/worker.mjs');
const MIME = {'.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.css': 'text/css'};
function database() {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(join(ROOT, 'swap-service/cloudflare/schema.sql'), 'utf8'));
  return {raw: db, async batch(statements) { for (const s of statements) await s.run(); }, prepare(sql) {
    const q = db.prepare(sql); let values = [];
    return {bind(...v) { values = v; return this; }, async first() { return q.get(...values) ?? null; }, async all() { return {results: q.all(...values)}; }, async run() { return q.run(...values); }};
  }};
}
async function startHost() {
  const env = {DB: database(), ASSETS: {fetch: async request => {
    let path = new URL(request.url).pathname; if (path === '/') path = '/index.html';
    const file = join(ROOT, 'swap-ui', path);
    if (!file.startsWith(join(ROOT, 'swap-ui')) || !existsSync(file)) return new Response('not found', {status: 404});
    return new Response(readFileSync(file), {headers: {'content-type': MIME[extname(file)] ?? 'application/octet-stream'}});
  }}};
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const headers = new Headers(); for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v);
    headers.set('CF-Connecting-IP', '127.0.0.1'); headers.set('origin', `http://${req.headers.host}`);
    const out = await worker.fetch(new Request(`http://${req.headers.host}${req.url}`, {method: req.method, headers, ...(body.length && req.method !== 'GET' ? {body} : {})}), env);
    res.writeHead(out.status, Object.fromEntries(out.headers)); res.end(Buffer.from(await out.arrayBuffer()));
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return {base: `http://127.0.0.1:${server.address().port}`, close: () => server.close()};
}

// ---- helpers shared by the chains
async function createBackup(page) {
  await page.locator('#vault-create [name="label"]').fill('qualification');
  await page.locator('#vault-create [name="passphrase"]').fill(PASSPHRASE);
  await page.locator('#vault-create [name="confirm"]').fill(PASSPHRASE);
  await page.getByRole('button', {name: 'Create encrypted secret'}).click();
  await page.waitForFunction(() => document.getElementById('vault-backup').value.includes('hashlock'));
  return JSON.parse(await page.locator('#vault-backup').inputValue()).envelope.hashlock;
}
const statusOf = (page, id) => page.locator('#' + id).innerText();
async function waitStatus(page, id, pattern, timeout = 120_000) {
  await page.waitForFunction(({id, source}) => new RegExp(source, 'i').test(document.getElementById(id).textContent), {id, source: pattern.source}, {timeout});
}
async function clearStatus(page, id) { await page.evaluate(id => { const el = document.getElementById(id); el.textContent = ''; el.className = ''; }, id); }
async function settled(page, id, pattern) {
  // Wait for a final status: success pattern or any error class.
  await page.waitForFunction(({id, source}) => { const el = document.getElementById(id); return el.className === 'error' || new RegExp(source, 'i').test(el.textContent); }, {id, source: pattern.source}, {timeout: 180_000});
  return {text: await statusOf(page, id), error: (await page.locator('#' + id).getAttribute('class')) === 'error'};
}
async function journal(page) { return page.evaluate(async () => (await import('/action-journal.mjs')).listActions()); }
function expect(chain, condition, what) { if (!condition) { log(chain, 'FAILED: ' + what); throw Error(chain + ': ' + what); } log(chain, 'ok: ' + what); }
async function observe(page, fields, {chain, timeoutMs = 1_200_000}) {
  await page.evaluate(() => { document.getElementById('observer-section').hidden = false; });
  await page.locator('#observer-form [name="chain"]').selectOption(chain);
  for (const [k, v] of Object.entries(fields)) await page.locator(`#observer-form [name="${k}"]`).fill(String(v));
  return until('the observer to find the claim', async () => {
    await clearStatus(page, 'observer-status');
    await page.locator('#observer-look').click();
    await page.waitForFunction(() => { const t = document.getElementById('observer-status').textContent; return t !== '' && t !== 'Reading the chain.'; });
    const text = await statusOf(page, 'observer-status');
    return /Claim found/.test(text) ? text : null;
  }, {timeoutMs, everyMs: 20_000});
}

// ---- Sepolia
const SEPOLIA_RPC = 'https://ethereum-sepolia-rpc.publicnode.com';
const rpc = (method, params = []) => retry(() => rpcOnce(method, params));
async function rpcOnce(method, params = []) {
  const response = await fetch(SEPOLIA_RPC, {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({jsonrpc: '2.0', id: 1, method, params})});
  const value = await response.json();
  if (value.error) throw Error(value.error.message);
  return value.result;
}
/** Signers run as child processes without blocking this process: the three chains and the hosted Worker share one event loop. */
function pythonSigner(op, wallet, request, extra = []) {
  return new Promise((resolveSigner, reject) => {
    const child = spawn('python3', [join(ROOT, 'scripts/qualification_signer.py'), op, '--wallet', wallet, ...extra], {
      env: {...process.env, PYTHONPATH: [join(ROOT, 'scripts'), process.env.PYTHONPATH].filter(Boolean).join(':')}, stdio: ['pipe', 'pipe', 'pipe']});
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(Error('signer timed out')); }, 180_000);
    child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
    child.on('close', () => {
      clearTimeout(timer);
      let out; try { out = JSON.parse(stdout.trim().split('\n').pop()); } catch { return reject(Error('signer failed: ' + stderr.slice(-300))); }
      if (out.error) return reject(Error('signer refused: ' + out.error));
      resolveSigner(out);
    });
    child.stdin.end(JSON.stringify(request));
  });
}
async function receipt(txid) { return rpc('eth_getTransactionReceipt', [txid]); }
async function confirmed(txid, depth) {
  const r = await receipt(txid); if (!r) return null;
  const head = Number(BigInt(await rpc('eth_blockNumber'))), mined = Number(BigInt(r.blockNumber));
  return head - mined + 1 >= depth ? r : null;
}

async function sepolia(browser) {
  const chain = 'sepolia', out = results.sepolia, host = await startHost();
  const journalDir = mkdtempSync(join(tmpdir(), 'qualify-eth-')); // 0700
  try {
    const who = {alice: addresses.alice.ethereum_sepolia.toLowerCase(), bob: addresses.bob.ethereum_sepolia.toLowerCase()};
    const state = {account: 'alice', chain: '0xaa36a7', lose: false, sent: [], lastTxid: null};
    const context = await browser.newContext();
    await context.exposeFunction('__wallet', async ({method, params = []}) => {
      if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [who[state.account]];
      if (method === 'eth_chainId') return state.chain;
      if (method === 'eth_sendTransaction') {
        const sent = await pythonSigner('eth-send', keyFile(state.account, 'ethereum-sepolia.key'), params[0], ['--journal', journalDir]);
        state.sent.push(sent.txid); state.lastTxid = sent.txid;
        if (state.lose) { state.lose = false; throw Error('wallet connection lost'); }
        return sent.txid;
      }
      return rpc(method, params);
    });
    await context.addInitScript(() => { window.ethereum = {request: args => window.__wallet(args)}; });
    const page = await context.newPage();
    page.on('dialog', dialog => dialog.accept());
    await page.goto(host.base);
    await page.evaluate(() => { for (const id of ['sepolia-action-section', 'observer-section']) document.getElementById(id).hidden = false; });
    const hashlock = await createBackup(page); out.hashlock = hashlock; save();
    const connect = async () => { await clearStatus(page, 'wallet-status'); await page.getByRole('button', {name: 'Connect Ethereum wallet'}).click(); await waitStatus(page, 'wallet-status', /Ethereum connected/, 30_000); };
    await connect();
    const fill = async terms => { for (const [k, v] of Object.entries(terms)) await page.locator(`#sepolia-action-form [name="${k}"]`).fill(v); };
    const base = {amount: '1000', claimant: who.bob, refundee: who.alice};
    const result = async () => { const t = await statusOf(page, 'sepolia-action-result'); return t.match(/0x[0-9a-f]{64}/i)?.[0]; };
    const press = name => page.getByRole('button', {name}).click();
    // Public RPC endpoints sit behind load balancers whose backends can lag: a fresh contract may read as missing for a
    // moment, which the page reports as a mismatch and refuses safely. Repeat only while no wallet request was made.
    const transient = /mismatch|do not match|not found|unavailable|fetch failed/i;
    const attempt = async (button, label, prepare = async () => {}) => {
      for (let i = 1; ; i++) {
        const before = state.sent.length;
        await prepare();
        await clearStatus(page, 'sepolia-action-status');
        await press(button);
        const result = await settled(page, 'sepolia-action-status', /Transaction submitted/);
        if (!result.error || state.sent.length !== before || !transient.test(result.text) || i >= 8) return result;
        log(chain, `${label}: refused before any wallet request (${result.text}); provider may lag, try ${i + 1}`);
        out.provider_lag_refusals = (out.provider_lag_refusals ?? 0) + 1;
        await sleep(15_000);
      }
    };

    // Wrong network: refused with no wallet request.
    state.chain = '0x1';
    await fill({...base, hashlock: '0x' + hashlock, expiry: String(unixNow() + 7200), contract: ''});
    await clearStatus(page, 'sepolia-action-status');
    await press('Deploy Sepolia escrow');
    let s = await settled(page, 'sepolia-action-status', /Transaction submitted/);
    expect(chain, s.error && /not connected to Ethereum Sepolia/.test(s.text) && state.sent.length === 0, 'wrong network refused before any wallet request: ' + s.text);
    out.wrong_network = 'refused';
    state.chain = '0xaa36a7';

    // Fund the escrow Bob will claim.
    const expiry = unixNow() + 7200, terms = {...base, hashlock: '0x' + hashlock, expiry: String(expiry), contract: ''};
    await fill(terms);
    await clearStatus(page, 'sepolia-action-status');
    await press('Deploy Sepolia escrow');
    s = await settled(page, 'sepolia-action-status', /Transaction submitted/);
    expect(chain, !s.error, 'deploy through the page: ' + s.text);
    const fundTx = state.sent.at(-1); out.claim_escrow_deploy_tx = fundTx; save();
    const mined = await until('deploy confirmation', () => confirmed(fundTx, 3), {everyMs: 12_000, timeoutMs: 600_000});
    expect(chain, mined.status === '0x1' && mined.contractAddress, 'deploy confirmed');
    const contract = mined.contractAddress.toLowerCase(); out.claim_escrow = contract; save();

    // Bob claims from the encrypted backup.
    state.account = 'bob';
    await connect();
    await fill({...terms, contract});
    await page.locator('#sepolia-claim-backup').selectOption(hashlock);
    await page.locator('#sepolia-claim-passphrase').fill(PASSPHRASE);
    s = await attempt('Claim with encrypted backup', 'claim', () => page.locator('#sepolia-claim-passphrase').fill(PASSPHRASE));
    expect(chain, !s.error, 'claim through the page: ' + s.text);
    const claimTx = state.sent.at(-1); out.claim_tx = claimTx; save();
    const claimed = await until('claim confirmation', () => confirmed(claimTx, 2), {everyMs: 12_000, timeoutMs: 600_000});
    expect(chain, claimed.status === '0x1', 'claim confirmed on Sepolia');
    const stored = await journal(page);
    expect(chain, stored.some(r => r.operation === 'claim' && r.state === 'completed'), 'the journal records the claim as completed');

    // Observer: the counterparty learns the secret from the chain with no manual lookup.
    const found = await observe(page, {hashlock, contract}, {chain: 'ethereum'});
    out.observer = found; expect(chain, /Claim found/.test(found), 'observer found the preimage on chain: ' + found); save();

    // Lost response: the wallet broadcasts and the page never hears back.
    state.account = 'alice';
    await connect();
    const refundExpiry = unixNow() + 1500;
    const lost = {...base, hashlock: '0x' + hashlock, expiry: String(refundExpiry), contract: ''};
    await fill(lost);
    state.lose = true; await clearStatus(page, 'sepolia-action-status');
    await press('Deploy Sepolia escrow');
    s = await settled(page, 'sepolia-action-status', /Transaction submitted/);
    expect(chain, s.error && /not confirmed/i.test(s.text), 'a lost wallet response is reported as unconfirmed: ' + s.text);
    const lostTx = state.lastTxid; out.refund_escrow_deploy_tx = lostTx; save();
    const records = await journal(page);
    expect(chain, records.some(r => r.state === 'uncertain'), 'the lost response left an uncertain action record');
    const refundMined = await until('refund escrow deploy', () => confirmed(lostTx, 3), {everyMs: 12_000, timeoutMs: 600_000});
    const refundContract = refundMined.contractAddress.toLowerCase(); out.refund_escrow = refundContract; save();

    // Refund once the head passes the expiry.
    await until('Sepolia head past expiry', async () => { const b = await rpc('eth_getBlockByNumber', ['latest', false]); return BigInt(b.timestamp) > BigInt(refundExpiry) + 30n; }, {everyMs: 20_000, timeoutMs: 3_000_000});
    await fill({...lost, contract: refundContract});
    s = await attempt('Refund expired escrow', 'refund');
    expect(chain, !s.error, 'refund through the page: ' + s.text);
    const refundTx = state.sent.at(-1); out.refund_tx = refundTx; save();
    const refunded = await until('refund confirmation', () => confirmed(refundTx, 2), {everyMs: 12_000, timeoutMs: 600_000});
    expect(chain, refunded.status === '0x1' && BigInt(await rpc('eth_getBalance', [refundContract, 'latest'])) === 0n, 'refund confirmed and the escrow holds nothing');
    out.result = 'passed';
  } finally { host.close(); rmSync(journalDir, {recursive: true, force: true}); save(); }
}

// ---- Cardano preview
const KOIOS = 'https://preview.koios.rest/api/v1';
const koios = (path, body) => retry(() => koiosOnce(path, body));
async function koiosOnce(path, body) {
  const response = await fetch(KOIOS + path, {method: body ? 'POST' : 'GET', headers: {'content-type': 'application/json', accept: 'application/json', 'user-agent': 'Mozilla/5.0'}, body: body ? JSON.stringify(body) : undefined});
  if (!response.ok) throw Error('koios ' + response.status);
  return response.json();
}
async function cardanoConfirmations(txid) {
  const [info] = await koios('/tx_info', {_tx_hashes: [txid]});
  if (!info?.block_height) return 0;
  const [tip] = await koios('/tip');
  return tip.block_no - info.block_height + 1;
}
function cardanoPerson(who) {
  const skey = JSON.parse(readFileSync(keyFile(who, 'cardano.skey'), 'utf8')).cborHex;
  if (!/^5820[0-9a-f]{64}$/.test(skey)) throw Error('unexpected Cardano key encoding');
  const seed = fromHex(skey.slice(4)), address = addresses[who].cardano_preview;
  return {seed, address, hash: toHex(blake2b(ed25519.getPublicKey(seed), {dkLen: 28}))};
}
async function adaUtxos(address) {
  const rows = await koios('/address_utxos', {_addresses: [address], _extended: true});
  return rows.filter(r => !(r.asset_list ?? []).length && !r.is_spent).map(r => ({ref: `${r.tx_hash}#${r.tx_index}`, address, lovelace: Number(r.value), assets: {}}));
}

async function cardano(browser) {
  const chain = 'cardano', out = results.cardano, host = await startHost();
  try {
    const people = {alice: cardanoPerson('alice'), bob: cardanoPerson('bob')};
    out.keyhashes = {alice: people.alice.hash, bob: people.bob.hash};
    const state = {account: 'alice', network: 0, lose: false, submitted: [], lastTxid: null};
    const context = await browser.newContext();
    await context.exposeFunction('__cardano', async (method, callArgs) => {
      const p = people[state.account], utxos = await adaUtxos(p.address);
      const collateral = utxos.filter(u => u.lovelace >= 5_000_000).sort((a, b) => a.lovelace - b.lovelace)[0];
      const wallet = softwareWallet({seed: p.seed, address: p.address, utxos, collateral: collateral ? [collateral.ref] : [], networkId: state.network});
      if (method === 'submitTx') {
        const raw = Buffer.from(callArgs[0], 'hex');
        const response = await fetch(KOIOS + '/submittx', {method: 'POST', headers: {'content-type': 'application/cbor', 'user-agent': 'Mozilla/5.0'}, body: raw});
        if (!response.ok) throw Error('submit rejected: ' + (await response.text()).slice(0, 200));
        const txid = (await response.json()).toString();
        state.submitted.push(txid); state.lastTxid = txid;
        if (state.lose) { state.lose = false; throw Error('wallet connection lost'); }
        return txid;
      }
      return wallet[method](...callArgs);
    });
    await context.addInitScript(() => {
      const call = method => (...a) => window.__cardano(method, a).catch(error => { throw Object.assign(new Error(String(error.message).replace(/^.*Error: /, '')), /declined/.test(error.message) ? {code: 2} : {}); });
      window.cardano = {qualify: {name: 'Software CIP-30 (ed25519 key file)', enable: async () => Object.fromEntries(['getNetworkId', 'getUtxos', 'getCollateral', 'getUsedAddresses', 'getUnusedAddresses', 'getChangeAddress', 'signTx', 'submitTx'].map(m => [m, call(m)]))}};
    });
    const page = await context.newPage();
    await page.goto(host.base);
    await page.evaluate(() => { for (const id of ['cardano-wallet-section', 'observer-section']) document.getElementById(id).hidden = false; });
    const hashlock = await createBackup(page); out.hashlock = hashlock; save();
    const connect = async () => {
      await clearStatus(page, 'wallet-status');
      await page.locator('#cardano-wallet').selectOption('qualify'); await page.locator('#connect-cardano').click();
      await page.waitForFunction(() => document.getElementById('wallet-status').textContent !== '');
    };
    const fill = async fields => { for (const [k, v] of Object.entries(fields)) await page.locator(`#cardano-wallet-form [name="${k}"]`).fill(v); };
    const terms = (expiryS, extra = {}) => ({lovelace: '5000000', assets: '', hashlock, claimant: people.bob.hash, refundee: people.alice.hash, expiry_ms: String(expiryS * 1000), ...extra});
    const act = async (button, {yes = true} = {}) => {
      await clearStatus(page, 'cardano-wallet-status');
      await page.locator(button).click();
      await page.waitForFunction(() => !document.getElementById('cardano-confirm').hidden || document.getElementById('cardano-wallet-status').className === 'error', null, {timeout: 120_000});
      if (await page.locator('#cardano-confirm').isHidden()) return {error: true, text: await statusOf(page, 'cardano-wallet-status')};
      const review = await statusOf(page, 'cardano-confirm-text');
      if (yes) await page.locator('#cardano-confirm-yes').click(); else await page.locator('#cardano-confirm-no').click();
      const s = await settled(page, 'cardano-wallet-status', /Transaction submitted/);
      return {...s, review};
    };

    // Wrong network: network id 1 is not accepted as a connection.
    state.network = 1; await connect(); await fill(terms(unixNow() + 7200));
    await clearStatus(page, 'cardano-wallet-status'); await page.locator('#cardano-fund').click();
    await waitStatus(page, 'cardano-wallet-status', /Connect a Cardano/);
    expect(chain, state.submitted.length === 0, 'wrong-network wallet refused before any signature');
    out.wrong_network = 'refused'; state.network = 0; await connect();

    // Fund the escrow Bob will claim.
    const expiry = unixNow() + 7200;
    await fill(terms(expiry));
    let r = await act('#cardano-fund');
    expect(chain, !r.error && /Lock 5000000 lovelace/.test(r.review), 'fund through the page after review: ' + r.text);
    const fundTx = state.lastTxid; out.claim_escrow_fund_tx = fundTx; save();
    await until('fund confirmation', async () => (await cardanoConfirmations(fundTx)) >= 3, {everyMs: 15_000, timeoutMs: 900_000});
    const outref = `${fundTx}#0`;

    // Bob claims from the encrypted backup.
    state.account = 'bob'; await connect();
    await fill(terms(expiry, {outref}));
    await page.locator('#cardano-claim-backup').selectOption(hashlock);
    await page.locator('#cardano-claim-passphrase').fill(PASSPHRASE);
    r = await act('#cardano-claim');
    expect(chain, !r.error && /reveals the swap secret/.test(r.review), 'claim through the page: ' + r.text);
    const claimTx = state.lastTxid; out.claim_tx = claimTx; save();
    await until('claim confirmation', async () => (await cardanoConfirmations(claimTx)) >= 2, {everyMs: 15_000, timeoutMs: 900_000});

    const found = await observe(page, {hashlock, outref}, {chain: 'cardano'});
    out.observer = found; expect(chain, /Claim found/.test(found), 'observer found the preimage on chain: ' + found); save();

    // Lost response on a second escrow, then refund after the deadline.
    state.account = 'alice'; await connect();
    const refundExpiry = unixNow() + 1500;
    await fill(terms(refundExpiry)); state.lose = true;
    r = await act('#cardano-fund');
    expect(chain, r.error, 'a lost submit response is an error in the page: ' + r.text);
    const lostTx = state.lastTxid; out.refund_escrow_fund_tx = lostTx; save();
    expect(chain, (await journal(page)).some(x => x.state === 'uncertain'), 'the lost response left an uncertain action record');
    await until('refund escrow confirmation', async () => (await cardanoConfirmations(lostTx)) >= 3, {everyMs: 15_000, timeoutMs: 900_000});
    await until('ledger slot past expiry', async () => { const [tip] = await koios('/tip'); return 1666656000 + tip.abs_slot > refundExpiry + 60; }, {everyMs: 20_000, timeoutMs: 3_000_000});
    await fill(terms(refundExpiry, {outref: `${lostTx}#0`}));
    r = await act('#cardano-refund');
    expect(chain, !r.error && /Refund 5000000 lovelace/.test(r.review), 'refund through the page: ' + r.text);
    const refundTx = state.lastTxid; out.refund_tx = refundTx; save();
    await until('refund confirmation', async () => (await cardanoConfirmations(refundTx)) >= 2, {everyMs: 15_000, timeoutMs: 900_000});
    out.result = 'passed';
  } finally { host.close(); save(); }
}

// ---- Bitcoin testnet4
const BTC_API = 'https://mempool.space/testnet4/api';
const btc = path => retry(() => btcOnce(path));
async function btcOnce(path) {
  const response = await fetch(BTC_API + path, {headers: {'user-agent': 'Mozilla/5.0'}});
  if (!response.ok) throw Error('btc ' + response.status);
  return response.headers.get('content-type')?.includes('json') ? response.json() : (await response.text()).trim();
}
const btcTip = async () => Number(await btc('/blocks/tip/height'));
async function btcConfirmations(txid) {
  const s = await btc('/tx/' + txid + '/status');
  return s.confirmed ? (await btcTip()) - s.block_height + 1 : 0;
}
const pubkeyOf = who => toHex(secp256k1.getPublicKey(fromHex(readFileSync(keyFile(who, 'bitcoin-testnet4.key'), 'utf8').trim()), true));

async function bitcoin(browser) {
  const chain = 'bitcoin', out = results.bitcoin, host = await startHost();
  try {
    const pub = {alice: pubkeyOf('alice'), bob: pubkeyOf('bob')};
    out.pubkeys = pub;
    const state = {loseBroadcast: false, broadcasts: []};
    const context = await browser.newContext();
    // A lost response: the real broadcast happens, then the connection drops before the page hears the answer.
    await context.route('**/bitcoin-testnet4/broadcast', async route => {
      const request = route.request();
      const forwarded = await fetch(host.base + '/bitcoin-testnet4/broadcast', {method: 'POST', headers: {'content-type': 'application/json'}, body: request.postData()});
      const body = await forwarded.text();
      if (forwarded.ok) state.broadcasts.push(JSON.parse(body).txid);
      if (state.loseBroadcast) { state.loseBroadcast = false; return route.abort('connectionreset'); }
      return route.fulfill({status: forwarded.status, contentType: 'application/json', body});
    });
    const page = await context.newPage();
    await page.goto(host.base);
    await page.evaluate(() => { for (const id of ['bitcoin-wallet-section', 'observer-section']) document.getElementById(id).hidden = false; });
    const hashlock = await createBackup(page); out.hashlock = hashlock; save();
    const form = async fields => { for (const [k, v] of Object.entries(fields)) await page.locator(`#bitcoin-wallet-form [name="${k}"]`).fill(String(v)); };
    const clickStatus = async selector => { await clearStatus(page, 'bitcoin-wallet-status'); await page.locator(selector).click(); await page.waitForFunction(() => { const t = document.getElementById('bitcoin-wallet-status').textContent; return t !== '' && !/^(Checking|Re-checking)/.test(t); }, null, {timeout: 120_000}); return {text: await statusOf(page, 'bitcoin-wallet-status'), error: (await page.locator('#bitcoin-wallet-status').getAttribute('class')) === 'error'}; };
    const lagging = /unavailable|inconsistent|fetch failed/i;
    const build = async (op, fields) => {
      await page.locator('#bitcoin-wallet-form [name="operation"]').selectOption(op); await form(fields);
      for (let i = 1; ; i++) {
        const result = await clickStatus('#bitcoin-build');
        if (!result.error || !lagging.test(result.text) || i >= 8) return result;
        log(chain, `build: provider read failed (${result.text}); try ${i + 1}`); out.provider_read_retries = (out.provider_read_retries ?? 0) + 1; await sleep(10_000);
      }
    };
    const signAndBroadcast = async (who, {backup = false} = {}) => {
      const signed = (await pythonSigner('btc-sign', keyFile(who, 'bitcoin-testnet4.key'), {psbt: await page.locator('#bitcoin-psbt-out').inputValue()})).psbt;
      await page.locator('#bitcoin-psbt-in').fill(signed);
      const before = state.broadcasts.length;
      if (backup) { await page.locator('#bitcoin-claim-backup').selectOption(hashlock); await page.locator('#bitcoin-claim-passphrase').fill(PASSPHRASE); }
      let s = await clickStatus('#bitcoin-broadcast');
      // A failed read before the broadcast is safe to repeat; anything that reached the broadcast step is not.
      for (let i = 1; s.error && lagging.test(s.text) && !/may have been accepted/.test(s.text) && state.broadcasts.length === before && i < 8; i++) {
        log(chain, `finalize: provider read failed (${s.text}); try ${i + 1}`); await sleep(10_000); s = await clickStatus('#bitcoin-broadcast');
      }
      const result = s.error ? null : JSON.parse(await statusOf(page, 'bitcoin-wallet-result'));
      return {...s, txid: result?.txid, state: result?.state};
    };
    const terms = refundHeight => ({hashlock, claimant_key: pub.bob, refund_key: pub.alice, refund_height: refundHeight, amount_sats: 20000});

    // Wrong network: a mainnet address is refused by the page.
    await page.locator('#bitcoin-wallet-form [name="operation"]').selectOption('fund');
    await form({address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', feerate: 2, ...terms((await btcTip()) + 200)});
    await page.locator('#bitcoin-build').click(); await sleep(1500);
    expect(chain, await page.locator('#bitcoin-wallet-form [name="address"]').evaluate(el => el.validity.patternMismatch) && await page.locator('#bitcoin-psbt-section').isHidden(), 'a mainnet address is refused by the form and builds nothing');
    out.wrong_network = 'refused';
    let s;

    let r;
    const refundOnly = process.env.QUALIFY_BITCOIN_REFUND_ONLY === '1'; // lets the slow refund wait overlap a claim run
    if (!refundOnly) {
      // Fund the escrow Bob will claim: 160 blocks ahead satisfies the claim policy (145).
      const height = (await btcTip()) + 170;
      s = await build('fund', {address: addresses.alice.bitcoin_testnet4, feerate: 2, ...terms(height)});
      expect(chain, !s.error, 'fund PSBT built by the page: ' + s.text);
      let r = await signAndBroadcast('alice');
      expect(chain, !r.error && r.state === 'submitted', 'fund broadcast through the page: ' + r.text);
      const fundTx = r.txid; out.claim_escrow_fund_tx = fundTx; out.claim_escrow_refund_height = height; save();
      await until('fund confirmation', async () => (await btcConfirmations(fundTx)) >= 2, {everyMs: 30_000, timeoutMs: 7_200_000});

      // Bob claims from the encrypted backup.
      const spend = (extra = {}) => ({txid: fundTx, vout: 0, address: addresses.bob.bitcoin_testnet4, feerate: 2, ...terms(height), ...extra});
      s = await build('claim', spend());
      expect(chain, !s.error, 'claim PSBT built by the page: ' + s.text);
      r = await signAndBroadcast('bob', {backup: true});
      expect(chain, !r.error && r.state === 'submitted', 'claim broadcast through the page: ' + r.text);
      out.claim_tx = r.txid; save();
      await until('claim confirmation', async () => (await btcConfirmations(out.claim_tx)) >= 2, {everyMs: 30_000, timeoutMs: 7_200_000});

      const found = await observe(page, {hashlock, txid: fundTx, vout: 0, claimant_key: pub.bob, refund_key: pub.alice, refund_height: height}, {chain: 'bitcoin'});
      out.observer = found; expect(chain, /Claim found/.test(found), 'observer found the preimage on chain: ' + found); save();
    }

    // Lost response on a second escrow whose refund height is close, then refund once reached.
    const near = (await btcTip()) + 3;
    s = await build('fund', {address: addresses.alice.bitcoin_testnet4, feerate: 2, ...terms(near)});
    expect(chain, !s.error, 'second fund PSBT built: ' + s.text);
    state.loseBroadcast = true;
    r = await signAndBroadcast('alice');
    expect(chain, r.error && /may have been accepted/.test(r.text), 'a lost broadcast response is reported as possibly accepted: ' + r.text);
    const lostTx = state.broadcasts.at(-1); out.refund_escrow_fund_tx = lostTx; out.refund_escrow_refund_height = near; save();
    expect(chain, (await journal(page)).some(x => x.state === 'uncertain'), 'the lost response left an uncertain action record');
    await until('refund escrow confirmation', async () => (await btcConfirmations(lostTx)) >= 2, {everyMs: 30_000, timeoutMs: 7_200_000});
    await until('tip at refund height', async () => (await btcTip()) >= near, {everyMs: 30_000, timeoutMs: 7_200_000});
    s = await build('refund', {txid: lostTx, vout: 0, address: addresses.alice.bitcoin_testnet4, feerate: 2, ...terms(near)});
    expect(chain, !s.error, 'refund PSBT built: ' + s.text);
    r = await signAndBroadcast('alice');
    expect(chain, !r.error && r.state === 'submitted', 'refund broadcast through the page: ' + r.text);
    out.refund_tx = r.txid; save();
    await until('refund confirmation', async () => (await btcConfirmations(out.refund_tx)) >= 1, {everyMs: 30_000, timeoutMs: 7_200_000});
    out.result = 'passed';
  } finally { host.close(); save(); }
}

// ---- Sweep: refund a leftover Cardano escrow from an aborted run through the page (terms are read from the on-chain datum)
async function cardanoSweep(browser, outref) {
  const chain = 'cardano-sweep', out = results.cardano, host = await startHost();
  try {
    const [row] = await koios('/utxo_info', {_utxo_refs: [outref], _extended: true});
    expect(chain, row && !row.is_spent, 'escrow output exists and is unspent');
    const datum = row.inline_datum?.value?.fields?.map(f => f.bytes ?? f.int);
    expect(chain, datum?.length === 4 && !(row.asset_list ?? []).length, 'inline datum has the four expected fields and the escrow holds only lovelace');
    const [hashlock, claimant, refundee, expiryMs] = datum;
    const alice = cardanoPerson('alice');
    expect(chain, refundee === alice.hash, 'the refundee in the datum is the Alice key');
    const [tip] = await koios('/tip');
    expect(chain, 1666656000 + tip.abs_slot > Number(expiryMs) / 1000 + 60, 'ledger time is past the escrow expiry');
    const state = {lastTxid: null, submitted: []};
    const context = await browser.newContext();
    await context.exposeFunction('__cardano', async (method, callArgs) => {
      const utxos = await adaUtxos(alice.address);
      const collateral = utxos.filter(u => u.lovelace >= 5_000_000).sort((a, b) => a.lovelace - b.lovelace)[0];
      const wallet = softwareWallet({seed: alice.seed, address: alice.address, utxos, collateral: collateral ? [collateral.ref] : [], networkId: 0});
      if (method === 'submitTx') {
        const response = await fetch(KOIOS + '/submittx', {method: 'POST', headers: {'content-type': 'application/cbor', 'user-agent': 'Mozilla/5.0'}, body: Buffer.from(callArgs[0], 'hex')});
        if (!response.ok) throw Error('submit rejected: ' + (await response.text()).slice(0, 200));
        state.lastTxid = (await response.json()).toString(); state.submitted.push(state.lastTxid);
        return state.lastTxid;
      }
      return wallet[method](...callArgs);
    });
    await context.addInitScript(() => {
      const call = method => (...a) => window.__cardano(method, a).catch(error => { throw Object.assign(new Error(String(error.message).replace(/^.*Error: /, '')), /declined/.test(error.message) ? {code: 2} : {}); });
      window.cardano = {qualify: {name: 'Software CIP-30 (ed25519 key file)', enable: async () => Object.fromEntries(['getNetworkId', 'getUtxos', 'getCollateral', 'getUsedAddresses', 'getUnusedAddresses', 'getChangeAddress', 'signTx', 'submitTx'].map(m => [m, call(m)]))}};
    });
    const page = await context.newPage();
    await page.goto(host.base);
    await page.evaluate(() => { for (const id of ['cardano-wallet-section']) document.getElementById(id).hidden = false; });
    await clearStatus(page, 'wallet-status');
    await page.locator('#cardano-wallet').selectOption('qualify'); await page.locator('#connect-cardano').click();
    await page.waitForFunction(() => document.getElementById('wallet-status').textContent !== '');
    const fields = {lovelace: String(row.value), assets: '', hashlock, claimant, refundee, expiry_ms: String(expiryMs), outref};
    for (const [k, v] of Object.entries(fields)) await page.locator(`#cardano-wallet-form [name="${k}"]`).fill(v);
    await clearStatus(page, 'cardano-wallet-status');
    await page.locator('#cardano-refund').click();
    await page.waitForFunction(() => !document.getElementById('cardano-confirm').hidden || document.getElementById('cardano-wallet-status').className === 'error', null, {timeout: 120_000});
    expect(chain, await page.locator('#cardano-confirm').isVisible(), 'the page reviewed the refund: ' + await statusOf(page, 'cardano-wallet-status'));
    const review = await statusOf(page, 'cardano-confirm-text');
    expect(chain, new RegExp(`Refund ${row.value} lovelace`).test(review), 'review names the refund and amount');
    await page.locator('#cardano-confirm-yes').click();
    await settled(page, 'cardano-wallet-status', /Transaction submitted/);
    out.sweep = {escrow: outref, refund_tx: state.lastTxid}; save();
    await until('refund confirmation', async () => (await cardanoConfirmations(state.lastTxid)) >= 2, {everyMs: 15_000, timeoutMs: 900_000});
    out.result = 'passed';
  } finally { host.close(); save(); }
}

// ---- run
const browser = await chromium.launch({executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox']});
const versions = {chromium: browser.version(), node: process.version};
results.wallets = {versions, sepolia: 'EIP-1193 provider backed by eth_account (scripts/qualification_signer.py); not a browser-extension wallet',
  cardano: 'CIP-30 software wallet, ed25519 key file (swap-service/tools/cardano-bridge.mjs); not a browser-extension wallet', bitcoin: 'embit PSBT signer (scripts/qualification_signer.py)'};
save();
if (option('--sweep-cardano')) {
  await cardanoSweep(browser, option('--sweep-cardano')).catch(error => { results.cardano.result = 'failed'; results.cardano.error = String(error.message).slice(0, 400); save(); console.error(error.message); process.exitCode = 1; });
  await browser.close(); console.log(JSON.stringify(results.cardano, null, 2)); process.exit(process.exitCode ?? 0);
}
const jobs = {sepolia, cardano, bitcoin};
const settledJobs = await Promise.allSettled([...ONLY].map((name, index) => sleep(20_000 * index).then(() => jobs[name](browser)).catch(error => { results[name].result = 'failed'; results[name].error = String(error.message).slice(0, 400); save(); throw error; })));
await browser.close();
results.finished = new Date().toISOString(); save();
console.log(JSON.stringify(results, null, 2));
process.exit(settledJobs.every(j => j.status === 'fulfilled') ? 0 : 1);
