import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {claimSepoliaEscrow} from './sepolia-actions.mjs';
import {expectedEtherRuntime} from './ethereum-escrow.mjs';
import {SEPOLIA_GENESIS} from './sepolia-verifier.mjs';

const claimant = '0x' + '2'.repeat(40), refundee = '0x' + '1'.repeat(40), contract = '0x' + '4'.repeat(40);
const names = ['hashlock', 'claimant', 'refundee', 'expiry'];
const template = {creation: '6000', runtime: '00'.repeat(32 * names.length), immutableReferences: Object.fromEntries(names.map((n, i) => [n, [{start: i * 32, length: 32}]]))};
const secret = Uint8Array.from({length: 32}, (_, i) => i + 1);
const secretHex = Buffer.from(secret).toString('hex');
const hashlock = '0x' + createHash('sha256').update(secret).digest('hex');
const terms = {kind: 'eth', contract, token: '', tokenId: '', amount: '100', hashlock, claimant, refundee, expiry: '10000'};

/** A Sepolia provider double. `headTimestamp` is the latest block time; `moveHead` changes the head hash after the first read of it. */
function wallet({wrongChain = false, account = claimant, headTimestamp = 5000, spent = 0, balance = 100, code, moveHead = false, failSend = false, noSend = false} = {}) {
  const log = [], sends = [];
  let latestReads = 0;
  const runtime = code ?? expectedEtherRuntime(template, terms);
  const block = (tag) => {
    if (tag === '0x0') return {hash: wrongChain ? '0x' + '0'.repeat(64) : SEPOLIA_GENESIS};
    if (tag === 'latest') {
      const flip = moveHead && latestReads++ >= 3;
      return {number: '0x100', timestamp: '0x' + headTimestamp.toString(16), hash: '0x' + (flip ? 'e' : 'b').repeat(64)};
    }
    return {number: tag, timestamp: '0x' + (headTimestamp - 24).toString(16), hash: '0x' + 'c'.repeat(64)};
  };
  return {
    sends, log,
    request: async ({method, params = []}) => {
      log.push({method, params});
      switch (method) {
        case 'eth_chainId': return '0xaa36a7';
        case 'eth_accounts': return [account];
        case 'eth_blockNumber': return '0x100';
        case 'eth_getBlockByNumber': return block(params[0]);
        case 'eth_getCode': return runtime;
        case 'eth_getBalance': return '0x' + balance.toString(16);
        case 'eth_call': return '0x' + spent.toString(16).padStart(64, '0');
        case 'eth_sendTransaction':
          sends.push(params[0]);
          if (failSend) throw Error('user rejected or connection lost');
          if (noSend) return undefined;
          return '0x' + '9'.repeat(64);
        default: throw Error('unexpected ' + method);
      }
    },
  };
}

test('a claim sends exactly one transaction with the preimage and tells the wallet nothing before approval', async () => {
  const p = wallet();
  const result = await claimSepoliaEscrow(p, template, terms, secret, {cutoffSeconds: 120});
  assert.equal(result.submitted, true);
  assert.equal(result.step, 'claim');
  assert.equal(p.sends.length, 1);
  assert.deepEqual(p.sends[0], {from: claimant, to: contract, data: '0xbd66528a' + secretHex, value: '0x0'});
  for (const entry of p.log.filter(e => e.method !== 'eth_sendTransaction')) assert.ok(!JSON.stringify(entry).includes(secretHex), entry.method + ' leaked the preimage');
});

test('refuses without sending: wrong preimage, wrong network, wrong account, bad bytecode, spent, unfunded', async () => {
  const other = Uint8Array.from({length: 32}, () => 7);
  const cases = [
    [wallet(), other, /does not match the escrow hashlock/],
    [wallet({wrongChain: true}), secret, /not connected to Ethereum Sepolia/],
    [wallet({account: refundee}), secret, /does not control the claimant address/],
    [wallet({code: '0x6000'}), secret, /bytecode or terms/],
    [wallet({spent: 1}), secret, /not funded and unspent/],
    [wallet({balance: 0}), secret, /not funded and unspent/],
  ];
  for (const [p, key, pattern] of cases) {
    await assert.rejects(claimSepoliaEscrow(p, template, terms, key, {cutoffSeconds: 120}), pattern);
    assert.equal(p.sends.length, 0);
  }
});

test('refuses inside the cutoff before the deadline and after it', async () => {
  for (const headTimestamp of [10000 - 119, 10000 - 1, 10000, 10001]) {
    const p = wallet({headTimestamp});
    await assert.rejects(claimSepoliaEscrow(p, template, terms, secret, {cutoffSeconds: 120}));
    assert.equal(p.sends.length, 0, 'head ' + headTimestamp);
  }
  const ok = wallet({headTimestamp: 10000 - 121});
  await claimSepoliaEscrow(ok, template, terms, secret, {cutoffSeconds: 120});
  assert.equal(ok.sends.length, 1);
});

test('the swap-level gate can refuse, and sees the head the claim will use', async () => {
  const p = wallet();
  let seen;
  await assert.rejects(claimSepoliaEscrow(p, template, terms, secret, {cutoffSeconds: 120, verify: async snapshot => { seen = snapshot; throw Error('the other leg is no longer safe'); }}), /other leg/);
  assert.equal(p.sends.length, 0);
  assert.equal(seen.headTimestamp, 5000);
});

test('a head that moves between the checks and the request fails safe', async () => {
  const p = wallet({moveHead: true});
  await assert.rejects(claimSepoliaEscrow(p, template, terms, secret, {cutoffSeconds: 120}), /head changed|snapshot or chain changed/);
  assert.equal(p.sends.length, 0);
});

test('a declined or lost wallet response is reported as uncertain and never retried', async () => {
  for (const options of [{failSend: true}, {noSend: true}]) {
    const p = wallet(options);
    await assert.rejects(claimSepoliaEscrow(p, template, terms, secret, {cutoffSeconds: 120}), /Check wallet history/);
    assert.equal(p.sends.length, 1);
  }
});

test('invalid inputs are rejected', async () => {
  await assert.rejects(claimSepoliaEscrow(wallet(), template, {...terms, kind: 'x'}, secret), /Invalid escrow type/);
  await assert.rejects(claimSepoliaEscrow(wallet(), template, terms, new Uint8Array(31)), /Invalid preimage/);
  await assert.rejects(claimSepoliaEscrow(wallet(), template, terms, secret, {cutoffSeconds: 0}), /Invalid claim cutoff/);
});
