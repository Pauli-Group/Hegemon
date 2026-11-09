import test from 'node:test';
import assert from 'node:assert/strict';
import {assetInfo, formatBaseUnits, parseOfferLink, toBaseUnits, validateAssetId} from './offer-draft.mjs';

test('native coin amounts are converted exactly to base units', () => {
  assert.equal(toBaseUnits('bitcoin:btc', '0.00000001'), '1');
  assert.equal(toBaseUnits('bitcoin:btc', '1.23456789'), '123456789');
  assert.equal(toBaseUnits('ethereum:eth', '1.000000000000000001'), '1000000000000000001');
  assert.equal(toBaseUnits('cardano:ada', '2.125'), '2125000');
  assert.equal(toBaseUnits('hegemon:hgn', '0.001'), '100000');
  assert.equal(toBaseUnits('ethereum:eth', '9007199254740993'), '9007199254740993000000000000000000');
});

test('offer amounts display exact native units without guessing token decimals', () => {
  assert.equal(formatBaseUnits('bitcoin:btc', '1'), '0.00000001 BTC (1 satoshi)');
  assert.equal(formatBaseUnits('hegemon:hgn', '100000'), '0.001 HGN (100000 atoms)');
  assert.equal(formatBaseUnits('ethereum:eth', '1000000000000000001'), '1.000000000000000001 ETH (1000000000000000001 wei)');
  assert.equal(formatBaseUnits('ethereum:erc20', '123456789'), '123456789 token base units');
  assert.throws(() => formatBaseUnits('bitcoin:btc', '0'), /Invalid/);
});

test('invalid, imprecise and out-of-range amounts are refused', () => {
  for (const amount of ['', '0', '0.00000000', '-1', '1e3', '.1', '1.', '01', '1,000', '0.000000001']) {
    assert.throws(() => toBaseUnits('bitcoin:btc', amount), undefined, amount);
  }
  assert.throws(() => toBaseUnits('ethereum:eth', '1.' + '0'.repeat(19)), /18 decimal/);
  assert.throws(() => toBaseUnits('ethereum:erc20', (1n << 256n).toString()), /range/);
  assert.throws(() => toBaseUnits('cardano:native', (1n << 63n).toString()), /too large/);
  assert.equal(toBaseUnits('cardano:native', ((1n << 63n) - 1n).toString()), ((1n << 63n) - 1n).toString());
  assert.throws(() => toBaseUnits('ethereum:erc20', '1.5'), /whole number/);
  assert.equal(toBaseUnits('ethereum:erc721', '1'), '1');
  assert.throws(() => toBaseUnits('ethereum:erc721', '2'), /exactly one/);
});

test('asset identifiers match the supported relay formats', () => {
  const contract = '0x' + 'Ab'.repeat(20), policy = 'f'.repeat(56);
  assert.equal(validateAssetId('ethereum:erc20', contract), contract);
  assert.equal(validateAssetId('ethereum:erc721', contract + ':42'), contract + ':42');
  assert.equal(validateAssetId('cardano:native', policy + '.00ff'), policy + '.00ff');
  assert.equal(validateAssetId('hegemon:hgn', ''), '');
  assert.throws(() => validateAssetId('bitcoin:btc', contract), /does not use/);
  assert.throws(() => validateAssetId('ethereum:erc20', '0x1234'), /contract address/);
  assert.throws(() => validateAssetId('ethereum:erc1155', contract + ':01'), /token ID/);
  assert.throws(() => validateAssetId('ethereum:erc721', contract + ':' + (1n << 256n)), /token ID/);
  assert.throws(() => validateAssetId('cardano:native', policy + '.0'), /policy ID/);
  assert.throws(() => assetInfo('unknown:asset'), /Choose an asset/);
});

test('shared links preserve message keys and identity codes without accepting another origin', () => {
  const origin = 'https://swap.example', id = 'a'.repeat(64), key = 'b'.repeat(64), code = 'c'.repeat(16);
  assert.equal(parseOfferLink(`${origin}/#${id}.${key}.${code}`, origin), `#${id}.${key}.${code}`);
  assert.equal(parseOfferLink(`#${id}.${key}`, origin), `#${id}.${key}`);
  assert.equal(parseOfferLink(`${origin}/#${id}`, origin), `#${id}`);
  assert.throws(() => parseOfferLink(`https://other.example/#${id}.${key}`, origin), /this site/);
  assert.throws(() => parseOfferLink(`${origin}/?elsewhere=1#${id}`, origin), /this site/);
  assert.throws(() => parseOfferLink(`${origin}/#${id}.bad`, origin), /invalid/);
});
