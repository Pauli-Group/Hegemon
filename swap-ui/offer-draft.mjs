/* Pure validation for the step-by-step offer form. The relay still validates every offer. */
const UINT256 = 1n << 256n;
const CARDANO_TOKEN_MAX = 1n << 63n;

export const OFFER_ASSETS = Object.freeze([
  {value: 'hegemon:hgn', label: 'Hegemon · HGN', unit: 'HGN', base: 'atoms', decimals: 8},
  {value: 'bitcoin:btc', label: 'Bitcoin · BTC', unit: 'BTC', base: 'satoshis', decimals: 8},
  {value: 'ethereum:eth', label: 'Ethereum · ETH', unit: 'ETH', base: 'wei', decimals: 18},
  {value: 'ethereum:erc20', label: 'Ethereum · ERC-20 token', unit: 'token base units', base: 'token base units', decimals: null},
  {value: 'ethereum:erc721', label: 'Ethereum · ERC-721 NFT', unit: 'NFT', base: 'NFT', decimals: null},
  {value: 'ethereum:erc1155', label: 'Ethereum · ERC-1155 token', unit: 'token units', base: 'token units', decimals: null},
  {value: 'cardano:ada', label: 'Cardano · ADA', unit: 'ADA', base: 'lovelace', decimals: 6},
  {value: 'cardano:native', label: 'Cardano · native asset', unit: 'asset base units', base: 'asset base units', decimals: null},
]);

export function assetInfo(value) {
  const asset = OFFER_ASSETS.find(item => item.value === value);
  if (!asset) throw Error('Choose an asset.');
  return asset;
}

export function validateAssetId(value, raw) {
  const {value: type} = assetInfo(value), id = String(raw ?? '').trim();
  const [, kind] = type.split(':');
  if (['hgn', 'btc', 'eth', 'ada'].includes(kind)) {
    if (id) throw Error('This coin does not use a token identifier.');
    return '';
  }
  if (kind === 'erc20') {
    if (!/^0x[0-9a-fA-F]{40}$/.test(id)) throw Error('Enter the ERC-20 contract address, starting with 0x.');
  } else if (kind === 'erc721' || kind === 'erc1155') {
    const match = /^(0x[0-9a-fA-F]{40}):(0|[1-9][0-9]{0,77})$/.exec(id);
    if (!match || BigInt(match[2]) >= UINT256) throw Error('Enter the contract address, a colon, and the decimal token ID.');
  } else if (kind === 'native') {
    if (!/^[0-9a-fA-F]{56}\.(?:[0-9a-fA-F]{2}){0,32}$/.test(id)) throw Error('Enter the hexadecimal policy ID and asset name separated by a dot.');
  }
  return id;
}

/** Convert the entered amount to the relay's positive integer string without floating point. */
export function toBaseUnits(value, raw) {
  const asset = assetInfo(value), amount = String(raw ?? '').trim(), kind = value.split(':')[1];
  if (amount.length > 100) throw Error('Amount is too large.');
  let units;
  if (asset.decimals === null) {
    if (!/^[1-9][0-9]*$/.test(amount)) throw Error('Enter a positive whole number of base units.');
    units = BigInt(amount);
  } else {
    const match = /^(0|[1-9][0-9]*)(?:\.([0-9]+))?$/.exec(amount);
    if (!match) throw Error('Enter a positive amount using digits and an optional decimal point.');
    const fraction = match[2] ?? '';
    if (fraction.length > asset.decimals) throw Error(`${asset.unit} supports at most ${asset.decimals} decimal places.`);
    units = BigInt(match[1]) * 10n ** BigInt(asset.decimals) + BigInt((fraction || '0').padEnd(asset.decimals, '0'));
  }
  if (units <= 0n || units >= UINT256) throw Error('Enter an amount within the supported range.');
  if (kind === 'native' && units >= CARDANO_TOKEN_MAX) throw Error('Cardano asset quantity is too large.');
  if (kind === 'erc721' && units !== 1n) throw Error('An ERC-721 offer must contain exactly one NFT.');
  return units.toString();
}

/** Render a positive integer amount without rounding or assuming token decimals. */
export function formatBaseUnits(value, raw) {
  const asset = assetInfo(value), units = String(raw ?? '');
  if (!/^[1-9][0-9]{0,77}$/.test(units) || BigInt(units) >= UINT256) throw Error('Invalid base-unit amount.');
  if (asset.decimals === null) return `${units} ${asset.unit}`;
  const padded = units.padStart(asset.decimals + 1, '0');
  const whole = padded.slice(0, -asset.decimals), fraction = padded.slice(-asset.decimals).replace(/0+$/, '');
  const base = units === '1' ? ({satoshis: 'satoshi', atoms: 'atom'}[asset.base] ?? asset.base) : asset.base;
  return `${whole}${fraction ? '.' + fraction : ''} ${asset.unit} (${units} ${base})`;
}

/** Public Hegemon spends pay this fee. It is not part of the offered amount. */
export const HEGEMON_PUBLIC_FEE_ATOMS = 1000n;

function decimalAtoms(value, label) {
  if (typeof value === 'bigint') {
    if (value < 0n || value >= UINT256) throw Error(label);
    return value;
  }
  const text = String(value ?? '').trim();
  if (!/^(0|[1-9][0-9]{0,77})$/.test(text) || BigInt(text) >= UINT256) throw Error(label);
  return BigInt(text);
}

/** True when ordinary available atoms cover the give amount plus the public fee. */
export function hegemonGiveCovered(amountAtoms, availableAtoms, feeAtoms = HEGEMON_PUBLIC_FEE_ATOMS) {
  const amount = decimalAtoms(amountAtoms, 'Enter a Hegemon amount.');
  const available = decimalAtoms(availableAtoms, 'Hegemon wallet balance is invalid.');
  const fee = decimalAtoms(feeAtoms, 'Hegemon fee is invalid.');
  if (amount <= 0n) throw Error('Enter a Hegemon amount.');
  const required = amount + fee;
  const covered = available >= required;
  return {covered, requiredAtoms: required.toString(), shortfallAtoms: covered ? '0' : (required - available).toString()};
}

/** Refuse a hosted HGN give unless this totals-only snapshot is fresh, spendable and sufficient. */
export function assertHegemonGiveSnapshot(amountAtoms, snapshot, now = Date.now()) {
  if (!snapshot || typeof snapshot !== 'object') throw Error('Hegemon wallet balance is unavailable.');
  for (const key of ['available_atoms', 'reserved_atoms', 'htlc_atoms', 'immature_atoms', 'synced_height', 'observed_height', 'observed_at']) {
    if (!/^(0|[1-9][0-9]{0,38})$/.test(String(snapshot[key] ?? ''))) throw Error('Hegemon wallet balance is invalid.');
  }
  if (snapshot.watch_only !== false) throw Error('A watch-only Hegemon wallet cannot fund an offer.');
  const clock = BigInt(now), observedAt = BigInt(snapshot.observed_at);
  if (clock + 5000n < observedAt || clock - observedAt > 60000n) throw Error('The Hegemon balance snapshot is stale. Read it again before creating the offer.');
  const behind = BigInt(snapshot.observed_height) - BigInt(snapshot.synced_height);
  if (behind < 0n || behind > 2n) throw Error('The Hegemon balance snapshot is stale. Read it again before creating the offer.');
  const result = hegemonGiveCovered(amountAtoms, snapshot.available_atoms);
  if (!result.covered) {
    throw Error(`This wallet is short ${formatBaseUnits('hegemon:hgn', result.shortfallAtoms)}, including the 1,000 atom public fee. The offer was not created. Listing an offer does not lock funds.`);
  }
  return result;
}

/** A shared-link fragment is deliberately never sent in an HTTP request. */
export function parseOfferLink(raw, origin) {
  const text = String(raw ?? '').trim();
  let fragment;
  if (text.startsWith('#')) fragment = text.slice(1);
  else {
    let url;
    try { url = new URL(text); } catch { throw Error('Paste a complete offer link or its # fragment.'); }
    if (url.origin !== origin || !['/', '/index.html'].includes(url.pathname) || url.search || url.username || url.password) {
      throw Error('Use an offer link from this site.');
    }
    fragment = url.hash.slice(1);
  }
  if (!/^[0-9a-f]{64}(?:\.[0-9a-f]{64}(?:\.[0-9a-f]{16})?)?$/.test(fragment)) {
    throw Error('That offer link is incomplete or invalid.');
  }
  return '#' + fragment;
}
