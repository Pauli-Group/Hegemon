import vectors from '../../wallet/tests/fixtures/reward-addresses.json';
import { accountFixture, statusFixture } from './rewardFixtures';
import { describe, it, expect } from 'vitest';
import {
  encodeNetworkAddress,
  encodeBech32m,
  decodeBech32m,
  validateAddress,
  cleanAddress,
  type AddressNetwork,
} from '../src/lib/addresses';
import {
  parseHgn,
  hgn,
  exact,
  checkedStatus,
  checkedAccount,
  sameRewardContext,
  type RewardStatus,
  type RewardAccount,
} from '../src/lib/rewardAccounts';
import { toBaseUnits, validateShieldedAddressInput } from '../src/lib/format';
const network: AddressNetwork = {
  class: 'testnet',
  discriminator: Array(32).fill(9),
};
const body = new Uint8Array(48).fill(34);
const account = encodeNetworkAddress('account', network, body);
const shieldBody = new Uint8Array(1663);
shieldBody.set([5, 7, 0]);
shieldBody.fill(17, 3);
const shield = encodeNetworkAddress('shielded', network, shieldBody);
describe('network-aware long Bech32m entry', () => {
  it('matches deterministic Rust vectors for all four successor prefixes', () => {
    for (const [name, value] of Object.entries(vectors)) {
      const n: AddressNetwork = {
        ...network,
        class: name.endsWith('Main') ? 'mainnet' : 'testnet',
      };
      const kind = name.startsWith('account') ? 'account' : 'shielded';
      expect(validateAddress(value, kind, n)).toBe(value);
      if (kind === 'account')
        expect(encodeNetworkAddress(kind, n, body)).toBe(value);
      else
        expect(
          encodeNetworkAddress(kind, n, decodeBech32m(value).bytes.slice(35)),
        ).toBe(value);
    }
  });
  it('accepts long typed recipients and preserves uppercase until verified', () => {
    expect(validateAddress(shield, 'shielded', network)).toBe(shield);
    expect(validateAddress(shield.toUpperCase(), 'shielded', network)).toBe(
      shield,
    );
    expect(cleanAddress(shield.toUpperCase())).toBe(shield.toUpperCase());
    expect(validateShieldedAddressInput(account, 'Recipient', network)).toMatch(
      /shielded/,
    );
  });
  it('rejects checksum changes, mixed case, wrong network, HRP relabeling and legacy reinterpretation', () => {
    for (const invalid of [
      account.slice(0, -1) + (account.endsWith('q') ? 'p' : 'q'),
      'H' + account.slice(1),
    ])
      expect(() => validateAddress(invalid, 'account', network)).toThrow();
    expect(() =>
      validateAddress(account, 'account', {
        ...network,
        discriminator: Array(32).fill(10),
      }),
    ).toThrow(/another network/);
    expect(() =>
      validateAddress(
        encodeBech32m('heg', decodeBech32m(account).bytes),
        'account',
        { ...network, class: 'mainnet' },
      ),
    ).toThrow(/another network/);
    expect(() => validateAddress(shield, 'shielded', null)).toThrow(/legacy/);
    expect(() =>
      validateAddress(
        encodeNetworkAddress('account', network, new Uint8Array(48)),
        'account',
        network,
      ),
    ).toThrow(/identifier/);
    expect(() =>
      validateAddress(
        encodeNetworkAddress('shielded', network, shieldBody.slice(0, -1)),
        'shielded',
        network,
      ),
    ).toThrow(/V8/);
  });
  it('rejects checksum-valid non-byte padding', () => {
    expect(() => decodeBech32m('heg_test1pwuz9v6')).toThrow(/padding/);
  });
  it('accepts explicit legacy V3/V8 with a checksum and rejects truncated legacy addresses', () => {
    for (const [length, version, crypto] of [
      [1639, 3, 3],
      [1663, 5, 7],
    ]) {
      const bytes = new Uint8Array(length);
      bytes.set([version, crypto, 0]);
      const address = encodeBech32m('shca', bytes);
      expect(validateAddress(address, 'shielded', null)).toBe(address);
      expect(() =>
        validateAddress(address.slice(0, -1), 'shielded', null),
      ).toThrow();
      expect(() => validateAddress(address, 'shielded', network)).toThrow();
    }
  });
});
describe('exact HGN input and public snapshots', () => {
  it('does not round, truncate or accept exponent notation', () => {
    for (const invalid of [
      '1.000000001',
      '1e8',
      '-1',
      '1junk',
      'NaN',
      'Infinity',
      '01',
      '1.',
      '21000000.00000001',
    ]) {
      expect(parseHgn(invalid)).toBeNull();
      expect(toBaseUnits(invalid)).toBeNull();
    }
    expect(parseHgn('0.00000001')).toBe('1');
    expect(toBaseUnits('21000000')).toBe(2100000000000000);
    expect(hgn('1')).toBe('0.00000001 HGN');
    expect(exact('18446744073709551615')).toBe(18446744073709551615n);
    expect(() => exact(9007199254740992)).toThrow();
  });
  it('reconciles supply and account buckets without floating point', () => {
    expect(checkedStatus(statusFixture()).treasury?.next_sequence).toBe(
      '9007199254740993',
    );
    const s = statusFixture();
    s.supply!.pending_account_atoms = '300000001';
    expect(() => checkedStatus(s)).toThrow(/reconcile/);
    const a = accountFixture();
    a.pending[0].release_epoch = '1';
    expect(() => checkedAccount(a)).toThrow(/release/);
  });
  it('rejects fabricated zeroes on inactive nodes, incorrect genesis cap and duplicate signers', () => {
    const s = statusFixture();
    s.active = false;
    expect(() => checkedStatus(s)).toThrow(/Inactive/);
    s.supply = null;
    s.treasury = null;
    s.governance = null;
    expect(checkedStatus(s).active).toBe(false);
    const wrong = statusFixture();
    wrong.parameters!.max_supply_atoms = '0';
    expect(() => checkedStatus(wrong)).toThrow(/budget/);
    const duplicate = statusFixture();
    duplicate.governance!.authority.members = 2;
    duplicate.governance!.authority.signer_key_hashes.push(
      duplicate.governance!.authority.signer_key_hashes[0],
    );
    expect(() => checkedStatus(duplicate)).toThrow(/authority/);
  });
  it('rejects incorrect release heights and duplicate epoch buckets', () => {
    const a = accountFixture();
    a.pending[0].release_height = '2880';
    expect(() => checkedAccount(a, '1440')).toThrow(/height/);
    const b = accountFixture();
    b.pending[1].earning_epoch = '0';
    expect(() => checkedAccount(b)).toThrow();
  });
  it('treats a changed block or state root as stale even at the same height', () => {
    const a = statusFixture().context,
      b = { ...a, accounts_root: '06'.repeat(48) };
    expect(sameRewardContext(a, b)).toBe(false);
    expect(
      sameRewardContext(a, {
        ...a,
        note_root: ['7', '1', '2', '3', '4', '5', '6'],
      }),
    ).toBe(false);
    expect(sameRewardContext(a, { ...a })).toBe(true);
  });
});
