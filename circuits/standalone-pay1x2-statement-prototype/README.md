# Standalone Pay1x2 statement prototype

This nested Cargo workspace is a prospective, consensus-inactive adapter for
the standalone SHAKE256 binary proof experiment. It does not modify or activate
the production transaction format.

The adapter fixes exactly one native-asset input and two outputs. It binds:

- statement, circuit, crypto-suite, backend, and profile identifiers;
- the `1-in/2-out` activity shape and native asset id;
- the scalar relation's 56-byte anchor, nullifier, and two output commitments;
- the public fee;
- two ordered SHAKE256-448 hashes of exact caller-supplied canonical
  ciphertext bytes;
- a typed SHAKE256-448 network binding over an exact 32-byte chain id, 48-byte
  genesis block id, and 48-byte rules hash; and
- a SHAKE256-448 balance tag reconstructed only from the public identifier,
  shape, asset, and fee fields.

The fresh `HGS2` / `HEG-S4V2` statement intentionally has no 48-byte digest
compatibility lane: generic post-quantum collision security needs the 56-byte
width and its composition margin. The exact statement is 478 bytes, uses
fixed-width big-endian fields, and has no optional sections or length aliases.
`decode_exact` rejects truncation,
trailing bytes, unsupported identifiers, any non-`1x2` shape, a non-native
asset, an out-of-range fee, and a stale derived balance tag.

`verify_action_statement` recomputes the network binding from caller-supplied
typed `ChainId32`, `BlockId48`, and `RulesHash48` values. A statement from a
different genesis, rule set, or chain id therefore cannot be replayed under the
same proof bytes. The deterministic `KAT_NETWORK_IDENTITY` is for prototype
vectors only; an integration must inject the active node identity.

`CanonicalCiphertextBytes::from_validated_exact` deliberately names an external
premise: a wallet/consensus ciphertext parser must first exact-decode and
canonically re-encode the ciphertext. This crate only enforces nonempty bounded
bytes and binds those exact bytes; it does not pretend to implement the
production ciphertext grammar.

## Frozen prospective action route

The fresh action projection is independent of the active `PendingAction` type
and is not registered in the production manifest. Its exact constants are:

- statement magic/profile: `HGS2` / `HEG-S4V2`;
- statement version `2`, circuit `5`, crypto suite `4` (Delta), backend `1`,
  Pay1x2 profile `1`;
- prospective Kernel binding V5/Delta: circuit `5`, crypto `4`;
- shielded family id `1` and **new Pay1x2 inline action id `7`** (the active
  inline id is `1` and is not reused);
- one nullifier, two ordered commitments, and two ordered exact-decoded
  ciphertexts with exact `u32` sizes;
- balance-slot asset ids `[0, u64::MAX, u64::MAX, u64::MAX]`,
  `value_balance = 0`, stablecoin absent, and candidate artifact absent; and
- `binding_digest = HGS2 statement.binding_digest()` (64 bytes).

The fresh `bal.tgv2` SHAKE256-448 balance tag is intentionally incompatible
with the active 48-byte balance tag. The other frozen fresh roles are
`ct.hshv2`, `net.bdv2`, and `stmt.bv2`.

`adapt_canonical_action` validates this complete projection and reconstructs
its unique HGS2 statement. `verify_canonical_action_statement` additionally
requires exact HGS2 bytes and the caller-supplied network identity; it rejects
route, count, order, size, relation, balance-slot, value-balance, optional
payload, binding-digest, and network drift.

Run in an ephemeral target directory:

```sh
CARGO_TARGET_DIR=/private/tmp/hegemon-pay1x2-statement-target \
  cargo test --manifest-path circuits/standalone-pay1x2-statement-prototype/Cargo.toml
CARGO_TARGET_DIR=/private/tmp/hegemon-pay1x2-statement-target \
  cargo clippy --manifest-path circuits/standalone-pay1x2-statement-prototype/Cargo.toml \
  --all-targets -- -D warnings
```
