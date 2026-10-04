# Standalone SHAKE256 semantic prototype

This isolated crate is the scalar semantic-hash foundation for the proposed
standalone binary transaction proof. It is not a consensus dependency and does
not authorize a proof profile.

Every semantic digest is exactly 56 bytes. Hash inputs use a small, fixed
registry rather than a generic serialization format:

    "HEG-S4V2" || role[8] || field_count[u8]
      || (field_length[u16-be] || field_bytes)*

The registry fixes both field count and every field length for each role before
hashing. In particular, a Merkle parent absorbs exactly 133 bytes: 17 header
bytes, two 2-byte length words, and two 56-byte children. That fits in one
136-byte SHAKE256 rate block, including SHAKE padding.

`HEG-S4V2` supersedes the prototype's original 32-byte secret grammar. Spend
keys, note `rho`, and note randomness are 48 bytes so the prospective profile
does not sit exactly on a single-target Grover `2^128` boundary with no
composition or multi-target margin.

Role separation is cSHAKE-style but this is deliberately SHAKE256, not the
SP 800-185 cSHAKE encoding: the compact fixed profile/function headers avoid an
extra `bytepad` block in every Merkle parent. A separate 75-byte key frame binds
`sp.keys1` and the explicit order tag `auth>nf1`; one 112-byte squeeze derives
`SpendAuthKey[56] || NullifierKey[56]` from a 48-byte spend key in one
Keccak-f call.

The frozen role registry is:

- `note.cm1`: `value[u64-be]`, `asset_id[u64-be]`, `pk_recipient[32]`,
  `rho[48]`, `randomness[48]`, `pk_auth[56]` (229 absorbed bytes, two
  permutations).
- `nullif.1`: `nullifier_key[56]`, `position[u64-be]`, `rho[48]` (135
  absorbed bytes, one permutation).
- `merk.nd1`: `left[56]`, `right[56]` (133 absorbed bytes, one permutation).

Run the isolated tests without populating the repository-wide target directory:

    CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
      CARGO_TARGET_DIR=/private/tmp/hegemon-shake256-prototype-target \
      cargo test --manifest-path circuits/standalone-shake256-prototype/Cargo.toml

Print the depth-32 `Pay1x2` workload geometry:

    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
      CARGO_TARGET_DIR=/private/tmp/hegemon-shake256-prototype-target \
      cargo run --manifest-path circuits/standalone-shake256-prototype/Cargo.toml \
      --example pay1x2

The `Pay1x2` evaluator is a differential-testing oracle and a source of exact
Keccak invocation preimages for a future binary circuit. It exposes the
spend-key derivation and the equality material needed to prove note ownership;
the evaluator fails if the input note carries a different authorization key.
Balance-tag hashing is intentionally absent: the future statement adapter must
reconstruct the active grammar from public fee, signed value balance,
stablecoin fields, and canonical balance slots. The evaluator does not itself
enforce value conservation or zero knowledge.

This scalar prototype retains ordinary Rust arrays so differential tests and a
binary-circuit adapter can inspect exact witness bytes. It is not safe to embed
in a wallet as-is. Wallet integration must replace spend-key, derived-key,
`rho`, randomness, and secret-frame storage with audited zeroizing containers;
remove unnecessary `Copy` paths; zeroize success and error paths; and add
memory-residue tests. Debug implementations in this crate redact semantic
digests and secret-bearing frames, but redaction is not a substitute for
zeroization.
