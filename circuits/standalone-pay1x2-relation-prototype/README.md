# Standalone Pay1x2 relation prototype

This isolated crate is the scalar reference for Hegemon's narrow normal-payment
profile: one native-asset input, one depth-32 membership path, one recipient
output, and one change output. It checks authorization-key ownership, a
48-byte-spend-key-derived nonzero nullifier, 48-byte rho and note randomness,
nonzero active note commitments, the active 61-bit monetary range, exact
conservation, and every binding in this narrow cryptographic core. The V2
semantic registry is fixed by `HEG-S4V2`. Zero nullifiers and commitments are
rejected because the active wire reserves them for inactive padding. The change
authorization key is derived from the spender, while its recipient/diversifier may rotate.
Consolidation, stablecoins, and multisig require separate profiles, so ordinary
payments do not pay for unused universal branches.

This is executable specification code, not a proof backend and not a consensus
route. Acceptance here does not establish zero knowledge, proof soundness, or
post-quantum security. `Pay1x2Statement` is not yet the canonical action
statement adapter. That adapter must additionally bind both ciphertext hashes,
the fixed input/output activity shape, version/crypto/proof profile identifiers,
and the verifier-derived balance-tag/value-balance projection. Those fields are
excluded from the reported 40 Keccak-f cryptographic-core permutations. This
crate exists so the eventual binary circuit and prover can be differentially
tested against one exact core relation.

From this directory, run:

    CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test --offline
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo run --offline --quiet

The executable prints the fixed witness/public sizes, exact SHAKE/Keccak work,
and the named mutation matrix. Every listed mutation must reject.
