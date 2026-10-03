# Bounded verifier branch validation (2026-10-02)

Branch baseline: `ce6d5d75`, worktree `/private/tmp/hegemon-verifier-20261002`.
This is branch evidence, not final integrated-source qualification or release
authorization. The coordinator owns final broad tests and fresh qualification.

## Commands and results

All Cargo commands used `CARGO_TARGET_DIR=/private/tmp/rp05-ci-20261001.223oOy/target`
and `CARGO_BUILD_JOBS=2`, sequentially in the granted heavy lane.

    cargo test --locked --offline --profile retained-proof -p hegemon-node --features poseidon2-v8-retained-test-support --lib bounded_ -- --test-threads=1

27 passed, zero failed, one genuine-fixture test ignored; build 3m31s, tests
2.32s. Covers ordered success/error replay, proof-versus-state failure order,
pre-dispatch bounds and actual mixed direct/window/nested shared-pool calls.

    /usr/bin/time -l env RAYON_NUM_THREADS=2 TARGET/retained-proof/examples/rp05_smza_disjoint_spends_artifact generate .agent/artifacts/smallwood-poseidon2-v8-smza/disjoint-parent2
    /usr/bin/time -l env RAYON_NUM_THREADS=2 TARGET/retained-proof/examples/rp05_smza_disjoint_spends_artifact verify .agent/artifacts/smallwood-poseidon2-v8-smza/disjoint-parent2

Create-only generation passed: 102.68s real, 185.36s user, 4.79s system,
2,197,094,400 bytes maximum RSS. Individual generation times in the manifest:
52.873403833s and 47.586262791s. Independent readback/source verification
passed: 0.80s real, 25,559,040 bytes maximum RSS. Carriers unchanged; disjoint
inputs, same parent, distinct proofs/salts/DECS roots. Both production flags
false. The helper uses exact authenticated source-fixture outputs, not newly
wallet-generated outputs.

Manifest SHA512:
`6ef38a9dee2a219766411c81184a4ddd540a75fca3fbdd02cf123b99746a934620aae88906771475bb7e10d86cef4d83ed4d5bff75a8d622d1e0b9d25e04f268`.
Proof SHA512s:

- spend-note0: `4bbed3e28ac6910182ed2e083a28ef15e7dff531c9acab6509d6c8dba1b9cf06e4058b1b80f58cf481e347ed023b351c52befb93595e863d5eef915521ab065e` (163,537 bytes).
- spend-note1: `4086d360d0d2b3313b9b5622c53f7d78b6d61986e84607fc4281b9812a77132c011165e42d4924ffcefbca6e041acbd92bf6b9afce54c09bbf60cd855bf3f66e` (163,665 bytes).

Generation/readback pin the generation-time full source inventory. Subsequent
assertion-only edits in the node test changed the verifier test source inventory
entry. The existing manifest is preserved unchanged, not relabeled as final
source evidence. Final integrated qualification must regenerate once.

    HEGEMON_TEST_DISJOINT_SMZA_DIRECTORY=/private/tmp/hegemon-verifier-20261002/.agent/artifacts/smallwood-poseidon2-v8-smza/disjoint-parent2 cargo test --locked --offline --profile retained-proof -p hegemon-node --features poseidon2-v8-retained-test-support --lib bounded_native_disjoint_smza_block_survives_restart_and_fresh_import -- --ignored --test-threads=1

Passed 1/1 in 1.43s (final-source build 2m27s). Real source proofs for two
distinct notes share height2/root. Both pass actual peer admission, are mined
in canonical action-id order, retain exact action bytes, and yield four notes,
two spent nullifiers and two lifetime proofs. Source-reverified native restart
and fresh exact block import agree on typed tip/note state/nullifiers. A block
with two copies of one valid spend rejects DuplicateNullifier; a later mutated
proof rejects ProofRejected. Both leave tip, notes, proof lifetime and spent
nullifiers unchanged.

    cargo test --locked --offline --profile retained-proof -p hegemon-node --features poseidon2-v8-retained-test-support --lib native::poseidon2_v8_ -- --test-threads=1

82 passed, two failed, seven ignored in 3.89s. Every changed runtime/state/
scheduler regression passed. Failure details preserved below, not suppressed.

    TARGET/retained-proof/deps/hegemon_node-880248efd9e2b700 native::poseidon2_v8_state::tests --test-threads=1

All 31 state tests passed in 2.11s on final source. Direct test binary is the
same Cargo-produced binary named above, not a separate compilation.

## Broader-suite exceptions

Exact selector:
`native::poseidon2_v8_verifier::tests::retained_carrier_pending_snapshot_encodes_map_values_without_the_map_key`.
Unchanged caller `node/src/native/poseidon2_v8_carrier_tests.rs:3025` invokes
`retained_coinbase_action(1, RETAINED_V8_COINBASE_0_SCALE, RETAINED_V8_COINBASE_0_SHA512)`
before the map-value encoding assertions. That historical retained ciphertext
uses obsolete version/suite 4/7. Failure output:

    thread 'native::poseidon2_v8_verifier::tests::retained_carrier_pending_snapshot_encodes_map_values_without_the_map_key' panicked at node/src/native/poseidon2_v8_verifier.rs:3595:14:
    retained action 11 payload is exact: Poseidon2 V8 coinbase ciphertext rejected: serialization error: Unsupported note ciphertext version/crypto suite: 4/7

The legacy helper body/caller were not changed by this runtime patch. Coordinator
will repair the fixture on integrated source without bypassing payload checks.

Exact selector:
`native::poseidon2_v8_verifier::tests::retained_carrier_process_group_cleanup_kills_owned_leader_and_descendant`.
Sandbox failure at `poseidon2_v8_carrier_tests.rs:3112`: PermissionDenied,
Operation not permitted. The same compiled exact test passed 1/1 in 0.09s under
approved escalation, which permits its owned-child process-group signals.

## Measurement scope

Raw cached-source verifier serial/1/2/4-worker CPU results and reproducible
commands/hashes are in `RP05_BOUNDED_VERIFIER_MEASUREMENTS.json`. Times are per
16-proof round. Four-worker median scaling is 3.46x component-only; it excludes
node decode/copy/FIFO/state application and alternates same-spend retained
proofs. The genuine block test, not that benchmark, supplies valid multi-proof
acceptance evidence. No network TPS or production readiness claim follows.
