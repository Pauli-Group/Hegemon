# Standalone SHAKE256 binary-proof prototype

This directory is the executable prototype for Hegemon's replacement transaction-proof architecture: one wallet-generated, self-contained proof per transaction, SHAKE256 semantic hashing, and a binary-native proof backend. It deliberately contains no production route, manifest entry, or consensus activation.

The prototype is split into independently testable pieces:

- `../../circuits/standalone-shake256-prototype` fixes the typed SHAKE256-448 grammar and scalar hash oracle.
- `../../circuits/standalone-pay1x2-relation-prototype` fixes the native-asset one-input/two-output depth-32 relation.
- `../../circuits/standalone-pay1x2-statement-prototype` fixes the 478-byte `HGS2` statement and prospective V5/Delta family-1/action-7 projection, including version/profile identity, exact activity shape and ciphertext sizes, native-only balance slots, two SHAKE256-448 ciphertext hashes, a typed chain/genesis/rules binding, and the public-derived balance tag.
- `../../circuits/standalone-proof-envelope-prototype` fixes the direct 12-byte envelope and exact parser.
- `backend` pins Binius64 revision `3f96163049f680b2909f6545690bd929f1b48c44` and proves the exact bit-level SHAKE256-448 Merkle-parent relation.
- `pay1x2-backend` proves the complete native Pay1x2 cryptographic core, observes the entire canonical statement in Fiat-Shamir, and composes exact `HGSP` parsing with authoritative action/network reconstruction before proof verification.
- `all-private-patch` contains the applyable pinned-upstream/private-input patch, exact full-circuit layout patch, hash-guarded disposable runner, and frozen optimized measurement.
- `m4-full-pay1x2-prototype` implements the exact relation as one native-word M4 main circuit; `m4-selected-wire-patch`, `m4-public-elision-patch`, and `m4-terminal-target-patch` freeze intermediate reductions, while `m4-padding-fiber-patch` freezes the 65,440-byte direct-proof minimum.
- `autoresearch` is the disk-bounded local optimization loop. It applies one allowlisted Binius patch at a time to a disposable tree, runs the frozen full evaluator, records a hash-chained ledger, and keeps strict-PQ128 and weak-profile Pareto frontiers separate.
- `m4-strict-full-shake400-v1` retains the source-bound full-maximum-M4 SHAKE256-400 proof-size experiment and its exact verified artifact; `strict-hash-profile-shake400` keeps its 50-byte hash plumbing isolated from the SHAKE256-512 profile.
- `../../scripts/measure_standalone_shake256_prototype.py` enforces byte, disk, verification, and security-report policy.
- `../../.agent/hardening/binius-pq128-proof-size/strict_pq_profile.py` is the fail-closed strict-profile calculator.

The `HEG-S4V2` scalar Pay1x2 profile has one native input, one recipient output, one mandatory owner-authorized change output with a fresh recipient diversifier, one hidden depth-32 path, 61-bit values and fee, 384-bit spend-secret/rho/randomness inputs, spend-key-derived authorization and nullifier keys, exact conservation, and public anchor/nullifier/output-commitment/fee bindings. It contains 37 semantic invocations, 5,153 absorbed bytes, and exactly 40 Keccak-f[1600] permutations. The balance tag is reconstructed by the statement adapter from canonical public fields, not hashed from hidden note values.

## Measured evidence

The checked-in backends are real proof roundtrips under the current upstream profile. At inverse-rate log 3:

- one exact SHAKE parent: 242,336 proof bytes and 242,348 envelope bytes;
- 40 independent SHAKE parents: 384,208 proof bytes and 384,220 envelope bytes;
- the complete 478-byte-network-bound Pay1x2 circuit in the ordinary layout: 380,496 proof bytes and 380,508 envelope bytes;
- the same complete circuit with all fixed witness-source bits in the existing private oracle: **350,800 proof bytes and 350,812 envelope bytes**, about 2.06 seconds to prove, 185 ms to composed-verify, and 5,474,025,472 peak resident bytes.
- the exact full single-main native-word M4 circuit: 109,264 stock proof bytes, and **65,440 proof bytes plus the 12-byte research envelope** after the verified compact wire, verifier-side deterministic-message reconstruction, terminal-target leaves, and known-zero terminal suffix.
- the exact full-maximum-M4 grouped-ZK-wrapper experiment with 50-byte SHAKE256-400 proof hashes: **1,344,828 envelope bytes** (`3 * 448,224`), 17.31% below its SHAKE256-512 baseline, with restart and mutation gates passing. Its 133.332424-bit value is an arithmetic screen, not an established PQ128 theorem or production point.

The 40-parent measurement remains a geometry proxy; the separate ordinary and optimized `pay1x2-backend` measurements are the actual transaction core. Its 478-byte adapter binds ciphertext bytes, shape, fee/balance projection, version/crypto/backend/profile identity, and a SHAKE256-448 digest of the exact chain id, genesis block id, and rules hash before the complete encoding enters Fiat-Shamir. The composed verifier rejects seven malformed envelope classes before projection, fifteen malformed action classes before proof work, and fresh raw-valid proofs for forged ciphertext-hash, network-binding, and balance-tag statements against the original authoritative action/network. Frozen reports and exact commands are in the backend and `all-private-patch` directories.

All reports are prototype-only. The M4 result is transparent, and upstream fixes a 96-bit query budget, SHA-256 proof hashing, and GF(2^128). Hegemon has not established end-to-end zero knowledge or a composed QROM reduction for the exact maximum relation. The target profile is SHAKE256-448 semantics, SHAKE256-512 proof hashing, compact binary/base-field commitments, and sufficiently wide algebraic challenges satisfying the executable 264-classical-bit scaffold. Production remains fail-closed.

## Run the fast prototype checks

From the repository root:

    CARGO_INCREMENTAL=0 cargo test --manifest-path circuits/standalone-shake256-prototype/Cargo.toml --locked
    CARGO_INCREMENTAL=0 cargo test --manifest-path circuits/standalone-pay1x2-relation-prototype/Cargo.toml --locked
    CARGO_INCREMENTAL=0 cargo test --manifest-path circuits/standalone-pay1x2-statement-prototype/Cargo.toml --locked
    CARGO_INCREMENTAL=0 cargo test --manifest-path circuits/standalone-proof-envelope-prototype/Cargo.toml --locked
    python3 .agent/hardening/binius-pq128-proof-size/test_strict_pq_profile.py
    python3 scripts/test_measure_standalone_shake256_prototype.py

Use disposable Cargo targets for the pinned Binius build. The autoresearch controller refuses a heavy run below 28 GiB free and terminates the complete process group before the shared APFS volume crosses its non-lowerable 20 GiB reserve. The exact build and benchmark commands are in `backend/measurements/README.md`. Reproduce the optimized full circuit with `all-private-patch/run-full-pay1x2.sh /private/tmp/binius64-api-3f961630`; the runner hash-checks every source-bearing input and removes its exact temporary source and target on exit. For iterative work, use `autoresearch/autoresearch.py` so runs are serialized, continuously monitored, bounded to a 4 GiB Cargo target and 5 GiB complete run root, and recorded without retaining proof/build artifacts.

## Optimization direction

The scalar backend's inverse-rate log 3 optimization culminates at 244,240 bytes after terminal-message, compact-frontier, and verifier-known-value encoding. Moving the same exact relation to native-word M4 drops the committed tier from `2^21` to `2^15`; the cumulative direct wire progresses through 72,880 bytes, 71,280 bytes after deterministic public-message reconstruction, 69,456 bytes after division-free terminal-target leaves, and 65,440 bytes after padding-fiber terminal compression and an inverse-rate-log-two-through-six sweep. BaseFold trace-oracle masking alone is not an acceptable privacy fix: it leaves other witness-dependent reduction messages visible and increases the transcript. Further work must build complete zero knowledge and the strict profile without discarding this tier reduction.

Naively widening every proof element to 48 bytes projects to 1,997,712 bytes for the 40-component strict profile even after the private-oracle improvement. Meeting the 1 MiB hard cap therefore requires a mixed-field/native binary PCS: compact committed symbols and wide algebraic challenges. Reduced security, reduced-round Keccak, off-proof validity checks, proof sidecars, and block aggregation are not acceptable substitutes.
