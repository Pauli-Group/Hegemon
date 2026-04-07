# Transaction Proof Backend Replacement

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

This plan starts from the current product reality: Hegemon ships a Plonky3 transaction proof, wraps that proof into a native `tx_leaf`, and then aggregates verified leaves into one `receipt_root` through the lattice folding layer. The user-visible goal of this plan is to make that per-transaction proof backend replaceable without destabilizing the block-level aggregation lane, then push the SmallWood branch forward until it either produces a real smaller tx proof under the `128-bit` post-quantum rule or gets killed honestly.

## Purpose / Big Picture

After this plan, a developer will be able to do three concrete things. First, they will be able to inspect the protocol manifest and see the active transaction-proof backend as a version-owned protocol parameter instead of a hard-coded assumption. Second, they will be able to verify that native `tx_leaf` artifacts carry enough information to dispatch to the correct transaction-proof verifier family while remaining backward-compatible with old artifacts. Third, they will have a dedicated SmallWood frontend implementation path that plugs into the same `tx_leaf -> receipt_root` aggregation lane without rewriting the lattice folding layer.

The observable result is not merely “support SmallWood someday.” The observable result is:

1. the current Plonky3 tx proof still builds and verifies,
2. a mutated `SmallwoodCandidate` tx proof or native `tx_leaf` fails cleanly instead of aliasing the current backend,
3. future backend work can land behind one explicit seam instead of touching wallet, node, pallet, and folding code independently.

## Progress

- [x] (2026-04-07T18:10Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and the checked-in SmallWood notes before making architecture changes.
- [x] (2026-04-07T18:10Z) Identified the real switch points: `protocol/versioning`, `runtime/src/manifest.rs`, `circuits/transaction/src/proof.rs`, and `circuits/superneo-hegemon/src/lib.rs`.
- [x] (2026-04-07T18:25Z) Added a version-owned `TxProofBackend` enum to `protocol/versioning` and projected it into the runtime manifest so the active tx proof family is now part of the protocol commitment surface.
- [x] (2026-04-07T18:25Z) Added a backend field to `TransactionProof`, made the proof digest bind the backend id, and changed high-level verification to dispatch on the backend instead of assuming “proof bytes means Plonky3.”
- [x] (2026-04-07T18:25Z) Added a trailing tx-proof-backend selector byte to native `tx_leaf` artifacts with backward-compatible decoding that defaults missing bytes to the current Plonky3 backend.
- [x] (2026-04-07T18:25Z) Added regression coverage for unsupported-backend rejection and backward-compatible native artifact decode.
- [x] (2026-04-07T19:12Z) Fixed the native `tx_leaf` builder to use the release tx-proof profile even in debug builds; the old path was silently generating fast-profile proofs that the native verifier rejected.
- [ ] Implement the semantic SmallWood frontend for `NativeTxValidityRelation`, starting with witness export and public-statement encoding.
- [ ] Add a real SmallWood verifier/prover adapter behind the new backend seam and keep it non-release until the no-grinding `128-bit` note exists.
- [ ] Version the `tx_leaf` / native receipt profile cleanly once a real SmallWood tx proof exists, then benchmark proof bytes and proving time against the current shipped Plonky3 lane.

## Surprises & Discoveries

- Observation: the smallest safe migration seam is not the lattice folding layer. It is the per-transaction proof object plus the native `tx_leaf` artifact format.
  Evidence: `circuits/superneo-hegemon/src/lib.rs` verifies `receipt_root` by replaying verified leaves, so the fold path only needs a stable verified-leaf object and does not care which tx prover produced it.

- Observation: adding explicit backend identity to the canonical receipt itself would have changed the tx-leaf relation statement surface immediately and forced a wider migration than necessary.
  Evidence: `CanonicalTxValidityReceiptRelation` binds the receipt bytes directly into the tx-leaf statement digest. Appending the backend byte to the native artifact and binding it through `proof_digest` gives a safer first seam.

- Observation: backward compatibility for native `tx_leaf` artifacts is cheap if the backend selector is appended at the end of the artifact instead of inserted in the middle.
  Evidence: old artifacts can be decoded by checking for trailing bytes after the leaf proof section and defaulting to `Plonky3Fri` when no selector byte is present.

- Observation: the old native `tx_leaf` builder was not actually release-honest in debug builds.
  Evidence: the first backward-compatibility test failed with `proof FRI profile mismatch: expected log_blowup=4 num_queries=32, got log_blowup=3 num_queries=8`, which came from `build_native_tx_leaf_artifact_bytes_with_params` using `TransactionProofParams::production_for_version` instead of a release-bound profile.

## Decision Log

- Decision: treat tx proof backend selection as a version-owned protocol parameter.
  Rationale: the backend choice is part of the consensus/security claim and must be committed in the manifest just like the release FRI profile.
  Date/Author: 2026-04-07 / Codex

- Decision: keep the lattice folding layer unchanged while replacing the per-transaction proof backend.
  Rationale: the folding layer is already the stable verified-leaf aggregation surface. Replacing both layers at once would mix two independent risks and make attribution impossible.
  Date/Author: 2026-04-07 / Codex

- Decision: carry the tx proof backend explicitly in native `tx_leaf` artifacts, but bind it to the canonical receipt indirectly through the proof digest.
  Rationale: this preserves the existing tx-leaf statement structure while still preventing backend aliasing.
  Date/Author: 2026-04-07 / Codex

- Decision: make `SmallwoodCandidate` fail closed everywhere until the semantic frontend and verifier exist.
  Rationale: an explicit unsupported error is better than accidental acceptance or half-routed proofs.
  Date/Author: 2026-04-07 / Codex

- Decision: force the native `tx_leaf` builder onto the release tx-proof profile, even in debug builds.
  Rationale: native product artifacts must reflect the release verifier surface. A debug-fast tx proof is useful for local proving experiments, but it is the wrong thing to embed in a native artifact that claims to be product-valid.
  Date/Author: 2026-04-07 / Codex

## Outcomes & Retrospective

The first milestone is complete. The repo no longer assumes that transaction proofs are eternally “Plonky3 bytes by convention.” The active backend is now protocol-owned, the transaction proof object carries explicit backend identity, the native `tx_leaf` artifact carries an explicit backend selector with backward-compatible decode, and the shipped lane still defaults to the current Plonky3 family. The acceptance checks now pass at all three layers: runtime manifest commitment, top-level transaction verification, and native `tx_leaf` verification.

This does not yet make SmallWood live. It does remove the main architectural excuse for not pursuing it: there is now a clean place to plug in a second tx proof backend without rewriting wallet submission, runtime receipt-root policy, or lattice folding.

## Context and Orientation

The files that matter are tightly scoped.

`protocol/versioning/src/lib.rs` defines version-owned protocol parameters. It now owns both the tx proof backend id and the release FRI profile for the current backend. Anything that claims to be consensus-relevant must start here.

`runtime/src/manifest.rs` projects those version-owned parameters into the protocol manifest and kernel family parameter commitment. If a tx proof backend is meant to be real, it must be visible here.

`circuits/transaction/src/proof.rs` defines the high-level transaction proof object used across the wallet, node, and native leaf builder. This is the correct place to stop assuming that every proof byte string is a Plonky3 proof.

`circuits/superneo-hegemon/src/lib.rs` is the bridge between per-transaction proofs and the lattice folding layer. The native `tx_leaf` artifact format lives here, and this file is the right place to carry the backend selector into product-visible artifacts.

`docs/crypto/tx_proof_smallwood_size_probe.md` and `docs/crypto/tx_proof_smallwood_investigation.md` record why the target backend is SmallWood and why the target witness is `NativeTxValidityRelation`, not the old AIR trace.

A “backend” in this plan means the family of per-transaction proof system used to prove tx validity. Today that backend is the shipped Plonky3 STARK. The future candidate is SmallWood. The block-level lattice folding backend is a different layer and is not being replaced by this plan.

## Plan of Work

The first phase is the seam, which is now landed. Keep the protocol manifest authoritative for tx proof backend selection, keep `TransactionProof` carrying explicit backend identity, and keep native `tx_leaf` artifacts carrying the backend selector byte. Any future tx proof backend must route through those seams.

The second phase is the semantic SmallWood frontend. Implement a crate or module that takes the existing `NativeTxValidityRelation` semantics, expands the witness with the real Poseidon2 subtrace, applies the recommended LPPC packing near `64`, and emits the exact public statement Hegemon wants to bind in `tx_leaf`. This work must not alter the lattice folding layer. It must only change the per-transaction proof producer and verifier.

The third phase is the backend adapter. Add a real `SmallwoodCandidate` prover/verifier path behind the explicit backend dispatch in `circuits/transaction/src/proof.rs`. Until the exact no-grinding `128-bit` note exists, that backend remains non-release and must fail release-gated verification paths by default.

The final phase is product comparison. Once the semantic SmallWood tx proof exists, measure proof bytes, proving time, and end-to-end native `tx_leaf -> receipt_root` behavior against the current shipped Plonky3 lane. If the real semantic prototype loses the structural win measured in the size probe, kill it. If it preserves a real `3x+` byte reduction under the no-compromise security note, version it and proceed to release hardening.

## Concrete Steps

Work from the repository root.

1. Validate the architecture seam:

       cargo test -p runtime manifest_includes_default_tx_stark_profile kernel_manifest_commits_tx_stark_profiles -- --nocapture
       cargo test -p transaction-circuit --test transaction verification_fails_for_unimplemented_backend --features plonky3-e2e --release -- --nocapture
       cargo test -p superneo-hegemon native_tx_leaf_artifact_defaults_missing_backend_byte_to_plonky3 native_tx_leaf_artifact_rejects_unimplemented_backend -- --nocapture

2. Build the next SmallWood milestone after the seam:

       cargo run -p smallwood-tx-shape-spike --release -- --output docs/crypto/tx_proof_smallwood_shape_spike.json

3. When the semantic SmallWood frontend exists, add its own spike command here and record the expected proof bytes and proving-time outputs.

## Validation and Acceptance

This plan’s current milestone is complete only if all of the following are true.

The runtime manifest commits the tx proof backend family and the tx FRI profile together.

The current Plonky3 transaction proof still builds and verifies.

Changing a proof or native artifact to `SmallwoodCandidate` fails cleanly with an unsupported-backend error instead of misrouting into the Plonky3 verifier.

Removing the trailing backend byte from a freshly built native `tx_leaf` artifact still verifies, proving backward-compatible decode.

The next milestone will be complete only when a real SmallWood semantic frontend exists and produces measured Hegemon transaction proof bytes, not just structural estimates.

## Idempotence and Recovery

The current seam changes are additive and safe to rerun. The tests above do not mutate persistent state. Native artifact backward compatibility is preserved by defaulting missing backend bytes to the current Plonky3 backend.

If the SmallWood branch later fails, the seam still remains valuable: it leaves the current shipped backend untouched while preserving a clean migration boundary for future proof families.

## Artifacts and Notes

The current measured proof-size motivation remains:

    current tx proof: 354081 bytes
    SmallWood structural probe: roughly 75128 .. 120568 bytes

The seam landed in the files below:

    protocol/versioning/src/lib.rs
    runtime/src/manifest.rs
    circuits/transaction/src/proof.rs
    circuits/superneo-hegemon/src/lib.rs

## Interfaces and Dependencies

The following interfaces must exist and remain stable after this milestone:

In `protocol/versioning/src/lib.rs`, define:

    pub enum TxProofBackend {
        Plonky3Fri,
        SmallwoodCandidate,
    }

    pub const fn tx_proof_backend_for_version(version: VersionBinding) -> Option<TxProofBackend>

In `circuits/transaction/src/proof.rs`, keep:

    pub struct TransactionProof {
        pub backend: TxProofBackend,
        pub stark_proof: Vec<u8>,
        ...
    }

    pub fn transaction_proof_digest_from_parts(
        backend: TxProofBackend,
        proof_bytes: &[u8],
    ) -> [u8; 48]

    pub fn verify_transaction_proof_bytes_for_backend(
        backend: TxProofBackend,
        proof_bytes: &[u8],
        pub_inputs: &TransactionPublicInputsP3,
        version: VersionBinding,
    ) -> Result<(), TransactionCircuitError>

In `circuits/superneo-hegemon/src/lib.rs`, keep:

    pub struct NativeTxLeafArtifact {
        pub proof_backend: TxProofBackend,
        ...
    }

and keep decoding backward-compatible by defaulting missing backend bytes to `Plonky3Fri`.

Update note at 2026-04-07T18:25Z: this plan was created after the first backend-replacement seam had already landed. It now serves as the authoritative guide for finishing the SmallWood migration without destabilizing the shipped lattice folding path.
