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
- [x] (2026-04-08T03:32Z) Implemented a semantic SmallWood frontend in `transaction-circuit` that rebuilds the exact `NativeTxValidityRelation` witness surface, expands it with the fixed-width Poseidon2 subtrace, and commits to LPPC packing metadata/digests without touching the folding layer.
- [x] (2026-04-08T03:32Z) Added a real `SmallwoodCandidate` prover/verifier adapter behind the backend seam. The candidate proof bytes now contain a real SmallWood PCS/ARK transcript over the packed expanded native witness, not an “unimplemented backend” placeholder.
- [x] (2026-04-08T03:32Z) Added an explicit non-default `SMALLWOOD_CANDIDATE_VERSION_BINDING` so candidate tx proofs remain version-owned instead of bypassing the manifest-owned backend seam.
- [x] (2026-04-08T09:15Z) Replaced the old witness-carrying random-linear-check envelope with a witness-free public SmallWood statement: direct `TransactionPublicInputsP3` field values plus fixed witness-shape metadata, bound through sparse public selector constraints.
- [x] (2026-04-08T09:15Z) Raised the candidate to the first exact no-grinding profile that clears the current term-wise `128-bit` bar for the implemented statement: `nb_opened_evals = 3`, `decs_nb_opened_evals = 37`, `decs_eta = 10`, `rho = 2`, `beta = 3`, zero grinding bits.
- [x] (2026-04-08T09:15Z) Wrote the exact no-grinding note for the implemented witness-free statement in `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md`.
- [x] (2026-04-08T17:02Z) Replaced the zero-polynomial placeholder with a real semantic SmallWood arithmetization over the native witness surface: duplicated scalar rows, Poseidon2 subtrace constraints, note-commitment/nullifier/Merkle bindings, spend-auth binding, selector routing, and balance equations.
- [x] (2026-04-08T17:02Z) Added a fast LPPC witness-check entry point and wired the candidate prover to preflight the semantic witness before invoking the expensive PCS/ARK prover.
- [x] (2026-04-08T20:41Z) Benchmarked the first full-semantic scalar SmallWood candidate honestly and found the first critical blocker: end-to-end proving works, but proofs were about `2.8 MB`, far above the shipped `354081`-byte Plonky3 baseline.
- [x] (2026-04-08T23:58Z) Replaced the scalar fallback with the real `64`-lane packed semantic relation, fixed randomized-constraint interpolation and public-target ordering in the bridge, and got full packed candidate prove/verify roundtrips green.
- [x] (2026-04-09T10:21Z) Added an exact serialized-proof projection for the current packed candidate and locked it with fast tests. After the Rust engine fixes for randomized interpolation, full-row openings, and opening-point collisions, the current Rust SmallWood candidate now projects to `242124` bytes, the passing release roundtrip emits `242132` proof bytes, and both sit below the shipped `354081`-byte proof and the `524288`-byte native `tx_leaf` cap.
- [x] (2026-04-09T12:04Z) Cut the first real prover hot spots. Witness interpolation is now parallel, DECS no longer Horner-evaluates every committed polynomial on all `4096` leaf points, and the bridge reuses a consecutive-domain evaluation cache for commit/open. The focused release tx roundtrip dropped to about `9.8s`, and the wrapped `superneo-hegemon` `tx_leaf` seam dropped to about `8.4s`.
- [x] (2026-04-08T22:14Z) Fixed the candidate bridge so polynomial constraints are interpolated from randomized witness-polynomial evaluations instead of constant coefficients. The fast LPPC witness checks stay green, the scalar candidate no longer dies in the old transcript-mismatch path, and the remaining blocker is now the scalar geometry itself plus the cost of full prove/verify.
- [x] (2026-04-08T20:41Z) Fixed two real vendor/adapter bugs exposed by that run: uninitialized polynomial coefficients in `get_constraint_pol_polynomials`, and a `piop_recompute_transcript` corner case where the linear recompute path underflowed `degree - nb_evals` when `out_plin_degree == nb_opened_evals`.
- [x] (2026-04-08T23:29Z) Built the real packed SmallWood frontend material in Rust. `transaction-circuit` now reconstructs the exact native raw witness (`3991` elements), adds the missing `balance_tag` Poseidon2 hash trace, and packs the expanded witness into the frozen `64`-lane / `934`-row statement shape used by the size probe.
- [x] (2026-04-09T02:08Z) Killed the recursive-compression detour and restored `SmallwoodCandidate` to the direct packed SmallWood/native bridge path. The active backend seam no longer routes through `recursive_candidate.rs`, and the fast packed-bridge witness check is green on the restored path.
- [x] (2026-04-09T03:11Z) Moved packed SmallWood semantic witness checking out of the C bridge and into a new Rust kernel (`smallwood_semantics.rs`). `test_candidate_witness` now validates the active packed `64`-lane bridge relation in Rust, so the remaining vendor/FFI wall is the proof engine and proof bytes, not the semantic constraint checker.
- [x] (2026-04-09T05:40Z) Removed the dead C/vendor SmallWood build path. `transaction-circuit` no longer compiles `build.rs`, `smallwood_candidate.c`, or `vendor/smallwood-prototype`; the active candidate backend is now Rust-native end to end.
- [ ] Cut the current Rust SmallWood prover runtime to something operationally sane. The current size target is met, but release tracing still shows witness-polynomial construction and PCS commit dominating wall-clock time.

## Surprises & Discoveries

- Observation: the smallest safe migration seam is not the lattice folding layer. It is the per-transaction proof object plus the native `tx_leaf` artifact format.
  Evidence: `circuits/superneo-hegemon/src/lib.rs` verifies `receipt_root` by replaying verified leaves, so the fold path only needs a stable verified-leaf object and does not care which tx prover produced it.

- Observation: adding explicit backend identity to the canonical receipt itself would have changed the tx-leaf relation statement surface immediately and forced a wider migration than necessary.
  Evidence: `CanonicalTxValidityReceiptRelation` binds the receipt bytes directly into the tx-leaf statement digest. Appending the backend byte to the native artifact and binding it through `proof_digest` gives a safer first seam.

- Observation: backward compatibility for native `tx_leaf` artifacts is cheap if the backend selector is appended at the end of the artifact instead of inserted in the middle.
  Evidence: old artifacts can be decoded by checking for trailing bytes after the leaf proof section and defaulting to `Plonky3Fri` when no selector byte is present.

- Observation: the old native `tx_leaf` builder was not actually release-honest in debug builds.
  Evidence: the first backward-compatibility test failed with `proof FRI profile mismatch: expected log_blowup=4 num_queries=32, got log_blowup=3 num_queries=8`, which came from `build_native_tx_leaf_artifact_bytes_with_params` using `TransactionProofParams::production_for_version` instead of a release-bound profile.

- Observation: the old candidate no-grinding profile did not actually clear `128` bits once the `ε3` and `ε4` terms were instantiated honestly.
  Evidence: with `nb_opened_evals = 2`, `ε3` only landed around `2^-110`, and with `decs_nb_opened_evals = 21`, `ε4` only landed around `2^-76`, so the exact no-grinding note forced a parameter bump before the milestone could be called complete.

- Observation: the scalar semantic fallback was useful for proving the relation, but it killed the SmallWood proof-size story.
  Evidence: the scalar fallback proved the real native relation but landed around `2.8 MB` because `packing_factor = 1` left `55,526` witness rows and forced the proof to ship three opened evaluation vectors over essentially the whole scalar witness. The later packed Rust candidate cut the exact serialized envelope to `242124` bytes, with a passing release roundtrip at `242132` proof bytes, below the shipped Plonky3 proof and below the native `tx_leaf` cap.

- Observation: the current blocker moved again, from size to proving cost.
  Evidence: a release trace of the packed Rust candidate reports about `24s` in `witness_polys` and about `49s` in `pcs_commit` before the later PIOP/opening stages. The current bottleneck is the prover’s material/interpolation path, not proof bytes.

- Observation: the missing blocker moved from “prove the right thing” to “prove it fast enough.”
  Evidence: the new LPPC witness-check path accepts the honest witness and rejects a one-word mutation immediately, the randomized-constraint interpolation bug in the scalar bridge is fixed, but the integrated candidate is still too large and too expensive to treat as a normal test-path backend.

- Observation: the packed frontend numbers were not aspirational; they were reproducible from code once the builder stopped using the 536-word shortcut.
  Evidence: `build_packed_smallwood_frontend_material_from_witness` now lands exactly on `public_value_count = 78`, `raw_witness_len = 3991`, `poseidon_permutation_count = 145`, `expanded_witness_len = 59749`, `lppc_row_count = 934`, and `lppc_packing_factor = 64`, and the unit test `packed_smallwood_frontend_matches_expected_shape` passes on the real sample witness.

- Observation: the first SmallWood backend bugs were in Hegemon’s bridge/recompute logic, not just in theory.
  Evidence: `piop_recompute_transcript` tried to call `poly_restore` with `degree = 3` and `nb_points = 4` in the linear recompute path, which underflowed `degree - nb_evals`. The repo now patches that path to interpolate directly when there are no high-degree terms, and the active engine is Rust-native.

- Observation: the version-owned backend seam was correct; the test failure was the point.
  Evidence: a candidate `tx_leaf` built under the default version was rejected with `native tx-leaf proof backend mismatch`, which forced the correct fix: add an explicit candidate version binding instead of weakening backend dispatch.

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

- Decision: replace the old random-linear-check envelope with a witness-free public statement before doing any more semantic work.
  Rationale: carrying the witness in proof bytes and binding it with dense transcript-derived checks was the wrong surface for a long-lived backend seam. The correct candidate surface is direct public values plus fixed witness-shape metadata.
  Date/Author: 2026-04-08 / Codex

- Decision: tune the candidate SmallWood parameters to the first exact no-grinding profile that clears the term-wise `128-bit` bar for the implemented statement.
  Rationale: an “exact no-grinding note” that merely records failure would have been lazy here because the parameter fix was local and cheap. The first successful point is `nb_opened_evals = 3`, `decs_nb_opened_evals = 37`, `decs_eta = 10`, `rho = 2`, `beta = 3`.
  Date/Author: 2026-04-08 / Codex

- Decision: bind `SmallwoodCandidate` to an explicit non-default protocol version instead of accepting it under the current shipped version.
  Rationale: backend selection is consensus-relevant. The candidate path should use the same version-owned contract as the shipped Plonky3 path.
  Date/Author: 2026-04-08 / Codex

## Outcomes & Retrospective

The second milestone is now complete too. The repo no longer just “has a seam.” It has a working candidate backend that proves and verifies a witness-free public SmallWood statement over a duplicated-column semantic native witness, dispatches through the version-owned backend selector, builds native `tx_leaf` artifacts, and participates in `receipt_root` aggregation without changing the folding layer. The shipped lane still defaults to the current Plonky3 family, and the candidate lane is isolated under its own non-default version binding.

This still does not make SmallWood live. The current candidate statement now has both an exact no-grinding `128-bit` note and a real semantic arithmetization over the native witness surface, and the integrated packed frontend now projects to an exact serialized proof envelope of `242124` bytes while the passing release roundtrip emits `242132` proof bytes. That is below both the shipped `354081`-byte tx-proof baseline and the `524288`-byte native `tx_leaf` cap. What remains open is prover cost, not proof size: the current release prover is materially faster than before, but it is still too slow for the default product/test lane, with the traced hot path now dominated by LVCS interpolation, DECS domain-evaluation extension, and PIOP constraint construction.

One dead branch is now explicitly gone: recursive compression of the shipped tx STARK is no longer the active `SmallwoodCandidate` path. That experiment attacked the wrong object, was too memory-heavy for normal local iteration, and did not belong in the live backend seam. The active candidate path is back where it should be: direct proving over the compact native witness surface.

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

The second phase is the witness-free SmallWood frontend. The first scalar version now exists: it takes the existing `NativeTxValidityRelation` witness surface, expands it with the real Poseidon2 subtrace, and emits the exact witness-free public statement Hegemon wants to bind in `tx_leaf`. This work does not alter the lattice folding layer. It only changes the per-transaction proof producer and verifier. The crucial new fact is that the scalar fallback is not the release path. It was only the fastest way to prove the semantics inside the vendored prototype.

The third phase is the backend adapter. Add a real `SmallwoodCandidate` prover/verifier path behind the explicit backend dispatch in `circuits/transaction/src/proof.rs`. That part is now landed, together with the exact no-grinding note for the implemented witness-free statement and a fast LPPC witness-check that validates the semantic statement before the heavy prover runs. The scalar adapter also flushed out real vendor bugs in the recompute path. The remaining release blocker is now sharper than before: the packed frontend material exists and matches the frozen target shape, but the vendored bridge still only consumes the scalar witness geometry.

The final phase is product comparison. Once the packed full-semantic SmallWood tx proof exists end to end, measure proof bytes, proving time, and end-to-end native `tx_leaf -> receipt_root` behavior against the current shipped Plonky3 lane. The scalar semantic prototype has already answered the kill-question for that geometry: it loses badly on bytes, so do not spend more time polishing it. The next comparison point must be the packed bridge, not another scalar benchmark.

## Concrete Steps

Work from the repository root.

1. Validate the architecture seam:

       cargo test -p runtime manifest_includes_default_tx_stark_profile kernel_manifest_commits_tx_stark_profiles -- --nocapture
       cargo test -p transaction-circuit --test transaction verification_fails_for_unimplemented_backend --features plonky3-e2e --release -- --nocapture
       cargo test -p superneo-hegemon native_tx_leaf_artifact_defaults_missing_backend_byte_to_plonky3 native_tx_leaf_artifact_rejects_unimplemented_backend -- --nocapture

2. Build the next SmallWood milestone after the seam:

       cargo run -p smallwood-tx-shape-spike --release -- --output docs/crypto/tx_proof_smallwood_shape_spike.json

3. When the full-semantic SmallWood frontend exists, add its own spike command here and record the expected proof bytes and proving-time outputs.

## Validation and Acceptance

This plan’s current milestone is complete only if all of the following are true.

The runtime manifest commits the tx proof backend family and the tx FRI profile together.

The current Plonky3 transaction proof still builds and verifies.

Changing a proof or native artifact to `SmallwoodCandidate` fails cleanly with an unsupported-backend error instead of misrouting into the Plonky3 verifier.

Removing the trailing backend byte from a freshly built native `tx_leaf` artifact still verifies, proving backward-compatible decode.

The next milestone will be complete only when the current witness-free candidate statement is upgraded from its selector-bound placeholder polynomial constraints to the full native tx-validity SmallWood arithmetization without losing the measured size headroom.

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
