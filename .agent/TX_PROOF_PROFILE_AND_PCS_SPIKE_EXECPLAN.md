# Transaction Proof Release Profile And PCS Spike

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

This plan builds on `.agent/TRANSACTION_PROVER_OPTIMIZATION_EXECPLAN.md`. That earlier plan slimmed the transaction AIR and proved that the current Goldilocks/Plonky3 stack can be materially improved without changing wallet semantics. This document picks up at the next bottleneck: the release FRI profile and the polynomial commitment system (the part of the proof that answers many low-degree queries). The goal is to make the release profile auditable, measure exactly what proof-size gains are available from query-count changes, and run honest spikes for STIR- and SmallWood-class replacements before anyone burns months on the wrong migration.

## Purpose / Big Picture

After this work, a developer can do three concrete things that were not possible before. First, they can inspect the protocol manifest and see the release transaction FRI profile as an audited protocol parameter instead of a hidden compile-time constant. Second, they can run one checked-in sweep command and get the exact code-derived proof-size and soundness report for the live transaction AIR at `log_blowup = 4` and query counts `32/28/24/20/16`. Third, they can open one checked-in note and see why the current tx proof is dominated by the opening layer, why `16` queries does not satisfy the current `128-bit` engineering rule, and how much a STIR- or SmallWood-class replacement would need to shrink the opening proof to deliver a real `2x` or `3x` total-byte win.

The observable outcome is not “some refactor happened.” The observable outcome is:

1. The runtime manifest commits to the tx proof release profile.
2. The strict version-bound verifier rejects low-query proofs even if they are otherwise valid.
3. The repo contains the exact sweep artifact and the exact engineering conclusion.

## Progress

- [x] (2026-04-07T03:55Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and the earlier transaction prover optimization ExecPlan to anchor this change in the current product path.
- [x] (2026-04-07T03:55Z) Audited the transaction prover/verifier plumbing in `circuits/transaction-core/src/p3_config.rs`, `circuits/transaction-core/src/p3_verifier.rs`, `circuits/transaction/src/p3_prover.rs`, `circuits/transaction/src/proof.rs`, `runtime/src/manifest.rs`, and `protocol/versioning/src/lib.rs`.
- [x] (2026-04-07T03:55Z) Moved the release tx FRI profile into a version-owned type (`protocol/versioning::TxFriProfile`) and exposed it through the protocol manifest so the live release profile is no longer just a local constant in `p3_config.rs`.
- [x] (2026-04-07T03:55Z) Added a code-derived tx AIR analysis helper and a sweep binary that proves the exact current circuit at `32/28/24/20/16` queries and reports proof bytes plus exact algebraic error terms.
- [x] (2026-04-07T04:16Z) Added strict regressions proving that the version-bound release verifier rejects a valid `16`-query proof and that the runtime manifest commits to the tx FRI release profile.
- [x] (2026-04-07T04:16Z) Checked in the exact sweep artifact under `docs/crypto/` and wrote the tx-proof soundness note and size-reduction path note.
- [x] (2026-04-07T04:16Z) Extended the tx-circuit spike so the STIR and SmallWood projections are framed against the exact proof-component breakdown and the exact opening-proof reduction required for `2x` and `3x` total-byte wins.
- [x] (2026-04-07T04:16Z) Re-ran the targeted tests and the sweep command after the docs/test landing and recorded the final outcome below: `16` queries gives `179934` bytes but fails the current `128-bit` engineering baseline.

## Surprises & Discoveries

- Observation: the current tx proof is almost entirely opening-proof bytes, not commitments or public inputs.
  Evidence: the first exact sweep reports `354081` total bytes with `349177` bytes in `opening_proof`.

- Observation: the near-`2x` proof-size win from cutting queries is real on the exact current tx circuit, but it fails the current Hegemon engineering soundness rule by a wide margin.
  Evidence: the exact sweep reports `179934` bytes at `16` queries, but the current heuristic floor is only `64` bits at fixed `log_blowup = 4`.

- Observation: the exact algebraic AIR error terms are materially smaller than the FRI heuristic term, so the current size/security trade-off is overwhelmingly controlled by the PCS/transcript layer.
  Evidence: the exact sweep reports an algebraic union floor of `111` bits while the release FRI heuristic term is `128` bits and the `16`-query term is only `64` bits.

- Observation: the new strict verifier path is behaving exactly as intended: a real low-query proof still verifies under the flexible proof-shape path, but the version-bound release verifier rejects it.
  Evidence: `cargo test -p transaction-circuit --test transaction low_query_proof_is_rejected_by_release_profile --release --features plonky3-e2e -- --nocapture` passed, proving acceptance under `verify_transaction_proof_bytes_p3` and rejection under `verify_transaction_proof_bytes_p3_for_version`.

## Decision Log

- Decision: make the release tx FRI profile a version-owned manifest parameter instead of a bare transaction-core constant.
  Rationale: the release proof shape is part of the protocol claim surface. If it is not version-bound and manifest-visible, it is too easy for the prover, verifier, docs, and runtime defaults to drift apart.
  Date/Author: 2026-04-07 / Codex

- Decision: keep the tx-proof size/soundness spike in-tree as a transaction-circuit binary rather than a one-off notebook.
  Rationale: the output needs to be reproducible from the repo and tied to the exact current AIR, not to a detached spreadsheet.
  Date/Author: 2026-04-07 / Codex

- Decision: treat STIR and SmallWood as honest engineering spikes, not as adopted protocol claims.
  Rationale: the current repo has exact tx proof composition numbers but no in-tree STIR or SmallWood implementation. The right output for now is “here is the exact opening-proof share and the exact shrink target required,” not “we shipped a new PCS.”
  Date/Author: 2026-04-07 / Codex

## Outcomes & Retrospective

The regressions, docs, and final sweep rerun all landed. The outcome is sharp.

The release tx FRI profile is now a real protocol surface. It lives in `protocol/versioning`, is projected into the runtime manifest, and is enforced by the strict version-bound verifier. That closes the old gap where the active tx proof shape could drift as a local proving/verifying constant without being visible in the audited manifest contract.

The exact current sweep answer is negative for lower-query release tuning. At fixed `log_blowup = 4`, `16` queries gives a real near-`2x` proof-size reduction (`179934` bytes vs `354081`), but it does not survive the current `128-bit` engineering baseline. Neither do `20`, `24`, or `28` queries. Under the current release discipline, query cuts alone are not the answer.

The tx proof is even more opening-dominated than intuition suggested: `349177` of `354081` bytes are in the opening proof. That makes the next engineering decision much cleaner. A transparent PCS replacement that can shrink the opening layer by about `2.03x` is enough for a real `2x` total-byte win. To get `3x`, the opening layer must shrink by about `3.09x`. That is exactly why the checked-in recommendation now says “prototype STIR first, then SmallWood if `3x` still matters, and do not lead with lattice PCS.”

## Context and Orientation

The files that matter are tightly scoped:

- `protocol/versioning/src/lib.rs` defines version-owned protocol parameters that are shared between the runtime and proving code. After this change it must be the source of truth for the release tx FRI profile.
- `runtime/src/manifest.rs` builds the protocol manifest and the shielded family `params_commitment`. If the tx proof release profile is auditable, it must appear here.
- `circuits/transaction-core/src/p3_config.rs` constructs the Goldilocks/Poseidon2/FRI configuration used by the tx proof. This file still needs local fast-profile support for debug builds, but release defaults must come from the version-owned profile.
- `circuits/transaction-core/src/p3_verifier.rs` is the low-level strict verifier. It must reject proofs whose inferred FRI profile does not match the version-bound release profile.
- `circuits/transaction/src/proof.rs` and `circuits/transaction/src/p3_prover.rs` are the high-level proving and verification APIs used by wallets, the node, and native tx-leaf generation.
- `circuits/transaction/src/bin/tx_proof_profile_sweep.rs` is the checked-in reproducible spike. It proves a sample valid transaction at a fixed `log_blowup = 4` and several query counts, verifies each proof, and emits a JSON report.
- `DESIGN.md` and `METHODS.md` are the user-facing architecture documents. They must describe the real release parameter ownership and the real proof-size/soundness result.

Three technical phrases matter in this plan.

“FRI profile” means the tuple `(log_blowup, num_queries, query_pow_bits)` that controls the low-degree testing configuration of the current tx proof.

“Opening proof” means the part of the proof that answers the verifier’s polynomial-opening queries. In the current Hegemon tx proof, this is by far the largest serialized component.

“PCS” means polynomial commitment system. In this repo, the current PCS is the Plonky3 FRI-based opening layer. STIR and SmallWood are alternative transparent proof-composition directions that may reduce the opening-proof burden.

## Plan of Work

The first step is to finish the release-profile hardening. Keep `protocol/versioning::TxFriProfile` as the single version-owned source of truth, keep the runtime manifest projection under `runtime/src/manifest.rs`, and ensure the verifier path in `circuits/transaction-core/src/p3_verifier.rs` rejects any proof whose inferred `(log_blowup, num_queries)` differs from the release profile for that transaction version. Add one slow end-to-end test in `circuits/transaction/tests/transaction.rs` proving a valid `16`-query proof and showing that the flexible verifier accepts it while the version-bound release verifier rejects it. Add one fast runtime-manifest regression in `runtime/src/manifest.rs` proving that the default binding’s tx FRI profile appears in the manifest and therefore contributes to the family `params_commitment`.

The second step is to publish the exact evidence. Re-run `cargo run -p transaction-circuit --bin tx_proof_profile_sweep` from the repository root and write its JSON output to `docs/crypto/tx_proof_profile_sweep.json`. Then write `docs/crypto/tx_proof_soundness_analysis.md` explaining exactly how the report is derived from code: the AIR row count, the symbolic constraint count, the maximum constraint degree, the exact algebraic error numerators, and the current engineering rule that treats the FRI term as `effective_log_blowup * num_queries + query_pow_bits`. The note must say plainly that the current repo now has an exact code-derived algebraic analysis, but still does not claim a theorem proving that `16` queries at `log_blowup = 4` meets the current `128-bit` bar.

The third step is to turn the PCS research request into a repo-local engineering spike. Extend `circuits/transaction/src/bin/tx_proof_profile_sweep.rs` so the JSON report includes the share of the proof that is opening-proof bytes and the exact opening-proof shrink required to achieve `2x` and `3x` total-byte reduction. Then write `docs/crypto/tx_proof_size_reduction_paths.md` that uses those exact values to compare three concrete paths: keeping current FRI and lowering queries, a STIR-class transparent PCS that shrinks opening proofs by roughly the range reported in the literature, and a SmallWood-class small-instance transparent PCS spike. This note must be brutally honest: `16` queries gives a near-`2x` byte win but fails the current security heuristic; a STIR-class replacement is the best `2x` candidate because it attacks the exact dominant component; SmallWood is the right `3x` spike to try before lattice PCS because the current tx AIR has only `8192` rows.

Finally, update `DESIGN.md` and `METHODS.md` so the whitepaper-level and methods-level documents no longer say the release tx FRI profile is “compile-time only.” They must say that the active release profile is version-owned and manifest-projected, that the current default release profile remains `(4, 32, 0)` for the default binding, and that the checked-in sweep shows the exact size/security trade-off for lower query counts.

## Concrete Steps

Work from the repository root.

1. Edit the strict verifier and manifest regressions.

       cargo test -p transaction-circuit --test transaction low_query_proof_is_rejected_by_release_profile --features plonky3-e2e --release -- --nocapture
       cargo test -p runtime manifest_includes_default_tx_stark_profile -- --nocapture

2. Re-run the sweep and write the JSON artifact.

       cargo run -p transaction-circuit --bin tx_proof_profile_sweep > docs/crypto/tx_proof_profile_sweep.json

3. Update the docs and rerun the targeted validation.

       cargo test -p transaction-circuit --test transaction --features plonky3-e2e --release -- --nocapture
       cargo test -p runtime manifest_includes_default_tx_stark_profile kernel_manifest_commits_tx_stark_profiles -- --nocapture
       cargo run -p transaction-circuit --bin tx_proof_profile_sweep

The expected evidence after the rerun is:

    32 queries -> about 354081 bytes, heuristic FRI term 128 bits
    16 queries -> about 179934 bytes, heuristic FRI term 64 bits
    opening_proof_bytes -> about 349177 of 354081 total bytes

## Validation and Acceptance

This plan is complete only if all of the following are true.

The runtime manifest exposes the default tx FRI release profile and the shielded family `params_commitment` covers it. The fast runtime tests must pass and prove this directly.

The strict version-bound tx verifier rejects a valid low-query proof. The end-to-end transaction test must prove a real `16`-query proof, verify it with the flexible low-level verifier, then show the version-bound release verifier rejecting it with a profile-mismatch error.

The repository contains a checked-in JSON sweep artifact and two checked-in notes under `docs/crypto/` that explain the result and the next engineering decision. The notes must say plainly that `16` queries does not satisfy the current `128-bit` engineering target and that STIR-class work is the best near-term `2x` path because the opening layer dominates the proof size.

## Idempotence and Recovery

The test commands and sweep command are safe to rerun. The JSON artifact should be overwritten in place by rerunning the sweep command. If the slow `plonky3-e2e` test fails due to build environment issues, rerun the exact same command after restoring the usual build environment; no migration state is changed by these commands.

## Artifacts and Notes

The first sweep before the docs landed already established the central result:

    release profile: log_blowup=4, num_queries=32, query_pow_bits=0
    32 queries: 354081 bytes
    28 queries: 310631 bytes
    24 queries: 267031 bytes
    20 queries: 223474 bytes
    16 queries: 179934 bytes
    opening_proof_bytes: 349177
    non_opening_bytes floor: 4904

Those numbers are the starting point for the checked-in docs and should remain visible even if later tweaks shift them slightly.

## Interfaces and Dependencies

The following interfaces must exist and remain stable after this plan:

In `protocol/versioning/src/lib.rs`, define:

    pub struct TxFriProfile {
        pub log_blowup: u8,
        pub num_queries: u8,
        pub query_pow_bits: u8,
    }

    pub const DEFAULT_TX_FRI_PROFILE: TxFriProfile
    pub const fn tx_fri_profile_for_version(version: VersionBinding) -> Option<TxFriProfile>

In `circuits/transaction-core/src/p3_config.rs`, define:

    pub fn release_tx_fri_profile_for_version(version: VersionBinding) -> TxFriProfile
    pub fn build_tx_fri_profile_for_version(version: VersionBinding) -> TxFriProfile
    pub fn config_with_profile(profile: TxFriProfile) -> TransactionStarkConfig

In `circuits/transaction-core/src/p3_verifier.rs`, define:

    pub fn verify_transaction_proof_bytes_p3_for_version(
        proof_bytes: &[u8],
        pub_inputs: &TransactionPublicInputsP3,
        version: VersionBinding,
    ) -> Result<(), TransactionVerifyErrorP3>

In `circuits/transaction-core/src/p3_analysis.rs`, define:

    pub fn analyze_transaction_air_profile(
        num_public_values: usize,
        requested_log_blowup: usize,
        num_queries: usize,
        query_pow_bits: usize,
    ) -> TransactionAirSecurityAnalysis

Update note at 2026-04-07T03:55Z: created this plan after the core plumbing and first exact sweep were already in place, because the remaining work is now about locking the result into tests, docs, and reproducible artifacts rather than inventing the architecture from scratch.
