# STIR Transaction PCS Spike

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

This plan extends `.agent/TX_PROOF_PROFILE_AND_PCS_SPIKE_EXECPLAN.md`. That earlier plan proved that lower-query FRI alone cannot deliver a release-safe `2x` tx-proof size win at Hegemon’s current `128-bit` engineering bar. This document focuses on one replacement path: a STIR-class transparent polynomial commitment system spike that is parameter-matched to the current Hegemon tx proof surface.

## Purpose / Big Picture

After this work, a developer can run one standalone spike command and get a concrete answer to the next engineering question: “if we keep the current Hegemon transaction AIR and only swap the transparent opening layer to a STIR-class PCS, do any conservative `128-bit` profiles actually buy us the `2x` proof-size win we want?”

The visible success condition is not “there is a note about STIR.” It is:

1. The repo contains a checked-in STIR spike crate under `spikes/stir-tx-pcs`.
2. That crate reads the current tx proof baseline, derives Hegemon’s actual degree/rate from code, runs parameter-matched STIR and FRI controls through the academic STIR prototype, and emits a JSON report.
3. The report marks conjectural or grinding-assisted candidates as unsupported for release.
4. A checked-in note explains the exact parameter choices, the exact release gate, and the actual result.

## Progress

- [x] (2026-04-07T04:28Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and `.agent/TX_PROOF_PROFILE_AND_PCS_SPIKE_EXECPLAN.md`.
- [x] (2026-04-07T04:28Z) Audited the academic STIR prototype at `https://github.com/WizardOfMenlo/stir`, including its parameter formulas, CLI defaults, and Goldilocks-compatible field support.
- [x] (2026-04-07T06:03Z) Created the standalone `spikes/stir-tx-pcs` crate and wired it to the current tx proof baseline and transaction-core code-derived degree/rate surface.
- [x] (2026-04-07T06:34Z) Wrote the Hegemon-specific STIR soundness and release-gating note under `docs/crypto/`.
- [x] (2026-04-07T06:34Z) Ran the STIR spike sweep, checked in the JSON artifact, and updated the existing tx-proof size-reduction note with the measured result.

## Surprises & Discoveries

- Observation: the public STIR prototype already supports the Goldilocks modulus through its `Field64` type, so the Hegemon spike does not have to jump to a different field just to run the PCS experiment.
  Evidence: `/tmp/stir/src/crypto/fields.rs` defines `Field64` over modulus `18446744069414584321`, the same modulus family Hegemon uses for Goldilocks.

- Observation: the STIR prototype’s default comparison binary runs at degree/rate parameters close to the Hegemon tx proof surface and exposes exactly the knobs we need: security level, protocol security level, starting degree, stopping degree, starting rate, folding factor, and soundness type.
  Evidence: `/tmp/stir/src/bin/main.rs` and `/tmp/stir/src/parameters.rs`.

- Observation: the exact Hegemon-shaped STIR spike is much weaker than the optimistic paper-range projection. The best conservative candidate only projects to about a `1.30x` total-byte reduction, and even unsupported comparison points stay around `1.32x`.
  Evidence: `docs/crypto/tx_proof_stir_spike.json`.

## Decision Log

- Decision: the Hegemon release gate for STIR candidates will be stricter than the academic prototype’s “security level” field.
  Rationale: the prototype lets proof-of-work bits fill missing security, but Hegemon does not currently have a settled PQ release story for counting grinding bits toward the tx proof’s `128-bit` bar. To avoid overclaiming, only `Provable` candidates with zero required PoW bits will count as release-supported.
  Date/Author: 2026-04-07 / Codex

- Decision: the spike will compare STIR against the prototype’s own FRI control and then project that ratio onto Hegemon’s measured opening-proof bytes.
  Rationale: this keeps the experiment parameter-matched to Hegemon’s real tx proof while avoiding the false precision of pretending the academic prototype is a drop-in replacement for Plonky3’s exact serialized proof format.
  Date/Author: 2026-04-07 / Codex

- Decision: the recommended conservative STIR candidate is `provable_nogrind_k16_stop64_p128`.
  Rationale: it ties the best projected release-safe total-byte result, matches the prototype’s conventional terminal degree, and avoids choosing a `stop32` tie purely because it appears earlier in a search list.
  Date/Author: 2026-04-07 / Codex

## Outcomes & Retrospective

The spike crate, docs, and sweep artifact landed.

The narrow question now has a measured answer:

- conservative STIR candidates do clear the Hegemon release gate
- the best release-safe candidate is `provable_nogrind_k16_stop64_p128`
- it projects the current tx proof from `354081` bytes to `273145` bytes, about `1.30x` smaller
- no release-supported candidate hits a real `2x` total-byte reduction

So the STIR spike is a measured negative result for the current product objective. STIR remains a plausible transparent PCS family, but this exact Hegemon-shaped experiment does not justify a tx-proof backend migration for the `2x` target.

## Context and Orientation

The current tx proof baseline is frozen in [docs/crypto/tx_proof_profile_sweep.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_profile_sweep.json). The critical fields are:

- `total_bytes = 354081`
- `opening_proof_bytes = 349177`
- `non_opening_bytes_floor = 4904`

The current release degree/rate surface comes from code:

- `circuits/transaction-core/src/p3_air.rs` fixes the tx trace at `8192` rows.
- `protocol/versioning/src/lib.rs` and `circuits/transaction-core/src/p3_config.rs` fix the default release tx FRI profile at `log_blowup = 4`.

That means the STIR spike should match:

- starting degree `8192`
- starting rate `2^-4`

The academic STIR prototype is external and explicitly not production-ready. It is useful here because it already exposes both STIR and FRI implementations over the same field/hash environment, which lets Hegemon measure a parameter-matched ratio instead of inventing one.

## Plan of Work

First, create a new standalone crate at `spikes/stir-tx-pcs`. Keep it outside the workspace by giving it its own `[workspace]` section, following the existing `spikes/circle-transaction-shape` pattern. This crate must depend on the STIR prototype by git revision, duplicate the STIR repo’s required `[patch.crates-io]` overrides so the dependency actually builds, and depend on Hegemon’s `transaction-core` and `protocol/versioning` crates so degree/rate are derived from code rather than copied by hand.

Second, define a small Hegemon baseline reader that loads `docs/crypto/tx_proof_profile_sweep.json` and extracts the current total, opening, and non-opening byte counts. The spike must refuse to run if the baseline artifact is missing or malformed, because the whole point is an apples-to-apples comparison against the checked-in tx proof evidence.

Third, define a small candidate sweep. Each candidate must specify:

- `soundness_type` (`Provable` or `Conjecture`)
- `security_level = 128`
- `protocol_security_level`
- `folding_factor`
- `stopping_degree`
- the fixed Hegemon `starting_degree` and `starting_rate`

The sweep must include at least:

- a fully conservative no-grinding provable candidate with `protocol_security_level = 128`
- a smaller provable candidate that requires grinding
- a conjectural paper-like candidate around the prototype defaults

Fourth, for each candidate, run both STIR and the prototype’s FRI control on the same random polynomial over the same Goldilocks-compatible field. Measure:

- proof bytes
- prover wall clock
- verifier wall clock
- prover hash count
- verifier hash count

Then compute:

- `stir_vs_fri_ratio = stir_proof_bytes / fri_proof_bytes`
- `projected_hegemon_opening_bytes = current_hegemon_opening_bytes * stir_vs_fri_ratio`
- `projected_hegemon_total_bytes = current_non_opening_bytes + projected_hegemon_opening_bytes`

Finally, apply the Hegemon release gate:

- `Provable` only
- `protocol_security_level >= 128`
- every derived PoW bit count must be zero

If a candidate fails that gate, the report must mark it unsupported for release even if the proof is small.

## Concrete Steps

Work from the repository root.

1. Build and run the spike crate:

       cargo run --manifest-path spikes/stir-tx-pcs/Cargo.toml --release

2. Write the JSON artifact:

       cargo run --manifest-path spikes/stir-tx-pcs/Cargo.toml --release -- --json > docs/crypto/tx_proof_stir_spike.json

3. Validate the gate logic and formatting:

       cargo test --manifest-path spikes/stir-tx-pcs/Cargo.toml

The expected output is a report that includes both supported and unsupported candidates and that states which, if any, survive the Hegemon release gate.

## Validation and Acceptance

This plan is complete only if all of the following are true.

The spike crate builds and runs on this checkout without editing the main tx AIR or the main tx proving path.

The report derives Hegemon’s starting degree and starting rate from local code and derives the baseline bytes from the checked-in tx proof sweep artifact.

At least one unsupported candidate appears in the report because it relies on conjectural soundness or nonzero PoW bits. This proves the release gate is not cosmetic.

The checked-in note under `docs/crypto/` explains the exact gate and the exact measured result.

## Idempotence and Recovery

The spike crate is additive. Running it does not mutate the main proof system. The JSON artifact can be overwritten safely by rerunning the spike with `--json`.

If the external STIR dependency changes upstream, pinning by git revision keeps the spike reproducible. If a future contributor updates the revision, they must refresh the JSON artifact and the accompanying note in the same change.

## Artifacts and Notes

The first direct run of the STIR prototype at Hegemon’s tx degree/rate already gave one useful calibration point:

    degree = 2^13, stopping_degree = 2^6, rate = 2^-4
    conjectural STIR, protocol security 106, folding factor 16 -> 32306 bytes
    conjectural FRI control, protocol security 106, folding factor 8 -> 37529 bytes

That is only about a `1.16x` STIR/FRI byte win inside the academic prototype, which is far short of the naive `2.46x` optimistic projection. The full Hegemon spike must therefore measure, not assume.

## Interfaces and Dependencies

The spike crate must define a CLI binary that:

- loads `docs/crypto/tx_proof_profile_sweep.json`
- derives the Hegemon starting degree and starting rate from local code
- emits a JSON report with:

    {
      "summary": ...,
      "candidates": [...],
      "best_release_supported_candidate": ...,
      "best_overall_candidate": ...
    }

The report must include, per candidate:

- STIR parameters
- derived repetitions, rates, OOD sample count, and PoW bits
- STIR proof bytes/time/hash counts
- FRI control proof bytes/time/hash counts
- projected Hegemon opening bytes
- projected Hegemon total bytes
- release support flag and reason

Update note at 2026-04-07T04:28Z: created after confirming that the public STIR prototype is a real Rust codebase with Goldilocks support and a usable parameter interface. The remaining work is implementation and evidence, not hypothesis generation.
