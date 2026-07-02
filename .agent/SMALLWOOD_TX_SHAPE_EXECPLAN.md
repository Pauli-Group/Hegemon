# SmallWood Transaction Shape Spike

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

This plan follows the measured STIR spike and the first SmallWood investigation note. The STIR branch established that a conservative transparent PCS swap against the current AIR does not reach the required `2x` proof-size cut. This document focuses on the next de-risking question: does Hegemon already have a compact transaction-validity witness shape that is small enough to justify a real SmallWood prototype, or is the current tx proof surface fundamentally too large?

## Purpose / Big Picture

After this work, a developer can run one standalone spike command and get a concrete, code-derived answer to the question:

“If Hegemon tries a SmallWood-style transaction proof, should it target the current AIR trace or the compact native tx-validity relation?”

Success is not another paper summary. Success is:

1. the repo contains a standalone spike crate under `spikes/smallwood-tx-shape`,
2. the spike derives the current tx AIR size and the native tx-validity witness size directly from code,
3. the spike emits a JSON report that compares those shapes against SmallWood’s intended witness regime,
4. the docs record the verdict and the exact next prototype target.

## Progress

- [x] (2026-04-07T05:43Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md` before starting the spike.
- [x] (2026-04-07T05:43Z) Re-read `docs/crypto/tx_proof_smallwood_investigation.md` and confirmed the existing caveat: the full tx AIR is much larger than SmallWood’s advertised sweet spot.
- [x] (2026-04-07T05:43Z) Located the compact native tx-validity relation and its witness schema in `circuits/superneo-hegemon/src/lib.rs`.
- [x] (2026-04-07T05:52Z) Created `spikes/smallwood-tx-shape` and made it emit a code-derived JSON fit report.
- [x] (2026-04-07T05:52Z) Checked in `docs/crypto/tx_proof_smallwood_shape_spike.json` and updated the SmallWood investigation and roadmap notes with the spike result.
- [x] (2026-04-07T05:52Z) Validated the spike with `cargo test -p smallwood-tx-shape-spike` and `cargo run -p smallwood-tx-shape-spike --release`.
- [x] (2026-04-07T06:28Z) Extended the spike from simple fit/no-fit reporting into a concrete LPPC frontend recommendation, including official Goldilocks profile extraction, candidate packings, and degree/payload estimates.
- [x] (2026-04-07T07:40Z) Ran a direct official-prototype size probe against a conservative expanded Hegemon-native witness model and checked in the result note.

## Surprises & Discoveries

- Observation: the current `TransactionAirP3` trace is the wrong object to compare to SmallWood’s witness-size regime.
  Evidence: `circuits/transaction-core/src/p3_air.rs` fixes `MIN_TRACE_LENGTH = 8192`, `BASE_TRACE_WIDTH = 104`, and `TRACE_WIDTH = 146`, which implies `851968` witness-side cells or `1196032` full main-trace cells.

- Observation: Hegemon already has a much smaller tx-validity witness shape in the live native backend path.
  Evidence: `circuits/superneo-hegemon/src/lib.rs` defines `NativeTxValidityRelation` with a `WitnessSchema`, and `circuits/superneo-ccs/src/lib.rs` exposes `total_witness_elements()` / `total_witness_bits()` so the exact compact witness size can be derived from code instead of guessed.

- Observation: the official SmallWood prototype expects an LPPC statement with a matrix witness shape, which lines up much better with `NativeTxValidityRelation` than with the current AIR trace.
  Evidence: `/tmp/smallwood-repo/smallwood/lppc/lppc.h` defines `nb_wit_rows` and `packing_factor` as the core witness-shape interface, while `/tmp/smallwood-repo/smallwood/smallwood/smallwood.h` builds proofs from that LPPC shape.

- Observation: the compact native tx-validity relation is not merely “smaller than the AIR”; it lands squarely inside the SmallWood paper’s intended regime after conservative padding.
  Evidence: `docs/crypto/tx_proof_smallwood_shape_spike.json` reports `NativeTxValidityRelation` at `3991` raw witness elements and `4096 = 2^12` padded elements.

- Observation: the public-bridge `TxLeafPublicRelation` is tiny, but it is the wrong replacement target because it still depends on an external STARK receipt.
  Evidence: `docs/crypto/tx_proof_smallwood_shape_spike.json` reports `TxLeafPublicRelation` at `90` raw witness elements and `128 = 2^7` padded elements, while its recommendation field explicitly rejects it as the tx-proof replacement path.

- Observation: all official Goldilocks-oriented SmallWood prototype profiles currently rely on nonzero grinding, so none is directly admissible under Hegemon’s current release posture.
  Evidence: `/tmp/smallwood-repo/capss/f64/anemoi/anemoi-sign-config.c` sets `opening_pow_bits` / `decs_pow_bits` to nonzero values for the `short`, `default`, and `fast` variants, and `docs/crypto/tx_proof_smallwood_shape_spike.json` records all three as `release_supported_under_hegemon_rule = false`.

- Observation: the first realistic Hegemon SmallWood frontend target is a `512 x 8` LPPC witness matrix for `NativeTxValidityRelation`.
  Evidence: `docs/crypto/tx_proof_smallwood_shape_spike.json` reports that the `512 x 8` candidate lands exactly on the padded `4096`-element witness surface, needs only `105` zero-padding elements, keeps witness polynomial degree at `9`, and has a smaller opened-evaluation payload floor than the `1024 x 4` candidate without the degree blow-up of `256 x 16`.

- Observation: once the native witness is conservatively expanded to include the Poseidon2 subtrace, SmallWood still appears capable of a real `3x+` transaction-proof shrink.
  Evidence: `docs/crypto/tx_proof_smallwood_size_probe.md` records a conservative expanded witness of `59671` elements and official-prototype proof sizes from `75128` bytes to `120568` bytes depending on packing and DECS settings, versus the current Hegemon tx proof at `354081` bytes.

## Decision Log

- Decision: the first SmallWood spike will be a shape-fit spike, not an FFI prover integration.
  Rationale: the gating uncertainty is not “can we call the C prototype.” The gating uncertainty is “does Hegemon have a tx-validity witness small enough to justify a real SmallWood frontend.” That question can and should be answered first with code-derived local evidence.
  Date/Author: 2026-04-07 / Codex

- Decision: the spike will compare at least two Hegemon surfaces: the current tx AIR and `NativeTxValidityRelation`.
  Rationale: the product decision depends on proving that the AIR is out-of-regime while the compact native relation is plausibly in-regime. Reporting only one surface would hide the actual architectural fork.
  Date/Author: 2026-04-07 / Codex

- Decision: the spike will treat SmallWood’s intended regime as a witness-size window of `2^6` to `2^16` field elements and will report the next power-of-two padded witness size for each Hegemon surface.
  Rationale: the paper and slides discuss concrete performance in that range, and the official LPPC frontend is matrix-shaped. Padding to a power of two is the right first approximation for “would this relation plausibly land in the intended operating regime.”
  Date/Author: 2026-04-07 / Codex

- Decision: the spike crate will live in the root workspace instead of using its own detached dependency graph.
  Rationale: the detached spike path pulled incompatible/yanked PQ crate updates from crates.io. The workspace already pins the monorepo’s working dependency graph, and this spike’s purpose is shape analysis, not independent dependency curation.
  Date/Author: 2026-04-07 / Codex

- Decision: recommend the `512 x 8` LPPC witness layout as the first SmallWood frontend target.
  Rationale: it matches the current native relation’s padded `4096`-element witness size exactly, keeps the witness polynomial degree moderate (`9`), and gives a cleaner first proving target than the row-heavier `1024 x 4` or degree-heavier `256 x 16` alternatives.
  Date/Author: 2026-04-07 / Codex

- Decision: move the practical SmallWood target from the raw native witness layout to an expanded native-plus-Poseidon subtrace frontend, with aggressive LPPC packing around `64` as the leading structural candidate.
  Rationale: the raw `512 x 8` witness is useful for orientation but understates the real proving witness. The direct prototype size probe shows the expanded witness is the right structural object, and that the best measured point in the probe lands around `75 KB .. 83 KB`.
  Date/Author: 2026-04-07 / Codex

## Outcomes & Retrospective

The spike landed and produced the intended binary product answer:

- `TransactionAirP3`: not a credible SmallWood frontend target
- `NativeTxValidityRelation`: credible next SmallWood prototype target

The exact measured numbers now checked into the repo are:

- `TransactionAirP3` base witness cells: `851968`
- `TransactionAirP3` full trace cells: `1196032`
- `NativeTxValidityRelation`: `3991` raw witness elements, `32787` witness bits, padded to `4096 = 2^12`
- `TxLeafPublicRelation`: `90` raw witness elements, `4935` witness bits, padded to `128 = 2^7`
- recommended LPPC frontend: `512` rows x `8` packed elements, witness polynomial degree `9`, zero padding `105`
- official Goldilocks prototype profiles: all require nonzero grinding and are therefore not direct Hegemon release candidates
- conservative expanded native witness for a semantic SmallWood tx proof: `59671` elements
- best measured prototype points on that expanded witness:
  - `75128` bytes (`short`, packing `64`)
  - `82776` bytes (`default`, packing `64`)
  - `120568` bytes (stronger no-grinding DECS-style point with packing `64`)

So the spike materially changed the SmallWood story. SmallWood is still not a drop-in replacement for the current tx AIR, but the repo now has a code-derived proof that the compact native tx-validity witness already sits in SmallWood’s intended witness regime.

## Context and Orientation

Three parts of the repo matter for this spike.

`circuits/transaction-core/src/p3_air.rs` defines the current transaction AIR. An AIR is the row-by-row algebraic execution trace used by the current STARK prover. This file exposes the exact row and width constants that determine the current proof surface.

`circuits/superneo-hegemon/src/lib.rs` defines Hegemon-specific compact relations used by the native backend. The important one here is `NativeTxValidityRelation`. Unlike the AIR trace, this is a fixed-width witness schema that stores only the direct tx-validity witness material: counts, note fields, Merkle siblings, and ciphertext hashes.

`circuits/superneo-ccs/src/lib.rs` defines `WitnessSchema`, which is a list of named witness fields with bit widths and element counts. It already provides `total_witness_elements()` and `total_witness_bits()`, which lets the spike compute exact sizes without duplicating logic.

The official SmallWood prototype is not part of this repo, but the investigation already inspected it under `/tmp/smallwood-repo`. The relevant interface is LPPC, a matrix-witness statement format with row count and packing factor. That is why the compact native relation is now the interesting target.

## Plan of Work

First, create a new spike crate at `spikes/smallwood-tx-shape` and keep it in the root workspace so it inherits the same pinned dependency graph as the rest of the repo. The crate should depend only on local Hegemon crates that expose the needed shapes: `transaction-core`, `superneo-hegemon`, and `superneo-ccs`.

Second, define a small report generator in that crate. It must derive, from code:

- tx AIR rows, base width, full width, base witness cells, full trace cells,
- `TxLeafPublicRelation` witness elements and bits for comparison,
- `NativeTxValidityRelation` witness elements and bits,
- each relation’s next power-of-two padded witness size,
- whether each surface lands inside the SmallWood witness window `2^6 .. 2^16`.

Third, make the spike emit one JSON artifact under `docs/crypto/`, for example `tx_proof_smallwood_shape_spike.json`. That artifact must include a summary verdict stating which Hegemon surface is a credible next SmallWood target.

Fourth, update `docs/crypto/tx_proof_smallwood_investigation.md` and `docs/crypto/tx_proof_size_reduction_paths.md` with the code-derived result. The note should stop speaking only in terms of “AIR too big” and should explicitly say whether the compact native relation fits the intended regime.

## Concrete Steps

Work from the repository root.

1. Run the spike locally:

       cargo run -p smallwood-tx-shape-spike --release

2. Write the checked-in JSON artifact:

       cargo run -p smallwood-tx-shape-spike --release -- --output docs/crypto/tx_proof_smallwood_shape_spike.json

3. Run the spike tests:

       cargo test -p smallwood-tx-shape-spike

4. Sanity-check the local dependencies still build:

       cargo check -p superneo-hegemon -p superneo-ccs -p transaction-core

The expected result is a JSON report that clearly distinguishes the oversized AIR path from the compact native relation path.

## Validation and Acceptance

This plan is complete only if all of the following are true.

The spike crate builds without editing the current tx prover or AIR logic.

The JSON report derives all sizes from local code and does not hard-code the witness totals by hand.

The report explicitly marks `TransactionAirP3` as out of SmallWood’s intended regime and explicitly states whether `NativeTxValidityRelation` is within that regime after power-of-two padding.

The checked-in note and roadmap doc reflect the spike result, not just the paper claims.

## Idempotence and Recovery

The spike is additive. Running it does not mutate the main transaction proof stack. The JSON artifact can be refreshed safely by rerunning the command above.

If the compact native relation changes later, rerunning the spike will refresh the exact witness totals. That is a feature, not a problem: this spike should track the live relation instead of freezing stale numbers in prose.

## Artifacts and Notes

The first hand-derived estimate already suggests why this spike matters:

    TransactionAirP3 base witness cells: 8192 * 104 = 851968
    TransactionAirP3 full trace cells: 8192 * 146 = 1196032

Those numbers are far outside SmallWood’s advertised `2^6 .. 2^16` witness range.

By contrast, the spike confirmed the compact native relation at:

    NativeTxValidityRelation raw witness elements: 3991
    NativeTxValidityRelation padded witness elements: 4096
    TxLeafPublicRelation raw witness elements: 90
    TxLeafPublicRelation padded witness elements: 128

The code-derived go/no-go answer is now explicit: SmallWood should target `NativeTxValidityRelation`, not the AIR.

## Interfaces and Dependencies

The spike crate must define a CLI binary that:

- imports `transaction_core::p3_air::{BASE_TRACE_WIDTH, TRACE_WIDTH, MIN_TRACE_LENGTH}`,
- imports `superneo_hegemon::{NativeTxValidityRelation, TxLeafPublicRelation}`,
- imports the `superneo_ccs::Relation` trait so it can inspect each relation shape,
- emits a JSON report with a summary and one entry per measured surface.

Each surface entry must include:

- a short label,
- raw witness elements and bits when applicable,
- padded witness elements as the next power of two,
- fit verdict against the SmallWood witness window,
- a brief recommendation field.

Update note at 2026-04-07T07:40Z: the branch is now materially beyond shape-fit analysis. The direct official-prototype size probe shows a realistic `3x .. 4.7x` path if Hegemon implements a SmallWood tx frontend around the expanded native witness plus Poseidon2 subtrace. The next real move is no longer another estimator; it is the semantic frontend implementation.
