# Next Big SmallWood Backend Compression Refactor

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the shipped SmallWood transaction proof should move materially below the current `~87.25 kB` exact band without weakening the current no-grinding `>=128-bit` post-quantum security floor. The goal is not another cosmetic `1-2%` trim. The goal is one more real backend step that changes the shipped economics of a private payment. Success is visible by running the existing release proof-size reporter and seeing the checked exact sampled proof band drop enough to justify another default promotion.

Today the shipped line is already much smaller than the old bridge baselines, but the easy wins are gone. The next improvement has to come from the proof backend itself: fewer authenticated openings, fewer bytes per opening, or a tighter authentication format. This plan defines the branches worth trying, the measurements required to keep them, and the kill criteria for dead directions.

## Progress

- [x] (2026-04-17T22:35Z) Wrote the next-step backend compression ExecPlan after the hostile import/persistence/cache sweep came back clear on audited critical/high issues.
- [x] (2026-04-18T00:27Z) Implemented the shipped-line backend opening-surface report in `smallwood_engine.rs` / `smallwood_frontend.rs`, added the release test `smallwood_backend_opening_surface_report`, and checked in `docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json`.
- [x] (2026-04-18T01:08Z) Prototyped the obvious `128x` inline-merkle geometry extension, verified it satisfies constraints, and killed it as a negative result after the frontier report landed at `112807` projected bytes versus the shipped `90830`.
- [x] (2026-04-18T01:54Z) Prototyped the direct opened-value attack by removing inline-merkle auxiliary words from the shipped `64x` line. Killed it after the projected `89294` bytes failed the live witness constraints; the helper aggregates are not row-local on the current poseidon trace, so the apparent win was fake headroom.
- [x] (2026-04-18T02:18Z) Extended the backend opening-surface report with invariant-column diagnostics for `opened_witness`, `subset_evals`, and `partial_evals`, regenerated the checked JSON artifact, and confirmed there is zero live repetition to exploit on the benchmark proof.
- [x] (2026-04-18T03:38Z) Ran the explicit `nb_opened_evals = 2` no-grinding frontier on the shipped inline-Merkle line and killed it. The frontier is empty: no `>=128-bit` candidate exists in the scanned realistic grid.
- [x] (2026-04-18T03:49Z) Extended the backend opening-surface report with planner-floor accounting (`row-scalar` floor, width spill, and subset-eval shape identity), regenerated the checked JSON artifact, and confirmed the current planner has only `384` raw opened-witness bytes of local width-spill headroom while `subset_evals` is fixed by `beta * packing_factor`.
- [x] (2026-04-18T04:18Z) Added an LVCS planner projection report and spiked the one plausible deeper row-opening rewrite, `SharedPackingRowsProjectionV1`. Killed it after the checked report showed it projects larger (`92326` vs `90830`) and drops the soundness floor to `110.62` bits.
- [ ] Prototype Branch A: opened-row set reduction on the shipped `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` line without changing statement semantics.
- [ ] Prototype Branch B: authentication-surface rewrite for DECS openings on the shipped line, keeping the same verified relation and no-grinding profile.
- [ ] Prototype Branch C: compact helper-aux semantic adapter revival only if Branch A or B proves the backend can carry it below the current shipped line.
- [ ] Promote the best winning branch only if it clears the materiality bar in `Validation and Acceptance`.
- [ ] Record final exact sampled proof band, profile, and rejection reasons for all killed branches in `DESIGN.md`, `METHODS.md`, and the checked JSON reports.

## Surprises & Discoveries

- Observation: the semantic LPPC frontier is structurally far smaller than the shipped bridge line, but once lane-visible helper rows come back as explicit opened rows the current backend loses that advantage.
  Evidence: [docs/crypto/tx_proof_smallwood_semantic_helper_floor_report.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_semantic_helper_floor_report.json) lands at `102120` bytes, above the shipped exact band.

- Observation: the current backend already captured the first meaningful semantic-helper win by moving helper surface into auxiliary witness inside the shipped bridge statement.
  Evidence: [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md) records the shipped `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` line at a `90830`-byte structural upper bound with exact sampled proofs in the `87246 .. 87278` band.

- Observation: a full DECS multiproof rewrite is not the next honest win on the current opened set.
  Evidence: [docs/crypto/tx_proof_smallwood_lppc_opening_investigation.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_lppc_opening_investigation.md) records only `16` duplicate sibling nodes remaining, which is at most `512` raw digest bytes before overhead.

- Observation: on the current shipped `23`-leaf opening set, authentication bytes are not the dominant term anymore.
  Evidence: [docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json) records `opened_witness_bytes = 30157`, `pcs_subset_evals_bytes = 23556`, and only `decs_auth_paths_bytes = 7545`.

- Observation: the remaining auth-path overlap ceiling is even smaller on the active shipped profile than the earlier `24`-leaf diagnostic suggested.
  Evidence: the new shipped-line backend report records `decs_total_auth_nodes = 235`, `decs_unique_auth_nodes = 228`, and only `7` duplicate auth nodes, which is `224` raw digest bytes before overhead.

- Observation: the shipped backend geometry leaves almost no room for a backend-only “opened-row reduction” without changing row/polynomial geometry upstream.
  Evidence: the same report records `opened_row_count = 3`, `opened_row_width = nb_polys = 1192`, `nb_unstacked_cols = 1208`, `pcs_partial_eval_width = 16`, and `pcs_subset_eval_width = 128`. On the active profile those widths are structural consequences of the current frontend geometry, not free backend knobs.

- Observation: the obvious “just increase packing again” variant is dead even for the inline-merkle shipped family.
  Evidence: the frontier test now records `DirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1` at a `112807`-byte structural projection, well above the shipped `90830`-byte point and only narrowly better than the already-killed explicit `128x` branch at `119047`.

- Observation: the obvious “drop the inline-merkle auxiliary words” branch is a projection trap, not a real backend win.
  Evidence: the no-aux variant projected to `89294` bytes in the geometry frontier, but the live witness self-check failed immediately with `smallwood packed witness poly constraint failed at lane 0, constraint 70`. The current helper aggregates depend on witness-level merkle path structure and are not reconstructible row-locally from the existing inline poseidon trace.

- Observation: the live opened-value payload has no column-wise redundancy to compress away with a simple “store repeated openings once” scheme.
  Evidence: the checked backend report now records `opened_witness_invariant_column_count = 0`, `pcs_subset_invariant_column_count = 0`, and `pcs_partial_invariant_column_count = 0` on the benchmark proof, so the current randomizing/opening machinery destroys the intuitive row-level repetition.

- Observation: reducing the shipped line to `nb_opened_evals = 2` is not a viable local backend win under the current no-grinding `>=128-bit` bar.
  Evidence: the explicit frontier scan in `smallwood_candidate_two_opening_eval_profile_frontier_is_empty` is empty across the realistic grid (`rho in {2,3}`, `beta in {1,2,3,4}`, `decs_nb_evals in {8192,16384,32768}`, `decs_nb_opened_evals in [18,28]`, `decs_eta in {2,3,4}`).

- Observation: the current planner has almost no local headroom left in `opened_witness`, and none in `subset_evals`, before any deeper LVCS geometry rewrite.
  Evidence: the refreshed backend report now records `opened_witness_row_scalar_floor_raw_bytes = 28608`, only `opened_witness_partial_extra_slot_count = 16` for `opened_witness_partial_raw_bytes = 384`, and `subset_eval_shape_floor_raw_bytes = 23552` with `subset_eval_shape_matches_beta_packing_identity = true`, so `subset_evals` is pinned by `decs_nb_opened_evals * beta * packing_factor`.

- Observation: the obvious deeper LVCS row-opening rewrite, sharing packing rows across `beta`, is not a viable next branch on the current backend.
  Evidence: the checked planner report in `docs/crypto/tx_proof_smallwood_lvcs_planner_projection_report.json` projects `SharedPackingRowsProjectionV1` at `92326` bytes versus the current `90830`, and its soundness floor drops to `110.62` bits because `n_cols` jumps from `604` to `1157`.

## Decision Log

- Decision: treat the next backend push as an opening/authentication refactor, not another frontend packing project.
  Rationale: the row/packing frontier, semantic helper floor, and multiproof headroom are already measured. The remaining live pressure is in opened-row count and authentication bytes, not in obvious bridge-local duplication.
  Date/Author: 2026-04-17 / Codex

- Decision: keep the current no-grinding profile and `>=128-bit` security floor fixed across all candidate branches.
  Rationale: shaving proof bytes by relaxing query counts or adding grinding would make the comparison dishonest and would not be acceptable for the shipped lane.
  Date/Author: 2026-04-17 / Codex

- Decision: require exact sampled release proof measurements for every serious branch before promotion.
  Rationale: the shipped line already exhibits a gap between structural upper bound and exact sampled proofs. Structural projection alone is not enough for promotion decisions anymore.
  Date/Author: 2026-04-17 / Codex

- Decision: Branch A is now the first real backend branch, and Branch B is demoted unless Branch A stalls quickly.
  Rationale: the shipped opening-surface report shows the dominant live pressure is opened witness plus subset-eval payload, not DECS auth paths. Chasing authentication bytes first is the wrong order on the measured backend.
  Date/Author: 2026-04-18 / Codex

- Decision: kill the `128x` inline-merkle geometry branch.
  Rationale: it compiles, satisfies constraints, and measures cleanly, but the structural projection is `112807` bytes. That is materially worse than the shipped `64x` inline-merkle winner, so it is not a serious candidate for promotion or deeper exact benchmarking.
  Date/Author: 2026-04-18 / Codex

- Decision: kill the no-aux inline-merkle branch.
  Rationale: the projected `89294` bytes would have beaten the shipped `90830` structural upper bound by roughly `1536` bytes, but the branch does not satisfy the current live constraints. The inline-merkle helper aggregates are not row-local on the current poseidon trace, so dropping auxiliary transport without a deeper trace redesign is unsound.
  Date/Author: 2026-04-18 / Codex

- Decision: kill the invariant-column compaction branch before implementation.
  Rationale: the live backend report shows zero invariant columns in `opened_witness`, `subset_evals`, and `partial_evals` on the benchmark proof. There is no real repetition left to exploit with a compact “repeat once” wire mode, so the branch has no headroom.
  Date/Author: 2026-04-18 / Codex

- Decision: kill the `nb_opened_evals = 2` profile branch on the shipped inline-Merkle line.
  Rationale: the scanned realistic no-grinding frontier is empty at the `>=128-bit` bar, so there is no honest two-opening backend point to promote or even benchmark exactly.
  Date/Author: 2026-04-18 / Codex

- Decision: stop treating `fullrank_cols` / `nb_unstacked_cols` local surgery as a serious backend branch on the current planner.
  Rationale: the refreshed backend report shows that `subset_evals` width is fixed by `beta * packing_factor`, while the entire local width spill in `opened_witness` is only `16` slots (`384` raw bytes). Any meaningful next win requires a deeper LVCS row-opening geometry rewrite, not another local planner tweak.
  Date/Author: 2026-04-18 / Codex

- Decision: kill `SharedPackingRowsProjectionV1` before any prover/verifier implementation work.
  Rationale: even the optimistic geometry projector makes it larger than the shipped planner and pushes the no-grinding soundness floor well below `128` bits. It is not a credible path to a keep-worthy backend refactor.
  Date/Author: 2026-04-18 / Codex

## Outcomes & Retrospective

The measurement seam is in place and the planner branches are now more constrained than they first looked. The active shipped line is still dominated by opened witness plus subset-eval payload, not by DECS auth paths. Those widths are now quantified: the current planner can only save `384` raw bytes in opened witness before hitting the one-scalar-per-poly floor, and `subset_evals` is fixed by `beta * packing_factor` under the current LVCS row planner. The first plausible deeper rewrite, sharing packing rows across `beta`, is also dead: it raises `n_cols` enough to lose both bytes and soundness. That means the next honest work is no longer “planner rewrite around `nb_polys / nb_unstacked_cols / fullrank_cols`”. It is a different backend commitment/opening geometry altogether, or another frontend/backend co-design branch that changes the committed/opened object shape more radically than the current row-oriented LVCS permits.

## Context and Orientation

The active transaction-proof backend lives in [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs). This file owns the actual proof object layout, opening/authentication bytes, transcript handling, serialization, and verification. The shipped arithmetization selection lives in [circuits/transaction/src/smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs). The current semantic LPPC experiments live in [circuits/transaction/src/smallwood_lppc_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_lppc_frontend.rs). Release-size and profile reports are checked into `docs/crypto/`.

The current shipped default is the `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` line. The exact current baseline, from [docs/crypto/tx_proof_smallwood_current_size_report.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_current_size_report.json), is:

    structural_upper_bound_bytes = 90830
    exact_sampled_release_bytes = 87246 .. 87278
    transcript_bytes = small relative term
    opening/authentication bytes = dominant term

The current profile, from [docs/crypto/tx_proof_smallwood_profile_sweep.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_profile_sweep.json), is:

    rho = 2
    nb_opened_evals = 3
    beta = 2
    decs_nb_evals = 32768
    decs_nb_opened_evals = 23
    decs_eta = 3
    grinding_bits = 0

Important terms in this plan:

- “Opened row” means one row of the low-degree proof system that is explicitly revealed at verifier-chosen positions so the verifier can check constraints.
- “Authentication bytes” means the sibling hashes or equivalent proof material used to convince the verifier that the opened rows actually came from the committed trace.
- “Semantic LPPC” means the smaller witness window derived directly from the native transaction-validity relation rather than the older bridge-shaped witness. It is attractive structurally, but it only wins if the backend can carry its helper information cheaply.
- “Material” means big enough to justify a shipped default change. For this repo, that means at least several kilobytes or several percentage points, not `200-500` bytes.

## Plan of Work

The work proceeds in three backend branches, in order of expected value.

First, add a more explicit measurement seam in [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs). The current JSON reports are enough to tell whether a branch wins overall, but they are not yet specific enough to compare “fewer opened rows” against “same rows, cheaper authentication.” Add per-branch reporting for:

- total opened row count
- distinct authenticated positions
- bytes spent on each authenticated section
- overlap between opened sets before and after compaction
- exact sampled release bytes on the benchmark witness

The new report writer should live next to the existing size-report helpers and should feed a new checked JSON artifact in `docs/crypto/`.

Second, prototype Branch A inside [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs): reduce the shipped opened-row set without changing the statement meaning. This is not a semantic LPPC rewrite. This is a direct attack on the opened-row schedule for the winning shipped line. The edits should focus on the row-opening planner and verifier replay path, not on `smallwood_frontend.rs`. The branch is successful only if it reduces exact sampled release bytes by reducing authenticated openings while preserving current verifier behavior and the no-grinding profile.

Third, prototype Branch B in the same engine file: rewrite the DECS authentication surface for the same opened rows. The previously measured full multiproof is not worth it, but there is still room for a more compact per-opening representation if it avoids the dead weight of the current format. This branch should reuse the existing commitment tree and verification semantics; the goal is a smaller representation, not a new cryptosystem. If this branch yields less than about `1.5 kB` exact savings, it should be killed quickly.

Fourth, only if Branch A or B proves that the backend can carry helper surface more cheaply, revive Branch C in [circuits/transaction/src/smallwood_lppc_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_lppc_frontend.rs): the compact helper-aux semantic adapter. The target here is not the dead explicit-helper floor (`102120`). The target is the already measured compact helper-aux floor around `94728` projected/exact bytes, and then pushing it below the current shipped exact band. If the revived semantic branch cannot beat the shipped exact band after the backend improvement, it is killed and recorded as such.

Throughout all three branches, keep [circuits/transaction/tests/transaction.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/tests/transaction.rs) as the main proving/verification regression surface. Every kept branch needs:

- exact sampled proof-size report
- release prove/verify roundtrip
- malformed-proof fail-closed regression if the wire format changes
- profile-digest consistency regression if the arithmetization or proof layout changes

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Start by refreshing the current baseline:

    cargo test -p transaction-circuit smallwood_candidate_proof_size_report_matches_current_release_bytes --release -- --ignored --nocapture

Expected result:

    test ... ok
    written docs/crypto/tx_proof_smallwood_current_size_report.json

Then add the deeper backend report and run it:

    cargo test -p transaction-circuit smallwood_backend_opening_surface_report --release -- --ignored --nocapture

Expected result:

    test ... ok
    written docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json

For Branch A, add an exact prove/verify regression and run:

    cargo test -p transaction-circuit smallwood_candidate_<branch_a_name>_roundtrip_verifies --release -- --ignored --nocapture

For Branch B, run the matching report and roundtrip:

    cargo test -p transaction-circuit smallwood_candidate_<branch_b_name>_proof_size_report_beats_current_release_bytes --release -- --ignored --nocapture
    cargo test -p transaction-circuit smallwood_candidate_<branch_b_name>_roundtrip_verifies --release -- --ignored --nocapture

If Branch C becomes justified, run:

    cargo test -p transaction-circuit smallwood_semantic_<branch_c_name>_exact_report_matches_projection --release -- --ignored --nocapture
    cargo test -p transaction-circuit smallwood_semantic_<branch_c_name>_roundtrip_verifies --release -- --ignored --nocapture

At each kept stopping point, run:

    cargo check -p transaction-circuit -p block-recursion -p consensus
    git diff --check -- circuits/transaction/src/smallwood_engine.rs circuits/transaction/src/smallwood_frontend.rs circuits/transaction/src/smallwood_lppc_frontend.rs circuits/transaction/tests/transaction.rs DESIGN.md METHODS.md docs/crypto .agent/NEXT_BIG_PROOF_COMPRESSION_BACKEND_REFACTOR_EXECPLAN.md

## Validation and Acceptance

The refactor is only worth shipping if it clears the following bars.

Minimum keep bar for a local branch:

- exact sampled release bytes improve by at least `1536` bytes, or by at least `1.75%`, on the checked benchmark witness
- prove/verify still succeeds on the existing release regression surface
- no-grinding `>=128-bit` security floor remains unchanged

Material promotion bar for a new shipped default:

- structural upper bound at or below `89 kB`
- exact sampled release band at or below `84 kB`
- no regression on existing malformed-proof fail-closed tests

Stretch target for this whole plan:

- exact sampled release band in the `78 .. 82 kB` region

Kill conditions:

- any branch that saves less than `1 kB` exact bytes after two focused passes
- any branch that only wins by relaxing the current profile or adding grinding
- any authentication rewrite whose theoretical max headroom is below `1 kB`
- any semantic branch that still lands above the current shipped exact band after backend improvements

## Idempotence and Recovery

All report-generation commands are safe to rerun. They overwrite checked JSON artifacts with current measurements. If a branch fails midway, revert only that branch’s local edits and keep the report and ExecPlan updated with the negative result. Do not leave the repo in a state where the current shipped default is ambiguous. The shipped default remains `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` until a new branch clears the promotion bar and all regressions are green.

## Artifacts and Notes

Important current evidence:

    shipped exact sampled band: 87246 .. 87278
    shipped structural upper bound: 90830
    semantic explicit-helper floor: 102120
    semantic compact helper-aux floor: 94728
    remaining full multiproof headroom: at most 512 raw digest bytes before overhead

Expected next outcomes:

    Branch A likely gain: 2 kB .. 5 kB exact
    Branch B likely gain: 1.5 kB .. 4 kB exact
    Branch C conditional gain after backend improvement: 4 kB .. 10 kB exact

The ranges above are aggressive but still plausible given the current measured floors. Anything better than `~10 kB` from one branch should be treated as surprising and documented with exact evidence.

## Interfaces and Dependencies

The implementation should stay inside the existing SmallWood backend and test surface.

In [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs), maintain or add helper interfaces shaped like:

    pub struct SmallwoodBackendOpeningSurfaceReport { ... }
    pub fn smallwood_backend_opening_surface_report(...) -> SmallwoodBackendOpeningSurfaceReport

    pub fn encode_smallwood_inner_proof_compact(...)
    pub fn decode_smallwood_inner_proof_compact(...)

If a new branch needs a distinct arithmetization tag, add it in [circuits/transaction/src/smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs) and bind it into the version/profile digest path the same way the current shipped line is bound today.

If a semantic branch is revived, keep its seam explicit in [circuits/transaction/src/smallwood_lppc_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_lppc_frontend.rs). Do not fold it invisibly into the shipped frontend until it wins on exact sampled bytes and passes release roundtrips.

Revision note: created on 2026-04-17 after the shipped SmallWood line reached a `90830`-byte structural upper bound with exact sampled release proofs in the `87246 .. 87278` byte band and the adjacent hostile security sweep came back clear on audited critical/high issues. The purpose of this plan is to redirect effort from broad security sweeps back to the next serious proof-economics frontier while preserving the hard-won current security bar.
