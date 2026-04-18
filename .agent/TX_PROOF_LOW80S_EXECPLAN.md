# Transaction Proof Low-80s ExecPlan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

This plan starts from the current shipped SmallWood tx-proof line, not from historical thread memory. The current evidence-backed baseline is:

- exact sampled proof bytes: `87,278`
- structural upper bound: `90,830`
- opening payload bytes: `46,321`
- opened witness bytes: `30,157`
- subset eval bytes: `23,556`
- DECS high coeffs bytes: `14,500`

Those numbers come from:

- `docs/crypto/tx_proof_smallwood_current_size_report.json`
- `docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json`

The current no-grinding `>=128-bit` profile is fixed unless this plan explicitly proves a new one sound:

- `rho = 2`
- `nb_opened_evals = 3`
- `beta = 2`
- `decs_nb_evals = 32768`
- `decs_nb_opened_evals = 23`
- `decs_eta = 3`

This plan exists because the remaining plausible route to the high `70s` / low `80s` is no longer local bridge cleanup. The dead branches are already known:

- packing-factor churn
- planner rewrites around `nb_polys / nb_unstacked_cols / fullrank_cols`
- `nb_opened_evals = 2`
- DECS auth multiproof-only work
- invariant-column compaction
- no-aux inline-merkle deletion
- full auxiliary Poseidon subtrace transport

What remains alive is narrower:

1. revive the semantic adapter only if it stays near the compact helper-aux floor instead of drifting back toward explicit helper rows,
2. redesign the opening/authentication line on the shipped winning statement,
3. combine both only if the combined line actually breaks into the low `80s` instead of creating a more fragile version of the current `87 kB` proof.

## Purpose / Big Picture

After this plan, the repo will have an honest answer to one concrete product question: can Hegemon push the shipped SmallWood tx proof from the current `~87.3 kB` line into the low `80s`, or even high `70s`, while keeping the exact no-grinding `>=128-bit` post-quantum bar?

The answer must not be “maybe.” It must end in one of three states:

1. a semantic-adapter revival that materially beats the shipped line,
2. an opening-layer redesign that materially beats the shipped line,
3. or a combined semantic-plus-opening branch that proves the low-`80s` target is reachable and should become the new default.

The user-visible outcome is:

1. exact proof-size reports tied to the current tree,
2. explicit keep/kill thresholds enforced by tests and notes,
3. and a clean branch decision instead of another round of ambiguous “promising” experiments.

## Progress

- [x] Reconfirmed the current shipped baseline on the current tree. The exact sampled proof is now `87,086` from `smallwood_candidate_proof_size_report_matches_current_release_bytes`, with the same `90,830` structural upper bound from the backend opening-surface report.
- [x] Built the next semantic-adapter revival floor: inline-Merkle transport, skip-initial-MDS grouped Poseidon rows, and zero lane-local helper words in auxiliary. The winning `64x` point projects to `88,994` bytes and proves exactly in the `86,795 .. 86,955` band.
- [x] Revalidated the live opening-layer redesign candidates on the current shipped statement. The shared-row LVCS planner is still a measured negative result at `92,326` projected bytes and `110.62` bits, and the two-opening frontier is still empty.
- [ ] Run a combined branch only if the semantic and opening branches both clear their phase gates.
- [ ] Promote a new shipped default only if the combined promotion criteria in this plan are met.

## Surprises & Discoveries

- Observation: the remaining proof bulk is still concentrated in the opened-value and opening payload surface, not in wrappers.
  Evidence: the current shipped report shows `opening_payload_bytes = 46,321`, `opened_witness_bytes = 30,157`, and `pcs_subset_evals_bytes = 23,556`.

- Observation: semantic LPPC is structurally small but currently loses once helper-row tax comes back.
  Evidence: the semantic identity frontier is `32,712 .. 54,240` bytes, the compact helper-aux floor is `94,728`, and the explicit-helper floor is `102,120`.

- Observation: planner-local width spill is too small to carry the next win.
  Evidence: the backend opening-surface report shows only `384` raw bytes of planner-local spill in opened witness, with `subset_eval_shape_floor_raw_bytes = 23,552` and no invariant-column redundancy left to exploit.

- Observation: the semantic-adapter floor beats the shipped proof exactly, but only barely.
  Evidence: the new `64x` semantic-adapter floor proves exactly in the `86,795 .. 86,955` band against the current shipped `87,086`-byte exact proof, a gain of only `131 .. 291` bytes.

- Observation: structural projection is conservative for the semantic-adapter floor by about `2.0 .. 2.2 kB`.
  Evidence: the `64x` semantic-adapter floor projects to `88,994` bytes but proves exactly in the `86,795 .. 86,955` band.

- Observation: the opening-layer branch is still dead on the current tree.
  Evidence: the shared-row LVCS planner remains at `92,326` projected bytes with a `110.62`-bit soundness floor, and the two-opening frontier remains empty.

## Decision Log

- Decision: this plan uses `87,278` exact and `90,830` structural as the baseline. No older `93k`, `100k`, or `108k` lines are allowed as branch comparison points.
  Rationale: the repo already carries stale historical reports. Branch decisions must be made against the current shipped line only.
  Date/Author: 2026-04-17 / Codex

- Decision: a branch is not “alive” unless it clears an exact byte threshold under the fixed no-grinding `>=128-bit` profile or a newly documented equivalent profile.
  Rationale: projection-only wins and helper-floor fantasies have already wasted enough time.
  Date/Author: 2026-04-17 / Codex

- Decision: semantic-adapter work is gated before opening-layer work is combined with it.
  Rationale: the semantic branch currently has the widest uncertainty band, and the combined branch is only worth the extra complexity if the semantic branch actually lands near the compact helper-aux floor.
  Date/Author: 2026-04-17 / Codex

- Decision: the low-`80s` target is the real bar. High-`80s` alone is not enough to justify a larger architectural branch.
  Rationale: the current shipped line is already `~87.3 kB`. A “win” of `1-2 kB` is not worth reopening the frontend/backend seam unless it compounds into a real product move.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

This section is intentionally blank until work lands. When this plan finishes, it must record:

- whether semantic revival lived or died,
- whether opening-layer redesign lived or died,
- whether a combined branch beat the shipped line enough to promote,
- and the final exact proof-size band with command-backed evidence.

Current partial result:

- Branch A produced one real exact improvement, but only a `291`-byte one, so it fails the material keep bar.
- Branch B remains a negative result on the current backend.
- Branch C is blocked because neither A nor B cleared the promotion gates.

## Context and Orientation

The files that matter are tightly scoped.

`circuits/transaction/src/smallwood_frontend.rs` owns the shipped winning statement geometry and the current default SmallWood candidate path.

`circuits/transaction/src/smallwood_lppc_frontend.rs` is the semantic LPPC branch seam. Any semantic-adapter revival must land here first.

`circuits/transaction/src/smallwood_semantics.rs` owns the nonlinear relation semantics and the helper-row burden. If the semantic branch fails again, the evidence will show up here.

`circuits/transaction/src/smallwood_engine.rs` owns the opening/authentication surface and is the only place where an opening-layer redesign can materially move the current shipped proof bytes.

`circuits/transaction/tests/transaction.rs` must carry the exact proof-size reports, regression gates, and promotion bars for any new branch.

`docs/crypto/tx_proof_smallwood_current_size_report.json` is the current shipped baseline.

`docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json` is the opening-surface budget report.

`docs/crypto/tx_proof_smallwood_lppc_opening_investigation.md` is the historical branch log and must be updated whenever this plan kills or keeps a branch.

The numbers that define the current branch frontier are:

- shipped exact proof: `87,278`
- shipped structural upper bound: `90,830`
- semantic compact helper-aux floor: `94,728`
- semantic explicit-helper floor: `102,120`
- semantic identity frontier: `32,712 .. 54,240`

That means the semantic branch must do better than its last measured helper-floor failure, and the opening branch must move a large part of the `46,321`-byte opening payload if it wants to get into the low `80s`.

## Plan of Work

This work happens in three branches, in order.

### Branch A: Semantic-adapter revival

The goal is not to prove the semantic identity frontier again. That result already exists. The goal is to build a real proving path that keeps the semantic branch close enough to the compact helper-aux floor that it can still matter.

Work should focus on:

- lane-local helper visibility instead of explicit helper rows,
- direct `NativeTxValidityRelation -> LPPC` witness binding,
- refusing any helper reintroduction that drifts toward the explicit-helper floor,
- exact proof reports on real prove/verify, not only projections.

#### Branch A keep/kill thresholds

Phase A1: projection gate

- Keep the branch only if the first honest structural projection is `<= 88,500` bytes.
- Strong keep if the first honest structural projection is `<= 86,500`.
- Kill immediately if the first honest structural projection is `>= 90,000`.

Phase A2: exact prove/verify gate

- Keep the branch only if the first exact proof is `<= 85,500` bytes.
- Strong keep if the first exact proof is `<= 83,500`.
- Stretch keep if the first exact proof is `<= 82,000`.
- Kill immediately if the first exact proof is `>= 88,000`.

Phase A3: helper-tax discipline

- Keep only if the measured exact proof stays at least `4,000` bytes below the compact helper-aux floor, meaning `<= 90,728`.
- Kill if the live branch drifts within `2,000` bytes of the explicit-helper floor, meaning `>= 100,120`.
- Kill if the branch needs full auxiliary Poseidon transport or any side payload previously killed in `tx_proof_smallwood_lppc_opening_investigation.md`.

Branch A final promotion bar

- Promote Branch A by itself only if exact sampled proof bytes are `<= 83,000` and structural upper bound is `<= 86,000`.

### Branch B: Opening-layer redesign on the shipped statement

This branch keeps the current shipped statement semantics and attacks the opened-value surface directly.

The target is not planner churn. The target is:

- lower opening payload bytes,
- lower subset-eval burden,
- or lower opened-witness burden,

without weakening the no-grinding `>=128-bit` bar.

The current opening payload is `46,321` bytes, so the real thresholds are:

- `~82 kB` exact needs about `5.3 kB` total savings
- `~80 kB` exact needs about `7.3 kB`
- `~78 kB` exact needs about `9.3 kB`

Equivalent opening-payload-only cuts, if the rest of the proof stays approximately flat:

- `~82 kB` exact needs about `11.5%` cut in opening payload
- `~80 kB` exact needs about `15.8%`
- `~78 kB` exact needs about `20.0%`

#### Branch B keep/kill thresholds

Phase B1: projection gate

- Keep the branch only if the first honest structural projection is `<= 85,000`.
- Strong keep if the first honest structural projection is `<= 83,500`.
- Kill immediately if the first honest structural projection is `>= 86,500`.

Phase B2: exact prove/verify gate

- Keep the branch only if the first exact proof is `<= 82,000`.
- Strong keep if the first exact proof is `<= 80,500`.
- Stretch keep if the first exact proof is `<= 78,500`.
- Kill immediately if the first exact proof is `>= 84,500`.

Phase B3: payload accountability

- Keep only if opening payload drops by at least `5,000` bytes from the current `46,321`, meaning `<= 41,321`.
- Strong keep if opening payload drops by at least `7,000` bytes, meaning `<= 39,321`.
- Kill after two focused passes if opening payload improvement is `< 2,500` bytes or total exact proof improvement is `< 1,536` bytes.

Branch B final promotion bar

- Promote Branch B by itself only if exact sampled proof bytes are `<= 81,500` and structural upper bound is `<= 84,500`.

### Branch C: Combined semantic + opening branch

This branch exists only if both A and B remain alive.

The combined branch is justified only if it breaks into the actual low-`80s` or high-`70s`. A combined branch that lands at `84-85 kB` is not worth the extra complexity over the current shipped path.

#### Branch C entry gate

Start the combined branch only if:

- Branch A exact proof is `<= 85,500`
- Branch B exact proof is `<= 82,500`
- both branches still satisfy the no-grinding `>=128-bit` rule

#### Branch C keep/kill thresholds

Phase C1: first combined projection

- Keep only if structural upper bound is `<= 84,000`.
- Strong keep if structural upper bound is `<= 82,500`.
- Kill immediately if structural upper bound is `>= 85,500`.

Phase C2: exact prove/verify

- Keep only if exact sampled proof bytes are `<= 82,000`.
- Strong keep if exact sampled proof bytes are `<= 80,000`.
- Stretch keep if exact sampled proof bytes are `<= 78,500`.
- Kill immediately if exact sampled proof bytes are `>= 83,500`.

Phase C3: complexity budget

- Keep only if prove time on the shipped benchmark witness is no worse than `1.5x` the current shipped release runtime.
- Kill if the combined branch is `> 2.0x` slower than the current shipped line and saves `< 4,000` bytes exact.
- Kill if the combined branch requires new auxiliary payload classes or a weaker soundness profile than the shipped no-grinding note.

Branch C final promotion bar

- Promote a combined branch to default only if all of the following are true:
  - exact sampled proof band is `<= 82,000`
  - structural upper bound is `<= 85,000`
  - no-grinding `>=128-bit` soundness remains documented and exact
  - release prove/verify passes on the benchmark witness
  - exact proof-size report is checked into `docs/crypto/`

Strong promotion bar:

- exact sampled band `<= 80,000`
- structural upper bound `<= 83,500`

Stretch promotion bar:

- exact sampled band `<= 78,500`
- structural upper bound `<= 82,000`

## Concrete Steps

Work from the repository root.

1. Reconfirm the current shipped baseline before touching either branch:

       cargo test -p transaction-circuit smallwood_candidate_proof_size_report_matches_current_release_bytes --release -- --ignored --nocapture
       cargo test -p transaction-circuit smallwood_backend_opening_surface_report --release -- --ignored --nocapture

2. Start Branch A in the semantic seam:

       cargo test -p transaction-circuit smallwood_semantic_lppc_ -- --nocapture
       cargo test -p transaction-circuit smallwood_semantic_helper_floor_frontier_exposes_lane_visible_semantic_tax -- --nocapture
       cargo test -p transaction-circuit smallwood_semantic_bridge_lower_bound_frontier_quantifies_current_backend_floor -- --nocapture

   Then add:

       cargo test -p transaction-circuit smallwood_semantic_<new_branch_name>_projection_report -- --nocapture
       cargo test -p transaction-circuit smallwood_semantic_<new_branch_name>_roundtrip_verifies --release -- --ignored --nocapture

3. Start Branch B in the opening/backend seam:

       cargo test -p transaction-circuit smallwood_backend_opening_surface_report --release -- --ignored --nocapture
       cargo test -p transaction-circuit smallwood_candidate_exact_best_projected_profile_matches_projection --release -- --ignored --nocapture

   Then add:

       cargo test -p transaction-circuit smallwood_opening_<new_branch_name>_projection_report -- --nocapture
       cargo test -p transaction-circuit smallwood_opening_<new_branch_name>_roundtrip_verifies --release -- --ignored --nocapture

4. Only if both branches survive, start Branch C:

       cargo test -p transaction-circuit smallwood_combined_<new_branch_name>_projection_report -- --nocapture
       cargo test -p transaction-circuit smallwood_combined_<new_branch_name>_roundtrip_verifies --release -- --ignored --nocapture

5. After every keep/kill decision, update:

       docs/crypto/tx_proof_smallwood_lppc_opening_investigation.md
       docs/crypto/tx_proof_smallwood_current_size_report.json
       .agent/TX_PROOF_SHRINK_ALL_BRANCHES_EXECPLAN.md
       .agent/NEXT_BIG_PROOF_COMPRESSION_BACKEND_REFACTOR_EXECPLAN.md

## Validation and Acceptance

This plan is complete only if one of the following is true:

1. a semantic branch is proven dead by the thresholds above,
2. an opening-layer branch is proven dead by the thresholds above,
3. or a promoted branch lands with exact proof bytes and soundness documented under the promotion bars above.

Every surviving branch must satisfy all of:

- exact prove/verify roundtrip passes,
- exact proof-size report is checked in,
- current shipped no-grinding profile is preserved or a replacement exact note is written,
- malformed/tampered proof regressions remain green,
- the branch is compared against `87,278` exact and `90,830` structural, not historical baselines.

## Idempotence and Recovery

This work is safe to rerun because all branch decisions are file-backed and threshold-backed.

If a semantic or opening branch fails:

- revert the branch-specific arithmetization mode or engine mode,
- keep the checked reports and kill notes,
- do not leave dead experimental defaults in the proving path,
- and preserve the current shipped default line as the rollback-safe baseline.

If multiple branches fail, the repo should still be left with:

- one correct shipped SmallWood line,
- updated reports,
- and explicit documentation that the low-`80s` target was not reached under the current proof family.

## Artifacts and Notes

The required artifacts for this plan are:

- `docs/crypto/tx_proof_smallwood_current_size_report.json`
- `docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json`
- one new JSON report per experimental branch kept long enough to measure
- updates to `docs/crypto/tx_proof_smallwood_lppc_opening_investigation.md`

The required note changes are:

- write exact keep/kill outcomes into this ExecPlan,
- update `DESIGN.md` and `METHODS.md` only after a branch is promoted or definitively killed,
- never update architecture docs for a branch that has only projection wins.

## Interfaces and Dependencies

The following interfaces are expected to move in this plan:

In `circuits/transaction/src/smallwood_lppc_frontend.rs`, any semantic revival branch must expose:

    pub fn semantic_<branch_name>_shape(...) -> ...
    pub fn semantic_<branch_name>_projection_report(...) -> ...

In `circuits/transaction/src/smallwood_engine.rs`, any opening-layer redesign branch must expose:

    pub fn opening_<branch_name>_projection_report(...) -> ...
    pub fn prove_and_verify_<branch_name>(...) -> ...

In `circuits/transaction/tests/transaction.rs`, every branch must own:

    #[test]
    fn <branch_name>_projection_report(...)

    #[test]
    #[ignore]
    fn <branch_name>_roundtrip_verifies(...)

The branch is not real until those surfaces exist and emit exact bytes on the current tree.
