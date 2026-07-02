# Transaction Proof Shrink: Try Every Serious Branch

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

This plan starts from the current product reality captured in `DESIGN.md`, `METHODS.md`, `docs/crypto/tx_proof_size_reduction_paths.md`, and `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md`: Hegemon’s active transaction-proof family is the in-repo SmallWood candidate, the shipped line now has a `90830`-byte structural upper bound with checked exact sampled proofs in the `87246 .. 87278` band, the statement is already witness-free, and the easy local waste has already been removed. The remaining work is therefore not “trim a wrapper” work. It is a deliberate campaign to test every serious branch that could still move the proof materially lower while keeping the current transparent, post-quantum, no-grinding `128-bit` release bar.

## Purpose / Big Picture

Make Hegemon’s per-transaction proof materially smaller than the current shipped SmallWood line (`90830`-byte structural upper bound, `87246 .. 87278` checked exact sampled bytes) without weakening the current security rule, without changing wallet-visible transaction semantics, and without introducing a fake benchmark story. After this plan is complete, a developer should be able to check out the repository, run a small set of commands, and see one of two honest outcomes:

Either the repo has a clearly better proof line, with exact measured proof bytes and runtime improvement over the current shipped baseline, or the repo has a checked-in negative result showing that a serious branch was tried, measured, and killed for a concrete reason.

The point is to beat Hegemon’s current proof, not to argue abstractly. Every branch in this plan therefore has explicit keep criteria, kill criteria, and exact commands that must demonstrate whether the branch helped.

## Progress

- [x] (2026-04-16T22:40Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `docs/crypto/tx_proof_size_reduction_paths.md`, `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md`, `docs/crypto/tx_proof_stir_soundness.md`, and `docs/crypto/tx_proof_smallwood_size_probe.md` to ground the plan in the current shipped proof surface and measured prior work.
- [x] (2026-04-16T22:40Z) Drafted this ExecPlan as the single place to coordinate all high-effort tx-proof shrink branches, including geometry reduction, semantic frontend replacement, PCS replacement, and transcript/authentication redesign.
- [x] (2026-04-16T23:12Z) Added an exact current-proof byte budget reporter for the live SmallWood proof in `circuits/transaction/src/smallwood_engine.rs` and `circuits/transaction/src/smallwood_frontend.rs`, exposed it through the public crate surface, and added a release test that emits a machine-readable JSON report from a real proof.
- [x] (2026-04-16T23:12Z) Checked the first real baseline against the live tree and found documentation drift: the current proof is `108028` bytes, not `108012`, and the projection matches the measured release proof exactly. Updated `DESIGN.md`, `METHODS.md`, and `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md` to match reality.
- [x] (2026-04-17T00:31Z) Landed the first real alternate geometry behind the new shape seam: `DirectPacked64CompactBindingsV1` removes the duplicated output ciphertext-hash rows and stablecoin binding rows that the nonlinear semantics already read directly from public values. The experimental compact-binding branch proves and verifies, shrinks the row geometry from `1447` to `1416`, and reduces exact release proof bytes from `108028` to `106900`.
- [x] (2026-04-17T03:20Z) Added an exact no-grinding SmallWood profile sweep over the live bridge and compact-binding statements, checked the machine-readable artifact into `docs/crypto/tx_proof_smallwood_profile_sweep.json`, and promoted the best realistic passing point (`rho = 2`, `nb_opened_evals = 3`, `beta = 2`, `decs_nb_evals = 32768`, `decs_nb_opened_evals = 24`, `decs_eta = 3`). That moved the active release proof from `108028` bytes to `100956`, and moved the compact-binding branch from `106900` to `99828`.
- [x] (2026-04-17T07:32Z) Finished the first real compact-binding packing frontier on the live backend. `DirectPacked16CompactBindingsV1`, `DirectPacked32CompactBindingsV1`, and `DirectPacked128CompactBindingsV1` all prove the same semantics correctly, but all lose on exact bytes. The measured projection frontier is `packed16=157428`, `packed32=110580`, `packed64=99828`, `packed128=119796`, and the `32` and `128` points were also validated with full prove/verify roundtrips as explicit negative results.
- [x] (2026-04-17T09:18Z) Implemented and measured the first real Poseidon-subtrace compression branch on the winning compact64 geometry: `DirectPacked64CompactBindingsSkipInitialMdsV1` removes the stored post-MDS boundary row for each grouped Poseidon permutation while preserving the same effective degree by folding step `0` and step `1` into one nonlinear transition. The exact projection improved from `99828` to `98532`, and a full prove/verify roundtrip confirmed the exact same `98532` bytes.
- [x] (2026-04-17T06:55Z) Promoted `DirectPacked64CompactBindingsSkipInitialMdsV1` to the shipped SmallWood default. `prove_smallwood_candidate`, projected-size helpers, and version-only SmallWood verifier-profile defaults now all resolve to the `98532`-byte line, and the checked current-size report in `docs/crypto/tx_proof_smallwood_current_size_report.json` now matches that exact object.
- [x] (2026-04-17T07:05Z) Re-ran the exact no-grinding profile sweep on the new shipped default by extending `tx_proof_smallwood_profile_sweep` to cover `DirectPacked64CompactBindingsSkipInitialMdsV1`. The sweep came back empty again: the same `32768 / 24 / 3` DECS point is still the smallest realistic passing profile on the new default line.
- [x] (2026-04-17T12:30Z) Finished the deeper backend branch and promoted `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` to the shipped default. The branch moves the Merkle aggregate helper surface off the opened-row witness and into the inner SmallWood proof’s auxiliary witness channel, proves and verifies cleanly at `93156` exact bytes, and beats both the old `98532` shipped line and the `94728` semantic helper-aux floor.
- [x] (2026-04-17T15:35Z) Pushed one level deeper into the backend and compacted DECS auth paths without changing the outer proof type: sibling hashes that are already opened elsewhere in the same batch are omitted and reconstructed during verification. That cut the shipped line from the old `91556` exact/projection coincidence to a `91556` structural upper bound with exact sampled proofs around `87940 .. 88132`, driven almost entirely by shrinking `decs_auth_paths_bytes` from `11232` to about `7616 .. 7808`.
- [x] (2026-04-17T18:35Z) Replaced the nested inner SmallWood bincode proof object with a compact flat wire format that stores one checked shape header per section instead of per-row `Vec` lengths. The shipped line now projects to `90830` bytes and the checked exact sampled release proofs on the current benchmark witness land in the `87246 .. 87278` band, with the kept delta coming mostly from removing wire-format shape overhead from `subset_evals`, `partial_evals`, `masking_evals`, `auth_paths`, and the opened-witness bundle.
- [x] (2026-04-17T19:20Z) Measured the remaining DECS multiproof headroom before attempting another backend rewrite. The live opened set stores `235` compact auth-path sibling nodes but only `219` of those positions are unique, so a perfect shared-node multiproof can save at most `16` digests, or `512` raw bytes before proof flags / format overhead. That is too little to justify a full DECS multiproof branch on the current backend.
- [x] (2026-04-17T07:32Z) Parameterized the current SmallWood frontend and engine so alternative witness geometries, packing factors, and public-binding layouts can be generated and measured without hand-editing constants across multiple files. The live compact-binding frontier now spans `16 / 32 / 64 / 128` packing variants through the same shape-aware entrypoints, and the engine/verifier surface accepts each explicit experimental arithmetization cleanly.
- [x] (2026-04-17T11:05Z) Wrote the current-frontier investigation in `docs/crypto/tx_proof_smallwood_lppc_opening_investigation.md`. That note now pins the next two serious branches to the exact current `98532`-byte proof composition instead of the older structural story: a real semantic `NativeTxValidityRelation -> LPPC` frontend is still the highest-value branch, while a strong `< 80 kB` target likely requires opening-layer work on top of that frontend.
- [x] (2026-04-17T04:57Z) Implemented the new semantic LPPC frontend seam in `circuits/transaction/src/smallwood_lppc_frontend.rs`, materializing the exact `NativeTxValidityRelation` witness order from `TransactionWitness`, binding the native statement/public-input digests, and running the resulting shapes through the current SmallWood structural projection and soundness path. The first checked frontier report is now `1024x4=54240`, `512x8=37776`, and `256x16=32712`, all still clearing the exact current no-grinding `128-bit` structural floor.
- [x] (2026-04-17T05:13Z) Promoted the semantic LPPC seam from “structural projection only” to an exact current-engine opening-layer spike. The new identity-constrained roundtrip on the semantic LPPC witness window now proves and verifies at exactly the same bytes as the structural projection: `1024x4=54240`, `512x8=37776`, and `256x16=32712`. That rules out the current SmallWood opening layer as the primary blocker on this branch.
- [x] (2026-04-17T06:34Z) Measured and killed the “semantic LPPC witness + auxiliary Poseidon subtrace” branch on the current engine. The new checked report in `docs/crypto/tx_proof_smallwood_semantic_lppc_auxiliary_poseidon_spike_report.json` projects `493536`, `477072`, and `472008` bytes for the `1024x4`, `512x8`, and `256x16` shapes once the full current Poseidon subtrace is carried as auxiliary witness. The exact `512x8` attempt also fail-closes with `smallwood piop transcript hash mismatch`, showing that the current auxiliary-witness replay path is not even a clean transport seam for this design.
- [x] (2026-04-17T07:58Z) Measured and effectively killed the “real semantic adapter on the current backend” branch. The new checked report in `docs/crypto/tx_proof_smallwood_semantic_helper_floor_report.json` restores only the lane-visible helper rows that the current nonlinear relation needs back on top of the semantic LPPC witness window and grouped Poseidon trace. The winning `64x` point lands at `102120` projected and exact bytes, above the shipped `98532`-byte default proof, so the current opened-row model no longer has a live path to a winning semantic adapter.
- [x] (2026-04-17T08:55Z) Pushed one level deeper into the backend and found the first live current-engine semantic branch below the shipped line. `docs/crypto/tx_proof_smallwood_semantic_helper_aux_report.json` now measures the exact “compact helper-aux” floor: keep the semantic LPPC witness window and grouped Poseidon rows in-domain, but move the lane-visible helper surface into auxiliary witness instead of explicit opened rows. The winning `64x` point lands at `94728` projected and exact bytes, `3804` bytes below the shipped `98532` proof. This same pass also fixed a real engine bug: auxiliary replay was incorrectly substituting auxiliary words for linear targets during transcript recomputation.
- [ ] Implement and measure the “shrink the current engine” branch: push the live `1447`-row statement down toward the frozen smaller geometry while preserving the current no-grinding `128-bit` floor.
- [x] Implemented and measured the “real semantic LPPC frontend on the current backend” branch far enough to kill it: the pure semantic witness window is dramatically smaller, but the moment the backend regains the lane-visible helper rows the nonlinear relation requires, the branch rises above the shipped bridge baseline.
- [ ] Implement and measure the “new opening layer” branch: attach at least one stronger transparent opening/proximity layer to the current SmallWood statement and measure whether it beats the current proof enough to justify the complexity.
- [ ] Gate the optional field-native transcript/authentication branch on actual byte-budget evidence. If transcript/authentication is not a meaningful share of the proof, kill this branch early and record the evidence.
- [ ] Promote only the best measured branch. Update `DESIGN.md`, `METHODS.md`, and the checked-in crypto notes to reflect the winning line and the killed branches honestly.

## Surprises & Discoveries

- Observation: the current active proof is already much smaller than the older Plonky3 release object, but the remaining structural gap is still real.
  Evidence: `DESIGN.md` and `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md` now record the current release proof at `108028` bytes, while the older release `TransactionAirP3` path was `354081` bytes.

- Observation: the first live size-report pass exposed stale proof-size documentation instead of a projected-vs-real mismatch.
  Evidence: `cargo test -p transaction-circuit smallwood_candidate_proof_size_report_matches_current_release_bytes --release -- --ignored --nocapture` emitted a real proof report with `total_bytes = 108028`, and `cargo test -p transaction-circuit smallwood_candidate_proof_stays_below_shipped_plonky3_baseline -- --nocapture` reported a matching projected size of `108028`.

- Observation: the current proof is no longer large because of an embedded witness blob.
  Evidence: `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md` states that the active statement is witness-free and public, and `circuits/transaction/src/smallwood_frontend.rs` derives the statement from public values plus fixed witness-shape metadata.

- Observation: the current size-reduction story already has one strong negative result.
  Evidence: `docs/crypto/tx_proof_stir_soundness.md` and `docs/crypto/tx_proof_stir_spike.json` show the first conservative STIR branch only projected about `1.30x` total-byte shrink on the older tx proof surface, which is not enough to justify a migration by itself.

- Observation: the repo already contains evidence that a smaller SmallWood-style frontend could still help materially.
  Evidence: `DESIGN.md`, `METHODS.md`, and `docs/crypto/tx_proof_smallwood_size_probe.md` all record a real gap between the live `1447`-row geometry and the smaller target region, with the size probe reporting structural points roughly in the `75 KB .. 121 KB` range.

- Observation: removing obviously duplicated public-binding rows does work, but it is only a marginal win on the current backend.
  Evidence: the new `DirectPacked64CompactBindingsV1` branch drops `31` secret rows and measured `106900` release bytes in `docs/crypto/tx_proof_smallwood_compact_bindings_size_report.json`, only `1128` bytes below the `108028` baseline.

- Observation: the live no-grinding profile was not locally optimal even after the earlier hardening passes.
  Evidence: `docs/crypto/tx_proof_smallwood_profile_sweep.json` shows the previous `16384 / 29 / 3` DECS point is beaten by the checked realistic `32768 / 24 / 3` point on both the live bridge and the compact-binding branch; the promoted bridge proof is now `100956` bytes and the compact-binding branch is now `99828`.

- Observation: widening or narrowing the current grouped-row compact-binding packing does not buy bytes on the live backend.
  Evidence: the compact-binding geometry frontier now measures `packed16=157428`, `packed32=110580`, `packed64=99828`, and `packed128=119796` projected bytes on the same semantics, and the `packed32` / `packed128` points also passed full prove/verify roundtrips while still losing to `packed64`. The current row-polynomial PCS still prefers the `64`-lane point.

- Observation: one pure-linear Poseidon boundary row per grouped permutation was still dead weight.
  Evidence: `DirectPacked64CompactBindingsSkipInitialMdsV1` keeps the same compact64 packing and the same semantics, but removes the stored post-MDS boundary row and replays step `0` plus step `1` as one transition in the nonlinear check. The shape drops from `1416` rows / `90624` expanded witness cells to `1380` rows / `88320` cells, and the exact proof drops from `99828` to `98532`.

- Observation: promoting the `98532`-byte line changed the shipped baseline, but it did not uncover a smaller no-grinding backend profile.
  Evidence: the refreshed `docs/crypto/tx_proof_smallwood_profile_sweep.json` now includes `DirectPacked64CompactBindingsSkipInitialMdsV1` and still reports the active `rho = 2`, `nb_opened_evals = 3`, `beta = 2`, `decs_nb_evals = 32768`, `decs_nb_opened_evals = 24`, `decs_eta = 3` point as the smallest realistic passing profile for the bridge baseline, the old compact64 branch, and the new shipped default.

- Observation: on the current engine, frontend shrink is only attacking part of the proof surface.
  Evidence: the exact current and compact-binding size reports show `transcript_bytes`, `commitment_bytes`, `opened_values_bytes`, `pcs_subset_evals_bytes`, and `decs_auth_paths_bytes` are unchanged across the bridge-to-compact shrink. The measured win lands almost entirely in `opened_witness_bytes` and `decs_high_coeffs_bytes`. This means the current bridge-side frontier is close to exhausted, and a strong sub-`80 kB` line likely needs opening-layer work in addition to a real semantic LPPC frontend.

- Observation: the semantic LPPC branch is still credible, but the raw `4096`-element witness fit is not the whole proving story.
  Evidence: `docs/crypto/tx_proof_smallwood_lppc_opening_investigation.md` ties the raw `NativeTxValidityRelation` witness window (`3991` elements padded to `4096`) back to the conservative structural size probe and the exact current proof report. The note shows that `< 95 kB` only needs about an `11%` shrink in the current opening payload, `< 90 kB` needs about `20%`, and `< 80 kB` needs about `38%`. That keeps the semantic LPPC branch squarely worth implementing while making it explicit that a strong sub-`80 kB` target probably needs opening-layer help too.

- Observation: the new semantic LPPC structural frontier is materially stronger than the earlier conservative investigation suggested.
  Evidence: `docs/crypto/tx_proof_smallwood_semantic_lppc_frontier_report.json` now records real current-tree structural projections over the exact native tx-validity witness order: `1024x4=54240`, `512x8=37776`, and `256x16=32712`, all with the current no-grinding `128-bit` structural floor still met. This shifts the main open risk from “is the opening layer too fat?” to “how much row-local proving baggage returns when the semantic frontend becomes truly provable on the live backend?”

- Observation: the current SmallWood opening layer preserves the semantic LPPC witness window exactly once the statement is reduced to identity form.
  Evidence: `docs/crypto/tx_proof_smallwood_semantic_lppc_identity_spike_report.json` records exact current-engine prove/verify roundtrips over the full semantic LPPC witness window with identity constraints, and every measured point matches the structural projection exactly: `1024x4=54240`, `512x8=37776`, `256x16=32712`. That eliminates “the opening layer eats the win” as the first-order explanation for the current gap.

- Observation: the auxiliary-witness path is not a viable way to carry the current Poseidon subtrace into the semantic LPPC branch.
  Evidence: `docs/crypto/tx_proof_smallwood_semantic_lppc_auxiliary_poseidon_spike_report.json` shows that simply attaching the full current Poseidon subtrace as auxiliary witness would balloon the structural semantic LPPC proof to `472008 .. 493536` bytes. The exact `512x8` attempt also fail-closes with `smallwood piop transcript hash mismatch`, which means the current auxiliary-witness replay path is not a drop-in transport seam for this branch even before the byte explosion is considered.

- Observation: the current backend no longer has a live semantic-adapter path once the nonlinear relation pays the helper-row tax it actually needs.
  Evidence: `docs/crypto/tx_proof_smallwood_semantic_helper_floor_report.json` restores only the lane-visible helper rows required by the current nonlinear model on top of the semantic LPPC witness window and grouped Poseidon trace. The best `64x` point is `102120` bytes, above the shipped `98532`-byte default proof, and the exact identity spike matches that number exactly.

- Observation: the backend still has a live semantic-adapter path if the helper surface moves through auxiliary instead of explicit opened rows.
  Evidence: `docs/crypto/tx_proof_smallwood_semantic_helper_aux_report.json` records the exact compact helper-aux floor. The winning `64x` point lands at `94728` projected and exact bytes, below the shipped `98532` proof and well below the explicit helper-row floor of `102120`.

- Observation: the old auxiliary-poseidon fail-closed result was caused by an engine bug, not by a sound transport rejection.
  Evidence: fixing `effective_linear_targets(...)` in `circuits/transaction/src/smallwood_engine.rs` so transcript replay keeps real linear targets made the exact auxiliary-poseidon spike roundtrip cleanly at its projected `477072` bytes. The branch is still dead, but now for the honest reason: bytes, not verifier breakage.

## Decision Log

- Decision: treat `108028` bytes as the baseline to beat, not the old `354081`-byte Plonky3 proof.
  Rationale: the user’s goal is to beat Hegemon’s current best line, not to keep re-beating an obsolete baseline.
  Date/Author: 2026-04-16 / Codex

- Decision: keep the current no-grinding `128-bit` post-quantum release bar fixed for every serious branch in this plan.
  Rationale: lowering the bar would produce fake wins and make the comparison meaningless. The point is to improve the proof object honestly.
  Date/Author: 2026-04-16 / Codex

- Decision: run the branches in this order: current-geometry shrink, semantic frontend replacement, opening-layer replacement, then optional transcript/authentication redesign.
  Rationale: this order follows the repo’s existing evidence. The most credible branch with the least new security surface is shrinking the current geometry. The next most credible branch is a real semantic LPPC frontend. Opening-layer replacement is higher risk and should only be pursued after the frontend work is honestly measured. Transcript/authentication redesign should be evidence-driven, not cargo cult.
  Date/Author: 2026-04-16 / Codex

- Decision: every branch must have a hard keep threshold and a hard kill threshold.
  Rationale: the user asked to try everything, not to let half-proven branches linger forever. A branch that does not hit a material threshold should die and leave behind a measured negative result.
  Date/Author: 2026-04-16 / Codex

## Outcomes & Retrospective

The first milestone is landed, and the second milestone now has both a real alternate geometry frontier on the shipped row-aligned bridge and a real semantic LPPC seam with exact current-engine backend numbers. The repo has an exact current-proof size reporter, a checked real shipped baseline of `98532` bytes, a machine-readable realistic profile sweep, two measured geometry improvements on top of the current row-aligned bridge, a semantic LPPC structural frontier report tied to the exact native tx-validity witness order, an exact current-engine identity spike report over that same witness window, a checked auxiliary-subtrace kill report, a checked explicit helper-floor loss report, and now a checked compact helper-aux win report for the current backend. `DirectPacked64CompactBindingsV1` proves and verifies cleanly at `99828` bytes, and the stronger `DirectPacked64CompactBindingsSkipInitialMdsV1` line proves and verifies cleanly at `98532` bytes and is now the shipped default. The profile sweep came back clean again: no smaller realistic passing point was found than the active `32768 / 24 / 3` DECS line, even after refreshing the sweep on the new default branch. The packing frontier also came back clean: `16`, `32`, and `128` lane compact-binding variants are explicit negative results, and the new Poseidon-subtrace compression only buys another `1296` bytes over the previous compact64 winner. The semantic LPPC seam changed the decision first by proving the structural frontier is `1024x4=54240`, `512x8=37776`, and `256x16=32712`, then by proving the current opening layer reproduces those exact bytes on identity spikes, then by proving that explicit helper rows lose (`102120` at the `64x` point), and finally by proving that compact helper transport through auxiliary can still beat the shipped line (`94728` exact at `64x`). That moves the next serious branch again. The current backend semantic-adapter story is no longer dead in general. It is now conditional: the next real branch is to build a real semantic adapter that stays close to the `94728` compact helper-aux floor instead of regressing toward the `102120` explicit helper-row floor. If that fails, only then does the work move cleanly to a deeper opened-row/backend redesign or a direct attack on the opening/authentication surface of the shipped winning statement.

## Context and Orientation

The current active per-transaction proof is the `SmallwoodCandidate` path. In this repository, a “transaction proof” means the proof bytes that show one native private payment is valid. Those proof bytes are then wrapped into a native `tx_leaf` artifact and eventually aggregated at the block layer, but this plan is about the standalone per-transaction proof object itself.

The key files today are:

`circuits/transaction/src/smallwood_frontend.rs` builds the public SmallWood statement and the live packed witness material. This file is where the live proof shape is defined. It currently exposes the active statement geometry and the exact no-grinding profile constants.

`circuits/transaction/src/smallwood_semantics.rs` contains the actual transaction-validity relation. In plain language, this is the code that enforces note commitments, nullifiers, Merkle authentication, spend authorization binding, selector routing, and balance equations. Any branch that claims to preserve semantics must still satisfy this relation.

`circuits/transaction/src/smallwood_engine.rs` is the Rust SmallWood prover/verifier engine. In plain language, this is the code that commits to the witness-shape polynomials, recomputes the transcript, answers opening challenges, and verifies the algebraic equalities. Any branch that changes the opening layer or authentication path will touch this file.

`circuits/transaction/src/smallwood_native.rs` is the bridge from the frontend statement to the native transaction-proof APIs. It is the right place to add projected-size reporting and shape-parameterized proof construction without polluting the higher-level wallet or node interfaces.

`circuits/transaction/src/proof.rs` is the transaction-proof wrapper that higher layers use. This file matters because any serious proof replacement must remain dispatchable through the existing backend seam and must keep the public `tx_leaf` path working.

`docs/crypto/tx_proof_smallwood_no_grinding_soundness.md` is the exact note for the current shipped proof. It records the current statement shape:

- `public_value_count = 78`
- `raw_witness_len = 295`
- `poseidon_permutation_count = 143`
- `poseidon_state_row_count = 4576`
- `expanded_witness_len = 92608`
- `lppc_row_count = 1447`
- `lppc_packing_factor = 64`
- `effective_constraint_degree = 8`

It also records the current no-grinding profile:

- `rho = 2`
- `nb_opened_evals = 3`
- `beta = 2`
- `decs_nb_evals = 32768`
- `decs_nb_opened_evals = 24`
- `decs_eta = 3`
- zero grinding bits

The important current constraints are:

1. The active proof is already witness-free, so wrapper trimming is not the main lever.
2. The current proof already reflects many low-level optimizations, so the remaining work is structural.
3. The repo still records a smaller target region. `DESIGN.md`, `METHODS.md`, and `docs/crypto/tx_proof_smallwood_size_probe.md` all make clear that the live `1447`-row object is not the only plausible geometry.
4. The user-visible semantics must not change. Wallets, nodes, and the native `tx_leaf` product path still need to prove the same private payment validity statement.

Two phrases need plain-language definitions because they matter for this plan.

A “polynomial commitment scheme”, abbreviated PCS, is the proof layer that lets the prover commit to many polynomials and later prove what those polynomials evaluate to at challenge points. In this repository, that layer is currently responsible for most of the serialized bytes.

“DECS” is the evaluation-authentication subsystem inside the current SmallWood engine. In plain language, it is the part that expands evaluations over a larger domain and authenticates the opened rows. The current size and runtime profile depends heavily on its parameters `decs_nb_evals`, `decs_nb_opened_evals`, and `decs_eta`.

The current baseline to beat is:

- exact current shipped line: structural upper bound `90830`, checked exact sampled proofs `87246 .. 87278`
- exact current release target: no-grinding `128-bit` floor
- exact current tx-proof wrapper target: keep the same backend seam and same `tx_leaf` product behavior

The three target bands for this plan are:

- acceptable win: below `95000` bytes and not materially slower
- strong win: below `80000` bytes and still within the current release discipline
- stretch win: below `65000` bytes with acceptable runtime and verifier cost

Nothing in this plan is considered a real success if it lowers the security bar, breaks the native `tx_leaf` path, or only helps a synthetic benchmark that no product code uses.

## Plan of Work

The work begins by making the current shipped line impossible to hand-wave away. The repository already has good historical notes, but it still lacks one machine-readable byte budget for the exact current SmallWood proof object. The first step therefore adds a proof report that splits the live proof bytes into the exact serialized sections that matter today: wrapper, commitments, opened values, opening/authentication payload, transcript-related payload, and any remaining fixed overhead. The purpose is not to admire the current proof. The purpose is to decide which later branches are even worth trying.

Once that current-proof report exists, the work splits into two serious frontend branches.

The first frontend branch keeps the current SmallWood engine and shrinks the live statement geometry. The current engine is already proving a real semantic witness-free statement. The missing question is whether the live `1447`-row object can be pushed materially downward without breaking the exact no-grinding floor. That means parameterizing the frontend shape instead of freezing constants across `smallwood_frontend.rs`, moving bridge/public-binding rows around deliberately, compressing or fusing dedicated secret rows where semantics permit it, and re-measuring the exact proof after every geometry step. This branch is the lowest-risk way to buy bytes because it does not add a new proof system or a new security model.

The second frontend branch stops trying to make the current row-aligned bridge perfect and instead builds the real semantic LPPC frontend that the size probes were implicitly asking for. In plain language, LPPC here means the packed witness layout that SmallWood likes for small-instance proofs: a compact witness polynomial layout chosen to minimize opening payload rather than to mirror the current row-local bridge. The repo already contains structural evidence that a smaller packed witness target could land in roughly the `75 KB .. 121 KB` region. The purpose of this branch is to replace the live bridge geometry with a real `NativeTxValidityRelation` frontend on that smaller target and then find out whether the structural win survives the real semantics.

Only after those two frontend branches are honestly measured does the plan move to the opening layer. The opening layer branch asks a narrower question than the older STIR discussion: not “does STIR beat old Plonky3 AIR,” but “can a stronger transparent opening/proximity layer beat the current SmallWood opening layer on this exact witness-free statement enough to matter?” The answer may still be no. That is acceptable. The branch exists because the current proof is still mostly opening/authentication bytes, and because a frontend shrink alone may not be enough to reach the best target band.

The optional final branch is the transcript/authentication redesign. This branch only activates if the new current-proof byte report shows that transcript and authentication machinery are still a meaningful share of the object after the higher-value branches are tried. If the proof report shows that the remaining size is overwhelmingly in unavoidable opening payload, this branch dies early and the plan records the negative result.

The plan ends by promoting exactly one winner, if there is one, and deleting or quarantining the losers. No branch is allowed to linger as an “almost shipped” story.

## Milestones

### Milestone 1: Make the current proof auditable

At the end of this milestone, a novice can run one command and get a JSON report for the exact current SmallWood proof object, not a historical note. The report must name each serialized section and its byte count. Add the reporting code in `circuits/transaction/src/smallwood_frontend.rs`, `circuits/transaction/src/smallwood_native.rs`, and any supporting proof-wrapper file needed to expose this structure. Add a focused test in `circuits/transaction/tests/transaction.rs` that generates a live proof, emits the section report, and asserts that the section totals sum back to the exact proof bytes.

This milestone also adds one checked-in artifact under `docs/crypto/` or `.agent/benchmarks/` with the exact current report and the exact command used to generate it. The report is the basis for every later go/no-go decision.

Acceptance is simple: run the report command, confirm that it prints the active checked-in sampled total and a nontrivial section breakdown, and confirm that the new test passes.

### Milestone 2: Shrink the current SmallWood geometry before changing proof systems

At the end of this milestone, the repository can generate at least three alternative frontends from the same semantics and measure them honestly:

- the current live `1447`-row geometry,
- one intermediate reduced geometry,
- one geometry at or near the frozen smaller target.

Implement this by parameterizing the frontend shape in `circuits/transaction/src/smallwood_frontend.rs` and keeping the semantic kernel in `circuits/transaction/src/smallwood_semantics.rs` fixed. The parameterization must cover at least the row count, packing factor, public-binding row layout, and any fixed Poseidon2 subtrace grouping that materially affects proof size.

Every candidate geometry must be run through:

- projected proof size,
- actual proof generation,
- actual verification,
- exact no-grinding soundness recomputation recorded in a checked-in note or JSON report.

The keep threshold for a local geometry change is a real product threshold:

- keep if proof bytes improve by at least `10%` and prove time does not regress by more than `15%`, or
- keep if proof bytes improve by at least `20%` even if runtime is roughly flat.

Kill the geometry branch if all serious candidates fail those thresholds or if the exact no-grinding floor cannot be kept at `128` bits.

### Milestone 3: Build the real semantic LPPC frontend

At the end of this milestone, the repo has a second full semantic SmallWood frontend that is not the current row-aligned bridge. This is the high-effort branch that tests whether the checked-in structural size probe can survive contact with the actual transaction-validity semantics.

The implementation belongs in a new frontend module under `circuits/transaction/src/`, with a name that makes the distinction obvious, for example `smallwood_lppc_frontend.rs`. It must prove the same `NativeTxValidityRelation` semantics and dispatch through the same backend seam in `circuits/transaction/src/proof.rs`. It must not bypass the semantic kernel with a synthetic witness. The core design requirement is that the packed witness shape follows the smaller LPPC target instead of the live bridge geometry.

This milestone is not complete when the code compiles. It is complete only when the branch produces:

- a real projected proof size,
- a real passing prove/verify roundtrip,
- a soundness note or report under the same no-grinding `128-bit` rule,
- and an exact comparison against the best result from Milestone 2.

The keep threshold for this branch is higher because the effort is much higher:

- keep if actual proof bytes land below `85000`, or
- keep if proof bytes improve by at least `20%` over the best Milestone 2 line and runtime is still operationally acceptable.

Kill the branch if the real semantics destroy the structural win and it cannot beat the best geometry-only line.

### Milestone 4: Attack the opening layer on the winning statement, not on a dead baseline

At the end of this milestone, the repository has measured at least one serious alternate transparent opening/proximity layer against the best surviving statement from Milestones 2 and 3. This is not the old STIR-on-Plonky3 experiment repeated blindly. It is a new experiment on the actual current winning statement.

Build the spike under `spikes/` so it does not destabilize product code. The spike must consume the exact same witness-free public statement and report:

- total proof bytes,
- opening/authentication bytes,
- prove time,
- verify time,
- exact security gate result under the no-grinding `128-bit` rule.

If the branch requires a new engine module, keep it isolated until the spike proves it is worth integrating.

The keep threshold is strict:

- keep only if the alternate opening layer improves total proof bytes by at least `15%` over the best current statement while preserving the security rule and keeping verify time within a sane multiple of the current verifier.

Kill the branch if it cannot clear that threshold. The repository already has one negative STIR result. This milestone is only worth keeping if it beats the current SmallWood line materially, not if it merely reproduces “about the same.”

### Milestone 5: Only if warranted, replace byte-oriented transcript/authentication machinery

At the end of this milestone, either the repo has a measured smaller transcript/authentication line, or it has a short checked-in note saying this branch was not worth running because the byte-budget report proved it was not material.

This milestone starts only if Milestone 1 and the later proof reports show that transcript/authentication machinery is still a meaningful slice of the proof after the higher-value branches. If activated, the likely code surfaces are `circuits/transaction/src/smallwood_engine.rs` and any helper modules that own transcript encoding and authentication hashing. The work may include field-native transcript serialization, field-native authentication trees, or a simpler proof encoding if and only if the branch produces a measurable size win on the exact winning statement.

The keep threshold is:

- keep only if the branch cuts at least `5%` off total proof bytes or produces a very clear runtime win on top of an already smaller proof.

Otherwise kill it and record the evidence.

### Milestone 6: Promote the winner, update docs, and freeze the losers honestly

At the end of this milestone, there is one clearly best tx-proof line. The best line becomes the default shipped narrative in `DESIGN.md`, `METHODS.md`, and the checked-in crypto notes. Every losing branch remains either isolated in `spikes/` with a short negative-result note or is deleted entirely.

This milestone updates:

- `DESIGN.md`
- `METHODS.md`
- `docs/crypto/tx_proof_size_reduction_paths.md`
- the winning branch’s exact soundness note
- benchmark artifacts under `docs/crypto/` or `.agent/benchmarks/`

Acceptance is not “docs updated.” Acceptance is that a novice can run the commands in this plan, produce the winning proof, and see the exact new bytes and runtime against the old `108028`-byte baseline.

## Concrete Steps

Work from the repository root.

To confirm the current baseline before touching code, run:

    cargo test -p transaction-circuit smallwood_candidate_roundtrip_verifies --release -- --ignored --nocapture

Expect the output to include the current proof size line at or near `108028` bytes. If the output has drifted, update this ExecPlan’s baseline first before proceeding.

To add the current-proof report in Milestone 1, add a test and a command shaped like:

    cargo test -p transaction-circuit smallwood_candidate_proof_size_report --release -- --ignored --nocapture

The expected output must include a machine-readable summary with a total equal to the exact generated proof size and named sections that sum back to that total.

To measure candidate frontends in Milestones 2 and 3, add explicit ignored tests or a small benchmark driver in `circuits/transaction` that can be run one candidate at a time. The commands should remain simple:

    cargo test -p transaction-circuit smallwood_candidate_geometry_frontier --release -- --ignored --nocapture
    cargo test -p transaction-circuit smallwood_candidate_lppc_frontier --release -- --ignored --nocapture

The expected output for each candidate must include:

- candidate name,
- exact proof bytes,
- exact prove time,
- exact verify time,
- and whether the candidate clears the current `128-bit` no-grinding gate.

To run the opening-layer spike in Milestone 4, use a separate spike crate under `spikes/` and a command shaped like:

    cargo run --manifest-path spikes/<new-spike>/Cargo.toml --release -- --json > /tmp/<new-spike>.json

The JSON must include the same four outputs: bytes, prove time, verify time, and gate result.

After any branch that survives, run the product-path sanity commands:

    cargo check -p transaction-circuit -p superneo-hegemon -p pallet-shielded-pool -p consensus -p hegemon-node
    cargo test -p transaction-circuit --release -- --nocapture
    cargo test -p superneo-hegemon native_tx_leaf_artifact_accepts_smallwood_candidate_backend --release -- --ignored --nocapture

If a branch touches the shipped default or benchmark story, also run:

    ./scripts/check-core.sh test

The exact command names may expand as the milestones add dedicated tests, but the commands above must remain the reproducible entrypoints a novice can follow.

## Validation and Acceptance

This plan succeeds only if all of the following are true.

The repo can prove and verify the same native transaction-validity statement as before. Wallet-visible private payment semantics do not change. The public `tx_leaf` path still works.

At least one serious branch is either kept or killed on measured evidence. There must be no hand-wavy “promising” branch left without exact bytes and exact runtime.

Any branch that is kept must satisfy the branch-specific keep threshold in this plan. The final promoted branch must beat the current `108028`-byte baseline materially under the same no-grinding `128-bit` rule.

The exact current best line must be documented in `DESIGN.md`, `METHODS.md`, and the checked-in crypto notes with exact proof bytes, exact security profile, and exact command(s) used to reproduce the result.

The final acceptance demonstration is:

1. run the old-baseline report command and confirm the historical `108028`-byte line;
2. run the winning-branch report command and confirm the new smaller proof;
3. run the product-path tests and confirm the proof still verifies through the native artifact path.

## Idempotence and Recovery

This plan is intentionally additive until the final promotion milestone. New frontends belong in separate modules, and new opening-layer experiments belong under `spikes/`. The current shipped line must remain intact until one branch has clearly won.

If a prototype stalls or fails halfway, leave behind:

- one checked-in note or JSON report,
- one short `Decision Log` entry here,
- and either a quarantined spike or a clean revert.

Do not let half-integrated branches leak into the product path. If a branch needs environment flags or custom profile switches to run, keep those isolated to tests or spikes until promotion.

## Artifacts and Notes

The current hard numbers this plan starts from are:

    active SmallWood proof bytes: structural upper bound 90830, checked exact sampled bytes 87246..87278
    active statement shape: raw_witness_len=295, lppc_row_count=1447, expanded_witness_len=92608
    active no-grinding profile: rho=2, nb_opened_evals=3, beta=2, decs_nb_evals=32768, decs_nb_opened_evals=23, decs_eta=3

The current stretch region this plan is chasing is:

    acceptable: < 95000 bytes
    strong:     < 80000 bytes
    stretch:    < 65000 bytes

The current already-measured reference points are:

    older Plonky3 release proof: 354081 bytes
    conservative STIR result on the old tx surface: about 273145 bytes projected
    structural SmallWood probe region: about 75128 .. 120568 bytes

Those numbers are the reason the plan prioritizes frontend/geometry work before more speculative PCS changes.

## Interfaces and Dependencies

At the end of Milestone 1, the repository must have one stable reporting interface for the live proof shape. In `circuits/transaction/src/smallwood_native.rs` or a sibling module, define:

    pub struct SmallwoodCandidateProofSizeReport {
        pub total_bytes: usize,
        pub wrapper_bytes: usize,
        pub commitment_bytes: usize,
        pub opened_values_bytes: usize,
        pub opening_payload_bytes: usize,
        pub transcript_bytes: usize,
        pub other_bytes: usize,
    }

    pub fn report_smallwood_candidate_proof_size(
        proof_bytes: &[u8],
    ) -> Result<SmallwoodCandidateProofSizeReport, TransactionCircuitError>

At the end of Milestone 2, the current frontend must be parameterizable by an explicit shape object instead of hidden constants scattered across multiple modules. In `circuits/transaction/src/smallwood_frontend.rs`, define a stable shape descriptor:

    pub struct SmallwoodFrontendShape {
        pub lppc_row_count: usize,
        pub lppc_packing_factor: usize,
        pub public_binding_mode: SmallwoodPublicBindingMode,
        pub poseidon_layout: SmallwoodPoseidonLayout,
    }

and expose one function that builds a statement from that shape:

    pub fn build_smallwood_candidate_statement_with_shape(
        witness: &TransactionWitness,
        public_inputs: &TransactionPublicInputs,
        shape: &SmallwoodFrontendShape,
        arithmetization: SmallwoodArithmetization,
    ) -> Result<SmallwoodConstraintAdapter, TransactionCircuitError>

At the end of Milestone 3, the semantic LPPC branch must exist behind the same backend seam instead of bypassing it. The winning shape must still feed the existing verification path in:

    crate::proof::verify_transaction_proof_bytes_for_backend

At the end of Milestone 4, any alternate opening-layer spike must emit a machine-readable report with:

    total_proof_bytes
    opening_payload_bytes
    prover_ms
    verifier_ms
    clears_release_gate

Any branch that cannot report those values is not mature enough to compare honestly.

Revision note: created on 2026-04-16 to consolidate every serious tx-proof shrink branch after the live SmallWood line reached `108028` bytes. Updated on 2026-04-16 after the first live proof-size report landed and exposed a stale `108012` documentation baseline. Updated again on 2026-04-17 after the first real alternate geometry, `DirectPacked64CompactBindingsV1`, landed and measured `106900` release bytes. Updated again on 2026-04-17 after the exact no-grinding profile sweep promoted the `32768 / 24 / 3` DECS point, moving the active bridge proof to `100956` bytes and the compact-binding branch to `99828`. Updated again on 2026-04-17 after `DirectPacked64CompactBindingsSkipInitialMdsV1` was promoted to the shipped default at `98532` bytes and the refreshed profile sweep showed no smaller realistic passing backend profile on that new default. Updated again on 2026-04-17 after the deeper backend pass found the compact helper-aux floor at `94728` exact bytes and fixed the auxiliary replay bug that had been hiding the exact current-engine behavior. Updated again on 2026-04-17 after the inline-Merkle auxiliary-helper branch proved and verified cleanly at `93156` bytes, replacing the `98532` line as the shipped default and pushing the old `94728` helper-aux floor back above the active shipped proof. Updated again on 2026-04-17 after the DECS auth-path compaction pass cut the shipped line to a `91556`-byte structural upper bound with exact sampled proofs around `88 kB`. Updated again on 2026-04-17 after the compact inner proof wire-format rewrite cut the shipped line to a `90830`-byte structural upper bound and the `87246 .. 87278` exact sampled band. The reason for this plan remains the same: the remaining work is structural and multi-branch; a single “optimize more” thread is no longer precise enough.
