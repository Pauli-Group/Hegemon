# Verify the stable-asset membership repair


This is a living ExecPlan maintained under `.agent/PLANS.md`. Its historical filename identifies the counterexample, but its current purpose is a repair regression. The coordinator owns the typed-specification and Rust repairs; this worker owns only this dossier and `formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticCompletenessCounterexample.lean`. No executable relation, shared cache, wallet, runtime, or production-status change is authorized here.

## Purpose / Big Picture


The repaired typed specification must reject the same stable burn that the existing HGV8RP03 packed program already rejects. The example enables stable asset 1001 while listing only native asset 0 and three padding slots. The new `CanonicalCompatibility` requires the enabled stable asset to occur exactly once in the balance-asset list. Its actual count is zero, so no typed witness can make the statement semantically valid.

The independent packed rejection remains unchanged: actual source root 1042 evaluates to 1001, while acceptance requires zero. The combined regression says both targets reject this formerly admitted example. It does not prove universal semantic-to-packed completeness, honest-materializer correctness, cryptographic security, or production authority.

## Progress


- [x] (2026-09-07 19:35Z) Historical pre-repair regression passed: the then-current typed target admitted this exact fixture, while every packed witness was rejected. That positive semantic theorem is superseded by the repaired target and has been removed.
- [x] (2026-09-07 20:23Z) Read the coordinator's repaired `CanonicalCompatibility`: the balance-asset list is now an explicit argument and both mint and burn require `count assetId = 1`.
- [x] (2026-09-07 20:25Z) Replaced the old positive and false-universal-completeness endpoints with typed rejection for every witness, preserving exact fixture arithmetic and actual packed rejection.
- [x] (2026-09-07 20:27Z) Strict command exited zero without warnings against the coordinator-refreshed specification cache; all six axiom printouts passed. Froze the Lean source and released the process slot.

## Surprises & Discoveries


Before the repair, `CanonicalCompatibility` in `formal/lean/Hegemon/Transaction/Poseidon2V8SemanticSpecification.lean` did not require stable-asset membership, while `V8BalanceValid` checked only the assets actually listed. The same omission existed in the Rust typed frontend. The coordinator has now added an exact-once requirement in the typed Lean predicate and in `validate_compatibility_stablecoin` in `circuits/transaction/src/smallwood_poseidon2_v8_types.rs`. The current source must not be described as still having that omission.

The packed check is `base.stable_asset_membership_excluding_padding` in `circuits/transaction/src/smallwood_poseidon2_v8_program.rs`, implemented by `enabled * slot_membership_zero(public, public[59])` in `circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs`. Its generated nonlinear root is 1042. For assets `[0, 4294967294, 4294967294, 4294967294]`, enabled flag 1, and stable asset 1001, its value is `1 * (1001 - 0) * 1 * 1 * 1 = 1001` in the field with modulus 18446744069414584321. The padding value is the external `u64::MAX` sentinel reduced into the field, not field-minus-one. This root is public-only, so no choice of private helpers repairs it.

The exact fixture's hash arithmetic was retained. Monolithic reduction exceeded the 3072 MiB process limit; 32-state tables instead check each of the 31 permutation transitions separately. One initial linear layer, four initial external rounds, 22 internal rounds, and four terminal external rounds compose to the unchanged kernel through `checked_permutation`. The 32 permutations cover 15 action-intent blocks, seven config-tree nodes, and ten before/after state-tree nodes: 992 exact round equalities, not additional assumptions.

A separate historical audit found no-retirement carry helpers incorrectly set to 1 when a mint had `enabled_at = parent_height = 4294967295`. Current `smallwood_poseidon2_v8_relation.rs` now gates those two carries on `retired_at.is_some()` and supplies zero otherwise. This dossier records that source change only. This Lean regression neither proves the complete repaired mint materializer nor treats the old helper issue as a universal no-packed-witness result.

## Decision Log


Decision (2026-09-07, coordinator): repair the typed target to require exact-once stable-asset membership and update this regression to reject the former example. Rationale: preserve the existing packed relation's membership rule instead of weakening it to accept a stable burn without its balance asset.

Decision (2026-09-07, regression worker): remove `burn_canonical_public`, `burn_semantically_valid`, and `semantic_to_packed_completeness_is_false` from the current module. Replace them with rejection against the repaired definitions, not a locally recreated pre-repair target. Rationale: old statements are no longer true of the current specification.

Decision (2026-09-07): retain the explicit 94-word stable witness, unchanged digest literals, and kernel-checked arithmetic. Rationale: demonstrate that the original fixture remains well formed in its other semantic components; the new rejection is specifically missing public membership, not an unrelated hash or malformed-witness failure. No `native_decide` KAT theorem is reused.

Decision (2026-09-07): keep all edits within the two owned files, no shared cache output, one Lean process at 3072 MiB, and at most 20 MiB of owned artifacts. Rationale: preserve the coordinator's concurrent repairs and resource boundary.

## Outcomes & Retrospective


The repair regression is strictly checked. The historical 19:35 positive result applied only before the specification change and is not current evidence of semantic validity. Both typed rejection endpoints use only `propext`; the packed rejection and combined endpoint use only `propext`, `Classical.choice`, and `Quot.sound`. There is no native-reduction axiom or admitted proof.

The checked endpoints are `burn_not_canonical_public`, `burn_not_semantically_valid` for every typed witness, the unchanged `burn_has_no_accepting_packed_witness` for every packed list, and their conjunction `stable_asset_membership_repair_closes_burn`. Their conclusion is closure of this known mismatch only. Universal semantic-to-packed completeness remains a separate proof obligation.

## Context and Orientation


The typed semantic target represents two input slots and two output slots. Inactive slots carry canonical zero openings and public digests. This example has four inactive slots and zero fee, with balance assets `[0, padding, padding, padding]`. It requests a burn of 25 units of stable asset 1001 under policy version 7, at parent height 9000. The stable state moves debt from 1000 to 975 and sequence from 9 to 10, retaining epoch 2 and minted count 100.

The stable witness uses the concrete known-answer configuration values, four tagged siblings 601/701/801/901, and a seven-zero issuer secret and authorization. It is retained as an explicit canonical 94-word list. The complete public statement's action intent is recomputed, not borrowed from the short known-answer fixture tag. Its projection zeros its own seven positions 87 through 93, avoiding a hash cycle. All note and nullifier hash links are inactive, while the required single-key zero accumulators and signer tags remain explicitly checked.

`burn_remaining_semantic_conjuncts_hold` preserves the canonical witness, cryptographic links, listed-slot balances, and exact stable transition as component evidence. It deliberately excludes canonical-public validity. `burn_stable_asset_count_zero` supplies the exact missing-membership fact. The new canonical-public rejection extracts compatibility field 16, follows the burn branch to its exact-once requirement, and derives the contradiction `0 = 1`. Therefore the statement is rejected for every typed witness.

The packed proof remains tied to the actual generated program. Existing `accepted_source_root_zero` makes every named nonlinear root zero under acceptance; `accepted_source_enabled` equates source expression 832 to public word 58. The retained source-node equations compute root 1042 as 1001 without any private-row restriction.

## Plan of Work and Milestones


Milestone one updates the semantic endpoint while preserving the fixture. Prove the stable-asset count is zero, reject `CanonicalPublicStatement` using the repaired exact-once requirement, and lift that rejection to `ExactV8RelationSemanticValid` for every typed witness. Retain the other semantic conjuncts and the exact digest certificates. Acceptance means the new rejection theorem actually references the current imported specification; no local weakened or historical substitute is permitted.

Milestone two preserves universal packed rejection for this fixed statement. Keep `burn_membership_root_value` and `burn_has_no_accepting_packed_witness` tied to source root 1042. Combine semantic and packed rejection into `stable_asset_membership_repair_closes_burn`. Acceptance means a conjunction of two fixed-statement rejection statements, not a quantified claim about all valid transactions.

Milestone three strictly checks the module and audits the principal endpoints. Record exact exit status and axiom dependencies here. The checker must reject any new admitted proof or native-reduction axiom; production authority remains outside this regression.

## Concrete Steps


The coordinator refreshed the repaired specification cache with `lake build Hegemon.Transaction.Poseidon2V8SemanticSpecification` and reported five jobs passed. The worker did not rebuild or write shared caches. The following strict command exited zero at 20:27 UTC. To reproduce it, obtain one process slot and run from `formal/crypto`:

    lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticCompletenessCounterexample.lean

Do not set `LEAN_PATH`, use `-o`, fetch caches, or start another Lean process. The worker's 20-minute budget starts at 20:23 UTC on 2026-09-07; the process must finish or stop by 20:43 UTC. Preserve the checked source and release the process slot after completion.

Inspect the six `#print axioms` outputs at the module end, including the retained intent/component certificates and all principal rejection endpoints. Search the two owned files for trailing whitespace; `git diff --check` alone does not inspect an untracked file. A documentation-only status update after a passing source check does not require another compile.

## Validation and Acceptance


The strict command must exit zero without warnings. The exact asset count must be zero, and the repaired canonical-public predicate must require one. `burn_not_semantically_valid` must quantify over every typed witness, not just the retained one. The actual packed rejection must still quantify over every packed list. The combined theorem must say only that both targets reject this fixed burn.

No endpoint may depend on `ofReduceBool`, an admitted declaration, or a new axiom. Independently calculated Python/JavaScript values are discovery cross-checks, not substitutes for retained kernel-checked arithmetic. Neither the separate retirement carry change nor universal completeness is credited by this module.

## Idempotence and Recovery


The edits are confined to the owned regression and dossier. Retry the strict check only after a local source diagnostic or a relevant dependency change. If imported definitions are stale, ask the coordinator to refresh its cache rather than writing it here. If a resource limit is reached, stop only this worker's process, preserve source and diagnostics, and state which obligations remain unchecked. Do not restore the obsolete positive semantic theorem or weaken the repaired specification to make a check pass.

## Artifacts and Notes


The fixed statement's membership coordinates are public words 54 through 57 for balance assets, 58 for enabled, and 59 for the stable asset. The source public-expression node is `4 + publicIndex`; node 905 is padding. Nodes 1031 through 1041 construct exclusion-aware factors and their product; node 1042 multiplies by enabled node 832. The typed count check and the packed root independently reject this layout.

The preserved exact intent is `[5602556155226632942, 13981622684500300234, 528746874842993661, 15760393224543938935, 9229931284164649943, 7069950181644397773, 8443097740411624375]`. All limbs are nonzero and below the field modulus. Exact before/after roots and all 32 arithmetic traces remain in the Lean source, with total owned text below 0.5 MiB.

The strict command exited zero with no warnings. Its six current axiom printouts, abbreviated only by removing the common namespace prefix, are:

    burn_intent_is_exact: [propext, Quot.sound]
    burn_remaining_semantic_conjuncts_hold: [propext, Quot.sound]
    burn_not_canonical_public: [propext]
    burn_not_semantically_valid: [propext]
    burn_has_no_accepting_packed_witness: [propext, Classical.choice, Quot.sound]
    stable_asset_membership_repair_closes_burn: [propext, Classical.choice, Quot.sound]

## Interfaces and Dependencies


The namespace remains `HegemonCrypto.SmallWood.V8Smz9SemanticCompletenessCounterexample`, and its direct import remains `HegemonCrypto.SmallWoodV8Smz9SemanticBalance`. The principal current endpoint is `stable_asset_membership_repair_closes_burn`, built from `burn_not_semantically_valid` and `burn_has_no_accepting_packed_witness`. Supporting endpoints include `burn_not_canonical_public`, `burn_stable_asset_count_zero`, and `burn_remaining_semantic_conjuncts_hold`. No production module imports this regression.

Revision note (2026-09-07 20:28Z): recast the retained counterexample as a repair regression after the coordinator strengthened the typed membership predicate, then recorded its successful strict check and all six axiom outputs. Removed obsolete current claims of semantic validity and false universal completeness, preserved the exact fixture and executable rejection, and kept separate materializer evidence outside the theorem boundary. No Lean source changed after the passing check.
