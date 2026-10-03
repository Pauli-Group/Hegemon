import SmzaRp04RawRoleSamplingQ38
import Q38Rp05PostFinalCompiler
import SmzaQ38DistinctCollector
import Mathlib.Data.List.Dedup

/-!
# The actual RP05 collector and the counted q38 decoder

The source collector stops after the first 38 distinct accepted indices;
the counted decoder takes 38 from reverse/dedup/reverse. Their equality is
proved below, including rejected candidates, duplicates and exhaustion.
This is a pure source-algorithm bridge, not a Rust-to-quantum-execution
refinement or a bound on adaptively reached quantum states.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05Q38ExecutionCountBridge

open SmzaRp04RawRoleSampling
open SmzaQ38McaSourceBinding
open V8Smz9RuntimeRandomness
open SmzaQ38DistinctCollector
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9HiddenPatch

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000
set_option maxHeartbeats 1500000


theorem accepted_bound_is_source_literal :
    q38AcceptedFactorBound = (goldilocksModulus / 8388608) * 8388608 := by
  exact q38_accepted_factor_bound_eq_source

private theorem candidate_index_is_source_literal (candidate : IdealFieldCoin) :
    q38CandidateIndex candidate =
      if candidate.val < (goldilocksModulus / 8388608) * 8388608 then
        some (⟨candidate.val % 8388608, Nat.mod_lt _ (by decide)⟩ : Position)
      else none := by
  unfold q38CandidateIndex
  rw [accepted_bound_is_source_literal]
  rfl

theorem source_collector_is_filtered_collector
    (candidates : List IdealFieldCoin) (selected : List Position) :
    Q38Rp05PostFinalCompiler.collectIndices candidates selected =
      collectDistinct 38 (candidates.filterMap q38CandidateIndex) selected := by
  induction candidates generalizing selected with
  | nil => rfl
  | cons candidate rest ih =>
      erw [Q38Rp05PostFinalCompiler.collectIndices]
      by_cases full : selected.length = 38
      · erw [if_pos full]
        exact (collectDistinct_full 38 _ selected full).symm
      · erw [if_neg full]
        by_cases accepted :
            candidate.val < (goldilocksModulus / 8388608) * 8388608
        · have decoded : q38CandidateIndex candidate = some
              (⟨candidate.val % 8388608, Nat.mod_lt _ (by decide)⟩ : Position) := by
            erw [candidate_index_is_source_literal, if_pos accepted]
          erw [if_pos accepted, List.filterMap_cons_some decoded]
          unfold collectDistinct
          erw [if_neg full]
          split
          · rename_i duplicate
            erw [if_pos duplicate]
            exact ih selected
          · rename_i fresh
            erw [if_neg fresh]
            exact ih _
        · have decoded : q38CandidateIndex candidate = none := by
            erw [candidate_index_is_source_literal, if_neg accepted]
          erw [if_neg accepted, List.filterMap_cons_none decoded]
          exact ih selected

/-- The actual insertion-order collector equals the counted first-distinct
decoder, including rejection, duplicates, and exhaustion. -/
theorem source_collector_eq_counted_first_distinct (candidates : List IdealFieldCoin) :
    Q38Rp05PostFinalCompiler.collectIndices candidates [] =
      q38FirstDistinctIndices candidates := by
  erw [source_collector_is_filtered_collector, collectDistinct_empty]
  rfl

theorem source_sorted_support_eq_counted_support (candidates : List IdealFieldCoin) :
    (Q38Rp05PostFinalCompiler.sortedIndices candidates).toFinset =
      q38SelectedIndexSet candidates := by
  unfold Q38Rp05PostFinalCompiler.sortedIndices
  have same := List.mergeSort_perm
    (Q38Rp05PostFinalCompiler.collectIndices candidates [])
    (fun left right => decide (left.val ≤ right.val))
  rw [List.toFinset_eq_of_perm _ _ same, source_collector_eq_counted_first_distinct]
  rfl

private theorem ofFn_get_cast {α : Type*} (items : List α) (count : Nat)
    (lengthEq : items.length = count) :
    List.ofFn (fun index : Fin count => items.get (index.cast lengthEq.symm)) =
      items := by
  subst count
  simp

/-- Forget only the serialization order, retaining the actual source targets. -/
def targetSupport {points : Fin 6 → Goldilocks}
    (targets : Q38Rp05PostFinalCompiler.IndexedTargets points) : Finset Position :=
  (List.ofFn targets.val).toFinset

theorem sampled_targets_support (points : Fin 6 → Goldilocks)
    (pointsDistinct : Function.Injective points) (candidates : List IdealFieldCoin) :
    (Q38Rp05PostFinalCompiler.sampledTargets points pointsDistinct candidates).map
        targetSupport =
      if (Q38Rp05PostFinalCompiler.sortedIndices candidates).length = 38 then
        some (Q38Rp05PostFinalCompiler.sortedIndices candidates).toFinset
      else none := by
  unfold Q38Rp05PostFinalCompiler.sampledTargets
  dsimp only
  split_ifs with enough
  · simp only [Option.map_some, targetSupport]
    rw [ofFn_get_cast _ 38 enough]
    rfl
  · rfl

/-- Exact source sampler/counting decoder equality on every fifty-word stream.
Rejection, duplicates and fewer than 38 distinct outputs remain in the equation. -/
theorem sampled_targets_support_eq_counted_decoder (points : Fin 6 → Goldilocks)
    (pointsDistinct : Function.Injective points) (stream : Q38CandidateStream) :
    (Q38Rp05PostFinalCompiler.sampledTargets points pointsDistinct
      (q38StreamCandidates stream)).map targetSupport =
        (q38Decoder stream).map Subtype.val := by
  rw [sampled_targets_support]
  have lengthEq :
      (Q38Rp05PostFinalCompiler.sortedIndices (q38StreamCandidates stream)).length =
        (q38SelectedIndexSet (q38StreamCandidates stream)).card := by
    rw [← source_sorted_support_eq_counted_support]
    exact (List.toFinset_card_of_nodup
      (Q38Rp05PostFinalCompiler.sorted_indices_nodup _)).symm
  rw [lengthEq, source_sorted_support_eq_counted_support]
  dsimp only [q38Decoder]
  simp only [q38OpeningCount]
  split_ifs <;> rfl

/-- The exact successful-support event used by the checked fiber count. -/
theorem sampled_targets_support_event (points : Fin 6 → Goldilocks)
    (pointsDistinct : Function.Injective points) (stream : Q38CandidateStream)
    (query : Query) :
    (Q38Rp05PostFinalCompiler.sampledTargets points pointsDistinct
      (q38StreamCandidates stream)).map targetSupport = some query.val ↔
        q38Decoder stream = some query := by
  rw [sampled_targets_support_eq_counted_decoder]
  cases decoded : q38Decoder stream with
  | none => simp
  | some output => simp [Subtype.ext_iff]

/-- The checked exact fiber symmetry now applies to actual sorted source
target supports, without a selector-equivalence hypothesis. -/
theorem source_target_support_fibers_nat_card_equal (points : Fin 6 → Goldilocks)
    (pointsDistinct : Function.Injective points) (left right : Query) :
    Nat.card {stream : Q38CandidateStream //
      (Q38Rp05PostFinalCompiler.sampledTargets points pointsDistinct
        (q38StreamCandidates stream)).map targetSupport = some left.val} =
    Nat.card {stream : Q38CandidateStream //
      (Q38Rp05PostFinalCompiler.sampledTargets points pointsDistinct
        (q38StreamCandidates stream)).map targetSupport = some right.val} := by
  calc
    _ = Nat.card (SuccessfulFiber q38Decoder left) :=
      Nat.card_congr (Equiv.subtypeEquivRight fun stream =>
        sampled_targets_support_event points pointsDistinct stream left)
    _ = Nat.card (SuccessfulFiber q38Decoder right) :=
      q38_decoder_fibers_nat_card_equal left right
    _ = _ := Nat.card_congr (Equiv.subtypeEquivRight fun stream =>
      (sampled_targets_support_event points pointsDistinct stream right).symm)

/-- The source's pending-failure check is retained explicitly. In particular,
`none` cannot be treated as selector failure: its poison words can select 38
distinct targets. This equation excludes that path through the actual flag. -/
theorem failure_checked_support_event (points : Fin 6 → Goldilocks)
    (pointsDistinct : Function.Injective points) (pending : Bool)
    (sampled : Option Q38CandidateStream)
    (query : Query) :
    (V8Smz9HonestOpeningSchedule.sourcePendingFailure pending
        (sampled.map q38StreamCandidates) = false ∧
      (Q38Rp05PostFinalCompiler.sampledTargets points pointsDistinct
        (V8Smz9HonestOpeningSchedule.sourceReturnedWords 50
          (sampled.map q38StreamCandidates))).map targetSupport = some query.val) ↔
      (pending = false ∧ sampled.bind q38Decoder = some query) := by
  cases sampled with
  | none => simp [V8Smz9HonestOpeningSchedule.sourcePendingFailure]
  | some stream =>
      change ((pending || false) = false ∧
        (Q38Rp05PostFinalCompiler.sampledTargets points pointsDistinct
          (q38StreamCandidates stream)).map targetSupport = some query.val) ↔
        (pending = false ∧ q38Decoder stream = some query)
      rw [Bool.or_false, sampled_targets_support_event points pointsDistinct stream query]

end
end HegemonCrypto.SmallWood.SmzaRp05Q38ExecutionCountBridge
