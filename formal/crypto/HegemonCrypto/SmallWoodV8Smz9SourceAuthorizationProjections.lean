import HegemonCrypto.SmallWoodV8Smz9SourceSpongeSegment
import Mathlib.Data.List.Basic

namespace HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
set_option Elab.async false
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

def AccumulatorGeometry (opening : V8AccumulatorOpening) : Prop :=
  opening.policyRoot.length = 7 ∧ opening.intentDigest.length = 7 ∧ opening.approvedSlots.length = 6

def PolicyGeometry (tags : List (List Nat)) : Prop :=
  tags.length = 6 ∧ ∀ slot, slot < 6 → (tags.getD slot []).length = 5

theorem zero_accumulator_geometry (opening : V8AccumulatorOpening) (h : ZeroAccumulator opening) :
    AccumulatorGeometry opening := by
  rcases h with ⟨policy, _, intent, _, _, _, _, slots, _⟩
  exact ⟨policy.1, intent.1, slots⟩

theorem canonical_accumulator_geometry (opening : V8AccumulatorOpening) (h : CanonicalAccumulator opening) :
    AccumulatorGeometry opening := by
  rcases h with ⟨policy, _, intent, _, _, _, _, _, slots, _⟩
  exact ⟨policy.1, intent.1, slots⟩

theorem zero_policy_geometry (tags : List (List Nat)) (h : ZeroSignerTags tags) : PolicyGeometry tags := by
  refine ⟨h.1, ?_⟩
  intro slot bound
  have inRange : slot < tags.length := by rw [h.1]; exact bound
  have member : tags.getD slot [] ∈ tags := by
    rw [List.getD_eq_getElem tags [] inRange]
    exact List.getElem_mem inRange
  exact (h.2 _ member).1.1

theorem canonical_policy_geometry (auth : V8AuthorizationWitness) (h : CanonicalSignerTags auth) :
    PolicyGeometry auth.policySignerTags :=
  ⟨h.1, fun slot bound => (h.2.1 slot bound).1⟩

theorem typed_valid_authorization_geometry (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    AccumulatorGeometry witness.authorization.current ∧
      AccumulatorGeometry witness.authorization.next ∧ PolicyGeometry witness.authorization.policySignerTags := by
  have auth := valid.2.2.1.2.2
  unfold V8AuthorizationValid at auth
  cases mode : witness.authorization.mode with
  | singleKey =>
      simp only [mode] at auth
      exact ⟨zero_accumulator_geometry _ auth.1, zero_accumulator_geometry _ auth.2.1,
        zero_policy_geometry _ auth.2.2.1⟩
  | approvalStep =>
      simp only [mode] at auth
      exact ⟨canonical_accumulator_geometry _ auth.2.2.1,
        canonical_accumulator_geometry _ auth.2.2.2.1,
        canonical_policy_geometry _ auth.2.2.2.2.1⟩
  | finalThresholdSpend =>
      simp only [mode] at auth
      exact ⟨canonical_accumulator_geometry _ auth.2.1, zero_accumulator_geometry _ auth.2.2.1,
        canonical_policy_geometry _ auth.2.2.2.1⟩

theorem source_accumulator_words_exact (opening : V8AccumulatorOpening)
    (shape : AccumulatorGeometry opening) : sourceAccumulatorWords opening = exactV8AccumulatorWords opening := by
  simp only [sourceAccumulatorWords, exactV8AccumulatorWords,
    fixed_words_exact 7 _ shape.1, fixed_words_exact 7 _ shape.2.1, fixed_words_exact 6 _ shape.2.2]

theorem source_value_lock_words_exact (opening : V8AccumulatorOpening)
    (shape : AccumulatorGeometry opening) :
    sourceValueLockWords opening = opening.policyRoot ++ opening.intentDigest := by
  simp only [sourceValueLockWords, fixed_words_exact 7 _ shape.1, fixed_words_exact 7 _ shape.2.1]

theorem range_tags_exact (tags : List (List Nat)) (shape : tags.length = 6) :
    (List.range 6).map (fun slot => tags.getD slot []) = tags := by
  apply List.ext_getElem (by simp only [List.length_map, List.length_range, shape])
  intro index _ bound
  simp only [List.getElem_map, List.getElem_range, List.getD_eq_getElem?_getD,
    List.getElem?_eq_getElem bound, Option.getD_some]

theorem source_policy_words_exact (auth : V8AuthorizationWitness)
    (shape : PolicyGeometry auth.policySignerTags) :
    sourcePolicyWords auth =
      [auth.current.threshold, auth.current.signerCount] ++ auth.policySignerTags.flatten := by
  unfold sourcePolicyWords
  congr 1
  have projection :
      (List.range 6).flatMap (fun slot => fixedWords 5 (auth.policySignerTags.getD slot [])) =
        (List.range 6).flatMap (fun slot => auth.policySignerTags.getD slot []) := by
    apply List.flatMap_congr
    intro slot member
    exact fixed_words_exact 5 _ (shape.2 slot (List.mem_range.mp member))
  rw [projection, List.flatMap_def, range_tags_exact _ shape.1]

theorem effective_next_geometry (auth : V8AuthorizationWitness)
    (current : AccumulatorGeometry auth.current) (next : AccumulatorGeometry auth.next) :
    AccumulatorGeometry (effectiveNext auth) :=
  ⟨current.1, current.2.1, next.2.2⟩

end HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
