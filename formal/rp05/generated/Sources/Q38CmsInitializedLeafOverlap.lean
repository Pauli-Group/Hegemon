import Q38CmsResamplingCoordinates
import Q38ControlledFreshSwapCore
import Q38LeafFrameHybridR4
import HegemonCrypto.SmallWoodV8Smz9MeasuredOracleHybrid

namespace HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.V8Smz9MeasuredOracleHybrid
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 20000
set_option linter.unusedSectionVars false

variable {Other : Type} [Fintype Other] [DecidableEq Other]
local notation "FullInput" => LeafInput ⊕ Other

/-- Generic sum-domain support injection.  Keeping the proof polymorphic
prevents the elaborator from normalizing the 1,307-byte concrete `LeafInput`
type throughout the Finset argument. -/
theorem sum_left_recorded_card_le_size
    {Left Right Output : Type*}
    [Fintype Left] [DecidableEq Left]
    [Fintype Right] [DecidableEq Right]
    (database : Left ⊕ Right → Option Output) :
    (Finset.univ.filter fun input : Left =>
      database (Sum.inl input) ≠ none).card ≤ size database := by
  let recorded : Finset Left := Finset.univ.filter fun input =>
    database (Sum.inl input) ≠ none
  let embedded : Finset (Left ⊕ Right) := recorded.image Sum.inl
  have cardEmbedded : embedded.card = recorded.card :=
    Finset.card_image_of_injective _ (fun _ _ equal => Sum.inl.inj equal)
  rw [← cardEmbedded]
  apply Finset.card_le_card
  intro input member
  rcases Finset.mem_image.mp member with ⟨left, recordedLeft, rfl⟩
  rw [mem_support_iff]
  have present : database (Sum.inl left) ≠ none := by
    simpa only [recorded, Finset.mem_filter, Finset.mem_univ, true_and] using recordedLeft
  cases value : database (Sum.inl left) with
  | none => exact (present value).elim
  | some output =>
      exact ⟨output, rfl⟩

def recordedLeafInputs
    (database : FullInput → Option DigestRegister) : Finset LeafInput :=
  Finset.univ.filter fun input => database (Sum.inl input) ≠ none

theorem recordedLeafInputs_card_le_size
    (database : FullInput → Option DigestRegister) :
    (recordedLeafInputs database).card ≤ size database := by
  exact sum_left_recorded_card_le_size database

def finsetIntersects {Input : Type*} [DecidableEq Input]
    (recorded patched : Finset Input) : Prop :=
  ∃ input ∈ recorded, input ∈ patched

abbrev leafIntersects := @finsetIntersects LeafInput inferInstance

/-- Intersection indicators are monotone under a pointwise support
inclusion.  The proof is elaborated over an abstract input type, so its
existential transport never reduces the concrete `LeafInput` equality
decision. -/
theorem average_finset_intersects_mono
    {Input : Type*} {Secret : Type} [DecidableEq Input]
    [Fintype Secret] [Nonempty Secret]
    (recorded : Finset Input) (small large : Secret → Finset Input)
    (subset : ∀ secret, small secret ⊆ large secret) :
    uniformAverage (fun secret =>
      if finsetIntersects recorded (small secret) then (1 : ℝ) else 0) ≤
    uniformAverage (fun secret =>
      if finsetIntersects recorded (large secret) then (1 : ℝ) else 0) := by
  apply average_mono
    (fun secret =>
      if finsetIntersects recorded (small secret) then (1 : ℝ) else 0)
    (fun secret =>
      if finsetIntersects recorded (large secret) then (1 : ℝ) else 0)
  intro secret
  by_cases hit : finsetIntersects recorded (small secret)
  · obtain ⟨input, inRecorded, inSmall⟩ := hit
    have largeHit : finsetIntersects recorded (large secret) :=
      ⟨input, inRecorded, subset secret inSmall⟩
    have smallHit : finsetIntersects recorded (small secret) :=
      ⟨input, inRecorded, inSmall⟩
    simp only [if_pos smallHit, if_pos largeHit]
    exact le_rfl
  · simp only [if_neg hit]
    positivity

theorem leaf_overlap_indicator_bound (recorded patched : Finset LeafInput) :
    (if leafIntersects recorded patched then (1 : ℝ) else 0) ≤
      ∑ input ∈ recorded, if input ∈ patched then (1 : ℝ) else 0 := by
  by_cases hit : leafIntersects recorded patched
  · obtain ⟨input, member, patchedMember⟩ := hit
    rw [if_pos ⟨input, member, patchedMember⟩]
    have bound := Finset.single_le_sum
      (f := fun input => if input ∈ patched then (1 : ℝ) else 0)
      (fun input _ => by positivity) member
    simpa only [if_pos patchedMember] using bound
  · rw [if_neg hit]
    exact Finset.sum_nonneg fun _ _ => by positivity

theorem indexed_leaf_record_overlap (recorded : Finset LeafInput) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      if leafIntersects recorded (indexedSupport rawInputIndex leafTapeProjection tapes)
      then (1 : ℝ) else 0) ≤
      (recorded.card : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
  apply (average_mono _ _ fun tapes => leaf_overlap_indicator_bound recorded _).trans
  simp only [uniformAverage, Finset.mul_sum]
  rw [Finset.sum_comm]
  calc
    _ ≤ ∑ _input ∈ recorded, (2 ^ 512 : ℝ)⁻¹ := by
      apply Finset.sum_le_sum
      intro input _
      exact average_support_indicator_le
        (indexedSupport rawInputIndex leafTapeProjection) (2 ^ 512 : ℝ)⁻¹
        (fun input => (indexed_leaf_tape_support_count
          rawInputIndex leafTapeProjection input).le) input
    _ = _ := by simp

theorem source_leaf_record_overlap (recorded : Finset LeafInput)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      if leafIntersects recorded
        (sourcePatchSupport Finset.univ (fun _ => header salt)
          (fun i => suffix (data i)) tapes)
      then (1 : ℝ) else 0) ≤
      (recorded.card : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
  exact (average_finset_intersects_mono
    (Input := LeafInput) (Secret := LeafIndex → LeafTape) recorded
    (fun tapes => sourcePatchSupport Finset.univ (fun _ => header salt)
      (fun i => suffix (data i)) tapes)
    (indexedSupport rawInputIndex leafTapeProjection)
    (fun tapes => source_patch_support_subset Finset.univ
      (fun _ => header salt) (fun i => suffix (data i)) tapes)).trans
        (indexed_leaf_record_overlap recorded)

def fullPhysicalSelected {Branch : Type}
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (tapes : LeafIndex → LeafTape) : Branch → LeafIndex → FullInput :=
  fun branch index => Sum.inl
    (sourceLeafInput (header (salt branch)) (suffix (data branch index))
      index (tapes index))

end
end HegemonCrypto.SmallWood.Q38CmsInitializedResampling
