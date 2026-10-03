import HegemonCrypto.SmallWoodV8Smz9SourceQueryBudget
import HegemonCrypto.SmallWoodV8Smz9PostFinalProgram

/-! Complete post-final source read counts. Rejected nonce trials, the repeated
selected trial, exhausted field/index sampling and every later continuation
remain charged. This is a syntactic interpreter bound, not Rust refinement. -/

namespace HegemonCrypto.SmallWood.V8Smz9PostFinalQueryBudget

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9SingleProofPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9CurrentProgramPiop
open V8Smz9CurrentProgramOpeningBinding V8Smz9ZeroKnowledge V8Smz9HonestHybrid
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler V8Smz9AdjacentComposition
open V8Smz9RuntimeDistribution V8Smz9RuntimeRandomness V8Smz9WholeViewObservation
open V8Smz9PostFinalSerializer V8Smz9PostFinalProgram V8Smz9SourceQueryBudget
open V8Smz9DynamicRequest
open V8Smz9CurrentPublicContext
open V8Smz9PrivacyGameComposition
open scoped Classical

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000
set_option Elab.async false

theorem source_opening_xof_read_bound (bound : Nat) (largeEnough : 25029 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister) :
    NonleafProgram.readCount (sourceOpeningXof bound largeEnough nonce digest) ≤ 5 := by
  unfold sourceOpeningXof
  exact (source_field_read_loop_count _ _ _).trans (by simp only [List.length_ofFn, Nat.le_refl])

attribute [local irreducible] sourceOpeningXof sourceOpeningValid

theorem source_opening_loop_read_bound (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (pending : Bool) (nonces : List (Fin 16)) :
    NonleafProgram.readCount (sourceChooseOpeningLoop bound largeEnough digest pending nonces) ≤
      5 * (nonces.length + 1) := by
  induction nonces generalizing pending with
  | nil => simp only [sourceChooseOpeningLoop, NonleafProgram.readCount]; omega
  | cons nonce rest ih =>
      rw [sourceChooseOpeningLoop]
      apply Nat.le_trans (m := NonleafProgram.readCount
        (sourceOpeningXof bound largeEnough nonce digest) + 5 * (rest.length + 1))
      · apply nonleaf_read_count_bind_le
        intro sampled
        dsimp only
        split
        · apply (nonleaf_read_count_map_le _ _).trans
          have cap := source_opening_xof_read_bound bound largeEnough nonce digest
          omega
        · exact ih _
      · have cap := source_opening_xof_read_bound bound largeEnough nonce digest
        simp only [List.length_cons]
        omega

theorem source_choose_opening_read_bound (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (pending : Bool) :
    NonleafProgram.readCount (sourceChooseOpening bound largeEnough digest pending) ≤ 85 := by
  unfold sourceChooseOpening
  exact (source_opening_loop_read_bound bound largeEnough digest pending _).trans
    (by simp only [List.length_ofFn]; norm_num)

theorem source_fixed_index_read_bound (bound : Nat) (largeEnough : 37434 ≤ bound)
    (digest : DigestRegister) :
    NonleafProgram.readCount (sourceFixedIndexXof bound largeEnough digest) ≤ 11 := by
  unfold sourceFixedIndexXof
  exact (source_field_read_loop_count _ _ _).trans (by simp only [List.length_ofFn, Nat.le_refl])

theorem source_decs_selection_read_bound (bound : Nat) (largeEnough : 37434 ≤ bound)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (digest : DigestRegister) (heads : Fin 12 → Fin 368 → Goldilocks)
    (tails : Fin 12 → Fin 20 → Goldilocks) (pending : Bool) :
    NonleafProgram.readCount (sourceDecsSelection bound largeEnough points distinct digest heads tails pending) ≤ 12 := by
  unfold sourceDecsSelection
  apply nonleaf_read_count_read_le
  intro challenge
  exact (nonleaf_read_count_map_le _ _).trans (source_fixed_index_read_bound bound largeEnough challenge)

section PostFinal
variable (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (values : WitnessPackingValues Goldilocks) (coins : SourceRemainingCoins Goldilocks)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)

theorem source_selected_bytes_read_bound (opening : ComputedOpening) :
    NonleafProgram.readCount (sourceSelectedBytesProgram bound largeEnough parameters opening gamma response
      transcript digest values coins salt tree tapes) ≤ 12 := by
  unfold sourceSelectedBytesProgram
  apply (nonleaf_read_count_map_le _ _).trans
  unfold sourcePhysicalIndexProgram sourceCurrentDecsSelection
  exact source_decs_selection_read_bound _ _ _ _ _ _ _ _

theorem source_post_final_read_bound (pending : Bool) :
    NonleafProgram.readCount (sourcePostFinalBytesProgram bound largeEnough parameters gamma response
      transcript digest pending values coins salt tree tapes) ≤ 97 := by
  unfold sourcePostFinalBytesProgram
  apply Nat.le_trans (m := NonleafProgram.readCount
    (sourceChooseOpening bound (by omega) digest pending) + 12)
  · apply nonleaf_read_count_bind_le
    intro result
    cases certifyOpening result with
    | none => exact Nat.zero_le _
    | some opening =>
        exact source_selected_bytes_read_bound bound largeEnough parameters gamma response transcript
          digest values coins salt tree tapes opening
  · have cap := source_choose_opening_read_bound bound (by omega) digest pending
    omega

variable {Work : Type} [Fintype Work]

theorem source_post_final_query_bound (pending : Bool)
    (next : Except String (List CanonicalBytes.Byte) → Program (FullRawInput bound) Work)
    (queries : Nat) (remaining : ∀ output, queryCount (next output) ≤ queries) :
    queryCount (sourcePostFinalProgram bound largeEnough parameters gamma response transcript digest pending
      values coins salt tree tapes next) ≤ 97 + queries := by
  unfold sourcePostFinalProgram
  exact (compiled_nonleaf_query_bound _ next queries remaining).trans
    (Nat.add_le_add_right (source_post_final_read_bound bound largeEnough parameters gamma response transcript
      digest values coins salt tree tapes pending) queries)

theorem source_post_final_programming_bound (pending : Bool)
    (next : Except String (List CanonicalBytes.Byte) → Program (FullRawInput bound) Work)
    (programs : Nat) (remaining : ∀ output, programmingCount (next output) ≤ programs) :
    programmingCount (sourcePostFinalProgram bound largeEnough parameters gamma response transcript digest pending
      values coins salt tree tapes next) ≤ programs := by
  exact compiled_nonleaf_program_bound _ next programs remaining

end PostFinal

section CompleteRequest
variable {Work : Type} [Fintype Work]
variable (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (coins : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : Except String (List CanonicalBytes.Byte) → Program (FullRawInput bound) Work)

/-- The concrete chronological source program now reaches its literal final
proof/error bytes: full leaf batch, computed DECS/PIOP responses, final digest,
all opening/index trials, then the complete caller continuation. -/
def sourceCompleteByteRequest : Program (FullRawInput bound) Work :=
  sourceAllLeavesThenComputedPrefix bound (by omega) statementBinding bindingFits statement
    values coins masks salt retainedRows rowBound fun tapes _labels stageResult response transcript digest pending =>
      sourcePostFinalProgram bound largeEnough
        (statementParameters statement (sourceDecodedPiopGamma retainedRows stageResult.piopGamma))
        (sourceDecodedDecsGamma stageResult.decsGamma) response transcript digest pending
        values coins salt stageResult.tree tapes next

theorem source_complete_byte_request_query_bound (queries : Nat)
    (remaining : ∀ output, queryCount (next output) ≤ queries) :
    queryCount (sourceCompleteByteRequest bound largeEnough statementBinding bindingFits statement
      values coins masks salt retainedRows rowBound next) ≤ 16790291 + queries := by
  unfold sourceCompleteByteRequest
  apply Nat.le_trans (m := 16790194 + (97 + queries))
  · apply source_all_leaves_computed_prefix_query_bound
    intro tapes labels stageResult response transcript digest pending
    exact source_post_final_query_bound _ _ _ _ _ _ _ _ _ _ _ _ pending next queries remaining
  · omega

theorem source_complete_byte_request_programming_bound (programs : Nat)
    (remaining : ∀ output, programmingCount (next output) ≤ programs) :
    programmingCount (sourceCompleteByteRequest bound largeEnough statementBinding bindingFits statement
      values coins masks salt retainedRows rowBound next) ≤ 8388608 + programs := by
  unfold sourceCompleteByteRequest
  apply source_all_leaves_computed_prefix_program_bound
  intro tapes labels stageResult response transcript digest pending
  exact source_post_final_programming_bound _ _ _ _ _ _ _ _ _ _ _ _ pending next programs remaining

end CompleteRequest


end
end HegemonCrypto.SmallWood.V8Smz9PostFinalQueryBudget
