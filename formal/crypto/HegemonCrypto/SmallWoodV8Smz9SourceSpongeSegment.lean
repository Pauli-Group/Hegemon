import HegemonCrypto.SmallWoodV8Smz9TypedScheduleInventory

namespace HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
set_option Elab.async false
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

def semanticPrefix (domain : Nat) (inputs : List Nat) (blocks count : Nat) : List Nat :=
  (List.range count).foldl (poseidon2V8AbsorbBlock domain inputs blocks) poseidon2V8InitialState

theorem semantic_prefix_succ (domain : Nat) (inputs : List Nat) (blocks count : Nat) :
    semanticPrefix domain inputs blocks (count+1) =
      poseidon2V8AbsorbBlock domain inputs blocks (semanticPrefix domain inputs blocks count) count := by
  simp only [semanticPrefix, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]

theorem zero_state_words : stateWords zeroState = poseidon2V8InitialState := rfl

/-- A real contiguous sequence of source absorption/permutation steps equals
the existing semantic fold. The only recurrence premise is one source step,
not its final digest or an evaluator/trace acceptance predicate. -/
theorem recurrence_is_semantic_prefix (finals : Nat → State)
    (start blocks domain : Nat) (inputs : List Nat)
    (step : ∀ block, block < blocks →
      stateWords (finals (start+block)) =
        poseidon2V8AbsorbBlock domain inputs blocks
          (if block = 0 then poseidon2V8InitialState else stateWords (finals (start+block-1))) block)
    (block : Nat) (bound : block < blocks) :
    stateWords (finals (start+block)) = semanticPrefix domain inputs blocks (block+1) := by
  induction block with
  | zero =>
      rw [step 0 bound, semantic_prefix_succ]
      rfl
  | succ n ih =>
      rw [step (n+1) bound, semantic_prefix_succ]
      have index : start+(n+1)-1 = start+n := by omega
      simp only [Nat.add_one_ne_zero, if_false, index]
      rw [ih (by omega)]

/-- The call plan is read from the actual typed source constructor. This proof
also uses its proved prior-final frame readback, including sponge predecessors. -/
theorem source_sponge_step (statement : V8PublicStatement) (witness : V8Witness)
    (start blocks domain : Nat) (inputs : List Nat) (role : Nat → Role)
    (fits : start+blocks ≤ 125)
    (plans : ∀ block, block < blocks →
      sourceCallPlan statement witness (start+block) (scheduledFinal statement witness) =
        .sponge (role block) domain inputs blocks block (previousSponge (start+block) block))
    (domainBound : domain < Poseidon2Width16Kernel.fieldModulus)
    (inputBound : inputs.length < Poseidon2Width16Kernel.fieldModulus)
    (block : Nat) (bound : block < blocks) :
    stateWords (scheduledFinal statement witness (start+block)) =
      poseidon2V8AbsorbBlock domain inputs blocks
        (if block = 0 then poseidon2V8InitialState
         else stateWords (scheduledFinal statement witness (start+block-1))) block := by
  rw [every_call_has_actual_kernel_final]
  rw [scheduled_initial_uses_actual_prior_finals statement witness ⟨start+block, by omega⟩]
  rw [plans block bound]
  by_cases first : block = 0
  · simp only [preparePlan, previousSponge, first, if_true]
    rw [sponge_frame_exact _ _ _ _ _ domainBound inputBound, zero_state_words]
    exact (sponge_absorb_is_source_preparation _ _ _ _ _).symm
  · simp only [preparePlan, previousSponge, first, if_false]
    rw [sponge_frame_exact _ _ _ _ _ domainBound inputBound]
    exact (sponge_absorb_is_source_preparation _ _ _ _ _).symm

theorem source_sponge_segment_digest (statement : V8PublicStatement) (witness : V8Witness)
    (start blocks domain : Nat) (inputs : List Nat) (role : Nat → Role)
    (fits : start+blocks ≤ 125) (nonempty : 0 < blocks)
    (plans : ∀ block, block < blocks →
      sourceCallPlan statement witness (start+block) (scheduledFinal statement witness) =
        .sponge (role block) domain inputs blocks block (previousSponge (start+block) block))
    (domainBound : domain < Poseidon2Width16Kernel.fieldModulus)
    (inputBound : inputs.length < Poseidon2Width16Kernel.fieldModulus)
    (blockCount : blocks = Nat.max 1 ((inputs.length + Poseidon2Width16Kernel.rate - 1) /
      Poseidon2Width16Kernel.rate)) :
    (stateWords (scheduledFinal statement witness (start+blocks-1))).take 7 =
      poseidon2V8Sponge domain inputs := by
  have folded := recurrence_is_semantic_prefix (scheduledFinal statement witness) start blocks domain inputs
    (source_sponge_step statement witness start blocks domain inputs role fits plans domainBound inputBound)
    (blocks-1) (by omega)
  have index : start+(blocks-1) = start+blocks-1 := by omega
  have count : blocks-1+1 = blocks := by omega
  rw [index, count] at folded
  rw [folded]
  simp only [semanticPrefix, poseidon2V8Sponge, digestWords, blockCount]

end HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
