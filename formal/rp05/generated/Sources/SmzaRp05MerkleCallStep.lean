import SmzaRp05MerkleOrientation
import SmzaRp05MerkleFold

/-!
# RP05 Merkle call step from finite frames

Only the current-call final-state identity remains abstract. It is a provider
interface for the 332-root kernel certificate or its paired-DAG replacement;
all orientation and initial-frame equations below follow from current RP05
accepted rows plus finite frame certificates.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05MerkleCallStep

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex)
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05MerkleFrameCertificate
open HegemonCrypto.SmallWood.SmzaRp05MerkleOrientation
open HegemonCrypto.SmallWood.SmzaRp05MerkleFold
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge

set_option autoImplicit false

def initialHalf (packed : List Nat) (step half : Nat) : Digest :=
  (List.range 7).map fun limb =>
    packed.getD (hashInitialIndex (callAt step) (7 * half + limb)) 0

private theorem initial_half_getD (packed : List Nat) (step half : Nat)
    {limb : Nat} (bound : limb < 7) :
    (initialHalf packed step half).getD limb 0 =
      packed.getD (hashInitialIndex (callAt step) (7 * half + limb)) 0 := by
  simp [initialHalf, List.getD_eq_getElem?_getD, bound]

def siblingDigest (packed : List Nat) (step : Nat) : Digest :=
  initialHalf packed step
    (if packed.getD (directionIndex step) 0 = 0 then 1 else 0)

/-- Generic current-call kernel provider. This proposition is not supplied
as an assumption of security; its fixture-specific proof must come from the
finite current Poseidon recurrence certificate. -/
def FinalCallCorrect (packed : List Nat) : Prop :=
  ∀ call, call < 128 →
    callDigest packed call =
      (Hegemon.Transaction.Poseidon2Width16Kernel.permutation (packedInitialState packed call)).take
        digestWords

theorem accepted_compress_frame
    {components : RelationProgramComponents}
    (frame : FrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    {step : Nat} (stepBound : step < 64) :
    packedInitialState packed (callAt step) =
      (List.range 16).map fun lane =>
        if lane < 7 then (initialHalf packed step 0).getD lane 0
        else if lane < 14 then (initialHalf packed step 1).getD (lane - 7) 0
        else if lane = 14 then poseidon2V8MerkleDomain
        else poseidon2V8SuiteMarker := by
  apply List.map_congr_left
  intro lane laneMember
  have laneBound : lane < 16 := List.mem_range.mp laneMember
  let cell : InitialCell := (⟨step, stepBound⟩, ⟨lane, laneBound⟩)
  by_cases left : lane < 7
  · rw [if_pos left, initial_half_getD packed step 0 left]
    simp only [packedWord, Nat.mul_zero, Nat.zero_add]
  · by_cases right : lane < 14
    · rw [if_neg left, if_pos right,
        initial_half_getD packed step 1 (show lane - 7 < 7 by omega)]
      have sum : 7 * 1 + (lane - 7) = lane := by omega
      rw [sum]
      rfl
    · rw [if_neg left, if_neg right]
      have source := accepted_initial_word frame accepted cell
      simpa only [cell, if_neg right, packedWord] using source

/-- Current previous-call digest is precisely the selected half of the
accepted Merkle frame; the other half remains the decoded sibling. -/
theorem accepted_previous_half
    {components : RelationProgramComponents}
    (frame : FrameCertificate components)
    (orientation : OrientationCertificate components)
    (directions : HegemonCrypto.SmallWood.SmzaRp05NullifierSource.DirectionCertificate
      components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    {step : Nat} (stepBound : step < 64) :
    callDigest packed (previousCall step) =
      initialHalf packed step
        (if packed.getD (directionIndex step) 0 = 0 then 0 else 1) := by
  apply List.ext_getElem
  · simp [callDigest, packedFinalState, digestWords, initialHalf]
  · intro limb leftBound rightBound
    have limbBound : limb < 7 := by simpa [initialHalf] using rightBound
    simp only [callDigest, packedFinalState, List.getElem_take,
      initialHalf, List.getElem_map, List.getElem_range]
    have current := accepted_current_copy frame accepted
      (⟨step, stepBound⟩, ⟨limb, limbBound⟩)
    have selected := accepted_selected_current frame orientation directions
      accepted stepBound limbBound
    by_cases bit : packed.getD (directionIndex step) 0 = 0
    · rw [if_pos bit] at selected ⊢
      have initial := accepted_initial_word frame accepted
        (⟨step, stepBound⟩, ⟨limb, by omega⟩)
      dsimp only at initial
      simp only [if_pos (show limb < 14 by omega), if_pos limbBound,
        Nat.mod_eq_of_lt limbBound] at initial
      simpa only [packedWord, Nat.mul_zero, Nat.zero_add] using
        current.symm.trans (selected.trans initial.symm)
    · rw [if_neg bit] at selected ⊢
      have initial := accepted_initial_word frame accepted
        (⟨step, stepBound⟩, ⟨7 + limb, by omega⟩)
      have rem : (7 + limb) % 7 = limb := by omega
      dsimp only at initial
      simp only [if_pos (show 7 + limb < 14 by omega),
        if_neg (show ¬ 7 + limb < 7 by omega), rem] at initial
      simpa only [packedWord, Nat.mul_one] using
        current.symm.trans (selected.trans initial.symm)

/-- This is the exact local 32-level fold obligation, now reduced to the
generic current-call final-state certificate. -/
theorem accepted_local_call_step
    {components : RelationProgramComponents}
    (frame : FrameCertificate components)
    (orientation : OrientationCertificate components)
    (directions : HegemonCrypto.SmallWood.SmzaRp05NullifierSource.DirectionCertificate
      components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (finalCall : FinalCallCorrect packed)
    (statement : V8PublicStatement) (input : Fin 2) (level : Fin 32) :
    callDigest packed (merkleCall input level.val) =
      foldStep
        (HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
          packed input.val)
        (HegemonCrypto.SmallWood.SmzaRp05BalanceCore.projectInput
          statement packed input.val).siblings level.val
        (callDigest packed (boundaryCall input level.val)) := by
  let step := input.val * 32 + level.val
  have stepBound : step < 64 := by
    dsimp [step]
    have inputBound := input.isLt
    have levelBound := level.isLt
    omega
  have stepParts : step / 32 = input.val ∧ step % 32 = level.val := by
    dsimp [step]; have := level.isLt; omega
  have inputBound := input.isLt
  have levelBound := level.isLt
  have callEq : callAt step = merkleCall input level.val := by
    simp [callAt, merkleCall, step]
    split_ifs <;> omega
  have priorEq : previousCall step = boundaryCall input level.val := by
    simp [previousCall, boundaryCall, callAt, merkleCall, noteFinalCall,
      step]
    split_ifs <;> omega
  have frameEq := accepted_compress_frame frame accepted stepBound
  have prior := accepted_previous_half frame orientation directions accepted
    stepBound
  rw [callEq] at frameEq
  rw [priorEq] at prior
  have callBound : merkleCall input level.val < 128 := by
    unfold merkleCall
    have inputBound := input.isLt
    have levelBound := level.isLt
    split_ifs <;> omega
  have hash := finalCall (merkleCall input level.val) callBound
  rw [frameEq] at hash
  change callDigest packed (merkleCall input level.val) =
    poseidon2V8Compress14 poseidon2V8MerkleDomain
      (initialHalf packed step 0) (initialHalf packed step 1) at hash
  have bitEq :
      ((HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
        packed input.val / 2 ^ level.val) % 2) =
        packed.getD (directionIndex step) 0 := by
    have source := HegemonCrypto.SmallWood.SmzaRp05AcceptedInputShape.accepted_position_bit_orientation
      directions accepted statement input level
    change (projectPosition packed input.val / 2 ^ level.val) % 2 =
      directionWord packed input.val level.val at source
    simpa [HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.directionWord,
      HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord,
      directionIndex, stepParts.1, stepParts.2] using source
  have siblingEq :
      (HegemonCrypto.SmallWood.SmzaRp05BalanceCore.projectInput
        statement packed input.val).siblings.getD level.val [] =
          siblingDigest packed step := by
    have decoderCallEq :
        HegemonCrypto.SmallWood.SmzaRp05BalanceCore.currentInputMerkleCall
          input.val level.val = merkleCall input level.val := by
      fin_cases input <;> rfl
    simp [HegemonCrypto.SmallWood.SmzaRp05BalanceCore.projectInput,
      siblingDigest, initialHalf, stepParts.1, stepParts.2, callEq,
      decoderCallEq,
      HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.directionWord,
      HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord,
      directionIndex, List.getD_eq_getElem?_getD, level.isLt]
  unfold foldStep
  rw [bitEq, siblingEq, prior]
  by_cases bit : packed.getD (directionIndex step) 0 = 0
  · simpa only [siblingDigest, if_pos bit] using hash
  · simpa only [siblingDigest, if_neg bit] using hash

theorem accepted_all_call_steps
    {components : RelationProgramComponents}
    (frame : FrameCertificate components)
    (orientation : OrientationCertificate components)
    (directions : HegemonCrypto.SmallWood.SmzaRp05NullifierSource.DirectionCertificate
      components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (finalCall : FinalCallCorrect packed)
    (statement : V8PublicStatement) (input : Fin 2) :
    CallStepCorrect packed input
      (HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
        packed input.val)
      (HegemonCrypto.SmallWood.SmzaRp05BalanceCore.projectInput
        statement packed input.val).siblings := by
  intro level bound
  exact accepted_local_call_step frame orientation directions accepted
    finalCall statement input ⟨level, bound⟩

end HegemonCrypto.SmallWood.SmzaRp05MerkleCallStep
