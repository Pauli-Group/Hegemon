import SmzaRp05ChunkedAcceptedRecurrence

/-! All current RP05 hash calls refine the existing reference permutation.
This consumes the current finite DAG/root certificates directly and does not
require an expanded SourceTerm KernelCertificate. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHashCalls

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packedWord packed_word_canonical)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
  (canonical_nat_cast_injective)

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem current_hash_call_final_eq_kernel
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {call limb : Nat} (callBound : call < 128) (limbBound : limb < 16) :
    packedWord packed (Poseidon2V8DecoderRefinement.hashFinalIndex call limb) =
      (Poseidon2Width16Kernel.permutation (packedInitialState packed call)).getD limb 0 := by
  have groupBound : call / 64 < 2 := by omega
  have laneBound : call % 64 < 64 := Nat.mod_lt _ (by decide)
  have initial : StateMatches
      (fun i => laneField packed (call % 64) (283 + 182 * (call / 64) + i))
      (packedInitialState packed call) := by
    constructor
    intro i bound
    rw [laneField_eq_packedWord packed _ _ (by omega)]
    simp only [packedInitialState, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range bound, Option.map_some, Option.getD_some]
    congr 2
    simp [Poseidon2V8DecoderRefinement.hashInitialIndex,
      Poseidon2V8DecoderRefinement.hashRowStart,
      Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Poseidon2V8DecoderRefinement.packingFactor,
      Nat.mul_add, Nat.mul_comm, Nat.add_assoc]
  have final := hash_recurrence_refines_kernel
    (fun n => (publicWords.getD n 0 : Goldilocks))
    (laneField packed (call % 64)) groupBound
    (fun _ bound => SmzaRp05ChunkedAcceptedRecurrence.accepted_hash_recurrence
      accepted groupBound bound laneBound)
    (packedInitialState packed call) initial ⟨limb, limbBound⟩
  rw [laneField_eq_packedWord packed _ _ (by omega)] at final
  have indexEq : (449 + 182 * (call / 64) + limb) * 64 + call % 64 =
      Poseidon2V8DecoderRefinement.hashFinalIndex call limb := by
    simp [Poseidon2V8DecoderRefinement.hashFinalIndex,
      Poseidon2V8DecoderRefinement.hashRowStart,
      Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Poseidon2V8DecoderRefinement.hashFinalRowOffset,
      Poseidon2V8DecoderRefinement.packingFactor,
      Nat.mul_add, Nat.mul_comm, Nat.add_assoc]
    omega
  have fieldEq :
      (packedWord packed (Poseidon2V8DecoderRefinement.hashFinalIndex call limb) :
        Goldilocks) =
      ((Poseidon2Width16Kernel.permutation (packedInitialState packed call)).getD
        limb 0 : Goldilocks) := by
    simpa only [indexEq] using final
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (kernel_permutation_word_canonical (packedInitialState packed call)
      ⟨limb, limbBound⟩) fieldEq

theorem current_hash_call_state {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {call : Nat} (bound : call < 128) :
    Poseidon2Width16Kernel.permutation (packedInitialState packed call) =
      packedFinalState packed call := by
  have permutation_length : ∀ input : List Nat,
      (Poseidon2Width16Kernel.permutation input).length = 16 := by
    intro input
    simp [Poseidon2Width16Kernel.permutation,
      Poseidon2Width16Kernel.externalRoundConstantsTerminal,
      Poseidon2Width16Kernel.width]
  apply List.ext_getElem
  · simp [packedFinalState, permutation_length]
  · intro limb leftBound rightBound
    have limbBound : limb < 16 := by simpa [permutation_length] using leftBound
    have equal := (current_hash_call_final_eq_kernel accepted bound limbBound).symm
    rw [List.getD_eq_getElem _ _ leftBound] at equal
    simpa [packedFinalState, List.getElem_map, List.getElem_range] using equal

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHashCalls
