import SmzaRp05SingleKeyPrfSemantic
import SmzaRp05ChunkedAcceptedRecurrence
import HegemonCrypto.SmallWoodV8Smz9SemanticPoseidonKernelBinding

/-! Accepted call-0 PRF output tied to its exact source-bound initial state. -/
namespace HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfKernel

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex hashRowStart hashRowsPerGroup
    hashFinalRowOffset)
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCertificate
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceData
open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05ChunkedAcceptedRecurrence
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

private theorem accepted_call0_recurrence
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) :
    HashRecurrence 0 (fun n => (publicWords.getD n 0 : Goldilocks))
      (laneField packed 0) := by
  intro wire wireBound
  exact SmzaRp05ChunkedAcceptedRecurrence.accepted_hash_recurrence
    (group := 0) (wire := wire) (lane := 0)
    accepted (by decide) wireBound (by decide)

private theorem accepted_call0_initial_matches
    {packed : List Nat} :
    StateMatches (fun i => laneField packed 0 (283 + i))
      (packedInitialState packed 0) := by
  constructor
  intro i bound
  rw [laneField_eq_packedWord packed 0 (283 + i) (by omega)]
  simp only [packedInitialState, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range bound, Option.map_some,
    Option.getD_some]
  congr 2
  simp [hashInitialIndex, hashRowStart, hashRowsPerGroup,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
    Nat.mul_add, Nat.mul_comm]

/-- Source-certified call-0 input frame: five global-key words, two explicit
zero pads, and the checked domain/frame cells (including the third zero lane). -/
theorem accepted_single_key_prf_initial_frame
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (lane : Fin 16) :
    (packed.getD (hashInitialIndex 0 lane.val) 0 : Goldilocks) =
      if lane.val < 5 then
        (packed.getD (227 * 64 + lane.val) 0 : Goldilocks)
      else if lane.val < 8 then 0 else (initialExpected lane : Goldilocks) :=
  accepted_call0_initial_word accepted lane

/-- Exact seven-word legacy digest of accepted call 0 equals the first seven
words of the width-16 Poseidon2 permutation on the source-bound input frame. -/
theorem accepted_single_key_prf_digest_word
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (limb : Fin 7) :
    packed.getD (106 * 64 + limb.val) 0 =
      (Poseidon2Width16Kernel.permutation (packedInitialState packed 0)).getD
        limb.val 0 := by
  have recurrence := accepted_call0_recurrence accepted
  have initial := accepted_call0_initial_matches (packed := packed)
  have kernelWord := hash_recurrence_refines_kernel
    (fun n => (publicWords.getD n 0 : Goldilocks)) (laneField packed 0)
    (group := 0) (by decide) recurrence (packedInitialState packed 0)
    initial ⟨limb.val, by omega⟩
  rw [laneField_eq_packedWord packed 0 (449 + limb.val) (by omega)] at kernelWord
  have finalIndex : (449 + limb.val) * 64 = hashFinalIndex 0 limb.val := by
    simp [hashFinalIndex, hashRowStart, hashRowsPerGroup,
      hashFinalRowOffset,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Nat.mul_add, Nat.mul_comm]
    omega
  have fieldEquality :
      (packed.getD (hashFinalIndex 0 limb.val) 0 : Goldilocks) =
        (Poseidon2Width16Kernel.permutation (packedInitialState packed 0)).getD
          limb.val 0 := by
    simpa [packedWord, finalIndex] using kernelWord
  have digestField :
      (packed.getD (106 * 64 + limb.val) 0 : Goldilocks) =
        (Poseidon2Width16Kernel.permutation (packedInitialState packed 0)).getD
          limb.val 0 := by
    rw [accepted_legacy_digest_word accepted limb]
    exact fieldEquality
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 (106 * 64 + limb.val))
    (kernel_permutation_word_canonical (packedInitialState packed 0)
      ⟨limb.val, by omega⟩)
    digestField

end HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfKernel
