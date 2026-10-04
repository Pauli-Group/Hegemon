import SmzaRp05AcceptedSingleKeySemanticIdentity
import SmzaRp05NullifierMuxCertificate

/-! Selector-conditional join from the accepted SingleKey semantic key to the
exact five key words consumed by the current RP05 nullifier preimage. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedNullifierMuxJoin

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05AcceptedSingleKeySemanticIdentity
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.SmzaRp05NullifierMuxCertificate
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packedWord packed_word_canonical)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (canonical_nat_cast_injective)

set_option autoImplicit false

private theorem packed_lane_row_getD (packed : List Nat) (lane row : Nat)
    (bound : row < relationRowCount) :
    (packedWitnessLaneRows packed lane).getD row 0 =
      packed.getD (row * packingFactor + lane) 0 := by
  have shape : (packedWitnessLaneRows packed lane).length = relationRowCount := by
    simp [packedWitnessLaneRows]
  rw [List.getD_eq_getElem _ _ (by omega)]
  simp only [packedWitnessLaneRows, List.getElem_map, List.getElem_range]

/-- Under explicit SingleKey mode selectors, the exact five words at the
front of either accepted RP05 nullifier preimage are the five accepted global
key words. This is conditional on mode; acceptance alone does not choose it. -/
theorem accepted_single_nullifier_preimage_key_word
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (certificate : CurrentNullifierMuxCertificate program)
    (input : Fin 2) (limb : Fin 5)
    (singleSelected :
      ((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) = 1)
    (approvalUnselected :
      ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) = 0)
    (finalUnselected :
      ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) = 0) :
    (nullifierPreimage packed input).getD limb.val 0 =
      acceptedGlobalKey packed limb := by
  have mux := accepted_single_nullifier_key_word certificate accepted input limb
    singleSelected approvalUnselected finalUnselected
  have inputBound : inputNullifierKeyRow input < relationRowCount := by
    fin_cases input <;> decide
  have globalBound : globalNullifierKeyRow < relationRowCount := by decide
  rw [packed_lane_row_getD packed limb.val (inputNullifierKeyRow input) inputBound,
    packed_lane_row_getD packed limb.val globalNullifierKeyRow globalBound] at mux
  have packedField :
      (packed.getD (inputNullifierKeyRow input * 64 + limb.val) 0 : Goldilocks) =
        (packed.getD (globalNullifierKeyRow * 64 + limb.val) 0 : Goldilocks) := by
    simpa [packingFactor] using mux
  have packedNat := canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1
      (inputNullifierKeyRow input * 64 + limb.val))
    (packed_word_canonical accepted.2.1
      (globalNullifierKeyRow * 64 + limb.val)) packedField
  fin_cases limb <;>
    simpa [nullifierPreimage, packedWord, inputNullifierKeyRow, globalNullifierKeyRow,
      acceptedGlobalKey] using packedNat

end HegemonCrypto.SmallWood.SmzaRp05AcceptedNullifierMuxJoin
