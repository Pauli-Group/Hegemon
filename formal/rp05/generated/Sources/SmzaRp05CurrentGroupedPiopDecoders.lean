import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentExecutedPiopMatrixReadback
import SmzaRp05CurrentExecutedOpeningOutput
import SmzaRp04RawRoleSampling
import SmzaRp05CurrentOpeningProgram

/-! Stored cells in the fixed grouped database determine the current PIOP
decoders on every source coordinate in the represented role group. The
matrix and opening statements remain separate; in particular, the opening
lemma is for one nonce and makes no first-success or nonce-independence claim.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedPiopDecoders

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05CurrentFiniteGroupedProgram (Key)
open SmzaRp05CurrentGroupedOracleVector
  (finiteGroupedDatabaseOracle stored_group_vector_answers_every_counter)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter groupEncode)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CurrentOpeningProgram (openingCounterInput)
open SmzaRp05CurrentExecutedPiopMatrixReadback
  (currentPiopMatrixRawBlocks currentPiopMatrixVector)
open SmzaRp05CurrentExecutedOpeningOutput
  (currentOpeningRawBlocks currentOpeningVector)
open SmzaRp04RawRoleSampling
  (actualPiopMatrixOutput rawPiopMatrixOutput actualPiopOpeningOutput
    rawPiopOpeningOutput selectedRawBlocks)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8SmzaOracleParser (RawDigest)
open V8Smz9AdaptiveFiniteAccounting.Historical (piopOpenings)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.SmallWoodTranscript (piopCoefficientDomain)

noncomputable section
set_option autoImplicit false

/-- A stored grouped vector gives the same current PIOP-matrix decode as the
finite database oracle, provided each decoder counter is the corresponding
coordinate of this exact canonical role prefix. The counter-address premise
is a source framing equality; all oracle-byte equalities are derived from the
stored-cell theorem. -/
theorem piop_matrix_decoder_from_stored_group_cell {Result : Type}
    (program : Program Result)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (fallback : RawDigest) (key : Key program)
    (rolePrefix : CanonicalRolePrefix)
    (keyIdentity : SmzaRp05CurrentFiniteGroupedProgram.included program key =
      Sum.inl rolePrefix)
    (vector : VectorOutput GroupCounter) (stored : database key = some vector)
    (digest : RawDigest) (width : Nat)
    (route : Fin (digestCallCap (5 * width)) ↪ GroupCounter)
    (counterAddress : ∀ index,
      counterInput piopCoefficientDomain digest index.val =
        groupEncode (rolePrefix, route index)) :
    actualPiopMatrixOutput route vector =
      actualPiopMatrixOutput (Equiv.refl (Fin (digestCallCap (5 * width))))
        (currentPiopMatrixVector
          (finiteGroupedDatabaseOracle program database fallback) digest width) := by
  let oracle := finiteGroupedDatabaseOracle program database fallback
  have fixedBlocks : selectedRawBlocks route vector =
      currentPiopMatrixRawBlocks oracle digest width := by
    funext index
    change rawDigestBits.symm (vector (route index)) =
      oracle (counterInput piopCoefficientDomain digest index.val)
    rw [counterAddress index]
    symm
    exact stored_group_vector_answers_every_counter program database fallback key
      rolePrefix keyIdentity vector stored (route index)
  have oracleBlocks : selectedRawBlocks
      (Equiv.refl (Fin (digestCallCap (5 * width))))
      (currentPiopMatrixVector oracle digest width) =
        currentPiopMatrixRawBlocks oracle digest width := by
    funext index
    change rawDigestBits.symm
        (rawDigestBits (oracle (counterInput piopCoefficientDomain digest index.val))) =
      oracle (counterInput piopCoefficientDomain digest index.val)
    exact rawDigestBits.symm_apply_apply _
  unfold actualPiopMatrixOutput rawPiopMatrixOutput
  rw [fixedBlocks, oracleBlocks]

/-- One nonce's six-point opening decoder is likewise fixed by the stored
vector over that nonce's canonical role prefix. This theorem is deliberately
per nonce: it does not identify the first successful nonce or claim that
different nonce prefixes share a stored vector. -/
theorem piop_opening_decoder_from_stored_group_cell {Result : Type}
    (program : Program Result)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (fallback : RawDigest) (key : Key program)
    (rolePrefix : CanonicalRolePrefix)
    (keyIdentity : SmzaRp05CurrentFiniteGroupedProgram.included program key =
      Sum.inl rolePrefix)
    (vector : VectorOutput GroupCounter) (stored : database key = some vector)
    (digest : RawDigest) (nonce : Nat)
    (route : Fin (digestCallCap piopOpenings) ↪ GroupCounter)
    (counterAddress : ∀ index,
      openingCounterInput digest nonce index.val =
        groupEncode (rolePrefix, route index)) :
    actualPiopOpeningOutput route vector =
      actualPiopOpeningOutput (Equiv.refl (Fin (digestCallCap piopOpenings)))
        (currentOpeningVector
          (finiteGroupedDatabaseOracle program database fallback) digest nonce) := by
  let oracle := finiteGroupedDatabaseOracle program database fallback
  have fixedBlocks : selectedRawBlocks route vector =
      currentOpeningRawBlocks oracle digest nonce := by
    funext index
    change rawDigestBits.symm (vector (route index)) =
      oracle (openingCounterInput digest nonce index.val)
    rw [counterAddress index]
    symm
    exact stored_group_vector_answers_every_counter program database fallback key
      rolePrefix keyIdentity vector stored (route index)
  have oracleBlocks : selectedRawBlocks
      (Equiv.refl (Fin (digestCallCap piopOpenings)))
      (currentOpeningVector oracle digest nonce) =
        currentOpeningRawBlocks oracle digest nonce := by
    funext index
    change rawDigestBits.symm
        (rawDigestBits (oracle (openingCounterInput digest nonce index.val))) =
      oracle (openingCounterInput digest nonce index.val)
    exact rawDigestBits.symm_apply_apply _
  unfold actualPiopOpeningOutput rawPiopOpeningOutput
  rw [fixedBlocks, oracleBlocks]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedPiopDecoders
