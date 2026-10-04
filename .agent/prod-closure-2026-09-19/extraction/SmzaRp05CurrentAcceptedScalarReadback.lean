import SmzaRp05ExecutablePiopCompletion
import SmzaRawWordReadback
import SmzaRp05RawScalarChecks
import SmzaRp05CurrentPiopFrameReadback

/-! # Scalar equations from the calculated current PIOP payload

The final transcript payload is read back as the current `piopResponse`, and
its coefficients are identified with the polynomials calculated by the
existing executable-reconstruction model.  The scalar equations then follow
for every recovered row family from the actual opened witness and masks.
This is a mathematical relation/refinement result, not Rust implementation
refinement or an accepted-execution receipt.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedScalarReadback

open Polynomial
open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript finalPayload)
open SmzaRp05ExecutableReconstruction
open SmzaRp05RawScalarChecks
open SmzaRp05RelationRefinement
open SmzaRp04RecordedTranscript (PiopInput bounded_polynomial_eq_of_coefficients)
open SmzaRp04RawRecordedTranscript
  (canonicalCoefficients digestPrefix rawInputOf rawPiopInput raw_piop_input_roundtrip)
open SmzaRawWordReadback
open V8Smz9HonestWholeViewFinalInput (Prefix fieldWord sourceFinalWords)
open SmzaRp05TracePrefixes (Payload piopResponse)
open V8Smz9EagerPrivacy (PiopCoefficients)
open V8Smz9HonestWholeViewFinalInput (alternatingCoefficientEquiv)
open V8Smz9PiopReconstruction V8Smz9PiopSoundness
open V8Smz9AdaptiveFiniteAccounting V8Smz9EagerSimulator V8Smz9ZeroKnowledge
open SmzaQ38Recovery
open SmzaRp05StatementNamespace
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "sourceWords" =>
  V8Smz9HonestWholeViewFinalInput.sourceFinalWords
local notation "alternatingCoefficientEquiv" =>
  V8Smz9HonestWholeViewFinalInput.alternatingCoefficientEquiv
local notation "RecoveredRows" => SmzaQ38Recovery.RecoveredRows

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 2000000

private theorem current_source_final_coefficient_word
    (pref : V8Smz9HonestWholeViewFinalInput.Prefix)
    (coefficients : PiopCoefficients Goldilocks) (index : Fin 3105) :
    (sourceWords pref coefficients)[8 + index.val]? =
      some (fieldWord (alternatingCoefficientEquiv.symm coefficients index)) := by
  unfold V8Smz9HonestWholeViewFinalInput.sourceFinalWords
  rw [List.getElem?_append_right (by simp only [List.length_ofFn]; omega)]
  simp only [List.length_ofFn, Nat.add_sub_cancel_left,
    List.getElem?_ofFn, dif_pos index.isLt]

private theorem current_raw_piop_coefficient_readback
    (pref : V8Smz9HonestWholeViewFinalInput.Prefix)
    (coefficients : PiopCoefficients Goldilocks) (index : Fin 3105) :
    toGoldilocks (V8SmzaOracleParser.wordAt
      (V8Smz9RawCounterCompiler.typedWordPayload
        (sourceWords pref coefficients)) (8 + index.val)) =
      alternatingCoefficientEquiv.symm coefficients index := by
  rw [word_at_typed_payload _ _ _
    (current_source_final_coefficient_word pref coefficients index)]
  exact toGoldilocks_fromGoldilocks _

private theorem current_raw_piop_all_coefficients_readback
    (pref : V8Smz9HonestWholeViewFinalInput.Prefix)
    (coefficients : PiopCoefficients Goldilocks) :
    alternatingCoefficientEquiv (fun index => toGoldilocks
      (V8SmzaOracleParser.wordAt
        (V8Smz9RawCounterCompiler.typedWordPayload
          (sourceWords pref coefficients)) (8 + index.val))) = coefficients := by
  have coordinates : (fun index : Fin 3105 => toGoldilocks
      (V8SmzaOracleParser.wordAt
        (V8Smz9RawCounterCompiler.typedWordPayload
          (sourceWords pref coefficients)) (8 + index.val))) =
      alternatingCoefficientEquiv.symm coefficients := by
    funext index
    exact current_raw_piop_coefficient_readback pref coefficients index
  rw [coordinates, Equiv.apply_symm_apply]

private def transcriptPiopInput (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (hashFpp : V8SmzaOracleParser.RawDigest) : PiopInput where
  commitmentPrefix := hashFpp
  nonlinear row index :=
    (SmzaRp05ExecutableReconstruction.nonlinearPolynomial
      dsl statement matrix opening proof row).coeff index.val
  linearHigh row index :=
    (SmzaRp05ExecutableReconstruction.linearPolynomial
      dsl statement matrix opening proof row).coeff (index.val + 1)

private theorem reconstructed_is_encoded_transcript
    (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (hashFpp : V8SmzaOracleParser.RawDigest)
    (pending : Bool) :
    reconstruct dsl statement matrix opening proof hashFpp pending =
      SmzaRp05ExecutablePcsClosureCodec.encodedTranscript
        (transcriptPiopInput dsl statement matrix opening proof hashFpp) pending := by
  rfl

private def finalPiopPayload (transcript : ReconstructedTranscript) : Payload :=
  ⟨.piop, finalPayload transcript⟩

private theorem final_payload_eq_source_payload
    (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (hashFpp : V8SmzaOracleParser.RawDigest)
    (pending : Bool) :
    finalPayload (reconstruct dsl statement matrix opening proof hashFpp pending) =
      V8Smz9RawCounterCompiler.typedWordPayload
        (sourceWords (digestPrefix hashFpp)
          (canonicalCoefficients
            (transcriptPiopInput dsl statement matrix opening proof hashFpp))) := by
  have framed := SmzaRp05ExecutablePcsClosureCodec.encoded_final_input_eq_raw_input
    (transcriptPiopInput dsl statement matrix opening proof hashFpp) pending
  rw [← reconstructed_is_encoded_transcript] at framed
  unfold SmzaRp05ExecutableFinalVerifier.finalInput
    SmzaRp04RawRecordedTranscript.rawInputOf
    SmzaRp04RawRecordedTranscript.rawPiopInput at framed
  let payload := finalPayload (reconstruct dsl statement matrix opening proof hashFpp pending)
  have payloadLength : payload.length = 24904 := by
    dsimp [payload]
    exact SmzaRp05CurrentPiopFrameReadback.current_final_payload_length _
  have aligned : 8 * (payload.length / 8) = payload.length := by
    rw [payloadLength]
  have countBound : payload.length / 8 < 256 ^ 8 := by
    rw [payloadLength]
    norm_num
  have parsedLeft := V8SmzaOracleParser.frame_roundtrip
    (SmallWoodTranscript.piopTranscriptDomain)
    payload
    (by decide)
    countBound aligned
  have parsedRight := raw_piop_input_roundtrip
    (digestPrefix hashFpp)
    (canonicalCoefficients (transcriptPiopInput dsl statement matrix opening proof hashFpp))
  have parsedSame := congrArg V8SmzaOracleParser.parseFramed framed
  change V8SmzaOracleParser.parseFramed
      (V8SmzaOracleParser.framedInput SmallWoodTranscript.piopTranscriptDomain payload) =
    V8SmzaOracleParser.parseFramed
      (SmzaRp04RawRecordedTranscript.rawPiopInput
        (digestPrefix hashFpp)
        (canonicalCoefficients
          (transcriptPiopInput dsl statement matrix opening proof hashFpp))) at parsedSame
  rw [parsedLeft, parsedRight] at parsedSame
  have payloadEq := congrArg Prod.snd (Option.some.inj parsedSame)
  exact payloadEq

/-- The actual final payload decodes to the same row polynomials reconstructed
from the stage's decoded highs and opened row scalars. -/
theorem final_payload_piop_response_is_reconstruction
    (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (hashFpp : V8SmzaOracleParser.RawDigest)
    (pending : Bool) :
    (∀ row : Fin 5,
    (piopResponse (finalPiopPayload
      (reconstruct dsl statement matrix opening proof hashFpp pending))).nonlinear row =
      SmzaRp05ExecutableReconstruction.nonlinearPolynomial
        dsl statement matrix opening proof row) ∧
    (∀ row : Fin 5,
      (piopResponse (finalPiopPayload
        (reconstruct dsl statement matrix opening proof hashFpp pending))).linearHigh row =
        fun index => (SmzaRp05ExecutableReconstruction.linearPolynomial
          dsl statement matrix opening proof row).coeff
          (index.val + 1)) := by
  have payloadEq := final_payload_eq_source_payload dsl statement matrix opening proof hashFpp pending
  have coefficients := current_raw_piop_all_coefficients_readback
    (digestPrefix hashFpp)
    (canonicalCoefficients (transcriptPiopInput dsl statement matrix opening proof hashFpp))
  have decoded : SmzaRp04TracePrefixes.piopCoefficients
      (finalPiopPayload (reconstruct dsl statement matrix opening proof hashFpp pending)) =
      canonicalCoefficients (transcriptPiopInput dsl statement matrix opening proof hashFpp) := by
    change alternatingCoefficientEquiv (fun index => toGoldilocks
      (V8SmzaOracleParser.wordAt
        (finalPayload (reconstruct dsl statement matrix opening proof hashFpp pending))
        (8 + index.val))) = _
    rw [payloadEq]
    exact coefficients
  constructor
  · intro row
    apply bounded_polynomial_eq_of_coefficients
      (left := (piopResponse (finalPiopPayload
        (reconstruct dsl statement matrix opening proof hashFpp pending))).nonlinear row)
      (right := SmzaRp05ExecutableReconstruction.nonlinearPolynomial
        dsl statement matrix opening proof row)
    · exact (piopResponse (finalPiopPayload
        (reconstruct dsl statement matrix opening proof hashFpp pending))).nonlinearDegree row
    · exact V8Smz9PiopReconstruction.restored_nonlinear_degree opening
        ((proofHighs proof).nonlinear row)
        ((SmzaRp05ExecutableReconstruction.evaluation dsl statement matrix opening proof).nonlinear row)
    · intro index
      change (V8Smz9EagerPrivacy.coefficientPolynomial
        ((SmzaRp04TracePrefixes.piopCoefficients
          (finalPiopPayload (reconstruct dsl statement matrix opening proof hashFpp pending))).1 row)).coeff index.val = _
      rw [show (SmzaRp04TracePrefixes.piopCoefficients
          (finalPiopPayload (reconstruct dsl statement matrix opening proof hashFpp pending))).1 row =
          (canonicalCoefficients
            (transcriptPiopInput dsl statement matrix opening proof hashFpp)).1 row from
            (congrArg (fun coeffs : PiopCoefficients Goldilocks => coeffs.1 row) decoded)]
      rw [show (canonicalCoefficients
          (transcriptPiopInput dsl statement matrix opening proof hashFpp)).1 row =
          (fun i => (SmzaRp05ExecutableReconstruction.nonlinearPolynomial
            dsl statement matrix opening proof row).coeff i.val) from rfl]
      have degreeLt :
          (SmzaRp05ExecutableReconstruction.nonlinearPolynomial
            dsl statement matrix opening proof row).natDegree < 489 := by
        change (V8Smz9PiopReconstruction.restoredNonlinear opening
          ((proofHighs proof).nonlinear row)
          ((SmzaRp05ExecutableReconstruction.evaluation dsl statement matrix opening proof).nonlinear row)).natDegree < 489
        exact Nat.lt_succ_of_le
          (V8Smz9PiopReconstruction.restored_nonlinear_degree opening
            ((proofHighs proof).nonlinear row)
            ((SmzaRp05ExecutableReconstruction.evaluation dsl statement matrix opening proof).nonlinear row))
      rw [V8Smz9EagerPrivacy.coefficient_polynomial_of_coefficients
        (SmzaRp05ExecutableReconstruction.nonlinearPolynomial
          dsl statement matrix opening proof row) degreeLt]
  · intro row
    have decodedLinear := congrArg Prod.snd decoded
    funext index
    change (SmzaRp04TracePrefixes.piopCoefficients
      (finalPiopPayload (reconstruct dsl statement matrix opening proof hashFpp pending))).2 row index =
        (SmzaRp05ExecutableReconstruction.linearPolynomial
          dsl statement matrix opening proof row).coeff (index.val + 1)
    rw [show (SmzaRp04TracePrefixes.piopCoefficients
      (finalPiopPayload (reconstruct dsl statement matrix opening proof hashFpp pending))).2 row =
      (canonicalCoefficients
        (transcriptPiopInput dsl statement matrix opening proof hashFpp)).2 row from
        congrArg (fun coefficients => coefficients row) decodedLinear]
    rw [show (canonicalCoefficients
        (transcriptPiopInput dsl statement matrix opening proof hashFpp)).2 row =
        (fun i => (SmzaRp05ExecutableReconstruction.linearPolynomial
          dsl statement matrix opening proof row).coeff (i.val + 1)) from rfl]

/-- The scalar-bearing projection of the existing decoded PIOP row scalars.
The remaining `OpeningMessage` fields are immaterial to `ScalarChecks`; their
values are fixed here rather than supplied as verifier evidence. -/
private def scalarOpeningMessage (proof : DecodedPiopFields) :
    SmzaRp04ChronologicalAlgebra.OpeningMessage where
  witness := SmzaRp05ExecutableReconstruction.witness proof
  masks := SmzaRp05ExecutableReconstruction.masks proof
  partials := (fun _ _ _ => 0, fun _ _ => 0)
  nonlinearHigh := fun row => nonlinearHighPart
    ((SmzaRp05ExecutableReconstruction.proofHighs proof).nonlinear row)
  linearHigh := fun row => linearHighPart
    ((SmzaRp05ExecutableReconstruction.proofHighs proof).linear row)
  correction := fun _ => 0
  claimedCoefficients := fun _ _ => 0

private theorem reconstructed_final_payload_supplies_scalar_checks
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (matrix : Matrix (dsl.width statement))
    (opening : Opening) (proof : DecodedPiopFields)
    (hashFpp : V8SmzaOracleParser.RawDigest) (pending : Bool)
    (rows : RecoveredRows) :
    ScalarChecks dsl certificates statement rows matrix
      (piopResponse (finalPiopPayload
        (reconstruct dsl statement matrix opening proof hashFpp pending)))
      opening (scalarOpeningMessage proof) := by
  let response := piopResponse (finalPiopPayload
    (reconstruct dsl statement matrix opening proof hashFpp pending))
  let message := scalarOpeningMessage proof
  let trace := SmzaRp05ExecutableReconstruction.evaluation dsl statement matrix opening proof
  let candidate := SmzaRp05RelationRefinement.candidate dsl certificates statement rows
  have responseReadback := final_payload_piop_response_is_reconstruction
    dsl statement matrix opening proof hashFpp pending
  have targetReadback := batched_target_eq_public dsl certificates statement rows matrix
  intro row coordinate
  change Fin 6 at coordinate
  let point := baseOpeningPoints opening.1 coordinate
  constructor
  · have responseEval : (response.nonlinear row).eval point = trace.nonlinear row coordinate := by
      rw [responseReadback.1 row]
      exact SmzaRp05ExecutableReconstruction.reconstructed_nonlinear_evaluation
        dsl statement matrix opening proof row coordinate
    have denominatorEq :
        (Interactive.packingVanishing (Finset.univ : Finset (Fin 64))
          V8Smz9EagerSimulator.canonicalPacking).eval point =
          SmzaRp04RestoredTranscriptChecks.denominator point := rfl
    have traceEq : trace.nonlinear row coordinate =
        (∑ check, matrix row check * paddedNonlinearScalar dsl statement
          (message.witness coordinate) check) /
          SmzaRp04RestoredTranscriptChecks.denominator point +
          message.masks.1 coordinate row := rfl
    rw [responseEval, denominatorEq, traceEq, add_sub_cancel_right]
    exact mul_div_cancel₀ _
      (SmzaRp04RestoredTranscriptChecks.admissible_denominator_nonzero opening coordinate)
  · have targetEq := congrArg (fun targets => targets row) targetReadback
    let transcript := V8Smz9PiopReconstruction.reconstructedTranscript opening
      (SmzaRp05ExecutableReconstruction.proofHighs proof) trace
      (fun index => batchedTarget candidate matrix index)
    have sameHigh : response.linearHigh row = transcript.linearHigh row := by
      funext index
      rw [responseReadback.2 row]
      change (SmzaRp05ExecutableReconstruction.linearPolynomial
        dsl statement matrix opening proof row).coeff (index.val + 1) = _
      unfold SmzaRp05ExecutableReconstruction.linearPolynomial
      unfold transcript V8Smz9PiopReconstruction.reconstructedTranscript
      change (V8Smz9PiopReconstruction.reconstructedLinear opening
          ((SmzaRp05ExecutableReconstruction.proofHighs proof).linear row)
          (trace.linear row) (publicBatchedTarget dsl statement matrix row)).coeff
          (index.val + 1) =
        (V8Smz9PiopReconstruction.reconstructedLinear opening
          ((SmzaRp05ExecutableReconstruction.proofHighs proof).linear row)
          (trace.linear row) (batchedTarget candidate matrix row)).coeff
          (index.val + 1)
      rw [targetEq]
    have claimedSame : claimedLinear candidate matrix response row =
        claimedLinear candidate matrix transcript row := by
      unfold claimedLinear
      rw [sameHigh]
    have claimedEval : (claimedLinear candidate matrix response row).eval point =
        trace.linear row coordinate := by
      rw [claimedSame,
        reconstructed_claimed_linear candidate matrix opening
          (SmzaRp05ExecutableReconstruction.proofHighs proof) trace row]
      rw [targetEq]
      change (SmzaRp05ExecutableReconstruction.linearPolynomial
        dsl statement matrix opening proof row).eval point = _
      exact SmzaRp05ExecutableReconstruction.reconstructed_linear_evaluation
        dsl statement matrix opening proof row coordinate
    have traceEq : trace.linear row coordinate =
        (∑ check, matrix row check * paddedLinearScalar dsl statement
          (message.witness coordinate) point check) + message.masks.2 coordinate row := rfl
    rw [claimedEval, traceEq, add_sub_cancel_right]

/-- Current generated relation scalar checks follow for every recovered row
family from the actual execution-stage proof fields and calculated final
PIOP payload. The theorem is mathematical/source-level; it does not assert
Rust evaluator refinement. -/
theorem execution_stages_supply_scalar_checks_for_all_rows
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (statement : Statement)
    (pending : Bool) (binding : List HegemonCrypto.CanonicalBytes.Byte)
    (statementBinding : List Nat) (nonce : Fin (2 ^ 32))
    (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : ReconstructedTranscript)
    (execution : SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement
      pending binding statementBinding nonce wire oracle transcript) :
    ∀ rows : RecoveredRows,
      ScalarChecks dsl certificates statement rows execution.matrix
        (piopResponse (finalPiopPayload transcript)) execution.opening
        (scalarOpeningMessage execution.piop) := by
  intro rows
  have result := reconstructed_final_payload_supplies_scalar_checks dsl certificates statement
    execution.matrix execution.opening execution.piop execution.hashFpp
    execution.finalPending rows
  have responseEq :
      piopResponse (finalPiopPayload
        (reconstruct dsl statement execution.matrix execution.opening execution.piop
          execution.hashFpp execution.finalPending)) =
      piopResponse (finalPiopPayload transcript) :=
    congrArg (fun calculated => piopResponse (finalPiopPayload calculated))
      execution.reconstructed
  rw [responseEq] at result
  exact result

/-- Scalar checks depend only on the opened witness and mask fields of the
post-opening message. Any real message with those two reconstructed fields
inherits the checks; its authenticated PCS views and claimed-coefficient
payload are left untouched. -/
theorem execution_stages_supply_scalar_checks_for_opening_message
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (statement : Statement)
    (pending : Bool) (binding : List HegemonCrypto.CanonicalBytes.Byte)
    (statementBinding : List Nat) (nonce : Fin (2 ^ 32))
    (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : ReconstructedTranscript)
    (execution : SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement
      pending binding statementBinding nonce wire oracle transcript)
    (message : SmzaRp04ChronologicalAlgebra.OpeningMessage)
    (witnessEq : message.witness = SmzaRp05ExecutableReconstruction.witness execution.piop)
    (masksEq : message.masks = SmzaRp05ExecutableReconstruction.masks execution.piop) :
    ∀ rows : RecoveredRows,
      ScalarChecks dsl certificates statement rows execution.matrix
        (piopResponse (finalPiopPayload transcript)) execution.opening message := by
  intro rows
  have scalar := execution_stages_supply_scalar_checks_for_all_rows ns dsl certificates
    statement pending binding statementBinding nonce wire oracle transcript execution rows
  intro row coordinate
  have fields := scalar row coordinate
  rw [witnessEq, masksEq]
  simpa only [scalarOpeningMessage] using fields

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedScalarReadback
