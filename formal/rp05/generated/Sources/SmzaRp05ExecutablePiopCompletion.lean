import SmzaRp05ExecutablePcsClosureStatement
import SmzaRp05ExecutablePcsClosureCodec
import SmzaRp05ExecutableReconstructionRestoreBridge

/-! # Accepted RP05 final PIOP completion

This names the final PIOP completion already calculated from the decoded
proof and the actual PCS/opening stages.  Nonlinear restoration uses the
existing 483 high words and six relation evaluations; linear restoration
uses the existing 126 high words, the appended zero point, and the public
packing correction.  The existing final-input codec serializes the resulting
3113 words in Rust's repetition-major order.  No coefficient array, digest,
or accepting predicate is supplied independently.

The accepted endpoint below starts with the assembled verifier's ordinary
`eval = some ()`, extracts its `ExecutionStages`, and proves the matching
finalizer accepts the calculated transcript.  This is the source-level
mathematical completion; refinement of relation evaluation and field
arithmetic to the Rust implementation remains a separate obligation.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePiopCompletion

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript finalize finalInput)
open SmzaRp05ExecutableReconstruction (DecodedPiopFields reconstruct)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000
noncomputable section

/-- Native-source-shaped coefficient restoration and linear correction
from the values calculated by `ExecutionStages`. -/
def completedTranscript (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    {ns : Namespace} {pending : Bool} {binding : List Byte}
    {statementBinding : List Nat} {nonce : Fin (2 ^ 32)}
    {wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView}
    {oracle : Oracle} {transcript : ReconstructedTranscript}
    (execution : ExecutionStages ns dsl statement pending binding statementBinding
      nonce wire oracle transcript) : ReconstructedTranscript :=
  reconstruct dsl statement execution.matrix execution.opening execution.piop
    execution.hashFpp execution.finalPending

/-- The existing encoded digest comparison, after the computed completion. -/
def completionProgram (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    {ns : Namespace} {pending : Bool} {binding : List Byte}
    {statementBinding : List Nat} {nonce : Fin (2 ^ 32)}
    {wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView}
    {oracle : Oracle} {transcript : ReconstructedTranscript}
    (execution : ExecutionStages ns dsl statement pending binding statementBinding
      nonce wire oracle transcript) : SmzaRp05ExecutableMerkleVerifier.Program Unit :=
  finalize wire.hPiop (completedTranscript dsl statement execution)

/-- All 489 nonlinear coefficients and the 132 corrected nonconstant linear
coefficients are the actual outputs of reconstruction on these stages. -/
theorem completion_coefficients_are_calculated
    (dsl : RelationDsl) (statement : SmzaRp05StatementNamespace.Statement)
    {ns : Namespace} {pending : Bool} {binding : List Byte}
    {statementBinding : List Nat} {nonce : Fin (2 ^ 32)}
    {wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView}
    {oracle : Oracle} {transcript : ReconstructedTranscript}
    (execution : ExecutionStages ns dsl statement pending binding statementBinding
      nonce wire oracle transcript) :
    completedTranscript dsl statement execution = transcript :=
  execution.reconstructed

private theorem completion_artifact_fields
    (dsl : RelationDsl) (statement : SmzaRp05StatementNamespace.Statement)
    {ns : Namespace} {pending : Bool} {binding : List Byte}
    {statementBinding : List Nat} {nonce : Fin (2 ^ 32)}
    {wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView}
    {oracle : Oracle} {transcript : ReconstructedTranscript}
    (execution : ExecutionStages ns dsl statement pending binding statementBinding
      nonce wire oracle transcript) :
    finalInput (completedTranscript dsl statement execution) =
        SmzaRp04RawRecordedTranscript.rawInputOf
          (SmzaRp04RecordedTranscript.transcriptInput execution.hashFpp
            (V8Smz9PiopReconstruction.reconstructedTranscript execution.opening
              (SmzaRp05ExecutableReconstruction.proofHighs execution.piop)
              (SmzaRp05ExecutableReconstruction.evaluation dsl statement
                execution.matrix execution.opening execution.piop)
              (SmzaRp05RawScalarChecks.publicBatchedTarget dsl statement
                execution.matrix))) ∧
      SmzaRp05ExecutableReconstructionRestoreBridge.nonlinearWords dsl statement
        execution.matrix execution.opening execution.piop =
          (completedTranscript dsl statement execution).nonlinear ∧
      SmzaRp05ExecutableReconstructionRestoreBridge.correctedWords dsl statement
        execution.matrix execution.opening execution.piop =
          (completedTranscript dsl statement execution).linearHigh := by
  have codec := SmzaRp05ExecutablePcsClosureCodec.reconstructed_final_input_eq_typed
    dsl statement execution.matrix execution.opening execution.piop execution.hashFpp
    execution.finalPending
  have arrays :=
    SmzaRp05ExecutableReconstructionRestoreBridge.final_coefficient_arrays
      dsl statement execution.matrix execution.opening execution.piop execution.hashFpp
      execution.finalPending
  refine ⟨?_, ?_⟩
  · change finalInput (reconstruct dsl statement execution.matrix execution.opening
      execution.piop execution.hashFpp execution.finalPending) = _
    exact codec
  · refine ⟨?_, ?_⟩
    · change SmzaRp05ExecutableReconstructionRestoreBridge.nonlinearWords dsl statement
        execution.matrix execution.opening execution.piop =
          (reconstruct dsl statement execution.matrix execution.opening
            execution.piop execution.hashFpp execution.finalPending).nonlinear
      exact arrays.1
    · change SmzaRp05ExecutableReconstructionRestoreBridge.correctedWords dsl statement
        execution.matrix execution.opening execution.piop =
          (reconstruct dsl statement execution.matrix execution.opening
            execution.piop execution.hashFpp execution.finalPending).linearHigh
      exact arrays.2

-- Keep the large reconstruction term opaque while elaborating the dependent
-- accepted-result tuple. The component coefficient/codec theorems below are
-- the explicit places that unfold or rewrite it.
attribute [local irreducible] completedTranscript

/-- An accepted assembled verifier has a computed final PIOP transcript
whose existing finalizer accepts, and whose exact final byte input is the
typed source transcript input.  Both the transcript and completion stages
are extracted from the accepted execution; neither is a caller certificate. -/
theorem accepted_verifier_has_piop_completion
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : Oracle)
    (accepted : (SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl
      statement pending nonce wire).eval oracle = some ()) :
    ∃ transcript,
      ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire oracle transcript,
        transcript.pendingXofFailure = false ∧
        (completionProgram dsl statement execution).eval oracle = some () ∧
        oracle (finalInput (completedTranscript dsl statement execution)) = wire.hPiop ∧
        finalInput (completedTranscript dsl statement execution) =
          SmzaRp04RawRecordedTranscript.rawInputOf
            (SmzaRp04RecordedTranscript.transcriptInput execution.hashFpp
              (V8Smz9PiopReconstruction.reconstructedTranscript execution.opening
                (SmzaRp05ExecutableReconstruction.proofHighs execution.piop)
                (SmzaRp05ExecutableReconstruction.evaluation dsl statement
                  execution.matrix execution.opening execution.piop)
                (SmzaRp05RawScalarChecks.publicBatchedTarget dsl statement
                  execution.matrix))) ∧
        SmzaRp05ExecutableReconstructionRestoreBridge.nonlinearWords dsl statement
          execution.matrix execution.opening execution.piop =
            (completedTranscript dsl statement execution).nonlinear ∧
        SmzaRp05ExecutableReconstructionRestoreBridge.correctedWords dsl statement
          execution.matrix execution.opening execution.piop =
            (completedTranscript dsl statement execution).linearHigh := by
  obtain ⟨transcript, ⟨execution⟩, clean, digestEqual, _recorded⟩ :=
    SmzaRp05ExecutablePcsClosureStatement.accepted_current_statement_has_stages
      ns dsl statement pending nonce wire oracle accepted
  have completionEq := completion_coefficients_are_calculated dsl statement execution
  have completionAccept :
      (completionProgram dsl statement execution).eval oracle = some () := by
    unfold completionProgram
    rw [SmzaRp05ExecutableFinalVerifier.finalize_evaluates, completionEq]
    simp [SmzaRp05ExecutableFinalVerifier.verdict, clean, digestEqual]
  have recomputedHash :
      oracle (finalInput (completedTranscript dsl statement execution)) = wire.hPiop := by
    rw [completionEq]
    exact digestEqual
  have artifact := completion_artifact_fields dsl statement execution
  apply Exists.intro transcript
  apply Exists.intro execution
  apply And.intro clean
  apply And.intro completionAccept
  apply And.intro recomputedHash
  exact artifact

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePiopCompletion
