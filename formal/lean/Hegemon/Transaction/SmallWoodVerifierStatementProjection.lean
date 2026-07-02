import Hegemon.Transaction.SmallWoodCandidateWrapperAdmission
import Hegemon.Transaction.SmallWoodPublicStatementBinding

namespace Hegemon
namespace Transaction
namespace SmallWoodVerifierStatementProjection

inductive VerifierStatementProjectionReject where
  | candidateWrapperRejected
  | publicStatementBindingRejected
  | transcriptBindingRejected
  | arithmetizationMismatch
  | publicValuesMismatch
  | rowCountMismatch
  | packingFactorMismatch
  | constraintDegreeMismatch
  | linearConstraintOffsetsMismatch
  | linearConstraintIndicesMismatch
  | linearConstraintCoefficientsMismatch
  | linearConstraintTargetsMismatch
  | auxiliaryWitnessLimbCountMismatch
  | profileMaterialMismatch
  | transcriptBytesMismatch
  | proofBytesEmpty
  | verifierRejected
deriving DecidableEq, Repr

structure VerifierStatementProjectionInput where
  candidateWrapperAccepted : Bool
  publicStatementBindingAccepted : Bool
  transcriptBindingAccepted : Bool
  arithmetizationMatches : Bool
  publicValuesMatch : Bool
  rowCountMatches : Bool
  packingFactorMatches : Bool
  constraintDegreeMatches : Bool
  linearConstraintOffsetsMatch : Bool
  linearConstraintIndicesMatch : Bool
  linearConstraintCoefficientsMatch : Bool
  linearConstraintTargetsMatch : Bool
  auxiliaryWitnessLimbCountMatches : Bool
  profileMaterialMatches : Bool
  transcriptBytesMatch : Bool
  proofBytesNonempty : Bool
  verifierAccepted : Bool
deriving DecidableEq, Repr

def smallWoodVerifierStatementProjectionAccepts
    (input : VerifierStatementProjectionInput) : Bool :=
  input.candidateWrapperAccepted
    && input.publicStatementBindingAccepted
    && input.transcriptBindingAccepted
    && input.arithmetizationMatches
    && input.publicValuesMatch
    && input.rowCountMatches
    && input.packingFactorMatches
    && input.constraintDegreeMatches
    && input.linearConstraintOffsetsMatch
    && input.linearConstraintIndicesMatch
    && input.linearConstraintCoefficientsMatch
    && input.linearConstraintTargetsMatch
    && input.auxiliaryWitnessLimbCountMatches
    && input.profileMaterialMatches
    && input.transcriptBytesMatch
    && input.proofBytesNonempty
    && input.verifierAccepted

def smallWoodVerifierStatementProjectionFacts
    (input : VerifierStatementProjectionInput) : Prop :=
  input.candidateWrapperAccepted = true
    ∧ input.publicStatementBindingAccepted = true
    ∧ input.transcriptBindingAccepted = true
    ∧ input.arithmetizationMatches = true
    ∧ input.publicValuesMatch = true
    ∧ input.rowCountMatches = true
    ∧ input.packingFactorMatches = true
    ∧ input.constraintDegreeMatches = true
    ∧ input.linearConstraintOffsetsMatch = true
    ∧ input.linearConstraintIndicesMatch = true
    ∧ input.linearConstraintCoefficientsMatch = true
    ∧ input.linearConstraintTargetsMatch = true
    ∧ input.auxiliaryWitnessLimbCountMatches = true
    ∧ input.profileMaterialMatches = true
    ∧ input.transcriptBytesMatch = true
    ∧ input.proofBytesNonempty = true
    ∧ input.verifierAccepted = true

def evaluateSmallWoodVerifierStatementProjectionRejection
    (input : VerifierStatementProjectionInput) :
    Option VerifierStatementProjectionReject :=
  if input.candidateWrapperAccepted then
    if input.publicStatementBindingAccepted then
      if input.transcriptBindingAccepted then
        if input.arithmetizationMatches then
          if input.publicValuesMatch then
            if input.rowCountMatches then
              if input.packingFactorMatches then
                if input.constraintDegreeMatches then
                  if input.linearConstraintOffsetsMatch then
                    if input.linearConstraintIndicesMatch then
                      if input.linearConstraintCoefficientsMatch then
                        if input.linearConstraintTargetsMatch then
                          if input.auxiliaryWitnessLimbCountMatches then
                            if input.profileMaterialMatches then
                              if input.transcriptBytesMatch then
                                if input.proofBytesNonempty then
                                  if input.verifierAccepted then
                                    none
                                  else
                                    some VerifierStatementProjectionReject.verifierRejected
                                else
                                  some VerifierStatementProjectionReject.proofBytesEmpty
                              else
                                some VerifierStatementProjectionReject.transcriptBytesMismatch
                            else
                              some VerifierStatementProjectionReject.profileMaterialMismatch
                          else
                            some VerifierStatementProjectionReject.auxiliaryWitnessLimbCountMismatch
                        else
                          some VerifierStatementProjectionReject.linearConstraintTargetsMismatch
                      else
                        some VerifierStatementProjectionReject.linearConstraintCoefficientsMismatch
                    else
                      some VerifierStatementProjectionReject.linearConstraintIndicesMismatch
                  else
                    some VerifierStatementProjectionReject.linearConstraintOffsetsMismatch
                else
                  some VerifierStatementProjectionReject.constraintDegreeMismatch
              else
                some VerifierStatementProjectionReject.packingFactorMismatch
            else
              some VerifierStatementProjectionReject.rowCountMismatch
          else
            some VerifierStatementProjectionReject.publicValuesMismatch
        else
          some VerifierStatementProjectionReject.arithmetizationMismatch
      else
        some VerifierStatementProjectionReject.transcriptBindingRejected
    else
      some VerifierStatementProjectionReject.publicStatementBindingRejected
  else
    some VerifierStatementProjectionReject.candidateWrapperRejected

theorem accepted_smallwood_verifier_statement_projection_implies_export_surface
    {input : VerifierStatementProjectionInput}
    (accepted : smallWoodVerifierStatementProjectionAccepts input = true) :
    smallWoodVerifierStatementProjectionFacts input := by
  unfold smallWoodVerifierStatementProjectionAccepts at accepted
  unfold smallWoodVerifierStatementProjectionFacts
  simp only [Bool.and_eq_true] at accepted ⊢
  simpa only [and_assoc] using accepted

def validInlineMerkleProjectionInput : VerifierStatementProjectionInput :=
  { candidateWrapperAccepted := true
    publicStatementBindingAccepted := true
    transcriptBindingAccepted := true
    arithmetizationMatches := true
    publicValuesMatch := true
    rowCountMatches := true
    packingFactorMatches := true
    constraintDegreeMatches := true
    linearConstraintOffsetsMatch := true
    linearConstraintIndicesMatch := true
    linearConstraintCoefficientsMatch := true
    linearConstraintTargetsMatch := true
    auxiliaryWitnessLimbCountMatches := true
    profileMaterialMatches := true
    transcriptBytesMatch := true
    proofBytesNonempty := true
    verifierAccepted := true }

theorem valid_inline_merkle_projection_accepts :
    evaluateSmallWoodVerifierStatementProjectionRejection
      validInlineMerkleProjectionInput = none := by
  decide

theorem public_value_drift_rejects_before_row_shape :
    evaluateSmallWoodVerifierStatementProjectionRejection
      { validInlineMerkleProjectionInput with
        publicValuesMatch := false
        rowCountMatches := false } =
      some VerifierStatementProjectionReject.publicValuesMismatch := by
  decide

theorem linear_constraint_offset_drift_rejects_before_indices :
    evaluateSmallWoodVerifierStatementProjectionRejection
      { validInlineMerkleProjectionInput with
        linearConstraintOffsetsMatch := false
        linearConstraintIndicesMatch := false } =
      some VerifierStatementProjectionReject.linearConstraintOffsetsMismatch := by
  decide

theorem transcript_byte_drift_rejects_before_empty_proof :
    evaluateSmallWoodVerifierStatementProjectionRejection
      { validInlineMerkleProjectionInput with
        transcriptBytesMatch := false
        proofBytesNonempty := false } =
      some VerifierStatementProjectionReject.transcriptBytesMismatch := by
  decide

theorem verifier_rejection_stays_last_after_projection_facts :
    evaluateSmallWoodVerifierStatementProjectionRejection
      { validInlineMerkleProjectionInput with verifierAccepted := false } =
      some VerifierStatementProjectionReject.verifierRejected := by
  decide

end SmallWoodVerifierStatementProjection
end Transaction
end Hegemon
