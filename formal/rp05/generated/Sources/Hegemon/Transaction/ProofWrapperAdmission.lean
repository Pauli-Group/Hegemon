namespace Hegemon
namespace Transaction
namespace ProofWrapperAdmission

inductive ProofWrapperReject where
  | nonExactConsumption
  | nonCanonicalReencode
  | unsupportedBackend
  | missingProofBytes
  | missingSerializedPublicInputs
  | invalidPublicInputs
  | nullifierVectorMismatch
  | commitmentVectorMismatch
  | balanceSlotMismatch
  | verifierRejected
deriving DecidableEq, Repr

structure ProofWrapperInput where
  exactConsumption : Bool
  canonicalReencode : Bool
  backendSupported : Bool
  proofBytesPresent : Bool
  serializedPublicInputsPresent : Bool
  publicInputsValid : Bool
  nullifierVectorAgrees : Bool
  commitmentVectorAgrees : Bool
  balanceSlotsAgree : Bool
  verifierAccepts : Bool
deriving DecidableEq, Repr

def proofWrapperPreconditions (input : ProofWrapperInput) : Bool :=
  input.exactConsumption
    && input.canonicalReencode
    && input.backendSupported
    && input.proofBytesPresent
    && input.serializedPublicInputsPresent
    && input.publicInputsValid
    && input.nullifierVectorAgrees
    && input.commitmentVectorAgrees
    && input.balanceSlotsAgree
    && input.verifierAccepts

def firstProofWrapperRejection (input : ProofWrapperInput) : ProofWrapperReject :=
  if !input.exactConsumption then
    ProofWrapperReject.nonExactConsumption
  else if !input.canonicalReencode then
    ProofWrapperReject.nonCanonicalReencode
  else if !input.backendSupported then
    ProofWrapperReject.unsupportedBackend
  else if !input.proofBytesPresent then
    ProofWrapperReject.missingProofBytes
  else if !input.serializedPublicInputsPresent then
    ProofWrapperReject.missingSerializedPublicInputs
  else if !input.publicInputsValid then
    ProofWrapperReject.invalidPublicInputs
  else if !input.nullifierVectorAgrees then
    ProofWrapperReject.nullifierVectorMismatch
  else if !input.commitmentVectorAgrees then
    ProofWrapperReject.commitmentVectorMismatch
  else if !input.balanceSlotsAgree then
    ProofWrapperReject.balanceSlotMismatch
  else if !input.verifierAccepts then
    ProofWrapperReject.verifierRejected
  else
    ProofWrapperReject.verifierRejected

def evaluateProofWrapperRejection (input : ProofWrapperInput) : Option ProofWrapperReject :=
  if proofWrapperPreconditions input then
    none
  else
    some (firstProofWrapperRejection input)

def proofWrapperAccepts (input : ProofWrapperInput) : Bool :=
  evaluateProofWrapperRejection input = none

def acceptedProofWrapperSurface (input : ProofWrapperInput) : Prop :=
  input.exactConsumption = true
    ∧ input.canonicalReencode = true
    ∧ input.backendSupported = true
    ∧ input.proofBytesPresent = true
    ∧ input.serializedPublicInputsPresent = true
    ∧ input.publicInputsValid = true
    ∧ input.nullifierVectorAgrees = true
    ∧ input.commitmentVectorAgrees = true
    ∧ input.balanceSlotsAgree = true
    ∧ input.verifierAccepts = true

theorem accepts_iff_proof_wrapper_preconditions {input : ProofWrapperInput} :
    proofWrapperAccepts input = true ↔ proofWrapperPreconditions input = true := by
  by_cases h : proofWrapperPreconditions input <;>
    simp [proofWrapperAccepts, evaluateProofWrapperRejection, h]

theorem proofWrapperAccepts_implies_statement_surface {input : ProofWrapperInput}
    (accepted : proofWrapperAccepts input = true) :
    acceptedProofWrapperSurface input := by
  have preconditions :=
    (accepts_iff_proof_wrapper_preconditions (input := input)).mp accepted
  simp [proofWrapperPreconditions] at preconditions
  rcases preconditions with ⟨preconditions, verifierAccepts⟩
  rcases preconditions with ⟨preconditions, balanceSlotsAgree⟩
  rcases preconditions with ⟨preconditions, commitmentVectorAgrees⟩
  rcases preconditions with ⟨preconditions, nullifierVectorAgrees⟩
  rcases preconditions with ⟨preconditions, publicInputsValid⟩
  rcases preconditions with ⟨preconditions, serializedPublicInputsPresent⟩
  rcases preconditions with ⟨preconditions, proofBytesPresent⟩
  rcases preconditions with ⟨preconditions, backendSupported⟩
  rcases preconditions with ⟨exactConsumption, canonicalReencode⟩
  exact
    ⟨exactConsumption, canonicalReencode, backendSupported, proofBytesPresent,
      serializedPublicInputsPresent, publicInputsValid, nullifierVectorAgrees,
      commitmentVectorAgrees, balanceSlotsAgree, verifierAccepts⟩

structure ProofWrapperMetadataProjectionInput where
  wrapperNullifiersEqualBoundStatement : Bool
  wrapperCommitmentsEqualBoundStatement : Bool
  wrapperBalanceSlotsEqualBoundStatement : Bool
  serializedPublicInputsEqualBoundProjection : Bool
  publicNullifierRowsWithinStatementBoundary : Bool
  publicCiphertextRowsWithinStatementBoundary : Bool
  publicAssetRowsWithinStatementBoundary : Bool
deriving DecidableEq, Repr

def metadataProjectionFromAdmissionInput
    (input : ProofWrapperInput) : ProofWrapperMetadataProjectionInput :=
  { wrapperNullifiersEqualBoundStatement := input.nullifierVectorAgrees
    wrapperCommitmentsEqualBoundStatement := input.commitmentVectorAgrees
    wrapperBalanceSlotsEqualBoundStatement := input.balanceSlotsAgree
    serializedPublicInputsEqualBoundProjection := input.publicInputsValid
    publicNullifierRowsWithinStatementBoundary := input.publicInputsValid
    publicCiphertextRowsWithinStatementBoundary := input.publicInputsValid
    publicAssetRowsWithinStatementBoundary :=
      input.publicInputsValid && input.balanceSlotsAgree }

def proofWrapperMetadataProjectionPreconditions
    (input : ProofWrapperMetadataProjectionInput) : Bool :=
  input.wrapperNullifiersEqualBoundStatement
    && input.wrapperCommitmentsEqualBoundStatement
    && input.wrapperBalanceSlotsEqualBoundStatement
    && input.serializedPublicInputsEqualBoundProjection
    && input.publicNullifierRowsWithinStatementBoundary
    && input.publicCiphertextRowsWithinStatementBoundary
    && input.publicAssetRowsWithinStatementBoundary

def proofWrapperMetadataProjectionAccepts
    (input : ProofWrapperMetadataProjectionInput) : Bool :=
  proofWrapperMetadataProjectionPreconditions input

def acceptedProofWrapperMetadataProjectionSurface
    (input : ProofWrapperMetadataProjectionInput) : Prop :=
  input.wrapperNullifiersEqualBoundStatement = true
    ∧ input.wrapperCommitmentsEqualBoundStatement = true
    ∧ input.wrapperBalanceSlotsEqualBoundStatement = true
    ∧ input.serializedPublicInputsEqualBoundProjection = true
    ∧ input.publicNullifierRowsWithinStatementBoundary = true
    ∧ input.publicCiphertextRowsWithinStatementBoundary = true
    ∧ input.publicAssetRowsWithinStatementBoundary = true

theorem metadataProjectionAccepts_iff_preconditions
    {input : ProofWrapperMetadataProjectionInput} :
    proofWrapperMetadataProjectionAccepts input = true
      ↔ proofWrapperMetadataProjectionPreconditions input = true := by
  rfl

theorem proofWrapperMetadataProjectionAccepts_implies_boundary_surface
    {input : ProofWrapperMetadataProjectionInput}
    (accepted : proofWrapperMetadataProjectionAccepts input = true) :
    acceptedProofWrapperMetadataProjectionSurface input := by
  simp [proofWrapperMetadataProjectionAccepts,
    proofWrapperMetadataProjectionPreconditions] at accepted
  rcases accepted with
    ⟨⟨⟨⟨⟨⟨hNullifiers, hCommitments⟩, hBalance⟩, hSerialized⟩,
      hNullifierRows⟩, hCiphertextRows⟩, hAssetRows⟩
  exact
    ⟨hNullifiers, hCommitments, hBalance, hSerialized, hNullifierRows,
      hCiphertextRows, hAssetRows⟩

theorem proofWrapperAccepts_implies_metadata_projection_from_admission_accepts
    {input : ProofWrapperInput}
    (accepted : proofWrapperAccepts input = true) :
    proofWrapperMetadataProjectionAccepts
      (metadataProjectionFromAdmissionInput input) = true := by
  have surface := proofWrapperAccepts_implies_statement_surface accepted
  rcases surface with
    ⟨_, _, _, _, _, publicInputsValid, nullifierVectorAgrees,
      commitmentVectorAgrees, balanceSlotsAgree, _⟩
  simp [metadataProjectionFromAdmissionInput,
    proofWrapperMetadataProjectionAccepts,
    proofWrapperMetadataProjectionPreconditions,
    publicInputsValid, nullifierVectorAgrees, commitmentVectorAgrees,
    balanceSlotsAgree]

theorem proofWrapperAccepts_implies_no_metadata_projection_or_row_extension
    {input : ProofWrapperInput}
    (accepted : proofWrapperAccepts input = true) :
    acceptedProofWrapperMetadataProjectionSurface
      (metadataProjectionFromAdmissionInput input) :=
  proofWrapperMetadataProjectionAccepts_implies_boundary_surface
    (proofWrapperAccepts_implies_metadata_projection_from_admission_accepts
      accepted)

def validWrapper : ProofWrapperInput :=
  { exactConsumption := true
    canonicalReencode := true
    backendSupported := true
    proofBytesPresent := true
    serializedPublicInputsPresent := true
    publicInputsValid := true
    nullifierVectorAgrees := true
    commitmentVectorAgrees := true
    balanceSlotsAgree := true
    verifierAccepts := true }

def validMetadataProjection : ProofWrapperMetadataProjectionInput :=
  metadataProjectionFromAdmissionInput validWrapper

theorem valid_wrapper_accepts :
    evaluateProofWrapperRejection validWrapper = none := by
  decide

theorem non_exact_consumption_rejects :
    evaluateProofWrapperRejection { validWrapper with exactConsumption := false } =
      some ProofWrapperReject.nonExactConsumption := by
  decide

theorem non_canonical_reencode_rejects_after_exact_consumption :
    evaluateProofWrapperRejection { validWrapper with canonicalReencode := false } =
      some ProofWrapperReject.nonCanonicalReencode := by
  decide

theorem unsupported_backend_rejects_after_codec_admission :
    evaluateProofWrapperRejection { validWrapper with backendSupported := false } =
      some ProofWrapperReject.unsupportedBackend := by
  decide

theorem missing_proof_bytes_rejects_before_public_inputs :
    evaluateProofWrapperRejection { validWrapper with proofBytesPresent := false } =
      some ProofWrapperReject.missingProofBytes := by
  decide

theorem missing_serialized_public_inputs_rejects_before_public_validity :
    evaluateProofWrapperRejection { validWrapper with serializedPublicInputsPresent := false } =
      some ProofWrapperReject.missingSerializedPublicInputs := by
  decide

theorem invalid_public_inputs_rejects_before_balance_slots :
    evaluateProofWrapperRejection { validWrapper with publicInputsValid := false } =
      some ProofWrapperReject.invalidPublicInputs := by
  decide

theorem nullifier_vector_mismatch_rejects_before_commitment_vector :
    evaluateProofWrapperRejection { validWrapper with nullifierVectorAgrees := false } =
      some ProofWrapperReject.nullifierVectorMismatch := by
  decide

theorem commitment_vector_mismatch_rejects_before_balance_slots :
    evaluateProofWrapperRejection { validWrapper with commitmentVectorAgrees := false } =
      some ProofWrapperReject.commitmentVectorMismatch := by
  decide

theorem balance_slot_mismatch_rejects_before_verifier_acceptance :
    evaluateProofWrapperRejection { validWrapper with balanceSlotsAgree := false } =
      some ProofWrapperReject.balanceSlotMismatch := by
  decide

theorem verifier_rejection_rejects_after_all_admission_checks :
    evaluateProofWrapperRejection { validWrapper with verifierAccepts := false } =
      some ProofWrapperReject.verifierRejected := by
  decide

theorem valid_metadata_projection_accepts :
    proofWrapperMetadataProjectionAccepts validMetadataProjection = true := by
  decide

theorem wrapper_nullifier_metadata_drift_rejects :
    proofWrapperMetadataProjectionAccepts
      { validMetadataProjection with
        wrapperNullifiersEqualBoundStatement := false } = false := by
  decide

theorem wrapper_commitment_metadata_drift_rejects :
    proofWrapperMetadataProjectionAccepts
      { validMetadataProjection with
        wrapperCommitmentsEqualBoundStatement := false } = false := by
  decide

theorem wrapper_balance_metadata_drift_rejects :
    proofWrapperMetadataProjectionAccepts
      { validMetadataProjection with
        wrapperBalanceSlotsEqualBoundStatement := false } = false := by
  decide

theorem serialized_public_input_projection_drift_rejects :
    proofWrapperMetadataProjectionAccepts
      { validMetadataProjection with
        serializedPublicInputsEqualBoundProjection := false } = false := by
  decide

theorem public_nullifier_row_outside_statement_boundary_rejects :
    proofWrapperMetadataProjectionAccepts
      { validMetadataProjection with
        publicNullifierRowsWithinStatementBoundary := false } = false := by
  decide

theorem public_ciphertext_row_outside_statement_boundary_rejects :
    proofWrapperMetadataProjectionAccepts
      { validMetadataProjection with
        publicCiphertextRowsWithinStatementBoundary := false } = false := by
  decide

theorem public_asset_row_outside_statement_boundary_rejects :
    proofWrapperMetadataProjectionAccepts
      { validMetadataProjection with
        publicAssetRowsWithinStatementBoundary := false } = false := by
  decide

end ProofWrapperAdmission
end Transaction
end Hegemon
