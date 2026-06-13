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

end ProofWrapperAdmission
end Transaction
end Hegemon
