namespace Hegemon
namespace Native
namespace SidecarUploadAdmission

inductive SidecarUploadReject where
  | tooManyCiphertexts
  | tooManyProofs
  | stagedCiphertextCapacityReached
  | stagedProofCapacityReached
  | proofBindingHashMissing
  | invalidBindingHash
  | proofMissing
  | proofEmpty
  | proofTooLarge
deriving DecidableEq, Repr

structure RequestCountInput where
  itemCount : Nat
  maxItems : Nat
deriving DecidableEq, Repr

structure CapacityInput where
  stagedCount : Nat
  maxStagedCount : Nat
  replacesExisting : Bool
deriving DecidableEq, Repr

structure ProofMetadataInput where
  bindingHashPresent : Bool
  bindingHashValid : Bool
  proofPresent : Bool
deriving DecidableEq, Repr

structure ProofDecodedInput where
  proofBytes : Nat
  maxProofBytes : Nat
deriving DecidableEq, Repr

def evaluateCiphertextRequest
    (input : RequestCountInput) : Except SidecarUploadReject Unit :=
  if input.itemCount > input.maxItems then
    Except.error SidecarUploadReject.tooManyCiphertexts
  else
    Except.ok ()

def evaluateProofRequest
    (input : RequestCountInput) : Except SidecarUploadReject Unit :=
  if input.itemCount > input.maxItems then
    Except.error SidecarUploadReject.tooManyProofs
  else
    Except.ok ()

def evaluateCiphertextCapacity
    (input : CapacityInput) : Except SidecarUploadReject Unit :=
  if input.replacesExisting = false then
    if input.stagedCount >= input.maxStagedCount then
      Except.error SidecarUploadReject.stagedCiphertextCapacityReached
    else
      Except.ok ()
  else
    Except.ok ()

def evaluateProofCapacity
    (input : CapacityInput) : Except SidecarUploadReject Unit :=
  if input.replacesExisting = false then
    if input.stagedCount >= input.maxStagedCount then
      Except.error SidecarUploadReject.stagedProofCapacityReached
    else
      Except.ok ()
  else
    Except.ok ()

def evaluateProofMetadata
    (input : ProofMetadataInput) : Except SidecarUploadReject Unit :=
  if input.bindingHashPresent = false then
    Except.error SidecarUploadReject.proofBindingHashMissing
  else if input.bindingHashValid = false then
    Except.error SidecarUploadReject.invalidBindingHash
  else if input.proofPresent = false then
    Except.error SidecarUploadReject.proofMissing
  else
    Except.ok ()

def evaluateProofDecoded
    (input : ProofDecodedInput) : Except SidecarUploadReject Unit :=
  if input.proofBytes = 0 then
    Except.error SidecarUploadReject.proofEmpty
  else if input.proofBytes > input.maxProofBytes then
    Except.error SidecarUploadReject.proofTooLarge
  else
    Except.ok ()

def accepts (result : Except SidecarUploadReject Unit) : Bool :=
  match result with
  | Except.ok _ => true
  | Except.error _ => false

def rejection (result : Except SidecarUploadReject Unit) : Option SidecarUploadReject :=
  match result with
  | Except.ok _ => none
  | Except.error reject => some reject

def capacityPreconditions (input : CapacityInput) : Bool :=
  if input.replacesExisting = false then
    if input.stagedCount >= input.maxStagedCount then false else true
  else
    true

def proofMetadataPreconditions (input : ProofMetadataInput) : Bool :=
  if input.bindingHashPresent = false then
    false
  else if input.bindingHashValid = false then
    false
  else if input.proofPresent = false then
    false
  else
    true

def proofDecodedPreconditions (input : ProofDecodedInput) : Bool :=
  if input.proofBytes = 0 then
    false
  else if input.proofBytes > input.maxProofBytes then
    false
  else
    true

theorem ciphertext_request_accepts_iff_not_over_limit
    {input : RequestCountInput} :
    accepts (evaluateCiphertextRequest input) = true ↔
      ¬ input.itemCount > input.maxItems := by
  unfold accepts evaluateCiphertextRequest
  by_cases over : input.itemCount > input.maxItems <;> simp [over]

theorem proof_request_accepts_iff_not_over_limit
    {input : RequestCountInput} :
    accepts (evaluateProofRequest input) = true ↔
      ¬ input.itemCount > input.maxItems := by
  unfold accepts evaluateProofRequest
  by_cases over : input.itemCount > input.maxItems <;> simp [over]

theorem ciphertext_capacity_accepts_iff_preconditions
    (input : CapacityInput) :
    accepts (evaluateCiphertextCapacity input) = capacityPreconditions input := by
  cases input with
  | mk stagedCount maxStagedCount replacesExisting =>
      unfold accepts evaluateCiphertextCapacity capacityPreconditions
      by_cases full : stagedCount >= maxStagedCount
      · cases replacesExisting <;> simp [full]
      · cases replacesExisting <;> simp [full]

theorem proof_capacity_accepts_iff_preconditions
    (input : CapacityInput) :
    accepts (evaluateProofCapacity input) = capacityPreconditions input := by
  cases input with
  | mk stagedCount maxStagedCount replacesExisting =>
      unfold accepts evaluateProofCapacity capacityPreconditions
      by_cases full : stagedCount >= maxStagedCount
      · cases replacesExisting <;> simp [full]
      · cases replacesExisting <;> simp [full]

theorem proof_metadata_accepts_iff_preconditions
    (input : ProofMetadataInput) :
    accepts (evaluateProofMetadata input) = proofMetadataPreconditions input := by
  cases input with
  | mk bindingHashPresent bindingHashValid proofPresent =>
      unfold accepts evaluateProofMetadata proofMetadataPreconditions
      cases bindingHashPresent <;> cases bindingHashValid <;> cases proofPresent <;> rfl

theorem proof_decoded_accepts_iff_preconditions
    (input : ProofDecodedInput) :
    accepts (evaluateProofDecoded input) = proofDecodedPreconditions input := by
  cases input with
  | mk proofBytes maxProofBytes =>
      unfold accepts evaluateProofDecoded proofDecodedPreconditions
      by_cases empty : proofBytes = 0
      · simp [empty]
      · by_cases tooLarge : proofBytes > maxProofBytes <;> simp [empty, tooLarge]

def requestExactLimit : RequestCountInput :=
  {
    itemCount := 4,
    maxItems := 4
  }

theorem ciphertext_request_exact_limit_accepts :
    evaluateCiphertextRequest requestExactLimit = Except.ok () := by
  rfl

theorem proof_request_exact_limit_accepts :
    evaluateProofRequest requestExactLimit = Except.ok () := by
  rfl

def requestTooMany : RequestCountInput :=
  {
    itemCount := 5,
    maxItems := 4
  }

theorem ciphertext_request_too_many_rejects :
    evaluateCiphertextRequest requestTooMany =
      Except.error SidecarUploadReject.tooManyCiphertexts := by
  rfl

theorem proof_request_too_many_rejects :
    evaluateProofRequest requestTooMany =
      Except.error SidecarUploadReject.tooManyProofs := by
  rfl

def newAtCapacity : CapacityInput :=
  {
    stagedCount := 4,
    maxStagedCount := 4,
    replacesExisting := false
  }

theorem ciphertext_new_at_capacity_rejects :
    evaluateCiphertextCapacity newAtCapacity =
      Except.error SidecarUploadReject.stagedCiphertextCapacityReached := by
  rfl

theorem proof_new_at_capacity_rejects :
    evaluateProofCapacity newAtCapacity =
      Except.error SidecarUploadReject.stagedProofCapacityReached := by
  rfl

def replacementAtCapacity : CapacityInput :=
  {
    stagedCount := 4,
    maxStagedCount := 4,
    replacesExisting := true
  }

theorem ciphertext_replacement_at_capacity_accepts :
    evaluateCiphertextCapacity replacementAtCapacity = Except.ok () := by
  rfl

theorem proof_replacement_at_capacity_accepts :
    evaluateProofCapacity replacementAtCapacity = Except.ok () := by
  rfl

def validProofMetadata : ProofMetadataInput :=
  {
    bindingHashPresent := true,
    bindingHashValid := true,
    proofPresent := true
  }

theorem valid_proof_metadata_accepts :
    evaluateProofMetadata validProofMetadata = Except.ok () := by
  rfl

theorem missing_binding_hash_rejects :
    evaluateProofMetadata { validProofMetadata with bindingHashPresent := false } =
      Except.error SidecarUploadReject.proofBindingHashMissing := by
  rfl

theorem invalid_binding_hash_rejects :
    evaluateProofMetadata { validProofMetadata with bindingHashValid := false } =
      Except.error SidecarUploadReject.invalidBindingHash := by
  rfl

theorem proof_missing_rejects :
    evaluateProofMetadata { validProofMetadata with proofPresent := false } =
      Except.error SidecarUploadReject.proofMissing := by
  rfl

theorem binding_hash_missing_precedes_proof_missing :
    evaluateProofMetadata
      { validProofMetadata with
        bindingHashPresent := false,
        proofPresent := false } =
      Except.error SidecarUploadReject.proofBindingHashMissing := by
  rfl

theorem invalid_binding_hash_precedes_proof_missing :
    evaluateProofMetadata
      { validProofMetadata with
        bindingHashValid := false,
        proofPresent := false } =
      Except.error SidecarUploadReject.invalidBindingHash := by
  rfl

def validProofDecoded : ProofDecodedInput :=
  {
    proofBytes := 7,
    maxProofBytes := 530368
  }

theorem valid_proof_decoded_accepts :
    evaluateProofDecoded validProofDecoded = Except.ok () := by
  rfl

theorem proof_exact_limit_accepts :
    evaluateProofDecoded
      { validProofDecoded with proofBytes := validProofDecoded.maxProofBytes } =
      Except.ok () := by
  rfl

theorem proof_empty_rejects :
    evaluateProofDecoded { validProofDecoded with proofBytes := 0 } =
      Except.error SidecarUploadReject.proofEmpty := by
  rfl

theorem proof_too_large_rejects :
    evaluateProofDecoded
      { validProofDecoded with proofBytes := validProofDecoded.maxProofBytes + 1 } =
      Except.error SidecarUploadReject.proofTooLarge := by
  rfl

theorem proof_empty_precedes_too_large_when_max_zero :
    evaluateProofDecoded { proofBytes := 0, maxProofBytes := 0 } =
      Except.error SidecarUploadReject.proofEmpty := by
  rfl

end SidecarUploadAdmission
end Native
end Hegemon
