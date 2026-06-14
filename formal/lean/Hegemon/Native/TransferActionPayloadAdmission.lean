namespace Hegemon
namespace Native
namespace TransferActionPayloadAdmission

inductive TransferPayloadReject where
  | proofMissing
  | proofTooLarge
  | anchorMismatch
  | commitmentsMismatch
  | inlineCiphertextTooLarge
  | ciphertextHashesMismatch
  | ciphertextSizesMismatch
  | bindingHashMismatch
  | proofBindingHashMismatch
  | feeMismatch
deriving DecidableEq, Repr

structure TransferPayloadInput where
  proofBytes : Nat
  maxProofBytes : Nat
  anchorMatches : Bool
  commitmentsMatch : Bool
  inlineCiphertextBytes : Nat
  maxCiphertextBytes : Nat
  ciphertextHashesMatch : Bool
  ciphertextSizesMatch : Bool
  bindingHashMatches : Bool
  proofBindingHashMatchesKey : Bool
  feeMatches : Bool
deriving DecidableEq, Repr

def evaluateTransferPayload
    (input : TransferPayloadInput) : Except TransferPayloadReject Unit :=
  if input.proofBytes = 0 then
    Except.error TransferPayloadReject.proofMissing
  else if input.proofBytes > input.maxProofBytes then
    Except.error TransferPayloadReject.proofTooLarge
  else if input.anchorMatches = false then
    Except.error TransferPayloadReject.anchorMismatch
  else if input.commitmentsMatch = false then
    Except.error TransferPayloadReject.commitmentsMismatch
  else if input.inlineCiphertextBytes > input.maxCiphertextBytes then
    Except.error TransferPayloadReject.inlineCiphertextTooLarge
  else if input.ciphertextHashesMatch = false then
    Except.error TransferPayloadReject.ciphertextHashesMismatch
  else if input.ciphertextSizesMatch = false then
    Except.error TransferPayloadReject.ciphertextSizesMismatch
  else if input.bindingHashMatches = false then
    Except.error TransferPayloadReject.bindingHashMismatch
  else if input.proofBindingHashMatchesKey = false then
    Except.error TransferPayloadReject.proofBindingHashMismatch
  else if input.feeMatches = false then
    Except.error TransferPayloadReject.feeMismatch
  else
    Except.ok ()

def transferPayloadAccepts (input : TransferPayloadInput) : Bool :=
  match evaluateTransferPayload input with
  | Except.ok _ => true
  | Except.error _ => false

def transferPayloadRejection
    (input : TransferPayloadInput) : Option TransferPayloadReject :=
  match evaluateTransferPayload input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def transferPayloadPreconditions (input : TransferPayloadInput) : Bool :=
  if input.proofBytes = 0 then
    false
  else if input.proofBytes > input.maxProofBytes then
    false
  else if input.anchorMatches = false then
    false
  else if input.commitmentsMatch = false then
    false
  else if input.inlineCiphertextBytes > input.maxCiphertextBytes then
    false
  else if input.ciphertextHashesMatch = false then
    false
  else if input.ciphertextSizesMatch = false then
    false
  else if input.bindingHashMatches = false then
    false
  else if input.proofBindingHashMatchesKey = false then
    false
  else if input.feeMatches = false then
    false
  else
    true

theorem accepts_iff_payload_preconditions (input : TransferPayloadInput) :
    transferPayloadAccepts input = transferPayloadPreconditions input := by
  cases input with
  | mk proofBytes maxProofBytes anchorMatches commitmentsMatch inlineCiphertextBytes
      maxCiphertextBytes ciphertextHashesMatch ciphertextSizesMatch bindingHashMatches
      proofBindingHashMatchesKey feeMatches =>
      unfold transferPayloadAccepts transferPayloadPreconditions evaluateTransferPayload
      by_cases noProof : proofBytes = 0
      · cases anchorMatches <;> cases commitmentsMatch <;> cases ciphertextHashesMatch <;>
          cases ciphertextSizesMatch <;> cases bindingHashMatches <;>
          cases proofBindingHashMatchesKey <;> cases feeMatches <;>
          simp [noProof]
      · by_cases proofOversized : proofBytes > maxProofBytes
        · cases anchorMatches <;> cases commitmentsMatch <;> cases ciphertextHashesMatch <;>
            cases ciphertextSizesMatch <;> cases bindingHashMatches <;>
            cases proofBindingHashMatchesKey <;> cases feeMatches <;>
            simp [noProof, proofOversized]
        · by_cases ciphertextOversized : inlineCiphertextBytes > maxCiphertextBytes
          · cases anchorMatches <;> cases commitmentsMatch <;> cases ciphertextHashesMatch <;>
              cases ciphertextSizesMatch <;> cases bindingHashMatches <;>
              cases proofBindingHashMatchesKey <;> cases feeMatches <;>
              simp [noProof, proofOversized, ciphertextOversized]
          · cases anchorMatches <;> cases commitmentsMatch <;> cases ciphertextHashesMatch <;>
              cases ciphertextSizesMatch <;> cases bindingHashMatches <;>
              cases proofBindingHashMatchesKey <;> cases feeMatches <;>
      simp [noProof, proofOversized, ciphertextOversized]

def TransferPayloadBindingFacts
    (input : TransferPayloadInput) : Prop :=
  input.bindingHashMatches = true
    ∧ input.proofBindingHashMatchesKey = true
    ∧ input.feeMatches = true

theorem transfer_payload_accepts_implies_preconditions
    {input : TransferPayloadInput}
    (accepted : transferPayloadAccepts input = true) :
    transferPayloadPreconditions input = true := by
  rw [← accepts_iff_payload_preconditions input]
  exact accepted

theorem transfer_payload_accepts_implies_binding_facts
    {input : TransferPayloadInput}
    (accepted : transferPayloadAccepts input = true) :
    TransferPayloadBindingFacts input := by
  have preconditions :=
    transfer_payload_accepts_implies_preconditions accepted
  cases input with
  | mk proofBytes maxProofBytes anchorMatches commitmentsMatch inlineCiphertextBytes
      maxCiphertextBytes ciphertextHashesMatch ciphertextSizesMatch bindingHashMatches
      proofBindingHashMatchesKey feeMatches =>
      simp [
        TransferPayloadBindingFacts,
        transferPayloadPreconditions
      ] at preconditions ⊢
      rcases preconditions with
        ⟨_present, _proofInBounds, _anchor, _commitments,
          _ciphertextInBounds, _hashes, _sizes, binding,
          proofBinding, fee⟩
      exact ⟨binding, proofBinding, fee⟩

def validTransferPayload : TransferPayloadInput :=
  {
    proofBytes := 32,
    maxProofBytes := 530368,
    anchorMatches := true,
    commitmentsMatch := true,
    inlineCiphertextBytes := 611,
    maxCiphertextBytes := 2147,
    ciphertextHashesMatch := true,
    ciphertextSizesMatch := true,
    bindingHashMatches := true,
    proofBindingHashMatchesKey := true,
    feeMatches := true
  }

theorem valid_transfer_payload_accepts :
    evaluateTransferPayload validTransferPayload = Except.ok () := by
  rfl

theorem proof_missing_rejects
    {input : TransferPayloadInput}
    (missing : input.proofBytes = 0) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.proofMissing := by
  unfold evaluateTransferPayload
  simp [missing]

theorem proof_too_large_rejects
    {input : TransferPayloadInput}
    (present : input.proofBytes ≠ 0)
    (tooLarge : input.proofBytes > input.maxProofBytes) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.proofTooLarge := by
  unfold evaluateTransferPayload
  simp [present, tooLarge]

theorem anchor_mismatch_rejects
    {input : TransferPayloadInput}
    (present : input.proofBytes ≠ 0)
    (proofInBounds : ¬ input.proofBytes > input.maxProofBytes)
    (mismatch : input.anchorMatches = false) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.anchorMismatch := by
  unfold evaluateTransferPayload
  simp [present, proofInBounds, mismatch]

theorem commitments_mismatch_rejects
    {input : TransferPayloadInput}
    (present : input.proofBytes ≠ 0)
    (proofInBounds : ¬ input.proofBytes > input.maxProofBytes)
    (anchor : input.anchorMatches = true)
    (mismatch : input.commitmentsMatch = false) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.commitmentsMismatch := by
  unfold evaluateTransferPayload
  simp [present, proofInBounds, anchor, mismatch]

theorem inline_ciphertext_too_large_rejects
    {input : TransferPayloadInput}
    (present : input.proofBytes ≠ 0)
    (proofInBounds : ¬ input.proofBytes > input.maxProofBytes)
    (anchor : input.anchorMatches = true)
    (commitments : input.commitmentsMatch = true)
    (tooLarge : input.inlineCiphertextBytes > input.maxCiphertextBytes) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.inlineCiphertextTooLarge := by
  unfold evaluateTransferPayload
  simp [present, proofInBounds, anchor, commitments, tooLarge]

theorem ciphertext_hashes_mismatch_rejects
    {input : TransferPayloadInput}
    (present : input.proofBytes ≠ 0)
    (proofInBounds : ¬ input.proofBytes > input.maxProofBytes)
    (anchor : input.anchorMatches = true)
    (commitments : input.commitmentsMatch = true)
    (ciphertextInBounds : ¬ input.inlineCiphertextBytes > input.maxCiphertextBytes)
    (mismatch : input.ciphertextHashesMatch = false) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.ciphertextHashesMismatch := by
  unfold evaluateTransferPayload
  simp [present, proofInBounds, anchor, commitments, ciphertextInBounds, mismatch]

theorem ciphertext_sizes_mismatch_rejects
    {input : TransferPayloadInput}
    (present : input.proofBytes ≠ 0)
    (proofInBounds : ¬ input.proofBytes > input.maxProofBytes)
    (anchor : input.anchorMatches = true)
    (commitments : input.commitmentsMatch = true)
    (ciphertextInBounds : ¬ input.inlineCiphertextBytes > input.maxCiphertextBytes)
    (hashes : input.ciphertextHashesMatch = true)
    (mismatch : input.ciphertextSizesMatch = false) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.ciphertextSizesMismatch := by
  unfold evaluateTransferPayload
  simp [
    present,
    proofInBounds,
    anchor,
    commitments,
    ciphertextInBounds,
    hashes,
    mismatch
  ]

theorem binding_hash_mismatch_rejects
    {input : TransferPayloadInput}
    (present : input.proofBytes ≠ 0)
    (proofInBounds : ¬ input.proofBytes > input.maxProofBytes)
    (anchor : input.anchorMatches = true)
    (commitments : input.commitmentsMatch = true)
    (ciphertextInBounds : ¬ input.inlineCiphertextBytes > input.maxCiphertextBytes)
    (hashes : input.ciphertextHashesMatch = true)
    (sizes : input.ciphertextSizesMatch = true)
    (mismatch : input.bindingHashMatches = false) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.bindingHashMismatch := by
  unfold evaluateTransferPayload
  simp [
    present,
    proofInBounds,
    anchor,
    commitments,
    ciphertextInBounds,
    hashes,
    sizes,
    mismatch
  ]

theorem proof_binding_hash_mismatch_rejects
    {input : TransferPayloadInput}
    (present : input.proofBytes ≠ 0)
    (proofInBounds : ¬ input.proofBytes > input.maxProofBytes)
    (anchor : input.anchorMatches = true)
    (commitments : input.commitmentsMatch = true)
    (ciphertextInBounds : ¬ input.inlineCiphertextBytes > input.maxCiphertextBytes)
    (hashes : input.ciphertextHashesMatch = true)
    (sizes : input.ciphertextSizesMatch = true)
    (binding : input.bindingHashMatches = true)
    (mismatch : input.proofBindingHashMatchesKey = false) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.proofBindingHashMismatch := by
  unfold evaluateTransferPayload
  simp [
    present,
    proofInBounds,
    anchor,
    commitments,
    ciphertextInBounds,
    hashes,
    sizes,
    binding,
    mismatch
  ]

theorem fee_mismatch_rejects
    {input : TransferPayloadInput}
    (present : input.proofBytes ≠ 0)
    (proofInBounds : ¬ input.proofBytes > input.maxProofBytes)
    (anchor : input.anchorMatches = true)
    (commitments : input.commitmentsMatch = true)
    (ciphertextInBounds : ¬ input.inlineCiphertextBytes > input.maxCiphertextBytes)
    (hashes : input.ciphertextHashesMatch = true)
    (sizes : input.ciphertextSizesMatch = true)
    (binding : input.bindingHashMatches = true)
    (proofBinding : input.proofBindingHashMatchesKey = true)
    (mismatch : input.feeMatches = false) :
    evaluateTransferPayload input =
      Except.error TransferPayloadReject.feeMismatch := by
  unfold evaluateTransferPayload
  simp [
    present,
    proofInBounds,
    anchor,
    commitments,
    ciphertextInBounds,
    hashes,
    sizes,
    binding,
    proofBinding,
    mismatch
  ]

theorem proof_missing_precedes_anchor_validation :
    evaluateTransferPayload
      { validTransferPayload with proofBytes := 0, anchorMatches := false } =
        Except.error TransferPayloadReject.proofMissing := by
  rfl

theorem exact_proof_limit_accepts :
    evaluateTransferPayload
      { validTransferPayload with
        proofBytes := validTransferPayload.maxProofBytes } =
        Except.ok () := by
  rfl

end TransferActionPayloadAdmission
end Native
end Hegemon
