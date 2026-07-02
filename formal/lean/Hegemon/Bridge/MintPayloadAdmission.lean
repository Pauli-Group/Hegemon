namespace Hegemon
namespace Bridge
namespace MintPayloadAdmission

inductive BridgeMintPayloadReject where
  | payloadDecodeFailed
  | payloadHashMismatch
  | receiptMessageHashMismatch
  | versionMismatch
  | sourceAppFamilyMismatch
  | destinationMismatch
  | mintNonceMismatch
  | recipientCommitmentZero
  | amountZero
  | amountOutOfBounds
  | nativeAssetNotAllowed
deriving DecidableEq, Repr

inductive CashVmMintBindingReject where
  | versionMismatch
  | sourceAppFamilyMismatch
  | destinationMismatch
  | mintNonceMismatch
  | recipientCommitmentZero
  | amountZero
  | amountOutOfBounds
  | nativeAssetNotAllowed
  | destinationPolicyMismatch
  | assetBindingMismatch
  | recipientBindingMismatch
deriving DecidableEq, Repr

inductive CashVmProofAdmissionReject where
  | emptyProof
  | statementMismatch
  | verifierScriptMismatch
  | insufficientPqSoundness
  | verifierUnavailable
  | verifierRejected
deriving DecidableEq, Repr

inductive CashVmReplayUpdateReject where
  | replayWitnessDepthMismatch
  | previousReplayRootMismatch
  | replayAlreadySpent
  | nextReplayRootMismatch
deriving DecidableEq, Repr

structure BridgeMintPayloadInput where
  payloadDecoded : Bool
  payloadHashMatches : Bool
  receiptMessageHashMatches : Bool
  versionMatches : Bool
  sourceAppFamilyMatches : Bool
  destinationMatches : Bool
  mintNonceMatches : Bool
  recipientCommitmentNonzero : Bool
  amountNonzero : Bool
  amountWithinBound : Bool
  assetNonNative : Bool
deriving DecidableEq, Repr

structure CashVmMintBindingInput where
  versionMatches : Bool
  sourceAppFamilyMatches : Bool
  destinationMatches : Bool
  mintNonceMatches : Bool
  recipientCommitmentNonzero : Bool
  amountNonzero : Bool
  amountWithinBound : Bool
  assetNonNative : Bool
  destinationMatchesBridgePolicy : Bool
  bridgeInstanceMatchesTokenCategory : Bool
  tokenCategoryMatchesPayloadAsset : Bool
  recipientHashMatchesPayloadRecipient : Bool
deriving DecidableEq, Repr

structure CashVmProofAdmissionInput where
  proofNonempty : Bool
  statementDigestMatches : Bool
  verifierScriptMatches : Bool
  pqSoundnessAtLeastPolicy : Bool
  verifierAvailable : Bool
  verifierAccepts : Bool
deriving DecidableEq, Repr

structure CashVmReplayUpdateInput where
  witnessDepthValid : Bool
  previousRootMatches : Bool
  replayLeafAbsent : Bool
  nextRootMatches : Bool
deriving DecidableEq, Repr

def evaluateBridgeMintPayload
    (input : BridgeMintPayloadInput) :
      Except BridgeMintPayloadReject Unit :=
  if input.payloadDecoded = false then
    Except.error BridgeMintPayloadReject.payloadDecodeFailed
  else if input.payloadHashMatches = false then
    Except.error BridgeMintPayloadReject.payloadHashMismatch
  else if input.receiptMessageHashMatches = false then
    Except.error BridgeMintPayloadReject.receiptMessageHashMismatch
  else if input.versionMatches = false then
    Except.error BridgeMintPayloadReject.versionMismatch
  else if input.sourceAppFamilyMatches = false then
    Except.error BridgeMintPayloadReject.sourceAppFamilyMismatch
  else if input.destinationMatches = false then
    Except.error BridgeMintPayloadReject.destinationMismatch
  else if input.mintNonceMatches = false then
    Except.error BridgeMintPayloadReject.mintNonceMismatch
  else if input.recipientCommitmentNonzero = false then
    Except.error BridgeMintPayloadReject.recipientCommitmentZero
  else if input.amountNonzero = false then
    Except.error BridgeMintPayloadReject.amountZero
  else if input.amountWithinBound = false then
    Except.error BridgeMintPayloadReject.amountOutOfBounds
  else if input.assetNonNative = false then
    Except.error BridgeMintPayloadReject.nativeAssetNotAllowed
  else
    Except.ok ()

def bridgeMintPayloadAccepts
    (input : BridgeMintPayloadInput) : Bool :=
  match evaluateBridgeMintPayload input with
  | Except.ok _ => true
  | Except.error _ => false

def bridgeMintPayloadRejection
    (input : BridgeMintPayloadInput) :
      Option BridgeMintPayloadReject :=
  match evaluateBridgeMintPayload input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def evaluateCashVmMintBinding
    (input : CashVmMintBindingInput) :
      Except CashVmMintBindingReject Unit :=
  if input.versionMatches = false then
    Except.error CashVmMintBindingReject.versionMismatch
  else if input.sourceAppFamilyMatches = false then
    Except.error CashVmMintBindingReject.sourceAppFamilyMismatch
  else if input.destinationMatches = false then
    Except.error CashVmMintBindingReject.destinationMismatch
  else if input.mintNonceMatches = false then
    Except.error CashVmMintBindingReject.mintNonceMismatch
  else if input.recipientCommitmentNonzero = false then
    Except.error CashVmMintBindingReject.recipientCommitmentZero
  else if input.amountNonzero = false then
    Except.error CashVmMintBindingReject.amountZero
  else if input.amountWithinBound = false then
    Except.error CashVmMintBindingReject.amountOutOfBounds
  else if input.assetNonNative = false then
    Except.error CashVmMintBindingReject.nativeAssetNotAllowed
  else if input.destinationMatchesBridgePolicy = false then
    Except.error CashVmMintBindingReject.destinationPolicyMismatch
  else if input.bridgeInstanceMatchesTokenCategory = false then
    Except.error CashVmMintBindingReject.assetBindingMismatch
  else if input.tokenCategoryMatchesPayloadAsset = false then
    Except.error CashVmMintBindingReject.assetBindingMismatch
  else if input.recipientHashMatchesPayloadRecipient = false then
    Except.error CashVmMintBindingReject.recipientBindingMismatch
  else
    Except.ok ()

def cashVmMintBindingAccepts
    (input : CashVmMintBindingInput) : Bool :=
  match evaluateCashVmMintBinding input with
  | Except.ok _ => true
  | Except.error _ => false

def cashVmMintBindingRejection
    (input : CashVmMintBindingInput) :
      Option CashVmMintBindingReject :=
  match evaluateCashVmMintBinding input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def evaluateCashVmProofAdmission
    (input : CashVmProofAdmissionInput) :
      Except CashVmProofAdmissionReject Unit :=
  if input.proofNonempty = false then
    Except.error CashVmProofAdmissionReject.emptyProof
  else if input.statementDigestMatches = false then
    Except.error CashVmProofAdmissionReject.statementMismatch
  else if input.verifierScriptMatches = false then
    Except.error CashVmProofAdmissionReject.verifierScriptMismatch
  else if input.pqSoundnessAtLeastPolicy = false then
    Except.error CashVmProofAdmissionReject.insufficientPqSoundness
  else if input.verifierAvailable = false then
    Except.error CashVmProofAdmissionReject.verifierUnavailable
  else if input.verifierAccepts = false then
    Except.error CashVmProofAdmissionReject.verifierRejected
  else
    Except.ok ()

def cashVmProofAdmissionAccepts
    (input : CashVmProofAdmissionInput) : Bool :=
  match evaluateCashVmProofAdmission input with
  | Except.ok _ => true
  | Except.error _ => false

def cashVmProofAdmissionRejection
    (input : CashVmProofAdmissionInput) :
      Option CashVmProofAdmissionReject :=
  match evaluateCashVmProofAdmission input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def evaluateCashVmReplayUpdate
    (input : CashVmReplayUpdateInput) :
      Except CashVmReplayUpdateReject Unit :=
  if input.witnessDepthValid = false then
    Except.error CashVmReplayUpdateReject.replayWitnessDepthMismatch
  else if input.previousRootMatches = false then
    Except.error CashVmReplayUpdateReject.previousReplayRootMismatch
  else if input.replayLeafAbsent = false then
    Except.error CashVmReplayUpdateReject.replayAlreadySpent
  else if input.nextRootMatches = false then
    Except.error CashVmReplayUpdateReject.nextReplayRootMismatch
  else
    Except.ok ()

def cashVmReplayUpdateAccepts
    (input : CashVmReplayUpdateInput) : Bool :=
  match evaluateCashVmReplayUpdate input with
  | Except.ok _ => true
  | Except.error _ => false

def cashVmReplayUpdateRejection
    (input : CashVmReplayUpdateInput) :
      Option CashVmReplayUpdateReject :=
  match evaluateCashVmReplayUpdate input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def bridgeMintPayloadPreconditions
    (input : BridgeMintPayloadInput) : Bool :=
  input.payloadDecoded
    && input.payloadHashMatches
    && input.receiptMessageHashMatches
    && input.versionMatches
    && input.sourceAppFamilyMatches
    && input.destinationMatches
    && input.mintNonceMatches
    && input.recipientCommitmentNonzero
    && input.amountNonzero
    && input.amountWithinBound
    && input.assetNonNative

def cashVmMintBindingPreconditions
    (input : CashVmMintBindingInput) : Bool :=
  input.versionMatches
    && input.sourceAppFamilyMatches
    && input.destinationMatches
    && input.mintNonceMatches
    && input.recipientCommitmentNonzero
    && input.amountNonzero
    && input.amountWithinBound
    && input.assetNonNative
    && input.destinationMatchesBridgePolicy
    && input.bridgeInstanceMatchesTokenCategory
    && input.tokenCategoryMatchesPayloadAsset
    && input.recipientHashMatchesPayloadRecipient

def cashVmProofAdmissionPreconditions
    (input : CashVmProofAdmissionInput) : Bool :=
  input.proofNonempty
    && input.statementDigestMatches
    && input.verifierScriptMatches
    && input.pqSoundnessAtLeastPolicy
    && input.verifierAvailable
    && input.verifierAccepts

def cashVmReplayUpdatePreconditions
    (input : CashVmReplayUpdateInput) : Bool :=
  input.witnessDepthValid
    && input.previousRootMatches
    && input.replayLeafAbsent
    && input.nextRootMatches

def BridgeMintPayloadFacts
    (input : BridgeMintPayloadInput) : Prop :=
  input.payloadDecoded = true
    ∧ input.payloadHashMatches = true
    ∧ input.receiptMessageHashMatches = true
    ∧ input.versionMatches = true
    ∧ input.sourceAppFamilyMatches = true
    ∧ input.destinationMatches = true
    ∧ input.mintNonceMatches = true
    ∧ input.recipientCommitmentNonzero = true
    ∧ input.amountNonzero = true
    ∧ input.amountWithinBound = true
    ∧ input.assetNonNative = true

def CashVmMintBindingFacts
    (input : CashVmMintBindingInput) : Prop :=
  input.versionMatches = true
    ∧ input.sourceAppFamilyMatches = true
    ∧ input.destinationMatches = true
    ∧ input.mintNonceMatches = true
    ∧ input.recipientCommitmentNonzero = true
    ∧ input.amountNonzero = true
    ∧ input.amountWithinBound = true
    ∧ input.assetNonNative = true
    ∧ input.destinationMatchesBridgePolicy = true
    ∧ input.bridgeInstanceMatchesTokenCategory = true
    ∧ input.tokenCategoryMatchesPayloadAsset = true
    ∧ input.recipientHashMatchesPayloadRecipient = true

def CashVmProofAdmissionFacts
    (input : CashVmProofAdmissionInput) : Prop :=
  input.proofNonempty = true
    ∧ input.statementDigestMatches = true
    ∧ input.verifierScriptMatches = true
    ∧ input.pqSoundnessAtLeastPolicy = true
    ∧ input.verifierAvailable = true
    ∧ input.verifierAccepts = true

def CashVmReplayUpdateFacts
    (input : CashVmReplayUpdateInput) : Prop :=
  input.witnessDepthValid = true
    ∧ input.previousRootMatches = true
    ∧ input.replayLeafAbsent = true
    ∧ input.nextRootMatches = true

theorem accepts_iff_bridge_mint_payload_preconditions
    (input : BridgeMintPayloadInput) :
    bridgeMintPayloadAccepts input =
      bridgeMintPayloadPreconditions input := by
  cases input with
  | mk payloadDecoded payloadHashMatches receiptMessageHashMatches
      versionMatches sourceAppFamilyMatches destinationMatches mintNonceMatches
      recipientCommitmentNonzero amountNonzero amountWithinBound assetNonNative =>
      unfold bridgeMintPayloadAccepts
        bridgeMintPayloadPreconditions
        evaluateBridgeMintPayload
      cases payloadDecoded <;>
        cases payloadHashMatches <;>
        cases receiptMessageHashMatches <;>
        cases versionMatches <;>
        cases sourceAppFamilyMatches <;>
        cases destinationMatches <;>
        cases mintNonceMatches <;>
        cases recipientCommitmentNonzero <;>
        cases amountNonzero <;>
        cases amountWithinBound <;>
        cases assetNonNative <;>
        rfl

theorem accepted_bridge_mint_payload_exposes_facts
    {input : BridgeMintPayloadInput}
    (accepted : bridgeMintPayloadAccepts input = true) :
    BridgeMintPayloadFacts input := by
  cases input with
  | mk payloadDecoded payloadHashMatches receiptMessageHashMatches
      versionMatches sourceAppFamilyMatches destinationMatches mintNonceMatches
      recipientCommitmentNonzero amountNonzero amountWithinBound assetNonNative =>
      cases payloadDecoded <;>
        cases payloadHashMatches <;>
        cases receiptMessageHashMatches <;>
        cases versionMatches <;>
        cases sourceAppFamilyMatches <;>
        cases destinationMatches <;>
        cases mintNonceMatches <;>
        cases recipientCommitmentNonzero <;>
        cases amountNonzero <;>
        cases amountWithinBound <;>
        cases assetNonNative <;>
        simp [
          bridgeMintPayloadAccepts,
          evaluateBridgeMintPayload,
          BridgeMintPayloadFacts
        ] at accepted ⊢

theorem accepts_iff_cashvm_mint_binding_preconditions
    (input : CashVmMintBindingInput) :
    cashVmMintBindingAccepts input =
      cashVmMintBindingPreconditions input := by
  cases input with
  | mk versionMatches sourceAppFamilyMatches destinationMatches mintNonceMatches
      recipientCommitmentNonzero amountNonzero amountWithinBound assetNonNative
      destinationMatchesBridgePolicy bridgeInstanceMatchesTokenCategory
      tokenCategoryMatchesPayloadAsset recipientHashMatchesPayloadRecipient =>
      unfold cashVmMintBindingAccepts
        cashVmMintBindingPreconditions
        evaluateCashVmMintBinding
      cases versionMatches <;>
        cases sourceAppFamilyMatches <;>
        cases destinationMatches <;>
        cases mintNonceMatches <;>
        cases recipientCommitmentNonzero <;>
        cases amountNonzero <;>
        cases amountWithinBound <;>
        cases assetNonNative <;>
        cases destinationMatchesBridgePolicy <;>
        cases bridgeInstanceMatchesTokenCategory <;>
        cases tokenCategoryMatchesPayloadAsset <;>
        cases recipientHashMatchesPayloadRecipient <;>
        rfl

theorem accepted_cashvm_mint_binding_exposes_facts
    {input : CashVmMintBindingInput}
    (accepted : cashVmMintBindingAccepts input = true) :
    CashVmMintBindingFacts input := by
  cases input with
  | mk versionMatches sourceAppFamilyMatches destinationMatches mintNonceMatches
      recipientCommitmentNonzero amountNonzero amountWithinBound assetNonNative
      destinationMatchesBridgePolicy bridgeInstanceMatchesTokenCategory
      tokenCategoryMatchesPayloadAsset recipientHashMatchesPayloadRecipient =>
      cases versionMatches <;>
        cases sourceAppFamilyMatches <;>
        cases destinationMatches <;>
        cases mintNonceMatches <;>
        cases recipientCommitmentNonzero <;>
        cases amountNonzero <;>
        cases amountWithinBound <;>
        cases assetNonNative <;>
        cases destinationMatchesBridgePolicy <;>
        cases bridgeInstanceMatchesTokenCategory <;>
        cases tokenCategoryMatchesPayloadAsset <;>
        cases recipientHashMatchesPayloadRecipient <;>
        simp_all [
          cashVmMintBindingAccepts,
          evaluateCashVmMintBinding,
          CashVmMintBindingFacts
        ]

theorem accepts_iff_cashvm_proof_admission_preconditions
    (input : CashVmProofAdmissionInput) :
    cashVmProofAdmissionAccepts input =
      cashVmProofAdmissionPreconditions input := by
  cases input with
  | mk proofNonempty statementDigestMatches verifierScriptMatches
      pqSoundnessAtLeastPolicy verifierAvailable verifierAccepts =>
      unfold cashVmProofAdmissionAccepts
        cashVmProofAdmissionPreconditions
        evaluateCashVmProofAdmission
      cases proofNonempty <;>
        cases statementDigestMatches <;>
        cases verifierScriptMatches <;>
        cases pqSoundnessAtLeastPolicy <;>
        cases verifierAvailable <;>
        cases verifierAccepts <;>
        rfl

theorem accepted_cashvm_proof_admission_exposes_facts
    {input : CashVmProofAdmissionInput}
    (accepted : cashVmProofAdmissionAccepts input = true) :
    CashVmProofAdmissionFacts input := by
  cases input with
  | mk proofNonempty statementDigestMatches verifierScriptMatches
      pqSoundnessAtLeastPolicy verifierAvailable verifierAccepts =>
      cases proofNonempty <;>
        cases statementDigestMatches <;>
        cases verifierScriptMatches <;>
        cases pqSoundnessAtLeastPolicy <;>
        cases verifierAvailable <;>
        cases verifierAccepts <;>
        simp_all [
          cashVmProofAdmissionAccepts,
        evaluateCashVmProofAdmission,
        CashVmProofAdmissionFacts
        ]

theorem accepts_iff_cashvm_replay_update_preconditions
    (input : CashVmReplayUpdateInput) :
    cashVmReplayUpdateAccepts input =
      cashVmReplayUpdatePreconditions input := by
  cases input with
  | mk witnessDepthValid previousRootMatches replayLeafAbsent nextRootMatches =>
      unfold cashVmReplayUpdateAccepts
        cashVmReplayUpdatePreconditions
        evaluateCashVmReplayUpdate
      cases witnessDepthValid <;>
      cases previousRootMatches <;>
        cases replayLeafAbsent <;>
        cases nextRootMatches <;>
        rfl

theorem accepted_cashvm_replay_update_exposes_facts
    {input : CashVmReplayUpdateInput}
    (accepted : cashVmReplayUpdateAccepts input = true) :
    CashVmReplayUpdateFacts input := by
  cases input with
  | mk witnessDepthValid previousRootMatches replayLeafAbsent nextRootMatches =>
      cases witnessDepthValid <;>
      cases previousRootMatches <;>
        cases replayLeafAbsent <;>
        cases nextRootMatches <;>
        simp_all [
          cashVmReplayUpdateAccepts,
          evaluateCashVmReplayUpdate,
          CashVmReplayUpdateFacts
        ]

def validBridgeMintPayload : BridgeMintPayloadInput :=
  {
    payloadDecoded := true,
    payloadHashMatches := true,
    receiptMessageHashMatches := true,
    versionMatches := true,
    sourceAppFamilyMatches := true,
    destinationMatches := true,
    mintNonceMatches := true,
    recipientCommitmentNonzero := true,
    amountNonzero := true,
    amountWithinBound := true,
    assetNonNative := true
  }

def validCashVmMintBinding : CashVmMintBindingInput :=
  {
    versionMatches := true,
    sourceAppFamilyMatches := true,
    destinationMatches := true,
    mintNonceMatches := true,
    recipientCommitmentNonzero := true,
    amountNonzero := true,
    amountWithinBound := true,
    assetNonNative := true,
    destinationMatchesBridgePolicy := true,
    bridgeInstanceMatchesTokenCategory := true,
    tokenCategoryMatchesPayloadAsset := true,
    recipientHashMatchesPayloadRecipient := true
  }

def validCashVmProofAdmission : CashVmProofAdmissionInput :=
  {
    proofNonempty := true,
    statementDigestMatches := true,
    verifierScriptMatches := true,
    pqSoundnessAtLeastPolicy := true,
    verifierAvailable := true,
    verifierAccepts := true
  }

def validCashVmReplayUpdate : CashVmReplayUpdateInput :=
  {
    witnessDepthValid := true,
    previousRootMatches := true,
    replayLeafAbsent := true,
    nextRootMatches := true
  }

theorem valid_bridge_mint_payload_accepts :
    bridgeMintPayloadAccepts validBridgeMintPayload = true := by
  decide

theorem valid_cashvm_mint_binding_accepts :
    cashVmMintBindingAccepts validCashVmMintBinding = true := by
  decide

theorem valid_cashvm_replay_update_accepts :
    cashVmReplayUpdateAccepts validCashVmReplayUpdate = true := by
  decide

theorem payload_decode_failure_precedes_hash
    {input : BridgeMintPayloadInput}
    (decodeFailed : input.payloadDecoded = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.payloadDecodeFailed := by
  unfold evaluateBridgeMintPayload
  simp [decodeFailed]

theorem payload_hash_mismatch_rejects
    {input : BridgeMintPayloadInput}
    (decoded : input.payloadDecoded = true)
    (hashMismatch : input.payloadHashMatches = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.payloadHashMismatch := by
  unfold evaluateBridgeMintPayload
  simp [decoded, hashMismatch]

theorem receipt_message_hash_mismatch_rejects
    {input : BridgeMintPayloadInput}
    (decoded : input.payloadDecoded = true)
    (payloadHash : input.payloadHashMatches = true)
    (receiptMismatch : input.receiptMessageHashMatches = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.receiptMessageHashMismatch := by
  unfold evaluateBridgeMintPayload
  simp [decoded, payloadHash, receiptMismatch]

theorem amount_zero_precedes_amount_bound
    {input : BridgeMintPayloadInput}
    (decoded : input.payloadDecoded = true)
    (payloadHash : input.payloadHashMatches = true)
    (receiptHash : input.receiptMessageHashMatches = true)
    (version : input.versionMatches = true)
    (sourceAppFamily : input.sourceAppFamilyMatches = true)
    (destination : input.destinationMatches = true)
    (mintNonce : input.mintNonceMatches = true)
    (recipient : input.recipientCommitmentNonzero = true)
    (amountZero : input.amountNonzero = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.amountZero := by
  unfold evaluateBridgeMintPayload
  simp [
    decoded,
    payloadHash,
    receiptHash,
    version,
    sourceAppFamily,
    destination,
    mintNonce,
    recipient,
    amountZero
  ]

theorem native_asset_rejected_after_amount_bound
    {input : BridgeMintPayloadInput}
    (decoded : input.payloadDecoded = true)
    (payloadHash : input.payloadHashMatches = true)
    (receiptHash : input.receiptMessageHashMatches = true)
    (version : input.versionMatches = true)
    (sourceAppFamily : input.sourceAppFamilyMatches = true)
    (destination : input.destinationMatches = true)
    (mintNonce : input.mintNonceMatches = true)
    (recipient : input.recipientCommitmentNonzero = true)
    (amount : input.amountNonzero = true)
    (bound : input.amountWithinBound = true)
    (nativeAsset : input.assetNonNative = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.nativeAssetNotAllowed := by
  unfold evaluateBridgeMintPayload
  simp [
    decoded,
    payloadHash,
    receiptHash,
    version,
    sourceAppFamily,
    destination,
    mintNonce,
    recipient,
    amount,
    bound,
    nativeAsset
  ]

theorem cashvm_asset_binding_mismatch_rejects_after_payload_facts
    {input : CashVmMintBindingInput}
    (version : input.versionMatches = true)
    (sourceAppFamily : input.sourceAppFamilyMatches = true)
    (destination : input.destinationMatches = true)
    (mintNonce : input.mintNonceMatches = true)
    (recipient : input.recipientCommitmentNonzero = true)
    (amount : input.amountNonzero = true)
    (bound : input.amountWithinBound = true)
    (asset : input.assetNonNative = true)
    (policyDestination : input.destinationMatchesBridgePolicy = true)
    (bridgeInstance : input.bridgeInstanceMatchesTokenCategory = true)
    (assetBinding : input.tokenCategoryMatchesPayloadAsset = false) :
    evaluateCashVmMintBinding input =
    Except.error CashVmMintBindingReject.assetBindingMismatch := by
  unfold evaluateCashVmMintBinding
  simp [
    version,
    sourceAppFamily,
    destination,
    mintNonce,
    recipient,
    amount,
    bound,
    asset,
    policyDestination,
    bridgeInstance,
    assetBinding
  ]

theorem cashvm_destination_policy_mismatch_rejects_after_payload_facts
    {input : CashVmMintBindingInput}
    (version : input.versionMatches = true)
    (sourceAppFamily : input.sourceAppFamilyMatches = true)
    (destination : input.destinationMatches = true)
    (mintNonce : input.mintNonceMatches = true)
    (recipient : input.recipientCommitmentNonzero = true)
    (amount : input.amountNonzero = true)
    (bound : input.amountWithinBound = true)
    (asset : input.assetNonNative = true)
    (policyDestination : input.destinationMatchesBridgePolicy = false) :
    evaluateCashVmMintBinding input =
      Except.error CashVmMintBindingReject.destinationPolicyMismatch := by
  unfold evaluateCashVmMintBinding
  simp [
    version,
    sourceAppFamily,
    destination,
    mintNonce,
    recipient,
    amount,
    bound,
    asset,
    policyDestination
  ]

theorem cashvm_bridge_instance_mismatch_rejects_as_asset_binding
    {input : CashVmMintBindingInput}
    (version : input.versionMatches = true)
    (sourceAppFamily : input.sourceAppFamilyMatches = true)
    (destination : input.destinationMatches = true)
    (mintNonce : input.mintNonceMatches = true)
    (recipient : input.recipientCommitmentNonzero = true)
    (amount : input.amountNonzero = true)
    (bound : input.amountWithinBound = true)
    (asset : input.assetNonNative = true)
    (policyDestination : input.destinationMatchesBridgePolicy = true)
    (bridgeInstance : input.bridgeInstanceMatchesTokenCategory = false) :
    evaluateCashVmMintBinding input =
      Except.error CashVmMintBindingReject.assetBindingMismatch := by
  unfold evaluateCashVmMintBinding
  simp [
    version,
    sourceAppFamily,
    destination,
    mintNonce,
    recipient,
    amount,
    bound,
    asset,
    policyDestination,
    bridgeInstance
  ]

theorem cashvm_recipient_binding_mismatch_rejects_after_asset_binding
    {input : CashVmMintBindingInput}
    (version : input.versionMatches = true)
    (sourceAppFamily : input.sourceAppFamilyMatches = true)
    (destination : input.destinationMatches = true)
    (mintNonce : input.mintNonceMatches = true)
    (recipient : input.recipientCommitmentNonzero = true)
    (amount : input.amountNonzero = true)
    (bound : input.amountWithinBound = true)
    (asset : input.assetNonNative = true)
    (policyDestination : input.destinationMatchesBridgePolicy = true)
    (bridgeInstance : input.bridgeInstanceMatchesTokenCategory = true)
    (assetBinding : input.tokenCategoryMatchesPayloadAsset = true)
    (recipientBinding : input.recipientHashMatchesPayloadRecipient = false) :
    evaluateCashVmMintBinding input =
      Except.error CashVmMintBindingReject.recipientBindingMismatch := by
  unfold evaluateCashVmMintBinding
  simp [
    version,
    sourceAppFamily,
    destination,
    mintNonce,
    recipient,
    amount,
    bound,
    asset,
    policyDestination,
    bridgeInstance,
    assetBinding,
    recipientBinding
  ]

theorem cashvm_replay_witness_depth_mismatch_rejects_first
    {input : CashVmReplayUpdateInput}
    (witnessDepth : input.witnessDepthValid = false) :
    evaluateCashVmReplayUpdate input =
      Except.error CashVmReplayUpdateReject.replayWitnessDepthMismatch := by
  unfold evaluateCashVmReplayUpdate
  simp [witnessDepth]

theorem cashvm_previous_replay_root_mismatch_rejects_first
    {input : CashVmReplayUpdateInput}
    (witnessDepth : input.witnessDepthValid = true)
    (previousRoot : input.previousRootMatches = false) :
    evaluateCashVmReplayUpdate input =
      Except.error CashVmReplayUpdateReject.previousReplayRootMismatch := by
  unfold evaluateCashVmReplayUpdate
  simp [witnessDepth, previousRoot]

theorem cashvm_duplicate_replay_leaf_rejects_after_previous_root
    {input : CashVmReplayUpdateInput}
    (witnessDepth : input.witnessDepthValid = true)
    (previousRoot : input.previousRootMatches = true)
    (leafAbsent : input.replayLeafAbsent = false) :
    evaluateCashVmReplayUpdate input =
      Except.error CashVmReplayUpdateReject.replayAlreadySpent := by
  unfold evaluateCashVmReplayUpdate
  simp [witnessDepth, previousRoot, leafAbsent]

theorem cashvm_next_replay_root_mismatch_rejects_after_absence
    {input : CashVmReplayUpdateInput}
    (witnessDepth : input.witnessDepthValid = true)
    (previousRoot : input.previousRootMatches = true)
    (leafAbsent : input.replayLeafAbsent = true)
    (nextRoot : input.nextRootMatches = false)
    :
    evaluateCashVmReplayUpdate input =
      Except.error CashVmReplayUpdateReject.nextReplayRootMismatch := by
  unfold evaluateCashVmReplayUpdate
  simp [witnessDepth, previousRoot, leafAbsent, nextRoot]

end MintPayloadAdmission
end Bridge
end Hegemon
