namespace Hegemon
namespace Native
namespace CodecAdmission

inductive SyncDecodeReject where
  | wireDecodeRejected
  | legacyBincodePayload
  | trailingBytes
deriving DecidableEq, Repr

structure SyncDecodeInput where
  boundedWireDecodeAccepts : Bool
  consumedAllBytes : Bool
  legacyBincodePayload : Bool
deriving DecidableEq, Repr

def evaluateSyncDecodeRejection (input : SyncDecodeInput) : Option SyncDecodeReject :=
  if input.boundedWireDecodeAccepts = false then
    some SyncDecodeReject.wireDecodeRejected
  else if input.legacyBincodePayload = true then
    some SyncDecodeReject.legacyBincodePayload
  else if input.consumedAllBytes = false then
    some SyncDecodeReject.trailingBytes
  else
    none

def syncDecodeAccepts (input : SyncDecodeInput) : Bool :=
  evaluateSyncDecodeRejection input = none

def syncDecodePreconditions (input : SyncDecodeInput) : Bool :=
  input.boundedWireDecodeAccepts
    && input.consumedAllBytes
    && !input.legacyBincodePayload

theorem sync_accepts_iff_preconditions
    {input : SyncDecodeInput} :
    syncDecodeAccepts input = true ↔ syncDecodePreconditions input = true := by
  cases input with
  | mk boundedWireDecodeAccepts consumedAllBytes legacyBincodePayload =>
      cases boundedWireDecodeAccepts <;>
        cases consumedAllBytes <;>
        cases legacyBincodePayload <;>
        simp [
          syncDecodeAccepts,
          syncDecodePreconditions,
          evaluateSyncDecodeRejection
        ]

theorem sync_rejects_wire_decode_failure
    {input : SyncDecodeInput}
    (wireRejected : input.boundedWireDecodeAccepts = false) :
    evaluateSyncDecodeRejection input =
      some SyncDecodeReject.wireDecodeRejected := by
  unfold evaluateSyncDecodeRejection
  simp [wireRejected]

theorem sync_rejects_trailing_bytes
    {input : SyncDecodeInput}
    (wireAccepted : input.boundedWireDecodeAccepts = true)
    (notLegacy : input.legacyBincodePayload = false)
    (hasTrailing : input.consumedAllBytes = false) :
    evaluateSyncDecodeRejection input =
      some SyncDecodeReject.trailingBytes := by
  unfold evaluateSyncDecodeRejection
  simp [wireAccepted, notLegacy, hasTrailing]

theorem sync_rejects_legacy_bincode_payload
    {input : SyncDecodeInput}
    (wireAccepted : input.boundedWireDecodeAccepts = true)
    (legacy : input.legacyBincodePayload = true) :
    evaluateSyncDecodeRejection input =
      some SyncDecodeReject.legacyBincodePayload := by
  unfold evaluateSyncDecodeRejection
  simp [wireAccepted, legacy]

theorem sync_decode_acceptance_excludes_malleability
    {input : SyncDecodeInput}
    (accepted : syncDecodeAccepts input = true) :
    input.boundedWireDecodeAccepts = true ∧
      input.consumedAllBytes = true := by
  cases input with
  | mk boundedWireDecodeAccepts consumedAllBytes legacyBincodePayload =>
      cases boundedWireDecodeAccepts <;>
        cases consumedAllBytes <;>
        cases legacyBincodePayload <;>
        simp [
          syncDecodeAccepts,
          evaluateSyncDecodeRejection
        ] at accepted ⊢

theorem sync_decode_acceptance_excludes_legacy_bincode
    {input : SyncDecodeInput}
    (accepted : syncDecodeAccepts input = true) :
    input.legacyBincodePayload = false := by
  cases input with
  | mk boundedWireDecodeAccepts consumedAllBytes legacyBincodePayload =>
      cases boundedWireDecodeAccepts <;>
        cases consumedAllBytes <;>
        cases legacyBincodePayload <;>
        simp [
          syncDecodeAccepts,
          evaluateSyncDecodeRejection
        ] at accepted ⊢

inductive ExactDecodeReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure ExactDecodeInput where
  parserAccepts : Bool
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def evaluateExactDecodeRejection (input : ExactDecodeInput) : Option ExactDecodeReject :=
  if input.parserAccepts = false then
    some ExactDecodeReject.parserRejected
  else if input.consumedAllBytes = false then
    some ExactDecodeReject.trailingBytes
  else if input.canonicalReencodeMatches = false then
    some ExactDecodeReject.nonCanonicalEncoding
  else
    none

def exactDecodeAccepts (input : ExactDecodeInput) : Bool :=
  evaluateExactDecodeRejection input = none

def exactDecodePreconditions (input : ExactDecodeInput) : Bool :=
  input.parserAccepts && input.consumedAllBytes && input.canonicalReencodeMatches

theorem exact_accepts_iff_preconditions
    {input : ExactDecodeInput} :
    exactDecodeAccepts input = true ↔ exactDecodePreconditions input = true := by
  cases input with
  | mk parserAccepts consumedAllBytes canonicalReencodeMatches =>
      cases parserAccepts <;>
        cases consumedAllBytes <;>
        cases canonicalReencodeMatches <;>
        simp [
          exactDecodeAccepts,
          exactDecodePreconditions,
          evaluateExactDecodeRejection
        ]

theorem exact_rejects_parser_failure
    {input : ExactDecodeInput}
    (parserRejected : input.parserAccepts = false) :
    evaluateExactDecodeRejection input =
      some ExactDecodeReject.parserRejected := by
  unfold evaluateExactDecodeRejection
  simp [parserRejected]

theorem exact_rejects_trailing_bytes
    {input : ExactDecodeInput}
    (parserAccepted : input.parserAccepts = true)
    (hasTrailing : input.consumedAllBytes = false) :
    evaluateExactDecodeRejection input =
      some ExactDecodeReject.trailingBytes := by
  unfold evaluateExactDecodeRejection
  simp [parserAccepted, hasTrailing]

theorem exact_rejects_noncanonical_encoding
    {input : ExactDecodeInput}
    (parserAccepted : input.parserAccepts = true)
    (consumedAll : input.consumedAllBytes = true)
    (nonCanonical : input.canonicalReencodeMatches = false) :
    evaluateExactDecodeRejection input =
      some ExactDecodeReject.nonCanonicalEncoding := by
  unfold evaluateExactDecodeRejection
  simp [parserAccepted, consumedAll, nonCanonical]

theorem exact_decode_acceptance_excludes_malleability
    {input : ExactDecodeInput}
    (accepted : exactDecodeAccepts input = true) :
    input.parserAccepts = true ∧
      input.consumedAllBytes = true ∧
      input.canonicalReencodeMatches = true := by
  cases input with
  | mk parserAccepts consumedAllBytes canonicalReencodeMatches =>
      cases parserAccepts <;>
        cases consumedAllBytes <;>
        cases canonicalReencodeMatches <;>
        simp [
          exactDecodeAccepts,
          evaluateExactDecodeRejection
        ] at accepted ⊢

inductive BlockActionDecodeReject where
  | actionCountMismatch
  | actionDecodeNotExact
deriving DecidableEq, Repr

structure BlockActionDecodeInput where
  declaredTxCount : Nat
  actualActionPayloadCount : Nat
  everyActionDecodesExactly : Bool
deriving DecidableEq, Repr

def actionCountMatches (input : BlockActionDecodeInput) : Bool :=
  input.declaredTxCount == input.actualActionPayloadCount

def evaluateBlockActionDecodeRejection
    (input : BlockActionDecodeInput) : Option BlockActionDecodeReject :=
  if actionCountMatches input = false then
    some BlockActionDecodeReject.actionCountMismatch
  else if input.everyActionDecodesExactly = false then
    some BlockActionDecodeReject.actionDecodeNotExact
  else
    none

def blockActionDecodeAccepts (input : BlockActionDecodeInput) : Bool :=
  evaluateBlockActionDecodeRejection input = none

def blockActionDecodePreconditions (input : BlockActionDecodeInput) : Bool :=
  actionCountMatches input && input.everyActionDecodesExactly

theorem block_action_decode_accepts_iff_preconditions
    {input : BlockActionDecodeInput} :
    blockActionDecodeAccepts input = true ↔
      blockActionDecodePreconditions input = true := by
  cases input with
  | mk declaredTxCount actualActionPayloadCount everyActionDecodesExactly =>
      cases h : (declaredTxCount == actualActionPayloadCount) <;>
        cases everyActionDecodesExactly <;>
        simp [
          blockActionDecodeAccepts,
          blockActionDecodePreconditions,
          evaluateBlockActionDecodeRejection,
          actionCountMatches,
          h
        ]

theorem block_action_decode_rejects_count_mismatch
    {input : BlockActionDecodeInput}
    (countMismatch : actionCountMatches input = false) :
    evaluateBlockActionDecodeRejection input =
      some BlockActionDecodeReject.actionCountMismatch := by
  unfold evaluateBlockActionDecodeRejection
  simp [countMismatch]

theorem block_action_decode_rejects_nonexact_action
    {input : BlockActionDecodeInput}
    (countMatches : actionCountMatches input = true)
    (nonExactAction : input.everyActionDecodesExactly = false) :
    evaluateBlockActionDecodeRejection input =
      some BlockActionDecodeReject.actionDecodeNotExact := by
  unfold evaluateBlockActionDecodeRejection
  simp [countMatches, nonExactAction]

theorem block_action_decode_acceptance_excludes_malleability
    {input : BlockActionDecodeInput}
    (accepted : blockActionDecodeAccepts input = true) :
    actionCountMatches input = true ∧
      input.everyActionDecodesExactly = true := by
  cases input with
  | mk declaredTxCount actualActionPayloadCount everyActionDecodesExactly =>
      cases h : (declaredTxCount == actualActionPayloadCount) <;>
        cases everyActionDecodesExactly <;>
        simp [
          blockActionDecodeAccepts,
          evaluateBlockActionDecodeRejection,
          actionCountMatches,
          h
        ] at accepted ⊢

theorem block_action_decode_acceptance_binds_declared_count
    {input : BlockActionDecodeInput}
    (accepted : blockActionDecodeAccepts input = true) :
    input.declaredTxCount = input.actualActionPayloadCount := by
  have countMatches :=
    (block_action_decode_acceptance_excludes_malleability
      accepted).left
  simpa [actionCountMatches] using countMatches

inductive NativeMetadataDecodeSource where
  | current
  | legacy
deriving DecidableEq, Repr

inductive NativeMetadataDecodeReject where
  | currentAndLegacyRejected
deriving DecidableEq, Repr

structure NativeMetadataDecodeInput where
  currentExact : ExactDecodeInput
  legacyExact : ExactDecodeInput
deriving DecidableEq, Repr

def evaluateNativeMetadataDecode
    (input : NativeMetadataDecodeInput) :
    Except NativeMetadataDecodeReject NativeMetadataDecodeSource :=
  if exactDecodeAccepts input.currentExact then
    Except.ok NativeMetadataDecodeSource.current
  else if exactDecodeAccepts input.legacyExact then
    Except.ok NativeMetadataDecodeSource.legacy
  else
    Except.error NativeMetadataDecodeReject.currentAndLegacyRejected

def nativeMetadataDecodeAccepts
    (input : NativeMetadataDecodeInput) : Bool :=
  match evaluateNativeMetadataDecode input with
  | Except.ok _ => true
  | Except.error _ => false

def nativeMetadataDecodeSource
    (input : NativeMetadataDecodeInput) :
    Option NativeMetadataDecodeSource :=
  match evaluateNativeMetadataDecode input with
  | Except.ok source => some source
  | Except.error _ => none

def nativeMetadataDecodePreconditions
    (input : NativeMetadataDecodeInput) : Bool :=
  exactDecodeAccepts input.currentExact
    || exactDecodeAccepts input.legacyExact

theorem native_metadata_decode_accepts_iff_preconditions
    (input : NativeMetadataDecodeInput) :
    nativeMetadataDecodeAccepts input =
      nativeMetadataDecodePreconditions input := by
  unfold nativeMetadataDecodeAccepts
    nativeMetadataDecodePreconditions
    evaluateNativeMetadataDecode
  cases hCurrent : exactDecodeAccepts input.currentExact <;>
    cases hLegacy : exactDecodeAccepts input.legacyExact <;>
    simp

theorem native_metadata_current_exact_decode_precedes_legacy
    {input : NativeMetadataDecodeInput}
    (currentAccepted : exactDecodeAccepts input.currentExact = true) :
    evaluateNativeMetadataDecode input =
      Except.ok NativeMetadataDecodeSource.current := by
  unfold evaluateNativeMetadataDecode
  simp [currentAccepted]

theorem native_metadata_legacy_decode_requires_current_rejection
    {input : NativeMetadataDecodeInput}
    (currentRejected : exactDecodeAccepts input.currentExact = false)
    (legacyAccepted : exactDecodeAccepts input.legacyExact = true) :
    evaluateNativeMetadataDecode input =
      Except.ok NativeMetadataDecodeSource.legacy := by
  unfold evaluateNativeMetadataDecode
  simp [currentRejected, legacyAccepted]

theorem native_metadata_decode_rejects_when_current_and_legacy_reject
    {input : NativeMetadataDecodeInput}
    (currentRejected : exactDecodeAccepts input.currentExact = false)
    (legacyRejected : exactDecodeAccepts input.legacyExact = false) :
    evaluateNativeMetadataDecode input =
      Except.error NativeMetadataDecodeReject.currentAndLegacyRejected := by
  unfold evaluateNativeMetadataDecode
  simp [currentRejected, legacyRejected]

structure NativeMetadataDecodeFacts
    (input : NativeMetadataDecodeInput) : Prop where
  acceptsIff :
    nativeMetadataDecodeAccepts input =
      nativeMetadataDecodePreconditions input
  currentExactPrecedesLegacy :
    exactDecodeAccepts input.currentExact = true ->
      evaluateNativeMetadataDecode input =
        Except.ok NativeMetadataDecodeSource.current
  legacyRequiresCurrentRejected :
    exactDecodeAccepts input.currentExact = false ->
      exactDecodeAccepts input.legacyExact = true ->
        evaluateNativeMetadataDecode input =
          Except.ok NativeMetadataDecodeSource.legacy
  bothRejectedFailClosed :
    exactDecodeAccepts input.currentExact = false ->
      exactDecodeAccepts input.legacyExact = false ->
        evaluateNativeMetadataDecode input =
          Except.error NativeMetadataDecodeReject.currentAndLegacyRejected

theorem native_metadata_decode_facts
    {input : NativeMetadataDecodeInput} :
    NativeMetadataDecodeFacts input := by
  exact {
    acceptsIff := native_metadata_decode_accepts_iff_preconditions input
    currentExactPrecedesLegacy :=
      fun currentAccepted =>
        native_metadata_current_exact_decode_precedes_legacy
          currentAccepted
    legacyRequiresCurrentRejected :=
      fun currentRejected legacyAccepted =>
        native_metadata_legacy_decode_requires_current_rejection
          currentRejected
          legacyAccepted
    bothRejectedFailClosed :=
      fun currentRejected legacyRejected =>
        native_metadata_decode_rejects_when_current_and_legacy_reject
          currentRejected
          legacyRejected
  }

inductive NativeMetadataBincodeBudgetReject where
  | metadataBytesOverLimit
  | actionCountOverLimit
  | actionPayloadOverLimit
  | actionPayloadBytesOverLimit
  | minerPublicKeyOverLimit
  | minerSignatureOverLimit
deriving DecidableEq, Repr

structure NativeMetadataBincodeBudgetInput where
  metadataBytes : Nat
  maxMetadataBytes : Nat
  actionCount : Nat
  maxActionCount : Nat
  largestActionPayloadBytes : Nat
  maxActionPayloadBytes : Nat
  actionPayloadBytesTotal : Nat
  maxActionPayloadBytesTotal : Nat
  minerPublicKeyBytes : Nat
  maxMinerPublicKeyBytes : Nat
  minerSignatureBytes : Nat
  maxMinerSignatureBytes : Nat
deriving DecidableEq, Repr

def evaluateNativeMetadataBincodeBudgetRejection
    (input : NativeMetadataBincodeBudgetInput) :
    Option NativeMetadataBincodeBudgetReject :=
  if input.metadataBytes > input.maxMetadataBytes then
    some NativeMetadataBincodeBudgetReject.metadataBytesOverLimit
  else if input.actionCount > input.maxActionCount then
    some NativeMetadataBincodeBudgetReject.actionCountOverLimit
  else if input.largestActionPayloadBytes > input.maxActionPayloadBytes then
    some NativeMetadataBincodeBudgetReject.actionPayloadOverLimit
  else if input.actionPayloadBytesTotal > input.maxActionPayloadBytesTotal then
    some NativeMetadataBincodeBudgetReject.actionPayloadBytesOverLimit
  else if input.minerPublicKeyBytes > input.maxMinerPublicKeyBytes then
    some NativeMetadataBincodeBudgetReject.minerPublicKeyOverLimit
  else if input.minerSignatureBytes > input.maxMinerSignatureBytes then
    some NativeMetadataBincodeBudgetReject.minerSignatureOverLimit
  else
    none

def nativeMetadataBincodeBudgetAccepts
    (input : NativeMetadataBincodeBudgetInput) : Bool :=
  evaluateNativeMetadataBincodeBudgetRejection input = none

structure AcceptedNativeMetadataBincodeBudgetFacts
    (input : NativeMetadataBincodeBudgetInput) : Prop where
  metadataBytesNotOverLimit :
    ¬ input.metadataBytes > input.maxMetadataBytes
  actionCountNotOverLimit :
    ¬ input.actionCount > input.maxActionCount
  largestActionPayloadNotOverLimit :
    ¬ input.largestActionPayloadBytes > input.maxActionPayloadBytes
  actionPayloadBytesTotalNotOverLimit :
    ¬ input.actionPayloadBytesTotal > input.maxActionPayloadBytesTotal
  minerPublicKeyNotOverLimit :
    ¬ input.minerPublicKeyBytes > input.maxMinerPublicKeyBytes
  minerSignatureNotOverLimit :
    ¬ input.minerSignatureBytes > input.maxMinerSignatureBytes

theorem native_metadata_bincode_budget_acceptance_excludes_overruns
    {input : NativeMetadataBincodeBudgetInput}
    (accepted : nativeMetadataBincodeBudgetAccepts input = true) :
    AcceptedNativeMetadataBincodeBudgetFacts input := by
  unfold nativeMetadataBincodeBudgetAccepts at accepted
  unfold evaluateNativeMetadataBincodeBudgetRejection at accepted
  by_cases hMetadata : input.metadataBytes > input.maxMetadataBytes
  · simp [hMetadata] at accepted
  · simp [hMetadata] at accepted
    by_cases hActionCount : input.actionCount > input.maxActionCount
    · simp [hActionCount] at accepted
    · simp [hActionCount] at accepted
      by_cases hActionPayload :
          input.largestActionPayloadBytes > input.maxActionPayloadBytes
      · simp [hActionPayload] at accepted
      · simp [hActionPayload] at accepted
        by_cases hActionPayloadTotal :
            input.actionPayloadBytesTotal > input.maxActionPayloadBytesTotal
        · simp [hActionPayloadTotal] at accepted
        · simp [hActionPayloadTotal] at accepted
          by_cases hMinerPublicKey :
              input.minerPublicKeyBytes > input.maxMinerPublicKeyBytes
          · simp [hMinerPublicKey] at accepted
          · simp [hMinerPublicKey] at accepted
            by_cases hMinerSignature :
                input.minerSignatureBytes > input.maxMinerSignatureBytes
            · exfalso
              exact (Nat.not_lt_of_ge accepted) hMinerSignature
            · exact {
                metadataBytesNotOverLimit := hMetadata,
                actionCountNotOverLimit := hActionCount,
                largestActionPayloadNotOverLimit := hActionPayload,
                actionPayloadBytesTotalNotOverLimit := hActionPayloadTotal,
                minerPublicKeyNotOverLimit := hMinerPublicKey,
                minerSignatureNotOverLimit := hMinerSignature
              }

structure CanonicalDecodeNonMalleabilityFacts
    (syncInput : SyncDecodeInput)
    (exactInput : ExactDecodeInput)
    (actionInput : BlockActionDecodeInput) : Prop where
  syncAcceptsIff :
    syncDecodeAccepts syncInput = true ↔
      syncDecodePreconditions syncInput = true
  exactAcceptsIff :
    exactDecodeAccepts exactInput = true ↔
      exactDecodePreconditions exactInput = true
  actionAcceptsIff :
    blockActionDecodeAccepts actionInput = true ↔
      blockActionDecodePreconditions actionInput = true
  syncAcceptanceExcludesMalleability :
    syncDecodeAccepts syncInput = true ->
      syncInput.boundedWireDecodeAccepts = true ∧
        syncInput.consumedAllBytes = true
  exactAcceptanceExcludesMalleability :
    exactDecodeAccepts exactInput = true ->
      exactInput.parserAccepts = true ∧
        exactInput.consumedAllBytes = true ∧
        exactInput.canonicalReencodeMatches = true
  actionAcceptanceExcludesMalleability :
    blockActionDecodeAccepts actionInput = true ->
      actionCountMatches actionInput = true ∧
        actionInput.everyActionDecodesExactly = true
  exactParserRejects :
    exactInput.parserAccepts = false ->
      evaluateExactDecodeRejection exactInput =
        some ExactDecodeReject.parserRejected
  exactTrailingRejects :
    exactInput.parserAccepts = true ->
      exactInput.consumedAllBytes = false ->
        evaluateExactDecodeRejection exactInput =
          some ExactDecodeReject.trailingBytes
  exactNoncanonicalRejects :
    exactInput.parserAccepts = true ->
      exactInput.consumedAllBytes = true ->
      exactInput.canonicalReencodeMatches = false ->
        evaluateExactDecodeRejection exactInput =
          some ExactDecodeReject.nonCanonicalEncoding
  syncWireRejects :
    syncInput.boundedWireDecodeAccepts = false ->
      evaluateSyncDecodeRejection syncInput =
        some SyncDecodeReject.wireDecodeRejected
  syncTrailingRejects :
    syncInput.boundedWireDecodeAccepts = true ->
      syncInput.legacyBincodePayload = false ->
      syncInput.consumedAllBytes = false ->
        evaluateSyncDecodeRejection syncInput =
          some SyncDecodeReject.trailingBytes
  syncLegacyBincodeRejects :
    syncInput.boundedWireDecodeAccepts = true ->
      syncInput.legacyBincodePayload = true ->
        evaluateSyncDecodeRejection syncInput =
          some SyncDecodeReject.legacyBincodePayload
  actionCountMismatchRejects :
    actionCountMatches actionInput = false ->
      evaluateBlockActionDecodeRejection actionInput =
        some BlockActionDecodeReject.actionCountMismatch
  actionNonExactRejects :
    actionCountMatches actionInput = true ->
      actionInput.everyActionDecodesExactly = false ->
        evaluateBlockActionDecodeRejection actionInput =
          some BlockActionDecodeReject.actionDecodeNotExact

theorem canonical_decode_non_malleability_facts
    {syncInput : SyncDecodeInput}
    {exactInput : ExactDecodeInput}
    {actionInput : BlockActionDecodeInput} :
    CanonicalDecodeNonMalleabilityFacts
      syncInput
      exactInput
      actionInput := by
  exact {
    syncAcceptsIff := sync_accepts_iff_preconditions
    exactAcceptsIff := exact_accepts_iff_preconditions
    actionAcceptsIff := block_action_decode_accepts_iff_preconditions
    syncAcceptanceExcludesMalleability :=
      fun accepted =>
        sync_decode_acceptance_excludes_malleability accepted
    exactAcceptanceExcludesMalleability :=
      fun accepted =>
        exact_decode_acceptance_excludes_malleability accepted
    actionAcceptanceExcludesMalleability :=
      fun accepted =>
        block_action_decode_acceptance_excludes_malleability accepted
    exactParserRejects :=
      fun parserRejected =>
        exact_rejects_parser_failure parserRejected
    exactTrailingRejects :=
      fun parserAccepted hasTrailing =>
        exact_rejects_trailing_bytes parserAccepted hasTrailing
    exactNoncanonicalRejects :=
      fun parserAccepted consumedAll nonCanonical =>
        exact_rejects_noncanonical_encoding
          parserAccepted
          consumedAll
          nonCanonical
    syncWireRejects :=
      fun wireRejected =>
        sync_rejects_wire_decode_failure wireRejected
    syncTrailingRejects :=
      fun wireAccepted notLegacy hasTrailing =>
        sync_rejects_trailing_bytes wireAccepted notLegacy hasTrailing
    syncLegacyBincodeRejects :=
      fun wireAccepted legacy =>
        sync_rejects_legacy_bincode_payload wireAccepted legacy
    actionCountMismatchRejects :=
      fun countMismatch =>
        block_action_decode_rejects_count_mismatch countMismatch
    actionNonExactRejects :=
      fun countMatches nonExactAction =>
        block_action_decode_rejects_nonexact_action
          countMatches
          nonExactAction
  }

def validSync : SyncDecodeInput :=
  {
    boundedWireDecodeAccepts := true,
    consumedAllBytes := true,
    legacyBincodePayload := false
  }

def validExactDecode : ExactDecodeInput :=
  {
    parserAccepts := true,
    consumedAllBytes := true,
    canonicalReencodeMatches := true
  }

def validBlockActions : BlockActionDecodeInput :=
  {
    declaredTxCount := 1,
    actualActionPayloadCount := 1,
    everyActionDecodesExactly := true
  }

def validNativeMetadataCurrent : NativeMetadataDecodeInput :=
  {
    currentExact := validExactDecode,
    legacyExact := { validExactDecode with parserAccepts := false }
  }

def validNativeMetadataLegacy : NativeMetadataDecodeInput :=
  {
    currentExact := { validExactDecode with parserAccepts := false },
    legacyExact := validExactDecode
  }

def trailingNativeMetadataCurrent : NativeMetadataDecodeInput :=
  {
    currentExact := { validExactDecode with consumedAllBytes := false },
    legacyExact := { validExactDecode with parserAccepts := false }
  }

def trailingNativeMetadataLegacy : NativeMetadataDecodeInput :=
  {
    currentExact := { validExactDecode with parserAccepts := false },
    legacyExact := { validExactDecode with consumedAllBytes := false }
  }

def productionMaxNativeMetadataBytes : Nat := 68477440
def productionMaxNativeBlockActions : Nat := 10000
def productionMaxNativeBlockActionPayloadBytes : Nat := 2113536
def productionMaxNativeBlockActionBytes : Nat := 67108864
def productionMaxMlDsaPublicKeyBytes : Nat := 1952
def productionMaxMlDsaSignatureBytes : Nat := 3309

def validNativeMetadataBincodeBudget : NativeMetadataBincodeBudgetInput :=
  {
    metadataBytes := 668,
    maxMetadataBytes := productionMaxNativeMetadataBytes,
    actionCount := 0,
    maxActionCount := productionMaxNativeBlockActions,
    largestActionPayloadBytes := 0,
    maxActionPayloadBytes := productionMaxNativeBlockActionPayloadBytes,
    actionPayloadBytesTotal := 0,
    maxActionPayloadBytesTotal := productionMaxNativeBlockActionBytes,
    minerPublicKeyBytes := 0,
    maxMinerPublicKeyBytes := productionMaxMlDsaPublicKeyBytes,
    minerSignatureBytes := 0,
    maxMinerSignatureBytes := productionMaxMlDsaSignatureBytes
  }

theorem valid_sync_accepts :
    evaluateSyncDecodeRejection validSync = none := by
  rfl

theorem legacy_bincode_sync_rejects :
    evaluateSyncDecodeRejection
      { validSync with
        legacyBincodePayload := true } =
      some SyncDecodeReject.legacyBincodePayload := by
  rfl

theorem trailing_sync_rejects :
    evaluateSyncDecodeRejection
      { validSync with consumedAllBytes := false } =
      some SyncDecodeReject.trailingBytes := by
  rfl

theorem valid_exact_decode_accepts :
    evaluateExactDecodeRejection validExactDecode = none := by
  rfl

theorem trailing_exact_decode_rejects :
    evaluateExactDecodeRejection
      { validExactDecode with consumedAllBytes := false } =
      some ExactDecodeReject.trailingBytes := by
  rfl

theorem parser_failure_rejects :
    evaluateExactDecodeRejection
      { validExactDecode with parserAccepts := false } =
      some ExactDecodeReject.parserRejected := by
  rfl

theorem noncanonical_exact_decode_rejects :
    evaluateExactDecodeRejection
      { validExactDecode with canonicalReencodeMatches := false } =
      some ExactDecodeReject.nonCanonicalEncoding := by
  rfl

theorem valid_block_actions_accept :
    evaluateBlockActionDecodeRejection validBlockActions = none := by
  rfl

theorem action_count_mismatch_rejects :
    evaluateBlockActionDecodeRejection
      { validBlockActions with actualActionPayloadCount := 0 } =
      some BlockActionDecodeReject.actionCountMismatch := by
  rfl

theorem nonexact_action_payload_rejects :
    evaluateBlockActionDecodeRejection
      { validBlockActions with everyActionDecodesExactly := false } =
      some BlockActionDecodeReject.actionDecodeNotExact := by
  rfl

theorem valid_native_metadata_current_selects_current :
    evaluateNativeMetadataDecode validNativeMetadataCurrent =
      Except.ok NativeMetadataDecodeSource.current := by
  rfl

theorem valid_native_metadata_legacy_selects_legacy :
    evaluateNativeMetadataDecode validNativeMetadataLegacy =
      Except.ok NativeMetadataDecodeSource.legacy := by
  rfl

theorem trailing_native_metadata_current_rejects :
    evaluateNativeMetadataDecode trailingNativeMetadataCurrent =
      Except.error NativeMetadataDecodeReject.currentAndLegacyRejected := by
  rfl

theorem trailing_native_metadata_legacy_rejects :
    evaluateNativeMetadataDecode trailingNativeMetadataLegacy =
      Except.error NativeMetadataDecodeReject.currentAndLegacyRejected := by
  rfl

theorem valid_native_metadata_bincode_budget_accepts :
    evaluateNativeMetadataBincodeBudgetRejection
      validNativeMetadataBincodeBudget = none := by
  native_decide

theorem native_metadata_bincode_budget_rejects_metadata_overrun :
    evaluateNativeMetadataBincodeBudgetRejection
      { validNativeMetadataBincodeBudget with
        metadataBytes := productionMaxNativeMetadataBytes + 1 } =
      some NativeMetadataBincodeBudgetReject.metadataBytesOverLimit := by
  native_decide

theorem native_metadata_bincode_budget_rejects_action_count_overrun :
    evaluateNativeMetadataBincodeBudgetRejection
      { validNativeMetadataBincodeBudget with
        actionCount := productionMaxNativeBlockActions + 1 } =
      some NativeMetadataBincodeBudgetReject.actionCountOverLimit := by
  native_decide

theorem native_metadata_bincode_budget_rejects_action_payload_overrun :
    evaluateNativeMetadataBincodeBudgetRejection
      { validNativeMetadataBincodeBudget with
        actionCount := 1,
        largestActionPayloadBytes := productionMaxNativeBlockActionPayloadBytes + 1,
        actionPayloadBytesTotal := productionMaxNativeBlockActionPayloadBytes + 1 } =
      some NativeMetadataBincodeBudgetReject.actionPayloadOverLimit := by
  native_decide

theorem native_metadata_bincode_budget_rejects_action_payload_total_overrun :
    evaluateNativeMetadataBincodeBudgetRejection
      { validNativeMetadataBincodeBudget with
        actionCount := productionMaxNativeBlockActions,
        largestActionPayloadBytes := productionMaxNativeBlockActionPayloadBytes,
        actionPayloadBytesTotal := productionMaxNativeBlockActionBytes + 1 } =
      some NativeMetadataBincodeBudgetReject.actionPayloadBytesOverLimit := by
  native_decide

theorem native_metadata_bincode_budget_rejects_miner_public_key_overrun :
    evaluateNativeMetadataBincodeBudgetRejection
      { validNativeMetadataBincodeBudget with
        minerPublicKeyBytes := productionMaxMlDsaPublicKeyBytes + 1 } =
      some NativeMetadataBincodeBudgetReject.minerPublicKeyOverLimit := by
  native_decide

theorem native_metadata_bincode_budget_rejects_miner_signature_overrun :
    evaluateNativeMetadataBincodeBudgetRejection
      { validNativeMetadataBincodeBudget with
        minerSignatureBytes := productionMaxMlDsaSignatureBytes + 1 } =
      some NativeMetadataBincodeBudgetReject.minerSignatureOverLimit := by
  native_decide

end CodecAdmission
end Native
end Hegemon
