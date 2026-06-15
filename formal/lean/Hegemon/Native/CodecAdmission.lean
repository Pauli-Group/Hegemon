namespace Hegemon
namespace Native
namespace CodecAdmission

inductive SyncDecodeReject where
  | wireDecodeRejected
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
  else if input.consumedAllBytes = false then
    some SyncDecodeReject.trailingBytes
  else
    none

def syncDecodeAccepts (input : SyncDecodeInput) : Bool :=
  evaluateSyncDecodeRejection input = none

def syncDecodePreconditions (input : SyncDecodeInput) : Bool :=
  input.boundedWireDecodeAccepts && input.consumedAllBytes

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
    (hasTrailing : input.consumedAllBytes = false) :
    evaluateSyncDecodeRejection input =
      some SyncDecodeReject.trailingBytes := by
  unfold evaluateSyncDecodeRejection
  simp [wireAccepted, hasTrailing]

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
      syncInput.consumedAllBytes = false ->
        evaluateSyncDecodeRejection syncInput =
          some SyncDecodeReject.trailingBytes
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
      fun wireAccepted hasTrailing =>
        sync_rejects_trailing_bytes wireAccepted hasTrailing
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

theorem valid_sync_accepts :
    evaluateSyncDecodeRejection validSync = none := by
  rfl

theorem legacy_bincode_sync_rejects :
    evaluateSyncDecodeRejection
      { validSync with
        boundedWireDecodeAccepts := false,
        legacyBincodePayload := true } =
      some SyncDecodeReject.wireDecodeRejected := by
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

end CodecAdmission
end Native
end Hegemon
