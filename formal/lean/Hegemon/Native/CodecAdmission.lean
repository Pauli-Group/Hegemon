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

inductive ExactDecodeReject where
  | parserRejected
  | trailingBytes
deriving DecidableEq, Repr

structure ExactDecodeInput where
  parserAccepts : Bool
  consumedAllBytes : Bool
deriving DecidableEq, Repr

def evaluateExactDecodeRejection (input : ExactDecodeInput) : Option ExactDecodeReject :=
  if input.parserAccepts = false then
    some ExactDecodeReject.parserRejected
  else if input.consumedAllBytes = false then
    some ExactDecodeReject.trailingBytes
  else
    none

def exactDecodeAccepts (input : ExactDecodeInput) : Bool :=
  evaluateExactDecodeRejection input = none

def exactDecodePreconditions (input : ExactDecodeInput) : Bool :=
  input.parserAccepts && input.consumedAllBytes

theorem exact_accepts_iff_preconditions
    {input : ExactDecodeInput} :
    exactDecodeAccepts input = true ↔ exactDecodePreconditions input = true := by
  cases input with
  | mk parserAccepts consumedAllBytes =>
      cases parserAccepts <;>
        cases consumedAllBytes <;>
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

def validSync : SyncDecodeInput :=
  {
    boundedWireDecodeAccepts := true,
    consumedAllBytes := true,
    legacyBincodePayload := false
  }

def validExactDecode : ExactDecodeInput :=
  {
    parserAccepts := true,
    consumedAllBytes := true
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
