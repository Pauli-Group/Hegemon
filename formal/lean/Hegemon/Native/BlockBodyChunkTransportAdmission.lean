namespace Hegemon
namespace Native
namespace BlockBodyChunkTransportAdmission

/-!
Executable admission model for the native V2 chunked block-body transport.

This covers manifest/chunk arithmetic, resource admission, request and
duplicate handling, the body-hash transcript preimage, and completion-check
precedence. It is not a model of BLAKE3 security, bincode correctness, peer
honesty, network liveness, storage durability, light-client block availability,
or the downstream block-import rules. These chunks are P2P block-body
fragments, not DA sampling chunks.
-/

def usizeMax : Nat := 18446744073709551615
def bodySchemaVersion : Nat := 3
def chunkBytes : Nat := 1048576
def maxBodyBytes : Nat := 68477440
def maxChunkCount : Nat := 66
def maxReassembliesPerPeer : Nat := 1
def maxReassembliesGlobal : Nat := 4
def maxReservedBytes : Nat := 273909760

def checkedAddUsize (lhs rhs : Nat) : Option Nat :=
  if lhs > usizeMax || rhs > usizeMax || lhs + rhs > usizeMax then none
  else some (lhs + rhs)

def derivedChunkCount (totalLen : Nat) : Nat :=
  (totalLen + chunkBytes - 1) / chunkBytes

inductive LocatorReject where
  | schemaVersion
  | chainId
  | rulesHash
  | totalLenEmpty
  | totalLenTooLarge
  | chunkCount
deriving DecidableEq, Repr

structure LocatorInput where
  schemaMatches : Bool
  chainIdMatches : Bool
  rulesHashMatches : Bool
  totalLen : Nat
  declaredChunkCount : Nat
deriving DecidableEq, Repr

def evaluateLocator (input : LocatorInput) : Except LocatorReject Nat :=
  if input.schemaMatches = false then Except.error LocatorReject.schemaVersion
  else if input.chainIdMatches = false then Except.error LocatorReject.chainId
  else if input.rulesHashMatches = false then Except.error LocatorReject.rulesHash
  else if input.totalLen = 0 then Except.error LocatorReject.totalLenEmpty
  else if input.totalLen > maxBodyBytes then Except.error LocatorReject.totalLenTooLarge
  else
    let expected := derivedChunkCount input.totalLen
    if input.declaredChunkCount != expected then Except.error LocatorReject.chunkCount
    else Except.ok expected

inductive ChunkReject where
  | totalLenEmpty
  | totalLenTooLarge
  | chunkCount
  | chunkIndex
  | payloadTooLarge
  | chunkLength
deriving DecidableEq, Repr

structure ChunkInput where
  totalLen : Nat
  declaredChunkCount : Nat
  chunkIndex : Nat
  declaredChunkLen : Nat
  actualChunkLen : Nat
deriving DecidableEq, Repr

def expectedChunkLength (totalLen chunkIndex : Nat) : Nat :=
  let start := chunkIndex * chunkBytes
  min (totalLen - start) chunkBytes

def evaluateChunk (input : ChunkInput) : Except ChunkReject Nat :=
  if input.totalLen = 0 then Except.error ChunkReject.totalLenEmpty
  else if input.totalLen > maxBodyBytes then Except.error ChunkReject.totalLenTooLarge
  else
    let expectedCount := derivedChunkCount input.totalLen
    if input.declaredChunkCount != expectedCount then Except.error ChunkReject.chunkCount
    else if input.chunkIndex ≥ input.declaredChunkCount then Except.error ChunkReject.chunkIndex
    else if input.actualChunkLen > chunkBytes then Except.error ChunkReject.payloadTooLarge
    else
      let expectedLen := expectedChunkLength input.totalLen input.chunkIndex
      if input.declaredChunkLen != expectedLen || input.actualChunkLen != expectedLen then
        Except.error ChunkReject.chunkLength
      else Except.ok expectedLen

inductive RegistrationReject where
  | locator
  | conflictingLocator
  | perPeerLimit
  | globalLimit
  | reservedByteOverflow
  | reservedByteLimit
deriving DecidableEq, Repr

structure RegistrationInput where
  locatorValid : Bool
  existingSame : Bool
  existingConflict : Bool
  peerEntries : Nat
  globalEntries : Nat
  reservedBytes : Nat
  incomingTotalLen : Nat
deriving DecidableEq, Repr

/-- Successful `false` means an identical active locator was already
registered; successful `true` means a new bounded assembly was inserted. -/
def evaluateRegistration (input : RegistrationInput) : Except RegistrationReject Bool :=
  if input.locatorValid = false then Except.error RegistrationReject.locator
  else if input.existingSame then Except.ok false
  else if input.existingConflict then Except.error RegistrationReject.conflictingLocator
  else if input.peerEntries ≥ maxReassembliesPerPeer then
    Except.error RegistrationReject.perPeerLimit
  else if input.globalEntries ≥ maxReassembliesGlobal then
    Except.error RegistrationReject.globalLimit
  else
    match checkedAddUsize input.reservedBytes input.incomingTotalLen with
    | none => Except.error RegistrationReject.reservedByteOverflow
    | some nextReserved =>
        if nextReserved > maxReservedBytes then
          Except.error RegistrationReject.reservedByteLimit
        else Except.ok true

inductive PushReject where
  | chunk
  | unsolicited
  | locatorConflict
  | duplicate
  | conflictingDuplicate
  | receivedByteOverflow
  | receivedBytesExceedTotal
deriving DecidableEq, Repr

structure PushInput where
  chunkValid : Bool
  requested : Bool
  locatorMatches : Bool
  duplicatePresent : Bool
  duplicateBytesMatch : Bool
  receivedBytes : Nat
  incomingBytes : Nat
  declaredTotalLen : Nat
deriving DecidableEq, Repr

def evaluatePush (input : PushInput) : Except PushReject Nat :=
  if input.chunkValid = false then Except.error PushReject.chunk
  else if input.requested = false then Except.error PushReject.unsolicited
  else if input.locatorMatches = false then Except.error PushReject.locatorConflict
  else if input.duplicatePresent then
    if input.duplicateBytesMatch then Except.error PushReject.duplicate
    else Except.error PushReject.conflictingDuplicate
  else
    match checkedAddUsize input.receivedBytes input.incomingBytes with
    | none => Except.error PushReject.receivedByteOverflow
    | some nextReceived =>
        if nextReceived > input.declaredTotalLen then
          Except.error PushReject.receivedBytesExceedTotal
        else Except.ok nextReceived

inductive CompletionReject where
  | receivedLength
  | reassembledLength
  | bodyHash
  | bincodeBudget
  | exactDecode
  | canonicalReencode
  | locatorMetadata
deriving DecidableEq, Repr

structure CompletionInput where
  receivedLengthMatches : Bool
  reassembledLengthMatches : Bool
  bodyHashMatches : Bool
  bincodeBudgetAccepts : Bool
  exactDecodeConsumesAll : Bool
  canonicalReencodeMatches : Bool
  locatorMetadataMatches : Bool
deriving DecidableEq, Repr

def evaluateCompletion (input : CompletionInput) : Except CompletionReject Unit :=
  if input.receivedLengthMatches = false then Except.error CompletionReject.receivedLength
  else if input.reassembledLengthMatches = false then
    Except.error CompletionReject.reassembledLength
  else if input.bodyHashMatches = false then Except.error CompletionReject.bodyHash
  else if input.bincodeBudgetAccepts = false then Except.error CompletionReject.bincodeBudget
  else if input.exactDecodeConsumesAll = false then Except.error CompletionReject.exactDecode
  else if input.canonicalReencodeMatches = false then
    Except.error CompletionReject.canonicalReencode
  else if input.locatorMetadataMatches = false then
    Except.error CompletionReject.locatorMetadata
  else Except.ok ()

def bodyHashDomain : List Nat :=
  [104, 101, 103, 101, 109, 111, 110, 45, 110, 97, 116, 105, 118, 101,
   45, 98, 108, 111, 99, 107, 45, 98, 111, 100, 121, 45, 118, 51, 0]

def u64LeBytes (value : Nat) : List Nat :=
  (List.range 8).map (fun index => (value / (256 ^ index)) % 256)

def bodyHashPreimage (body : List Nat) : List Nat :=
  bodyHashDomain ++ u64LeBytes body.length ++ body

theorem exact_chunk_count_boundaries :
    derivedChunkCount 1 = 1 ∧
    derivedChunkCount chunkBytes = 1 ∧
    derivedChunkCount (chunkBytes + 1) = 2 ∧
    derivedChunkCount maxBodyBytes = maxChunkCount := by
  decide

theorem final_chunk_uses_exact_remainder :
    expectedChunkLength (chunkBytes + 17) 1 = 17 := by
  decide

theorem locator_precedence_is_schema_chain_rules_length_count :
    evaluateLocator
      {
        schemaMatches := false
        chainIdMatches := false
        rulesHashMatches := false
        totalLen := 0
        declaredChunkCount := 0
      } = Except.error LocatorReject.schemaVersion := by
  rfl

theorem chunk_precedence_checks_count_before_index_and_length :
    evaluateChunk
      {
        totalLen := chunkBytes + 1
        declaredChunkCount := 1
        chunkIndex := 2
        declaredChunkLen := 0
        actualChunkLen := chunkBytes + 1
      } = Except.error ChunkReject.chunkCount := by
  rfl

theorem completion_hash_precedes_decode :
    evaluateCompletion
      {
        receivedLengthMatches := true
        reassembledLengthMatches := true
        bodyHashMatches := false
        bincodeBudgetAccepts := false
        exactDecodeConsumesAll := false
        canonicalReencodeMatches := false
        locatorMetadataMatches := false
      } = Except.error CompletionReject.bodyHash := by
  rfl

theorem sample_hash_preimage_binds_domain_length_and_body :
    bodyHashPreimage [1, 2, 3] =
      bodyHashDomain ++ [3, 0, 0, 0, 0, 0, 0, 0] ++ [1, 2, 3] := by
  decide

end BlockBodyChunkTransportAdmission
end Native
end Hegemon
