import SmzaRp05LeafNamespace
import SmzaRp04StatementRecordFilter
import SmzaRp04TracePrefixes

/-!
# SMZA RP05 statement-filtered leaf-v2 readback

This module instantiates the RP04 statement-record filter with the literal
strict-leaf-v2 parser.  Traversal is not delegated to the historical
`rawOnlineNext`: that function uses the v1-only `rawPayload`.  Instead, the
new `currentOnlineNext` explicitly normalizes an accepted v2 leaf to its old
1,280-byte Merkle payload and otherwise preserves the historical nonleaf
payloads before calling the parser-independent `payloadNext`.

The least-preimage extractor continues to store and select the original raw
input.  In particular, a leaf trace contains the full v2 frame and its
2,384-byte payload; normalization occurs only when that trace is read as a
Merkle payload.  No extraction-success or accepted-proof outcome is assumed.
The namespace relation digest remains a parameter pending generated pinning.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05FilteredReadback

open V8Smz9CoherentMerkleGeometry
open V8SmzaOracleParser V8SmzaOnlineParser
open HegemonCrypto.CanonicalBytes
open SmzaRecordedTracePath SmzaRawRecordedPrefix
open SmzaRp04StatementRecordFilter SmzaRp05LeafNamespace
open SmzaRp04TracePrefixes
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev Payload := V8SmzaOracleParser.Payload
abbrev Trace := ExtractionTrace RawInput
abbrev Records := V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest

/-- Salt-independent parser used by the global record filter.  Salt is not
part of the statement namespace: it is recovered from the old leaf payload's
first 32 bytes and then checked by the fixed-context parser. -/
def globalLeafStatement (ns : Namespace) :
    StatementParser RawInput (List Byte) :=
  fun input => do
    let (_, bytes) ← V8SmzaOracleParser.parseFramed input
    leafStatement ns ((bytes.drop preambleBytes).take 32) input

def freshRecords (ns : Namespace) (statement : List Byte)
    (records : Records) : Records :=
  oneStatementFilter (globalLeafStatement ns) statement records

def outsideAuthorizedRecords (ns : Namespace)
    (authorized : Finset (List Byte)) (records : Records) : Records :=
  authorizedFilter (globalLeafStatement ns) authorized records

/-- Every fixed-context canonical leaf, for every salt, is recognized by the
single global statement parser as its complete preamble. -/
theorem fixed_context_leaf_is_global_statement
    (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) :
    globalLeafStatement ns
      (encodeLeaf leaf.preamble leaf.legacyPayload) = some leaf.preamble := by
  have framed := encode_frame_roundtrip leaf.preamble leaf.legacyPayload
    leaf.preamble_length leaf.legacy_payload_length
  have dropped : (leaf.preamble ++ leaf.legacyPayload).drop preambleBytes =
      leaf.legacyPayload := by
    simp [← leaf.preamble_length]
  have saltRead : leaf.legacyPayload.take 32 = salt :=
    leaf.legacyCanonical.2.2.1
  simp [globalLeafStatement, framed, dropped, saltRead,
    leaf_statement_roundtrip ns salt leaf]

/-- V2-aware traversal.  Its return edges are still the existing exact
node/root/FPP/PIOP/DECS geometry; only leaf decoding is replaced. -/
def currentOnlineNext (ns : Namespace) (salt : List Byte)
    (stage : Stage) (input : RawInput) :
    Option (List (Stage × RawDigest)) := do
  let parsed ← normalizedPayload ns salt input
  payloadNext stage parsed

/-- RP05 semantic validation.  Framing and edge geometry remain reusable, but
the historical `Payload.Valid` is deliberately not used because its context
hard-pins an older relation digest.  Root and FPP trailing bindings are checked
by the current ns predicate. -/
def CurrentPayloadValid (ns : Namespace) (salt : List Byte)
    (payload : Payload) : Prop :=
  salt.length = 32 ∧ payload.bytes.length = payloadBytes payload.kind ∧
  match payload.kind with
  | .leaf => LegacyLeafCanonical salt payload.bytes
  | .node => True
  | .root => payload.bytes.take 32 = salt ∧
      ns.canonicalPreamble (payload.bytes.drop 96) = true
  | .fpp =>
      (∀ i : Fin 2030, V8SmzaOracleParser.wordAt payload.bytes (8 + i.val) < goldilocksModulus) ∧
      ns.canonicalPreamble (payload.bytes.drop 16304) = true
  | .piop => ∀ i : Fin 3105,
      V8SmzaOracleParser.wordAt payload.bytes (8 + i.val) < goldilocksModulus
  | .decs => ∀ i : Fin 4872,
      V8SmzaOracleParser.wordAt payload.bytes (8 + i.val) < goldilocksModulus

instance (ns : Namespace) (salt : List Byte) (payload : Payload) :
    Decidable (CurrentPayloadValid ns salt payload) := by
  unfold CurrentPayloadValid
  cases payload.kind <;> infer_instance

def parseAcceptedPayload (ns : Namespace) (salt : List Byte)
    (input : RawInput) : Option { payload : Payload //
      CurrentPayloadValid ns salt payload } := do
  let payload ← normalizedPayload ns salt input
  if valid : CurrentPayloadValid ns salt payload then
    some ⟨payload, valid⟩
  else none

theorem current_leaf_accepted_roundtrip
    (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) :
    (parseAcceptedPayload ns salt
      (encodeLeaf leaf.preamble leaf.legacyPayload)).map Subtype.val =
      some leaf.normalized := by
  have valid : CurrentPayloadValid ns salt leaf.normalized :=
    ⟨leaf.legacyCanonical.1, leaf.legacy_payload_length,
      leaf.legacyCanonical⟩
  simp [parseAcceptedPayload, normalized_roundtrip ns salt leaf, valid]

theorem accepted_root_retains_current_namespace
    (ns : Namespace) (salt : List Byte) (payload : Payload)
    (valid : CurrentPayloadValid ns salt payload)
    (kind : payload.kind = .root) :
    payload.bytes.take 32 = salt ∧
      ns.canonicalPreamble (payload.bytes.drop 96) = true := by
  simpa [CurrentPayloadValid, kind] using valid.2.2

theorem accepted_root_retains_current_relation_digest
    (ns : Namespace) (salt : List Byte) (payload : Payload)
    (valid : CurrentPayloadValid ns salt payload)
    (kind : payload.kind = .root) :
    ((payload.bytes.drop 96).drop 36).take 48 = ns.relationDigest := by
  exact ns.canonicalRelationDigest _
    (accepted_root_retains_current_namespace ns salt payload valid kind).2

theorem accepted_fpp_retains_current_relation_digest
    (ns : Namespace) (salt : List Byte) (payload : Payload)
    (valid : CurrentPayloadValid ns salt payload)
    (kind : payload.kind = .fpp) :
    ((payload.bytes.drop 16304).drop 36).take 48 =
      ns.relationDigest := by
  have retained : ns.canonicalPreamble
      (payload.bytes.drop 16304) = true := by
    have shape := valid.2.2
    simp only [kind] at shape
    exact shape.2
  exact ns.canonicalRelationDigest _ retained

theorem current_leaf_terminal (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) :
    currentOnlineNext ns salt (.tree 0)
      (encodeLeaf leaf.preamble leaf.legacyPayload) = some [] := by
  simp [currentOnlineNext, normalized_roundtrip ns salt leaf,
    CurrentLeaf.normalized, payloadNext]

/-- All old nonleaf frames feed exactly the same payload into the existing
edge decoder.  This is the explicit bridge for internal nodes and wrappers. -/
theorem historical_nonleaf_next_preserved
    (ns : Namespace) (salt bytes : List Byte)
    (kind : Kind) (notLeaf : kind ≠ .leaf)
    (payloadLength : bytes.length = payloadBytes kind) (stage : Stage) :
    currentOnlineNext ns salt stage
      (framedInput (roleName kind) bytes) = payloadNext stage ⟨kind, bytes⟩ := by
  simp [currentOnlineNext,
    framed_nonleaf_payload_preserved ns salt bytes kind notLeaf payloadLength]

/-- A canonical source write is retained by its own statement view. -/
theorem source_write_retained_in_fresh_records
    (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) (output : RawDigest) (records : Records)
    (recorded : (encodeLeaf leaf.preamble leaf.legacyPayload, output) ∈ records) :
    (encodeLeaf leaf.preamble leaf.legacyPayload, output) ∈
      freshRecords ns leaf.preamble records := by
  apply Finset.mem_filter.mpr
  refine ⟨recorded, ?_⟩
  right
  exact fixed_context_leaf_is_global_statement ns salt leaf

/-- Once the complete preamble is marked authorized, inserting its canonical
source write leaves the outside-authorization relation unchanged. -/
theorem source_write_marked_filter_unchanged
    (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) (authorized : Finset (List Byte))
    (marked : leaf.preamble ∈ authorized) (output : RawDigest)
    (records : Records) :
    outsideAuthorizedRecords ns authorized
        (insert (encodeLeaf leaf.preamble leaf.legacyPayload, output) records) =
      outsideAuthorizedRecords ns authorized records := by
  exact authorizedFilter_insert_authorized
    (globalLeafStatement ns) authorized leaf.preamble marked
    (encodeLeaf leaf.preamble leaf.legacyPayload)
    (fixed_context_leaf_is_global_statement ns salt leaf)
    output records

theorem fresh_records_collision_free
    (ns : Namespace) (statement : List Byte)
    (authorized : Finset (List Byte)) (fresh : statement ∉ authorized)
    (records : Records)
    (collisionFree : RecordsCollisionFree
      (outsideAuthorizedRecords ns authorized records)) :
    RecordsCollisionFree (freshRecords ns statement records) := by
  exact oneStatementFilter_collisionFree_of_authorized
    (globalLeafStatement ns) authorized statement fresh records
    collisionFree

/-- The trace reader parses payloads through the v2 normalization bridge while
leaving the trace's stored raw input untouched. -/
def normalizedTracePayload (ns : Namespace) (salt : List Byte)
    (kind : Kind) (trace : Trace) : Option Payload := do
  let input ← match trace with
    | .record input _ => some input
    | _ => none
  let parsed ← normalizedPayload ns salt input
  if parsed.kind = kind then some parsed else none

theorem normalized_payload_of_read_path
    (ns : Namespace) (salt : List Byte)
    (path : List Nat) (trace : Trace) (input : RawInput) (parsed : Payload)
    (readback : readPath path trace = some input)
    (parse : normalizedPayload ns salt input = some parsed) :
    normalizedTracePayload ns salt parsed.kind (subtree path trace) =
      some parsed := by
  induction path generalizing trace with
  | nil =>
      cases trace with
      | missing => cases readback
      | budget => cases readback
      | record actual children =>
          have same : actual = input := Option.some.inj readback
          subst actual
          simp [subtree, normalizedTracePayload, parse]
  | cons index rest ih =>
      cases trace with
      | missing => cases readback
      | budget => cases readback
      | record actual children =>
          simp only [readPath] at readback
          cases selected : children[index]? with
          | none => simp [selected] at readback
          | some childTrace =>
              have below : readPath rest childTrace = some input := by
                simpa only [selected, Option.bind_some] using readback
              simpa only [subtree, selected, Option.getD_some] using
                ih childTrace below

def indexPath (coordinate : SmzaQ38McaSourceBinding.Position) : Nat → List Nat
  | 0 => []
  | depth + 1 =>
      (if coordinate.val.testBit depth then 1 else 0) ::
        indexPath coordinate depth

theorem index_path_length (coordinate : SmzaQ38McaSourceBinding.Position)
    (depth : Nat) : (indexPath coordinate depth).length = depth := by
  induction depth with
  | zero => rfl
  | succ depth ih => simp only [indexPath, List.length_cons, ih]

theorem child_eq_subtree (trace : Trace) (index : Nat) :
    child trace index = subtree [index] trace := by
  cases trace <;> rfl

theorem descend_eq_subtree
    (coordinate : SmzaQ38McaSourceBinding.Position)
    (depth : Nat) (trace : Trace) :
    descend coordinate depth trace = subtree (indexPath coordinate depth) trace := by
  induction depth generalizing trace with
  | zero => simp only [descend, indexPath, subtree]
  | succ depth ih =>
      rw [descend, indexPath, subtree_cons, ← child_eq_subtree, ih]

/-- Current committed-oracle readback: only the payload reader changes; the
tree coordinate geometry and field-word layout are unchanged. -/
def currentRootOracle (ns : Namespace) (salt : List Byte)
    (root : Trace) : SmzaQ38OracleExtraction.CommittedOracle :=
  fun coordinate row =>
    match normalizedTracePayload ns salt .leaf
        (descend coordinate 23 (child root 0)) with
    | none => 0
    | some leaf =>
        if V8SmzaOracleParser.wordAt leaf.bytes 4 = coordinate.val ∧
            V8SmzaOracleParser.wordAt leaf.bytes 13 = 140 ∧
            V8SmzaOracleParser.wordAt leaf.bytes 154 = 5 then
          fieldWordAt leaf.bytes
            (if row.val < 140 then 14 + row.val else 155 + (row.val - 140))
        else 0

/-- Direct least-preimage readback of the complete v2 frame.  The returned
input is the original record key, not the normalized 1,280-byte payload. -/
theorem fresh_raw_leaf_address_readback
    (ns : Namespace) (salt : List Byte)
    (authorized : Finset (List Byte)) (leaf : CurrentLeaf ns salt)
    (fresh : leaf.preamble ∉ authorized) (records : Records)
    (collisionFree : RecordsCollisionFree
      (outsideAuthorizedRecords ns authorized records))
    (stage : Stage) (target : RawDigest) (path : List Nat)
    (recorded : RecordedPath (currentOnlineNext ns salt)
      (freshRecords ns leaf.preamble records) stage target path
      (encodeLeaf leaf.preamble leaf.legacyPayload))
    (fuel : Nat) (enough : path.length < fuel) :
    readPath path
        (extract (currentOnlineNext ns salt)
          (freshRecords ns leaf.preamble records) fuel stage target) =
      some (encodeLeaf leaf.preamble leaf.legacyPayload) := by
  exact recorded_path_readback (currentOnlineNext ns salt)
    (freshRecords ns leaf.preamble records)
    (fresh_records_collision_free ns leaf.preamble authorized fresh
      records collisionFree)
    stage target path (encodeLeaf leaf.preamble leaf.legacyPayload)
    recorded fuel enough

/-- Fresh, canonical v2 leaf readback through the actual least-preimage
extractor.  `RecordedPath` supplies concrete recorded leaf/node edges; it is
not a successful-extraction premise.  The selected trace retains the literal
v2 raw address, while `currentRootOracle` consumes its normalized payload. -/
theorem fresh_current_root_oracle_cell_of_recorded_path
    (ns : Namespace) (salt : List Byte)
    (authorized : Finset (List Byte)) (leaf : CurrentLeaf ns salt)
    (fresh : leaf.preamble ∉ authorized) (records : Records)
    (collisionFree : RecordsCollisionFree
      (outsideAuthorizedRecords ns authorized records))
    (root : RawDigest) (coordinate : SmzaQ38McaSourceBinding.Position)
    (row : Fin 145)
    (recorded : RecordedPath (currentOnlineNext ns salt)
      (freshRecords ns leaf.preamble records) .root root
      (0 :: indexPath coordinate 23)
      (encodeLeaf leaf.preamble leaf.legacyPayload))
    (index : V8SmzaOracleParser.wordAt leaf.legacyPayload 4 = coordinate.val)
    (fuel : Nat) (enough : 25 ≤ fuel) :
    currentRootOracle ns salt
        (extract (currentOnlineNext ns salt)
          (freshRecords ns leaf.preamble records) fuel .root root)
        coordinate row =
      fieldWordAt leaf.legacyPayload
        (if row.val < 140 then 14 + row.val else 155 + (row.val - 140)) := by
  have pathRead := fresh_raw_leaf_address_readback ns salt authorized leaf
    fresh records collisionFree .root root (0 :: indexPath coordinate 23)
    recorded fuel
    (by simp only [List.length_cons, index_path_length]; omega)
  have payloadRead := normalized_payload_of_read_path ns salt
    (0 :: indexPath coordinate 23)
    (extract (currentOnlineNext ns salt)
      (freshRecords ns leaf.preamble records) fuel .root root)
    (encodeLeaf leaf.preamble leaf.legacyPayload) leaf.normalized pathRead
    (normalized_roundtrip ns salt leaf)
  rw [subtree_cons] at payloadRead
  change normalizedTracePayload ns salt .leaf
      (subtree (indexPath coordinate 23)
        (subtree [0]
          (extract (currentOnlineNext ns salt)
            (freshRecords ns leaf.preamble records) fuel .root root))) =
      some leaf.normalized at payloadRead
  have childZero : subtree [0]
      (extract (currentOnlineNext ns salt)
        (freshRecords ns leaf.preamble records) fuel .root root) =
      child (extract (currentOnlineNext ns salt)
        (freshRecords ns leaf.preamble records) fuel .root root) 0 := by
    cases extract (currentOnlineNext ns salt)
      (freshRecords ns leaf.preamble records) fuel .root root <;> rfl
  rw [childZero, ← descend_eq_subtree] at payloadRead
  have dataCount : V8SmzaOracleParser.wordAt leaf.legacyPayload 13 = 140 :=
    leaf.legacyCanonical.2.2.2.2.1
  have maskCount : V8SmzaOracleParser.wordAt leaf.legacyPayload 154 = 5 :=
    leaf.legacyCanonical.2.2.2.2.2.1
  unfold currentRootOracle
  rw [payloadRead]
  exact if_pos ⟨index, dataCount, maskCount⟩

end
end HegemonCrypto.SmallWood.SmzaRp05FilteredReadback
