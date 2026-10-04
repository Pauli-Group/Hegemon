import SmallWoodV8SmzaOracleParserR2

/-!
# SMZA RP05 strict-leaf-v2 statement namespace

This module specializes only the SMZA leaf role.  The historical R2 parser,
its strict-leaf-v1 role, and its fixed RP04 relation digest remain unchanged.
The new parser keeps the raw v2 address, extracts the complete 1,104-byte
canonical preamble as the statement namespace, and normalizes only the final
1,280 bytes to the historical leaf payload used by Merkle readback.

The namespace predicate and relation digest are parameters until generated
source pins instantiate them.  This file is not a Rust/Lean refinement,
accepted-proof, raw-decoder transport, extraction, or production receipt.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05LeafNamespace

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8SmzaOracleParser
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical

set_option autoImplicit false
set_option maxRecDepth 5000
set_option maxHeartbeats 1000000

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev Payload := V8SmzaOracleParser.Payload

def preambleBytes : Nat := 1104
def preambleWords : Nat := 138
def legacyLeafPayloadBytes : Nat := 1280
def currentLeafPayloadBytes : Nat := 2384
def currentLeafPayloadWords : Nat := 298

theorem preamble_bytes_exact : preambleBytes = 1104 := rfl
theorem preamble_words_exact : preambleWords = 138 := rfl
theorem preamble_word_bytes_exact : 8 * preambleWords = preambleBytes := by decide
theorem current_payload_bytes_exact :
    preambleBytes + legacyLeafPayloadBytes = currentLeafPayloadBytes := by decide
theorem current_payload_words_exact :
    currentLeafPayloadBytes / 8 = currentLeafPayloadWords := by decide
theorem current_payload_aligned :
    8 * (currentLeafPayloadBytes / 8) = currentLeafPayloadBytes := by decide

/-- Exact runtime role `hegemon.smallwood.strict-zk.merkle-leaf.v2`. -/
def leafV2Role : List Byte :=
  [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,
   115,116,114,105,99,116,45,122,107,46,109,101,114,107,108,101,45,108,
   101,97,102,46,118,50]

theorem leaf_v2_role_length : leafV2Role.length = 42 := by decide

theorem leaf_v2_role_ne_v1 :
    leafV2Role ≠ V8SmzaOracleParser.roleName .leaf := by decide

theorem old_role_ne_v2 (kind : V8SmzaOracleParser.Kind) :
    V8SmzaOracleParser.roleName kind ≠ leafV2Role := by
  cases kind <;> decide

theorem decode_old_role_rejects_v2 :
    V8SmzaOracleParser.decodeRole leafV2Role = none := by decide

/-- The source-generated instantiation supplies the exact canonical-preamble
predicate and relation digest.  A Boolean predicate keeps parsing executable;
the laws prevent a predicate from admitting a wrong length or digest. -/
structure Namespace where
  relationDigest : List Byte
  canonicalPreamble : List Byte → Bool
  relationDigestLength : relationDigest.length = 48
  canonicalLength : ∀ preamble,
    canonicalPreamble preamble = true → preamble.length = preambleBytes
  canonicalRelationDigest : ∀ preamble,
    canonicalPreamble preamble = true →
      (preamble.drop 36).take 48 = relationDigest

/-- Exact validation retained from the old 1,280-byte leaf payload, with the
salt supplied by the accepted proof context.  No RP04 binding bytes occur in
this normalized payload. -/
def LegacyLeafCanonical (salt bytes : List Byte) : Prop :=
  salt.length = 32 ∧ bytes.length = legacyLeafPayloadBytes ∧
  bytes.take 32 = salt ∧
  V8SmzaOracleParser.wordAt bytes 4 < 8388608 ∧
  V8SmzaOracleParser.wordAt bytes 13 = 140 ∧
  V8SmzaOracleParser.wordAt bytes 154 = 5 ∧
  (∀ i : Fin 140,
    V8SmzaOracleParser.wordAt bytes (14 + i.val) < goldilocksModulus) ∧
  (∀ i : Fin 5,
    V8SmzaOracleParser.wordAt bytes (155 + i.val) < goldilocksModulus)

instance (salt bytes : List Byte) : Decidable (LegacyLeafCanonical salt bytes) := by
  unfold LegacyLeafCanonical
  infer_instance

structure CurrentLeaf (ns : Namespace) (salt : List Byte) where
  preamble : List Byte
  legacyPayload : List Byte
  preambleCanonical : ns.canonicalPreamble preamble = true
  legacyCanonical : LegacyLeafCanonical salt legacyPayload

def CurrentLeaf.normalized {ns : Namespace} {salt : List Byte}
    (leaf : CurrentLeaf ns salt) : Payload :=
  ⟨.leaf, leaf.legacyPayload⟩

theorem CurrentLeaf.preamble_length {ns : Namespace} {salt : List Byte}
    (leaf : CurrentLeaf ns salt) : leaf.preamble.length = preambleBytes :=
  ns.canonicalLength leaf.preamble leaf.preambleCanonical

theorem CurrentLeaf.legacy_payload_length {ns : Namespace} {salt : List Byte}
    (leaf : CurrentLeaf ns salt) :
    leaf.legacyPayload.length = legacyLeafPayloadBytes :=
  leaf.legacyCanonical.2.1

theorem CurrentLeaf.relation_digest {ns : Namespace} {salt : List Byte}
    (leaf : CurrentLeaf ns salt) :
    (leaf.preamble.drop 36).take 48 = ns.relationDigest :=
  ns.canonicalRelationDigest leaf.preamble leaf.preambleCanonical

def encodeLeaf (preamble legacyPayload : List Byte) : RawInput :=
  V8SmzaOracleParser.framedInput leafV2Role (preamble ++ legacyPayload)

def parseCurrentLeaf (ns : Namespace) (salt : List Byte)
    (input : RawInput) : Option (CurrentLeaf ns salt) := do
  let (role, bytes) ← V8SmzaOracleParser.parseFramed input
  if _ : role = leafV2Role then
    let preamble := bytes.take preambleBytes
    let legacyPayload := bytes.drop preambleBytes
    if preambleOk : ns.canonicalPreamble preamble = true then
      if payloadOk : LegacyLeafCanonical salt legacyPayload then
        some ⟨preamble, legacyPayload, preambleOk, payloadOk⟩
      else none
    else none
  else none

/-- Statement parser interface consumed by `SmzaRp04StatementRecordFilter`.
`none` covers nonleaf, malformed, and historical v1-leaf inputs. -/
def leafStatement (ns : Namespace) (salt : List Byte)
    (input : RawInput) : Option (List Byte) :=
  (parseCurrentLeaf ns salt input).map CurrentLeaf.preamble

/-- Current readback preserves every old nonleaf role.  A valid v2 leaf is
normalized to the old 1,280-byte `Payload`; the historical v1 leaf is rejected
instead of being silently reinterpreted as the current SMZA leaf. -/
def normalizedPayload (ns : Namespace) (salt : List Byte)
    (input : RawInput) : Option Payload :=
  match parseCurrentLeaf ns salt input with
  | some leaf => some leaf.normalized
  | none =>
      match V8SmzaOracleParser.rawPayload input with
      | some payload => if payload.kind = .leaf then none else some payload
      | none => none

theorem encode_frame_roundtrip
    (preamble legacyPayload : List Byte)
    (preambleLength : preamble.length = preambleBytes)
    (payloadLength : legacyPayload.length = legacyLeafPayloadBytes) :
    V8SmzaOracleParser.parseFramed (encodeLeaf preamble legacyPayload) =
      some (leafV2Role, preamble ++ legacyPayload) := by
  apply V8SmzaOracleParser.frame_roundtrip
  · simp [leaf_v2_role_length]
  · simp [preambleLength, payloadLength, preambleBytes,
      legacyLeafPayloadBytes]
  · simp [preambleLength, payloadLength, preambleBytes,
      legacyLeafPayloadBytes]

theorem encode_decode_roundtrip (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) :
    parseCurrentLeaf ns salt
      (encodeLeaf leaf.preamble leaf.legacyPayload) = some leaf := by
  rcases leaf with ⟨preamble, legacyPayload, preambleOk, payloadOk⟩
  have preambleLength := ns.canonicalLength preamble preambleOk
  have payloadLength := payloadOk.2.1
  have takePreamble :
      (preamble ++ legacyPayload).take preambleBytes = preamble := by
    simp [← preambleLength]
  have dropPreamble :
      (preamble ++ legacyPayload).drop preambleBytes = legacyPayload := by
    simp [← preambleLength]
  simp [parseCurrentLeaf,
    encode_frame_roundtrip preamble legacyPayload preambleLength payloadLength,
    takePreamble, dropPreamble, preambleOk, payloadOk]

theorem leaf_statement_roundtrip (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) :
    leafStatement ns salt (encodeLeaf leaf.preamble leaf.legacyPayload) =
      some leaf.preamble := by
  simp [leafStatement, encode_decode_roundtrip ns salt leaf]

theorem normalized_roundtrip (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) :
    normalizedPayload ns salt
      (encodeLeaf leaf.preamble leaf.legacyPayload) = some leaf.normalized := by
  simp [normalizedPayload, encode_decode_roundtrip ns salt leaf]

theorem encoded_leaf_payload_length (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) :
    (leaf.preamble ++ leaf.legacyPayload).length = currentLeafPayloadBytes := by
  rw [List.length_append, leaf.preamble_length, leaf.legacy_payload_length]
  decide

/-- Equality of raw v2 addresses forces equality of the complete canonical
preamble, independently of the trailing legacy payload bytes. -/
theorem namespace_prefix_injective
    (ns : Namespace) (salt : List Byte)
    (left right : CurrentLeaf ns salt)
    (sameAddress : encodeLeaf left.preamble left.legacyPayload =
      encodeLeaf right.preamble right.legacyPayload) :
    left.preamble = right.preamble := by
  have parsed := congrArg V8SmzaOracleParser.parseFramed sameAddress
  rw [encode_frame_roundtrip left.preamble left.legacyPayload
      left.preamble_length left.legacy_payload_length,
    encode_frame_roundtrip right.preamble right.legacyPayload
      right.preamble_length right.legacy_payload_length] at parsed
  have pairEq := Option.some.inj parsed
  have payloadEq : left.preamble ++ left.legacyPayload =
      right.preamble ++ right.legacyPayload := congrArg Prod.snd pairEq
  have prefixEq := congrArg (List.take preambleBytes) payloadEq
  simpa [left.preamble_length, right.preamble_length] using prefixEq

theorem unequal_namespaces_have_disjoint_inputs
    (ns : Namespace) (salt : List Byte)
    (left right : CurrentLeaf ns salt)
    (differentPreamble : left.preamble ≠ right.preamble) :
    encodeLeaf left.preamble left.legacyPayload ≠
      encodeLeaf right.preamble right.legacyPayload := by
  intro sameAddress
  exact differentPreamble
    (namespace_prefix_injective ns salt left right sameAddress)

theorem historical_v1_leaf_rejected
    (ns : Namespace) (salt legacyPayload : List Byte)
    (payloadLength : legacyPayload.length = legacyLeafPayloadBytes) :
    parseCurrentLeaf ns salt
      (V8SmzaOracleParser.framedInput
        (V8SmzaOracleParser.roleName .leaf) legacyPayload) = none := by
  have framed : V8SmzaOracleParser.parseFramed
      (V8SmzaOracleParser.framedInput
        (V8SmzaOracleParser.roleName .leaf) legacyPayload) =
      some (V8SmzaOracleParser.roleName .leaf, legacyPayload) := by
    apply V8SmzaOracleParser.frame_roundtrip
    · decide
    · simp [payloadLength, legacyLeafPayloadBytes]
    · simp [payloadLength, legacyLeafPayloadBytes]
  simp [parseCurrentLeaf, framed, old_role_ne_v2]

theorem historical_v1_leaf_statement_none
    (ns : Namespace) (salt legacyPayload : List Byte)
    (payloadLength : legacyPayload.length = legacyLeafPayloadBytes) :
    leafStatement ns salt
      (V8SmzaOracleParser.framedInput
        (V8SmzaOracleParser.roleName .leaf) legacyPayload) = none := by
  simp [leafStatement,
    historical_v1_leaf_rejected ns salt legacyPayload payloadLength]

/-- The historical parser does not reinterpret a v2 leaf under its v1 role. -/
theorem historical_raw_parser_rejects_v2
    (preamble legacyPayload : List Byte)
    (preambleLength : preamble.length = preambleBytes)
    (payloadLength : legacyPayload.length = legacyLeafPayloadBytes) :
    V8SmzaOracleParser.rawPayload (encodeLeaf preamble legacyPayload) = none := by
  have framed := encode_frame_roundtrip preamble legacyPayload
    preambleLength payloadLength
  simp [V8SmzaOracleParser.rawPayload, framed, decode_old_role_rejects_v2]

theorem historical_v1_leaf_not_current_payload
    (ns : Namespace) (salt legacyPayload : List Byte)
    (payloadLength : legacyPayload.length = legacyLeafPayloadBytes) :
    normalizedPayload ns salt
      (V8SmzaOracleParser.framedInput
        (V8SmzaOracleParser.roleName .leaf) legacyPayload) = none := by
  have current := historical_v1_leaf_rejected ns salt legacyPayload payloadLength
  have framed : V8SmzaOracleParser.parseFramed
      (V8SmzaOracleParser.framedInput
        (V8SmzaOracleParser.roleName .leaf) legacyPayload) =
      some (V8SmzaOracleParser.roleName .leaf, legacyPayload) := by
    apply V8SmzaOracleParser.frame_roundtrip
    · decide
    · simp [payloadLength, legacyLeafPayloadBytes]
    · simp [payloadLength, legacyLeafPayloadBytes]
  simp [normalizedPayload, current, V8SmzaOracleParser.rawPayload, framed,
    V8SmzaOracleParser.role_roundtrip, payloadLength,
    legacyLeafPayloadBytes, V8SmzaOracleParser.payloadBytes]

theorem nonleaf_payload_preserved
    (ns : Namespace) (salt input : List Byte) (payload : Payload)
    (oldParsed : V8SmzaOracleParser.rawPayload input = some payload)
    (notLeaf : payload.kind ≠ .leaf)
    (notCurrent : parseCurrentLeaf ns salt input = none) :
    normalizedPayload ns salt input = some payload := by
  simp [normalizedPayload, notCurrent, oldParsed, notLeaf]

/-- Concrete preservation theorem for every historical nonleaf role and exact
payload length.  Only `.leaf` is replaced by the v2 ns. -/
theorem framed_nonleaf_payload_preserved
    (ns : Namespace) (salt bytes : List Byte)
    (kind : V8SmzaOracleParser.Kind) (notLeaf : kind ≠ .leaf)
    (payloadLength : bytes.length = V8SmzaOracleParser.payloadBytes kind) :
    normalizedPayload ns salt
      (V8SmzaOracleParser.framedInput (V8SmzaOracleParser.roleName kind) bytes) =
      some ⟨kind, bytes⟩ := by
  have framed : V8SmzaOracleParser.parseFramed
      (V8SmzaOracleParser.framedInput
        (V8SmzaOracleParser.roleName kind) bytes) =
      some (V8SmzaOracleParser.roleName kind, bytes) := by
    apply V8SmzaOracleParser.frame_roundtrip
    · cases kind <;> decide
    · cases kind <;> simp [payloadLength, V8SmzaOracleParser.payloadBytes]
    · cases kind <;> simp [payloadLength, V8SmzaOracleParser.payloadBytes]
  have notCurrent : parseCurrentLeaf ns salt
      (V8SmzaOracleParser.framedInput
        (V8SmzaOracleParser.roleName kind) bytes) = none := by
    simp [parseCurrentLeaf, framed, old_role_ne_v2]
  simp [normalizedPayload, notCurrent, V8SmzaOracleParser.rawPayload, framed,
    V8SmzaOracleParser.role_roundtrip, payloadLength, notLeaf]

/-- Exact source-write address theorem used to instantiate the generic record
filter: a canonical v2 write is parsed and marked by its complete preamble. -/
theorem source_write_address_parsed_marked_namespace
    (ns : Namespace) (salt : List Byte)
    (leaf : CurrentLeaf ns salt) :
    leafStatement ns salt
      (encodeLeaf leaf.preamble leaf.legacyPayload) = some leaf.preamble :=
  leaf_statement_roundtrip ns salt leaf

end HegemonCrypto.SmallWood.SmzaRp05LeafNamespace
