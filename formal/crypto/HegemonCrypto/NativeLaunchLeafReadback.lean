import HegemonCrypto.NativeLaunchLeafNamespace
import HegemonCrypto.NativeLaunchCommitmentReadback

/-! Complete executable native strict-leaf codec. This is literal byte readback,
not Merkle authentication, SourceReadback, canonical semantic statement checking,
accepted Rust execution, QROM/security, or release authority. -/
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchLeafReadback
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Family Word)
open NativeLaunchRelationModelStatement
open NativeLaunchLeafNamespace
open NativeLaunchCommitmentReadback (encodeFields readFields fields_roundtrip fields_eq_words)
open SmallWood.V8Smz9RawCounterCompiler (typedWordPayload typed_word_payload_length)

structure DecodedLeaf where
  statement : List Byte
  salt : List Byte
  index : Fin (2^23)
  tape : List Byte
  committed : List FieldWord
  masks : List FieldWord

def readIndex (input : List Byte) : Option (Fin (2^23) × List Byte) := do
  let (bytes, rest) ← readFixed 8 input
  if bound : decodeLE bytes < 2^23 then some (⟨decodeLE bytes, bound⟩, rest) else none

def encodeCounted (fields : List FieldWord) : List Byte :=
  encodeLE 8 fields.length ++ encodeFields fields

def readCounted (count : Nat) (input : List Byte) : Option (List FieldWord × List Byte) := do
  let (bytes, rest) ← readFixed 8 input
  if decodeLE bytes = count then readFields count rest else none

theorem index_roundtrip (index : Fin (2^23)) (suffix : List Byte) :
    readIndex (encodeLE 8 index.val ++ suffix) = some (index, suffix) := by
  have modulus : index.val % 18446744073709551616 = index.val :=
    Nat.mod_eq_of_lt (lt_trans index.isLt (by decide))
  simp [readIndex, readFixed_append (encodeLE_length 8 index.val),
    decodeLE_encodeLE, modulus]

theorem counted_roundtrip (fields : List FieldWord) (suffix : List Byte)
    (bound : fields.length < 18446744073709551616) :
    readCounted fields.length (encodeCounted fields ++ suffix) = some (fields, suffix) := by
  have modulus := Nat.mod_eq_of_lt bound
  simp [readCounted, encodeCounted, List.append_assoc,
    readFixed_append (encodeLE_length 8 fields.length), decodeLE_encodeLE,
    modulus, fields_roundtrip]

def suffixBytes (fields : LeafFields) : List Byte :=
  typedWordPayload (List.ofFn fields.salt) ++ encodeLE 8 fields.index.val ++
  typedWordPayload (List.ofFn fields.tape) ++ encodeCounted (List.ofFn fields.committed) ++
  encodeCounted (List.ofFn fields.masks)

theorem singleton_payload (word : Word) : typedWordPayload [word] = encodeLE 8 word.val := by
  simp [typedWordPayload]

theorem source_suffix_exact {family : Family} (statement : Statement family) (fields : LeafFields) :
    (typedWordPayload (strictLeafWords statement fields)).drop (preambleByteCount family) =
      suffixBytes fields := by
  simp only [strictLeafWords, typed_payload_append, List.append_assoc]
  change (statementBytes statement ++ _).drop (preambleByteCount family) = _
  rw [← statement_bytes_length statement, List.drop_left]
  have cells : typedWordPayload (List.ofFn (fieldAsWord ∘ fields.committed)) =
      encodeFields (List.ofFn fields.committed) := by
    rw [fields_eq_words, List.map_ofFn]
  have masks : typedWordPayload (List.ofFn (fieldAsWord ∘ fields.masks)) =
      encodeFields (List.ofFn fields.masks) := by
    rw [fields_eq_words, List.map_ofFn]
  simp only [leafTailWords, typed_payload_append, singleton_payload, cells, masks,
    suffixBytes, encodeCounted, List.length_ofFn, List.append_assoc]
  rfl

def parseSuffix (statement input : List Byte) : Option DecodedLeaf := do
  let (salt, rest) ← readFixed 32 input
  let (index, rest) ← readIndex rest
  let (tape, rest) ← readFixed 64 rest
  let (cells, rest) ← readCounted 140 rest
  let (masks, suffix) ← readCounted 5 rest
  if suffix = [] then some ⟨statement, salt, index, tape, cells, masks⟩ else none

def parseCompleteLeaf (family : Family) (input : List Byte) : Option DecodedLeaf := do
  let (statement, suffix) ← parseLeafNamespace family input
  parseSuffix statement suffix

def decodedFields (statement : List Byte) (fields : LeafFields) : DecodedLeaf :=
  ⟨statement, typedWordPayload (List.ofFn fields.salt), fields.index,
    typedWordPayload (List.ofFn fields.tape), List.ofFn fields.committed, List.ofFn fields.masks⟩

theorem suffix_roundtrip (statement : List Byte) (fields : LeafFields) :
    parseSuffix statement (suffixBytes fields) = some (decodedFields statement fields) := by
  have saltLength : (typedWordPayload (List.ofFn fields.salt)).length = 32 := by
    simp [typed_word_payload_length]
  have tapeLength : (typedWordPayload (List.ofFn fields.tape)).length = 64 := by
    simp [typed_word_payload_length]
  have cellsRead := counted_roundtrip (List.ofFn fields.committed)
    (encodeCounted (List.ofFn fields.masks)) (by simp)
  have masksRead := counted_roundtrip (List.ofFn fields.masks) [] (by simp)
  simp only [List.length_ofFn, List.append_nil] at cellsRead masksRead
  simp only [parseSuffix, suffixBytes, List.append_assoc]
  rw [readFixed_append saltLength]
  simp only [Option.bind_eq_bind', Option.bind_some, index_roundtrip,
    readFixed_append tapeLength, cellsRead, masksRead, if_true, decodedFields]

theorem complete_leaf_roundtrip {family : Family} (statement : Statement family) (fields : LeafFields) :
    parseCompleteLeaf family (strictLeafFrame statement fields) =
      some (decodedFields (statementBytes statement) fields) := by
  simp [parseCompleteLeaf, namespace_roundtrip, source_suffix_exact, suffix_roundtrip]

theorem committed_projection (statement : List Byte) (fields : LeafFields) (column : Fin 140) :
    ((decodedFields statement fields).committed).getD column.val 0 = fields.committed column := by
  simp only [decodedFields, List.getD_eq_getElem?_getD, List.getElem?_ofFn,
    dif_pos column.isLt, Option.getD_some]

theorem masking_projection (statement : List Byte) (fields : LeafFields) (row : Fin 5) :
    ((decodedFields statement fields).masks).getD row.val 0 = fields.masks row := by
  simp only [decodedFields, List.getD_eq_getElem?_getD, List.getElem?_ofFn,
    dif_pos row.isLt, Option.getD_some]

/-- Literal raw-key equality recovers all fields. No digest equality or
Merkle membership is silently substituted for this raw-byte hypothesis. -/
theorem raw_leaf_equality_recovers_fields {family : Family}
    (left right : Statement family) (lf rf : LeafFields)
    (equal : strictLeafFrame left lf = strictLeafFrame right rf) :
    left = right ∧ lf.index = rf.index ∧ lf.committed = rf.committed ∧
      lf.masks = rf.masks ∧ lf.salt = rf.salt ∧ lf.tape = rf.tape := by
  have parsed := congrArg (parseCompleteLeaf family) equal
  rw [complete_leaf_roundtrip, complete_leaf_roundtrip] at parsed
  have records := Option.some.inj parsed
  refine ⟨statementBytes_injective family (congrArg DecodedLeaf.statement records),
    congrArg DecodedLeaf.index records, ?_, ?_, ?_, ?_⟩
  · exact List.ofFn_injective (congrArg DecodedLeaf.committed records)
  · exact List.ofFn_injective (congrArg DecodedLeaf.masks records)
  · exact List.ofFn_injective
      (SmallWood.V8Smz9RawCounterCompiler.typed_word_payload_injective (congrArg DecodedLeaf.salt records))
  · exact List.ofFn_injective
      (SmallWood.V8Smz9RawCounterCompiler.typed_word_payload_injective (congrArg DecodedLeaf.tape records))
end HegemonCrypto.NativeLaunchLeafReadback
