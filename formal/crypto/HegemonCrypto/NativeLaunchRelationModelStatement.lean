import HegemonCrypto.NativeLaunchWireTypes
import HegemonCrypto.NativeLaunchAdaptiveHistoryCodec

/-!
# Actual native-launch statement and strict-leaf source shapes

Pinned source: 82f5e79d7fa2fddf570747cfca15df272707d007.
RP06 is the 149-word `rp06_transcript_bytes` grammar; HTLC is the 72-word
`candidate_binding_bytes` grammar. These constructors preserve every header,
field, duplicated network word, option marker and padding word. They do not
replace Rust's semantic statement validation with a caller-supplied predicate.

Remaining source obligations are explicit: RP06 base public-structure validation,
the source-program SHA-512 first-48 digest and derived Poseidon2 action intent;
HTLC source-file SHA-512 identity and the adapter-computed row count; and both
families' authenticated runtime context. Digest and row fields below are data,
not certificates of those obligations. The concrete `StructureChecks` predicates
check only the source conditions they spell out. No accepted-proof claim occurs.
-/

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

namespace HegemonCrypto.NativeLaunchRelationModelStatement

open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Family Word profileDomain)
open SmallWood.V8Smz9RawCounterCompiler
  (typedWordPayload typed_word_payload_length typed_word_payload_injective)
open SmallWood.V8Smz9WholeViewObservation (RawSha512OracleKey)

def preambleWordCount : Family → Nat | .rp06 => 149 | .htlc => 72
def preambleByteCount (family : Family) : Nat := 8 * preambleWordCount family
abbrev Statement (family : Family) := Fin (preambleWordCount family) → Word

def statementWords {family : Family} (statement : Statement family) : List Word :=
  List.ofFn statement
def statementBytes {family : Family} (statement : Statement family) : List Byte :=
  typedWordPayload (statementWords statement)

theorem statement_words_length {family : Family} (statement : Statement family) :
    (statementWords statement).length = preambleWordCount family := List.length_ofFn
theorem statement_bytes_length {family : Family} (statement : Statement family) :
    (statementBytes statement).length = preambleByteCount family := by
  simp [statementBytes, statementWords, typed_word_payload_length, preambleByteCount]
theorem statementBytes_injective (family : Family) :
    Function.Injective (statementBytes (family := family)) := by
  intro left right equal
  exact List.ofFn_injective (typed_word_payload_injective equal)

def statementOfWords (family : Family) (words : List Word)
    (length : words.length = preambleWordCount family) : Statement family :=
  fun i => words[i.val]'(by rw [length]; exact i.isLt)

@[simp] theorem statementWords_ofWords (family : Family) (words : List Word)
    (length : words.length = preambleWordCount family) :
    statementWords (statementOfWords family words length) = words := by
  apply List.ext_getElem
  · simp [statementWords, length]
  · intro i leftBound rightBound
    simp [statementWords, statementOfWords]

/-- Four literal u64 chunks: HGR6PB01, HGV8RP06, six u16 identity fields,
then backend/profile/inline/reserved bytes. -/
def rp06Header : List Word :=
  [3544405819016759112, 3904709190992938824, 281505042071553, 292478683316238]

abbrev U32 := Fin (2^32)
def packU32 (low high : U32) : Word :=
  ⟨low.val + 2^32 * high.val, by have l := low.isLt; have h := high.isLt; omega⟩

structure Rp06Fields where
  relationDigest : Fin 6 → Word
  network : Fin 8 → U32
  publicValues : Fin 120 → Word
  actionIntent : Fin 7 → Word

def rp06ChainWords (fields : Rp06Fields) : Fin 4 → Word := fun i =>
  packU32 (fields.network ⟨2*i.val, by omega⟩)
    (fields.network ⟨2*i.val+1, by omega⟩)
def rp06PublicWords (fields : Rp06Fields) : List Word :=
  List.ofFn fields.publicValues ++ List.ofFn (fun i =>
    (⟨(fields.network i).val, lt_trans (fields.network i).isLt (by decide)⟩ : Word))
def rp06Words (fields : Rp06Fields) : List Word :=
  rp06Header ++ List.ofFn fields.relationDigest ++ List.ofFn (rp06ChainWords fields) ++
    rp06PublicWords fields ++ List.ofFn fields.actionIntent
theorem rp06_words_length (fields : Rp06Fields) : (rp06Words fields).length = 149 := by
  simp [rp06Words, rp06Header, rp06PublicWords]
def rp06Statement (fields : Rp06Fields) : Statement .rp06 :=
  statementOfWords .rp06 (rp06Words fields) (rp06_words_length fields)

/-- These explicit necessary checks do not stand in for the base V8 parser
or the derived action-intent/source-digest computations. -/
def Rp06StructureChecks (fields : Rp06Fields) : Prop :=
  (∃ i, fields.network i ≠ 0) ∧
  (∀ i, (fields.publicValues i).val < 18446744069414584321) ∧
  fields.publicValues 58 = 0 ∧ fields.publicValues 83 = 0 ∧
  (∀ i, (fields.actionIntent i).val < 18446744069414584321)

theorem rp06_public_projection (fields : Rp06Fields) :
    ((statementWords (rp06Statement fields)).drop 14).take 128 =
      rp06PublicWords fields := by
  simp [rp06Statement, rp06Words, rp06Header, rp06PublicWords]
theorem rp06_intent_projection (fields : Rp06Fields) :
    (statementWords (rp06Statement fields)).drop 142 = List.ofFn fields.actionIntent := by
  simp [rp06Statement, rp06Words, rp06Header, rp06PublicWords]

def fieldAsWord (word : FieldWord) : Word :=
  ⟨word.val, lt_trans word.isLt (by decide)⟩
abbrev Action := Fin 3
def htlcHeader (action : Action) : List Word :=
  [3544405784707614536, 281505042137089,
    ⟨30249451533 + 2^48 * action.val, by have h := action.isLt; omega⟩]

structure HtlcFields where
  action : Action
  network : Fin 4 → Word
  parentHash : Fin 4 → Word
  parentHeight : Fin (2^48)
  nullifier : Fin 7 → FieldWord
  merkleRoot : Fin 7 → FieldWord
  outputCommitment : Fin 7 → FieldWord
  ciphertextCommitment : Fin 6 → Word
  fee : Fin (2^56)
  revealedSecret : Option (Fin 4 → Word)
  relationDigest : Fin 8 → Word
  rows : Word

def secretFlag (secret : Option (Fin 4 → Word)) : Word := if secret.isSome then 1 else 0
def secretWords (secret : Option (Fin 4 → Word)) : List Word :=
  match secret with | none => List.replicate 4 0 | some value => List.ofFn value
theorem secret_words_length (secret : Option (Fin 4 → Word)) :
    (secretWords secret).length = 4 := by cases secret <;> simp [secretWords]

/-- Exact source order is nullifier, root, output (the older development
binding used a different order). Version 1 and SMZC share one final u64. -/
def htlcWords (fields : HtlcFields) : List Word :=
  htlcHeader fields.action ++ List.ofFn fields.network ++ List.ofFn fields.parentHash ++
  [⟨fields.parentHeight.val, lt_trans fields.parentHeight.isLt (by decide)⟩] ++
  List.ofFn (fieldAsWord ∘ fields.nullifier) ++ List.ofFn (fieldAsWord ∘ fields.merkleRoot) ++
  List.ofFn (fieldAsWord ∘ fields.outputCommitment) ++ List.ofFn fields.ciphertextCommitment ++
  [⟨fields.fee.val, lt_trans fields.fee.isLt (by decide)⟩, secretFlag fields.revealedSecret] ++
  secretWords fields.revealedSecret ++ List.ofFn fields.relationDigest ++
  [fields.rows, 64, 2, 4853276567322755073] ++ List.replicate 15 0
theorem htlc_words_length (fields : HtlcFields) : (htlcWords fields).length = 72 := by
  simp [htlcWords, htlcHeader, secret_words_length]
def htlcStatement (fields : HtlcFields) : Statement .htlc :=
  statementOfWords .htlc (htlcWords fields) (htlc_words_length fields)

/-- Exactly the remaining value checks in HtlcStatement.validate_structure:
version, ranges and field canonicality are already enforced by the constructor. -/
def HtlcStructureChecks (fields : HtlcFields) : Prop :=
  (∃ i, fields.network i ≠ 0) ∧ (∃ i, fields.nullifier i ≠ 0) ∧
  (∃ i, fields.merkleRoot i ≠ 0) ∧ (∃ i, fields.outputCommitment i ≠ 0) ∧
  (∃ i, fields.ciphertextCommitment i ≠ 0) ∧
  (fields.action ≠ 1 → fields.revealedSecret = none)

theorem htlc_relation_projection (fields : HtlcFields) :
    ((statementWords (htlcStatement fields)).drop 45).take 8 =
      List.ofFn fields.relationDigest := by
  simp [htlcStatement, htlcWords, htlcHeader, secret_words_length]
theorem htlc_geometry_projection (fields : HtlcFields) :
    ((statementWords (htlcStatement fields)).drop 53).take 4 =
      [fields.rows, 64, 2, 4853276567322755073] := by
  cases secret : fields.revealedSecret <;>
    simp [htlcStatement, htlcWords, htlcHeader, secretWords, secret]
theorem htlc_padding_projection (fields : HtlcFields) :
    (statementWords (htlcStatement fields)).drop 57 = List.replicate 15 0 := by
  cases secret : fields.revealedSecret <;>
    simp [htlcStatement, htlcWords, htlcHeader, secretWords, secret]

/-- Source shape is defined by the actual constructors and explicit structural
checks. This is not a variable Boolean namespace predicate or a source-refinement
receipt. In particular the digest, RP06 intent, and HTLC rows still need the
source computations documented above. -/
def SourceShape : (family : Family) → Statement family → Prop
  | .rp06, statement => ∃ fields, Rp06StructureChecks fields ∧ statement = rp06Statement fields
  | .htlc, statement => ∃ fields, HtlcStructureChecks fields ∧ statement = htlcStatement fields

theorem typed_payload_append (left right : List Word) :
    typedWordPayload (left ++ right) = typedWordPayload left ++ typedWordPayload right := by
  induction left with
  | nil => rfl
  | cons word words ih => simp [typedWordPayload, ih, List.append_assoc]

def leafRole : Family → List Byte
  | .rp06 => [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,115,116,114,105,99,116,45,122,107,46,109,101,114,107,108,101,45,108,101,97,102,46,118,50]
  | .htlc => [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,115,116,114,105,99,116,45,122,107,46,109,101,114,107,108,101,45,108,101,97,102,46,104,116,108,99,46,118,49]

structure LeafFields where
  salt : Fin 4 → Word
  index : Fin (2^23)
  tape : Fin 8 → Word
  committed : Fin 140 → FieldWord
  masks : Fin 5 → FieldWord

def leafTailWords (fields : LeafFields) : List Word :=
  [140] ++ List.ofFn (fieldAsWord ∘ fields.committed) ++
    [5] ++ List.ofFn (fieldAsWord ∘ fields.masks)
def strictLeafWords {family : Family} (statement : Statement family) (fields : LeafFields) : List Word :=
  statementWords statement ++ List.ofFn fields.salt ++
    [⟨fields.index.val, lt_trans fields.index.isLt (by decide)⟩] ++
    List.ofFn fields.tape ++ leafTailWords fields
theorem strict_leaf_word_count {family : Family} (statement : Statement family) (fields : LeafFields) :
    (strictLeafWords statement fields).length = preambleWordCount family + 160 := by
  simp [strictLeafWords, statementWords, leafTailWords]

def strictLeafFrame {family : Family} (statement : Statement family) (fields : LeafFields) : List Byte :=
  (RawSha512OracleKey.mk (some (profileDomain family)) (leafRole family)
    ((strictLeafWords statement fields).map Fin.val) 0).preimage

def leafRawBytes : Family → Nat | .rp06 => 2591 | .htlc => 1987
def leafTapeOffset : Family → Nat | .rp06 => 1343 | .htlc => 739

def strictLeafHead {family : Family} (statement : Statement family) (fields : LeafFields) : List Byte :=
  encodeLE 8 (profileDomain family).length ++ profileDomain family ++
  encodeLE 8 (leafRole family).length ++ leafRole family ++
  encodeLE 8 (preambleWordCount family + 160) ++ statementBytes statement ++
  typedWordPayload (List.ofFn fields.salt) ++ encodeLE 8 fields.index.val

theorem strict_leaf_frame_split {family : Family} (statement : Statement family) (fields : LeafFields) :
    strictLeafFrame statement fields = strictLeafHead statement fields ++
      typedWordPayload (List.ofFn fields.tape) ++ typedWordPayload (leafTailWords fields) ++
      encodeLE 8 0 := by
  simp only [strictLeafFrame, RawSha512OracleKey.preimage, List.length_map,
    strict_leaf_word_count]
  rw [← SmallWood.V8Smz9RawCounterCompiler.typed_word_payload_is_source_payload]
  simp [strictLeafHead, strictLeafWords, typed_payload_append, statementBytes,
    typedWordPayload, List.append_assoc]

theorem strict_leaf_head_length {family : Family} (statement : Statement family) (fields : LeafFields) :
    (strictLeafHead statement fields).length = leafTapeOffset family := by
  simp only [strictLeafHead, List.length_append, encodeLE_length,
    statement_bytes_length, typed_word_payload_length, List.length_ofFn]
  cases family <;> decide

theorem strict_leaf_tape_projection {family : Family} (statement : Statement family) (fields : LeafFields) :
    ((strictLeafFrame statement fields).drop (leafTapeOffset family)).take 64 =
      typedWordPayload (List.ofFn fields.tape) := by
  rw [strict_leaf_frame_split, ← strict_leaf_head_length statement fields]
  simp only [List.append_assoc, List.drop_left]
  have tapeLength : (typedWordPayload (List.ofFn fields.tape)).length = 64 := by
    simp [typed_word_payload_length]
  have keep :
      ((typedWordPayload (List.ofFn fields.tape)) ++
        (typedWordPayload (leafTailWords fields) ++ encodeLE 8 0)).take
          (typedWordPayload (List.ofFn fields.tape)).length =
        typedWordPayload (List.ofFn fields.tape) := List.take_left
  simpa only [tapeLength] using keep

theorem strict_leaf_raw_length {family : Family} (statement : Statement family) (fields : LeafFields) :
    (strictLeafFrame statement fields).length = leafRawBytes family := by
  have payload := typed_word_payload_length (strictLeafWords statement fields)
  rw [SmallWood.V8Smz9RawCounterCompiler.typed_word_payload_is_source_payload] at payload
  simp only [strictLeafFrame, RawSha512OracleKey.preimage, List.length_append,
    encodeLE_length, List.length_map]
  rw [payload, strict_leaf_word_count]
  cases family <;> decide

theorem strict_leaf_statement_projection {family : Family}
    (statement : Statement family) (fields : LeafFields) :
    (typedWordPayload (strictLeafWords statement fields)).take (preambleByteCount family) =
      statementBytes statement := by
  simp only [strictLeafWords, typed_payload_append]
  rw [← statement_bytes_length statement]
  simp only [statementBytes, List.append_assoc]
  exact List.take_left

theorem source_shape_statement_byte_lengths :
    preambleByteCount .rp06 = 1192 ∧ preambleByteCount .htlc = 576 := by decide

end HegemonCrypto.NativeLaunchRelationModelStatement
