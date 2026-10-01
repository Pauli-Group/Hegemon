import SmzaRp05FilteredReadback

/-!
# Concrete RP05 statement namespace framing

This module instantiates `SmzaRp05LeafNamespace.Namespace` with the exact
1,104-byte SMZA binding-preamble layout constructed by
`SmallwoodPoseidon2V8BindingPreamble::from_verifier_input_with_profile` and
`smza_candidate_transcript_preamble_v1`:

* bytes `0..24` are the fixed `HGV8PB02`/V8/SMZA header fields;
* bytes `24..28` are the caller-selected network id in little-endian form;
* bytes `28..36` are the fixed 120-word/7-limb/`SMZA` suffix;
* bytes `36..84` are the parameterized 48-byte RP05 relation digest;
* bytes `84..1044` are the 120 little-endian public words;
* bytes `1044..1100` are the seven little-endian relation-binding limbs; and
* bytes `1100..1104` are canonical zero padding.

The public-word and relation-binding regions are represented as fixed byte
arrays here.  Their higher-level canonicality is checked by Rust before
`prepare_preamble`; this file proves only the byte framing needed by the leaf
namespace and global parser.  It is not a universal Rust refinement theorem,
an accepted-proof theorem, or a production receipt.  The relation digest
remains a parameter until genuine RP05 artifact regeneration supplies it.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05StatementNamespace

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.SmzaRp05LeafNamespace
open HegemonCrypto.SmallWood.SmzaRp05FilteredReadback
open scoped Classical

set_option autoImplicit false
set_option maxRecDepth 5000
set_option maxHeartbeats 1000000

abbrev NetworkBytes := Fin 4 → Byte
abbrev PublicValueBytes := Fin 960 → Byte
abbrev RelationBindingBytes := Fin 56 → Byte

/-- Fixed-size statement carrier suitable for a later finite quantum index.
The existing generic record-filter interface still returns `List Byte`; the
length theorem below is the explicit bridge, not a claim that those generic
theorems have already been retyped. -/
abbrev Statement := Fin preambleBytes → Byte

@[reducible] def statementFintype : Fintype Statement := inferInstance
@[reducible] def statementDecidableEq : DecidableEq Statement := inferInstance

namespace Statement

def toBytes (statement : Statement) : List Byte := List.ofFn statement

theorem toBytes_length (statement : Statement) :
    statement.toBytes.length = preambleBytes := by
  simp only [toBytes, List.length_ofFn]

theorem toBytes_injective : Function.Injective toBytes := by
  intro left right same
  exact List.ofFn_injective same

end Statement

structure PreambleFields where
  publicValues : PublicValueBytes
  relationBinding : RelationBindingBytes
deriving DecidableEq

/-- Bytes `0..24`.  All multi-byte scalars are in Rust's little-endian order:
grammar 2, circuit 8, crypto 7, family 1, action 10, backend 2, profile 9,
SMZA domain set 5, inline mode 1, and reserved zero. -/
def fixedPrefix : List Byte :=
  [72, 71, 86, 56, 80, 66, 48, 50,
   2, 0, 8, 0, 7, 0, 1, 0, 10, 0, 2, 9, 5, 0, 1, 0]

/-- Bytes `28..36`: 120 public words, seven relation-binding limbs, and the
SMZA inner-proof magic. -/
def fixedSuffix : List Byte := [120, 0, 7, 0, 83, 77, 90, 65]

def zeroPadding : List Byte := [0, 0, 0, 0]

theorem fixed_prefix_length : fixedPrefix.length = 24 := by decide
theorem fixed_suffix_length : fixedSuffix.length = 8 := by decide
theorem zero_padding_length : zeroPadding.length = 4 := by decide

private theorem take_first {α : Type*} (first rest : List α) :
    (first ++ rest).take first.length = first := by simp

private theorem take_middle {α : Type*} (first middle rest : List α) :
    ((first ++ middle ++ rest).drop first.length).take middle.length = middle := by
  simp

private theorem drop_first {α : Type*} (first rest : List α) :
    (first ++ rest).drop first.length = rest := by simp

/-- Literal source-order encoding of the RP05 verifier input.  `network` is
already the exact four-byte little-endian encoding produced by `write_u32`;
the two larger regions are concatenated eight-byte words in source order. -/
def encodePreamble (relationDigest : List Byte) (network : NetworkBytes)
    (fields : PreambleFields) : List Byte :=
  fixedPrefix ++ List.ofFn network ++ fixedSuffix ++ relationDigest ++
    List.ofFn fields.publicValues ++ List.ofFn fields.relationBinding ++
    zeroPadding

theorem encode_preamble_length
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) (fields : PreambleFields) :
    (encodePreamble relationDigest network fields).length = preambleBytes := by
  simp only [encodePreamble, List.length_append, List.length_ofFn,
    fixed_prefix_length, fixed_suffix_length,
    zero_padding_length, digestLength, preambleBytes]

theorem encode_preamble_words
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) (fields : PreambleFields) :
    (encodePreamble relationDigest network fields).length / 8 = preambleWords := by
  rw [encode_preamble_length relationDigest digestLength network fields]
  decide

theorem encode_preamble_relation_digest
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) (fields : PreambleFields) :
    ((encodePreamble relationDigest network fields).drop 36).take 48 =
      relationDigest := by
  have prefixLength :
      (fixedPrefix ++ List.ofFn network ++ fixedSuffix).length = 36 := by
    simp only [List.length_append, List.length_ofFn,
      fixed_prefix_length, fixed_suffix_length]
  have segment := take_middle (fixedPrefix ++ List.ofFn network ++ fixedSuffix)
      relationDigest
      (List.ofFn fields.publicValues ++ List.ofFn fields.relationBinding ++ zeroPadding)
  rw [prefixLength, digestLength] at segment
  simpa only [encodePreamble, List.append_assoc] using segment

theorem encode_preamble_network
    (relationDigest : List Byte) (network : NetworkBytes)
    (fields : PreambleFields) :
    ((encodePreamble relationDigest network fields).drop 24).take 4 =
      List.ofFn network := by
  simpa only [encodePreamble, fixed_prefix_length, List.length_ofFn,
    List.append_assoc]
    using take_middle fixedPrefix (List.ofFn network)
      (fixedSuffix ++ relationDigest ++ List.ofFn fields.publicValues ++
        List.ofFn fields.relationBinding ++ zeroPadding)

theorem encode_preamble_fixed_prefix
    (relationDigest : List Byte) (network : NetworkBytes)
    (fields : PreambleFields) :
    (encodePreamble relationDigest network fields).take 24 = fixedPrefix := by
  simpa only [encodePreamble, fixed_prefix_length, List.append_assoc]
    using take_first fixedPrefix (List.ofFn network ++ fixedSuffix ++
      relationDigest ++ List.ofFn fields.publicValues ++
      List.ofFn fields.relationBinding ++ zeroPadding)

theorem encode_preamble_fixed_suffix
    (relationDigest : List Byte) (network : NetworkBytes)
    (fields : PreambleFields) :
    ((encodePreamble relationDigest network fields).drop 28).take 8 =
      fixedSuffix := by
  have prefixLength : (fixedPrefix ++ List.ofFn network).length = 28 := by
    simp only [List.length_append, List.length_ofFn,
      fixed_prefix_length]
  simpa only [encodePreamble, prefixLength, fixed_suffix_length,
    List.append_assoc]
    using take_middle (fixedPrefix ++ List.ofFn network) fixedSuffix
      (relationDigest ++ List.ofFn fields.publicValues ++
        List.ofFn fields.relationBinding ++ zeroPadding)

theorem encode_preamble_public_values
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) (fields : PreambleFields) :
    ((encodePreamble relationDigest network fields).drop 84).take 960 =
      List.ofFn fields.publicValues := by
  have prefixLength :
      (fixedPrefix ++ List.ofFn network ++ fixedSuffix ++ relationDigest).length = 84 := by
    simp only [List.length_append, List.length_ofFn,
      fixed_prefix_length, fixed_suffix_length, digestLength]
  have segment := take_middle
      (fixedPrefix ++ List.ofFn network ++ fixedSuffix ++ relationDigest)
      (List.ofFn fields.publicValues)
      (List.ofFn fields.relationBinding ++ zeroPadding)
  rw [prefixLength] at segment
  simpa only [encodePreamble, List.length_ofFn, List.append_assoc] using segment

theorem encode_preamble_relation_binding
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) (fields : PreambleFields) :
    ((encodePreamble relationDigest network fields).drop 1044).take 56 =
      List.ofFn fields.relationBinding := by
  have prefixLength :
      (fixedPrefix ++ List.ofFn network ++ fixedSuffix ++ relationDigest ++
        List.ofFn fields.publicValues).length = 1044 := by
    simp only [List.length_append, List.length_ofFn,
      fixed_prefix_length, fixed_suffix_length, digestLength]
  have segment := take_middle
      (fixedPrefix ++ List.ofFn network ++ fixedSuffix ++ relationDigest ++
        List.ofFn fields.publicValues)
      (List.ofFn fields.relationBinding) zeroPadding
  rw [prefixLength] at segment
  simpa only [encodePreamble, List.length_ofFn, List.append_assoc] using segment

theorem encode_preamble_zero_padding
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) (fields : PreambleFields) :
    (encodePreamble relationDigest network fields).drop 1100 = zeroPadding := by
  have prefixLength :
      (fixedPrefix ++ List.ofFn network ++ fixedSuffix ++ relationDigest ++
        List.ofFn fields.publicValues ++ List.ofFn fields.relationBinding).length = 1100 := by
    simp only [List.length_append, List.length_ofFn,
      fixed_prefix_length, fixed_suffix_length, digestLength]
  have segment := drop_first
      (fixedPrefix ++ List.ofFn network ++ fixedSuffix ++ relationDigest ++
        List.ofFn fields.publicValues ++ List.ofFn fields.relationBinding)
      zeroPadding
  rw [prefixLength] at segment
  simpa only [encodePreamble, List.append_assoc] using segment

/-- Executable byte/framing predicate for every source-layout preamble on one
network and relation digest.  The middle public-value and relation-binding
regions remain statement variables; Rust is responsible for their semantic
canonicality before constructing this frame. -/
def canonicalPreamble (relationDigest : List Byte) (network : NetworkBytes)
    (bytes : List Byte) : Bool :=
  decide (bytes.length = preambleBytes ∧
    bytes.take 24 = fixedPrefix ∧
    (bytes.drop 24).take 4 = List.ofFn network ∧
    (bytes.drop 28).take 8 = fixedSuffix ∧
    (bytes.drop 36).take 48 = relationDigest ∧
    bytes.drop 1100 = zeroPadding)

theorem canonical_preamble_iff
    (relationDigest : List Byte) (network : NetworkBytes) (bytes : List Byte) :
    canonicalPreamble relationDigest network bytes = true ↔
      bytes.length = preambleBytes ∧
      bytes.take 24 = fixedPrefix ∧
      (bytes.drop 24).take 4 = List.ofFn network ∧
      (bytes.drop 28).take 8 = fixedSuffix ∧
      (bytes.drop 36).take 48 = relationDigest ∧
      bytes.drop 1100 = zeroPadding := by
  simp [canonicalPreamble]

/-- Concrete namespace instance consumed unchanged by the RP05 leaf parser,
the salt-independent global statement parser, and the record filters. -/
def rp05Namespace
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) : Namespace where
  relationDigest := relationDigest
  canonicalPreamble := canonicalPreamble relationDigest network
  relationDigestLength := digestLength
  canonicalLength := by
    intro bytes admitted
    exact ((canonical_preamble_iff relationDigest network bytes).mp admitted).1
  canonicalRelationDigest := by
    intro bytes admitted
    exact ((canonical_preamble_iff relationDigest network bytes).mp admitted).2.2.2.2.1

theorem encoded_canonical_preamble_admitted
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) (fields : PreambleFields) :
    (rp05Namespace relationDigest digestLength network).canonicalPreamble
      (encodePreamble relationDigest network fields) = true := by
  change canonicalPreamble relationDigest network
    (encodePreamble relationDigest network fields) = true
  rw [canonical_preamble_iff]
  exact ⟨encode_preamble_length relationDigest digestLength network fields,
    encode_preamble_fixed_prefix relationDigest network fields,
    encode_preamble_network relationDigest network fields,
    encode_preamble_fixed_suffix relationDigest network fields,
    encode_preamble_relation_digest relationDigest digestLength network fields,
    encode_preamble_zero_padding relationDigest digestLength network fields⟩

/-- The global parser recognizes the actual source-layout encoding for every
32-byte salt accepted by the legacy payload predicate.  No salt is fixed or
omitted by the namespace instantiation. -/
theorem encoded_preamble_is_global_statement_for_all_salts
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) (fields : PreambleFields)
    (salt legacyPayload : List Byte)
    (legacyCanonical : LegacyLeafCanonical salt legacyPayload) :
    globalLeafStatement (rp05Namespace relationDigest digestLength network)
      (encodeLeaf (encodePreamble relationDigest network fields) legacyPayload) =
        some (encodePreamble relationDigest network fields) := by
  let leaf : CurrentLeaf
      (rp05Namespace relationDigest digestLength network) salt :=
    { preamble := encodePreamble relationDigest network fields
      legacyPayload := legacyPayload
      preambleCanonical := encoded_canonical_preamble_admitted
        relationDigest digestLength network fields
      legacyCanonical := legacyCanonical }
  exact fixed_context_leaf_is_global_statement
    (rp05Namespace relationDigest digestLength network) salt leaf

/-- Unequal canonical preamble bytes occupy disjoint raw leaf addresses, even
when their salts and normalized legacy payloads differ only outside the
statement prefix. -/
theorem unequal_canonical_bytes_separate
    (relationDigest : List Byte) (digestLength : relationDigest.length = 48)
    (network : NetworkBytes) (leftFields rightFields : PreambleFields)
    (salt : List Byte) (leftPayload rightPayload : List Byte)
    (leftCanonical : LegacyLeafCanonical salt leftPayload)
    (rightCanonical : LegacyLeafCanonical salt rightPayload)
    (different : encodePreamble relationDigest network leftFields ≠
      encodePreamble relationDigest network rightFields) :
    encodeLeaf (encodePreamble relationDigest network leftFields) leftPayload ≠
      encodeLeaf (encodePreamble relationDigest network rightFields) rightPayload := by
  let ns := rp05Namespace relationDigest digestLength network
  let left : CurrentLeaf ns salt :=
    { preamble := encodePreamble relationDigest network leftFields
      legacyPayload := leftPayload
      preambleCanonical := encoded_canonical_preamble_admitted
        relationDigest digestLength network leftFields
      legacyCanonical := leftCanonical }
  let right : CurrentLeaf ns salt :=
    { preamble := encodePreamble relationDigest network rightFields
      legacyPayload := rightPayload
      preambleCanonical := encoded_canonical_preamble_admitted
        relationDigest digestLength network rightFields
      legacyCanonical := rightCanonical }
  exact unequal_namespaces_have_disjoint_inputs ns salt left right different

end HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
