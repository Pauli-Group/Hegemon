import Q38Rp05LeafSupport
import HegemonCrypto.SmallWoodV8Smz9HonestFinalGame
import SmzaRp05LeafNamespace
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler

/-!
# One address for each physical RP05 oracle input

RP05 leaves have length 2511. The legacy `OtherRawInput` excludes length
1407, so reusing it beside `Rp05LeafInput` duplicates every RP05 leaf address.
The correct complement below excludes 2511 instead. This file supplies the
partition, not the still-needed transport of the complete request compiler.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05RawInputPartition

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.V8Smz9HonestFinalGame
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler

set_option autoImplicit false

abbrev Rp05OtherRawInput (bound : Nat) :=
  { input : RawTuple bound // input.1.val ≠ rp05LeafBytes }

abbrev Rp05FullRawInput (bound : Nat) :=
  Rp05LeafInput ⊕ Rp05OtherRawInput bound

def rp05RawBytes {bound : Nat} : Rp05FullRawInput bound → List CanonicalBytes.Byte
  | .inl leaf => List.ofFn leaf
  | .inr other => rawTupleBytes other.val

/-- No two tags or tuple coordinates can name the same physical byte string. -/
theorem rp05_raw_bytes_injective (bound : Nat) :
    Function.Injective (@rp05RawBytes bound) := by
  intro left right same
  cases left with
  | inl left =>
      cases right with
      | inl right =>
          have sameBytes : List.ofFn left = List.ofFn right := same
          have sameLeaf : left = right :=
            List.ofFn_injective (α := CanonicalBytes.Byte) (n := rp05LeafBytes) sameBytes
          exact congrArg Sum.inl sameLeaf
      | inr right =>
          have lengths := congrArg List.length same
          have bad : right.val.1.val = rp05LeafBytes := by
            simpa only [rp05RawBytes, rawTupleBytes, List.length_ofFn]
              using lengths.symm
          exact False.elim (right.property bad)
  | inr left =>
      cases right with
      | inl right =>
          have lengths := congrArg List.length same
          have bad : left.val.1.val = rp05LeafBytes := by
            simpa only [rp05RawBytes, rawTupleBytes, List.length_ofFn]
              using lengths
          exact False.elim (left.property bad)
      | inr right =>
          exact congrArg Sum.inr
            (Subtype.ext (raw_tuple_bytes_injective bound same))

/-- Every bounded physical input is retained, including malformed inputs
and all historical profiles. Only the length determines the finite tag. -/
def rp05Classify {bound : Nat} (input : RawTuple bound) : Rp05FullRawInput bound :=
  if same : input.1.val = rp05LeafBytes then
    .inl (fun index => input.2
      ⟨index.val, by rw [same]; exact index.isLt⟩)
  else .inr ⟨input, same⟩

theorem rp05_classify_preserves_bytes {bound : Nat} (input : RawTuple bound) :
    rp05RawBytes (rp05Classify input) = rawTupleBytes input := by
  rcases input with ⟨⟨size, bounded⟩, bytes⟩
  by_cases same : size = rp05LeafBytes
  · subst size
    simp [rp05Classify, rp05RawBytes, rawTupleBytes]
  · simp [rp05Classify, rp05RawBytes, rawTupleBytes, same]

def rp05OtherRawKey (bound : Nat) (input : List CanonicalBytes.Byte)
    (bounded : input.length ≤ bound)
    (notLeafLength : input.length ≠ rp05LeafBytes) : Rp05OtherRawInput bound :=
  ⟨⟨⟨input.length, Nat.lt_succ_of_le bounded⟩, input.get⟩, notLeafLength⟩

theorem rp05_other_raw_key_preserves_bytes (bound : Nat) (input : List CanonicalBytes.Byte)
    (bounded : input.length ≤ bound)
    (notLeafLength : input.length ≠ rp05LeafBytes) :
    rp05RawBytes (.inr (rp05OtherRawKey bound input bounded notLeafLength)) = input :=
  List.ofFn_get input

/-- The live SMZA profile, not a relabelling of the SMZ9 byte string. The
role and word framing are unchanged; only the actual profile constant is
selected, matching `Sha512Poseidon2V8Smza` in the source transcript backend. -/
def rp05SourcePrefix (role : List CanonicalBytes.Byte) (words : List Nat) :
    List CanonicalBytes.Byte :=
  encodeLE 8 53 ++ V8SmzaOracleParser.profileDomain ++
    encodeLE 8 role.length ++ role ++ encodeLE 8 words.length ++
      (words.map (encodeLE 8)).flatten

theorem rp05_source_counter_raw_length (role : List CanonicalBytes.Byte) (words : List Nat)
    (counter : Fin (2 ^ 64)) :
    (counterInput (rp05SourcePrefix role words) counter).length =
      85 + role.length + 8 * words.length := by
  have payload : ((words.map (encodeLE 8)).flatten).length = 8 * words.length := by
    induction words with
    | nil => rfl
    | cons word words ih =>
        simp only [List.map_cons, List.flatten_cons, List.length_append,
          encodeLE_length, List.length_cons, ih]
        omega
  have profile : V8SmzaOracleParser.profileDomain.length = 53 := by decide
  simp only [counterInput, rp05SourcePrefix, List.length_append,
    encodeLE_length, profile, payload]
  omega

/-- Concrete SMZA-framed nonleaf key in the corrected raw partition.
The length exclusion concerns current leaves, not historical 1407-byte keys. -/
def rp05SourceCounterKey (bound : Nat) (role : List CanonicalBytes.Byte) (words : List Nat)
    (bounded : 85 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 85 + role.length + 8 * words.length ≠ rp05LeafBytes)
    (counter : Fin (2 ^ 64)) : Rp05OtherRawInput bound :=
  rp05OtherRawKey bound (counterInput (rp05SourcePrefix role words) counter)
    (by rw [rp05_source_counter_raw_length]; exact bounded)
    (by rw [rp05_source_counter_raw_length]; exact notLeaf)

theorem rp05_source_counter_key_is_literal_input
    (bound : Nat) (role : List CanonicalBytes.Byte) (words : List Nat)
    (bounded : 85 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 85 + role.length + 8 * words.length ≠ rp05LeafBytes)
    (counter : Fin (2 ^ 64)) :
    rp05RawBytes (.inr (rp05SourceCounterKey bound role words bounded notLeaf counter)) =
      counterInput (rp05SourcePrefix role words) counter :=
  rp05_other_raw_key_preserves_bytes _ _ _ _

/-- The incompatible legacy sum, recorded to make the rejected model precise. -/
def legacyRp05RawBytes {bound : Nat} :
    Rp05LeafInput ⊕ OtherRawInput bound → List CanonicalBytes.Byte
  | .inl leaf => List.ofFn leaf
  | .inr other => rawTupleBytes other.val

/-- This is an address alias in the old mathematical model, not a SHA-512
collision or an implementation exploit. A single physical oracle cannot give
these two sum tags independent answers. -/
theorem legacy_rp05_raw_bytes_not_injective
    (bound : Nat) (largeEnough : rp05LeafBytes ≤ bound) :
    ¬ Function.Injective (@legacyRp05RawBytes bound) := by
  intro injective
  let leaf : Rp05LeafInput := fun _ => 0
  let duplicate := otherRawKey bound (List.ofFn leaf)
    (by simpa only [List.length_ofFn] using largeEnough)
    (by rw [List.length_ofFn]; decide)
  have bytes : legacyRp05RawBytes (bound := bound) (.inr duplicate) =
      legacyRp05RawBytes (bound := bound) (.inl leaf) := by
    change rawTupleBytes duplicate.val = List.ofFn leaf
    have literal := other_raw_key_is_literal_input bound (List.ofFn leaf)
      (by simpa only [List.length_ofFn] using largeEnough)
      (by rw [List.length_ofFn]; decide)
    simpa only [rawBytes] using literal
  have impossible := injective bytes
  cases impossible

end HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
