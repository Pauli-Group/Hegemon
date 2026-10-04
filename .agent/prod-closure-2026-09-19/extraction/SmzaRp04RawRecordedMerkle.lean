import SmzaRp04Payload
import HegemonCrypto.SmallWoodV8Smz9EagerOracleGame
import HegemonCrypto.SmallWoodV8Smz9HiddenPatch

/-! RP04's typed 145-word payload embedded in the canonical source leaf domain. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawRecordedMerkle

open HegemonCrypto.SmallWood.SmzaRp04RecordedClaims
open V8Smz9EagerOracleGame V8Smz9OracleExtraction
open V8Smz9HiddenPatch V8Smz9HiddenLeafQrom
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.RecordedMerkleExtraction
open HegemonCrypto.FiniteOracleDatabase
open scoped BigOperators

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 5000

abbrev RawLeaf := LeafInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest

def payloadRows (payload : Rp04Payload) : Fin 140 → Goldilocks :=
  fun row => wordToGoldilocks (payload.words ⟨row.val, by omega⟩)

def payloadMasks (payload : Rp04Payload) : Fin 5 → Goldilocks :=
  fun row => wordToGoldilocks (payload.words ⟨140 + row.val, by omega⟩)

/-- The current SMZA profile, not the older same-width SMZ9 header. -/
def smzaCanonicalLeafHeader (salt : SaltBytes) : LeafHeader :=
  Fin.append
    (Fin.append (rawWordBytes ⟨53, by norm_num⟩)
      (Fin.append
        (literalBytes "hegemon.smallwood.poseidon2-v8.smza.sha512.profile.v1" 53 (by decide))
        (Fin.append (rawWordBytes ⟨42, by norm_num⟩)
          (Fin.append (literalBytes (V8Smz9HonestHybrid.hashRoleTag .leaf) 42 (by decide))
            (rawWordBytes ⟨160, by norm_num⟩))))) salt

def rawLeafOf (payload : Rp04Payload) : RawLeaf :=
  sourceLeafInput (smzaCanonicalLeafHeader payload.salt)
    (canonicalLeafSuffix (payloadRows payload) (payloadMasks payload))
    payload.index payload.tape

theorem fin_append_eq_split {α : Type*} {m n : Nat}
    {left left' : Fin m → α} {right right' : Fin n → α}
    (equal : Fin.append left right = Fin.append left' right') :
    left = left' ∧ right = right' := by
  constructor
  · funext index
    simpa only [Fin.append_left] using congrFun equal (Fin.castAdd n index)
  · funext index
    simpa only [Fin.append_right] using congrFun equal (Fin.natAdd m index)

theorem field_vector_bytes_injective {count : Nat} :
    Function.Injective (fieldVectorBytes (count := count)) := by
  intro left right equal
  funext row
  apply canonical_field_bytes_injective
  funext byte
  simpa only [field_vector_bytes_at] using
    congrFun equal (finProdFinEquiv (row, byte))

theorem field_word_injective :
    Function.Injective V8Smz9OracleExtraction.wordToGoldilocks := by
  intro left right equal
  apply Fin.ext
  have values := congrArg fromGoldilocks equal
  change fromGoldilocks (toGoldilocks left.val) =
    fromGoldilocks (toGoldilocks right.val) at values
  simpa only [fromGoldilocks_toGoldilocks, fieldValue,
    Nat.mod_eq_of_lt left.isLt, Nat.mod_eq_of_lt right.isLt] using values

/-- Every part of the committed leaf is recovered; no payload field is dropped. -/
theorem raw_leaf_injective : Function.Injective rawLeafOf := by
  intro left right equal
  have layout := equal
  change Fin.append
      (Fin.append (smzaCanonicalLeafHeader left.salt) (indexBytes left.index))
      (Fin.append left.tape (canonicalLeafSuffix (payloadRows left) (payloadMasks left))) =
    Fin.append
      (Fin.append (smzaCanonicalLeafHeader right.salt) (indexBytes right.index))
      (Fin.append right.tape (canonicalLeafSuffix (payloadRows right) (payloadMasks right)))
    at layout
  obtain ⟨leadingEquality, tail⟩ := fin_append_eq_split layout
  have header := (fin_append_eq_split leadingEquality).1
  have salt : left.salt = right.salt := (fin_append_eq_split header).2
  obtain ⟨tape, suffix⟩ := fin_append_eq_split tail
  have rowsAndRest := (fin_append_eq_split suffix).2
  obtain ⟨rowsBytes, maskCountAndRest⟩ := fin_append_eq_split rowsAndRest
  have masksAndCounter := (fin_append_eq_split maskCountAndRest).2
  have masksBytes := (fin_append_eq_split masksAndCounter).1
  have rows := field_vector_bytes_injective rowsBytes
  have masks := field_vector_bytes_injective masksBytes
  have index : left.index = right.index := by
    apply Fin.ext
    simpa only [rawLeafOf, source_leaf_index_projection] using
      congrArg (fun input => (rawInputIndex input).val) equal
  have words : left.words = right.words := by
    funext row
    apply field_word_injective
    by_cases data : row.val < 140
    · exact congrFun rows ⟨row.val, data⟩
    · have mask : row.val - 140 < 5 := by omega
      have recovered := congrFun masks ⟨row.val - 140, mask⟩
      simpa only [payloadMasks, Nat.add_sub_of_le (by omega : 140 ≤ row.val)] using recovered
  cases left
  cases right
  simp_all

def typedHashInput : HashInput Rp04Payload RawDigest → HashInput RawLeaf RawDigest
  | .leaf payload => .leaf (rawLeafOf payload)
  | .node left right => .node left right

theorem typed_hash_input_injective : Function.Injective typedHashInput := by
  intro left right equal
  cases left with
  | leaf left =>
    cases right with
    | leaf right =>
      have same := raw_leaf_injective (HashInput.leaf.inj equal)
      exact congrArg HashInput.leaf same
    | node _ _ => cases equal
  | node leftChild rightChild =>
    cases right with
    | leaf _ => cases equal
    | node leftChild' rightChild' =>
      exact congrArg₂ HashInput.node (HashInput.node.inj equal).1
        (HashInput.node.inj equal).2

def pullbackLeafDatabase
    (rawDatabase : Database (HashInput RawLeaf RawDigest) RawDigest) :
    Database (HashInput Rp04Payload RawDigest) RawDigest :=
  fun input => rawDatabase (typedHashInput input)

theorem pullback_collision_free
    (database : Database (HashInput RawLeaf RawDigest) RawDigest)
    (collisionFree : CollisionFree database) :
    CollisionFree (pullbackLeafDatabase database) := by
  rintro ⟨left, right, digest, different, leftRecorded, rightRecorded⟩
  apply different
  apply typed_hash_input_injective
  exact input_unique_of_same_recorded_output collisionFree leftRecorded rightRecorded

theorem raw_recorded_opening_is_typed
    (rawDatabase : Database (HashInput RawLeaf RawDigest) RawDigest)
    (payload : Rp04Payload) (digest : RawDigest)
    (recorded : rawDatabase (.leaf (rawLeafOf payload)) = some digest) :
    pullbackLeafDatabase rawDatabase (.leaf payload) = some digest := by
  exact recorded

/-- Transfer the entire recorded path, including every internal-node record. -/
theorem raw_recorded_path_is_typed
    (database : Database (HashInput RawLeaf RawDigest) RawDigest)
    (payload : Rp04Payload) (sides : List ChildSide) (root : RawDigest)
    (opening : RecordedOpening database (rawLeafOf payload) sides root) :
    RecordedOpening (pullbackLeafDatabase database) payload sides root := by
  generalize encoded : rawLeafOf payload = leaf at opening
  induction opening generalizing payload with
  | leaf digest recorded =>
    rw [← encoded] at recorded
    exact RecordedOpening.leaf payload digest recorded
  | left childOpening recorded ih =>
    exact RecordedOpening.left (ih payload encoded) recorded
  | right childOpening recorded ih =>
    exact RecordedOpening.right (ih payload encoded) recorded

end
end HegemonCrypto.SmallWood.SmzaRp04RawRecordedMerkle
