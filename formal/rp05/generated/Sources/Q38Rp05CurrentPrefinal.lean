import Q38Rp05RawInputPartition
import Q38Rp05RequestCompiler

/-!
Current-SMZA RP05 prefinal schedule on the physical raw-input partition.
All nonleaf keys below have the SMZA profile and exclude the 2511-byte leaf
length.  In particular the Merkle node is the 249-byte, 16-word framed input,
not the historical SMZ9 `sourceNodeInput`.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9WholeViewObservation
open HegemonCrypto.SmallWood.V8Smz9CoherentMerkleInstrument
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

def rp05NodeInput (left right : DigestRegister) : List CanonicalBytes.Byte :=
  encodeLE 8 53 ++ V8SmzaOracleParser.profileDomain ++
    encodeLE 8 SmallWoodTranscript.merkleNodeDomain.length ++
    SmallWoodTranscript.merkleNodeDomain ++ encodeLE 8 16 ++
    (List.ofFn (rawDigestBits.symm left) ++
      List.ofFn (rawDigestBits.symm right)) ++ encodeLE 8 0

theorem rp05_node_input_length (left right : DigestRegister) :
    (rp05NodeInput left right).length = 249 := by
  have profile : V8SmzaOracleParser.profileDomain.length = 53 := by decide
  have role : SmallWoodTranscript.merkleNodeDomain.length = 36 := by decide
  simp only [rp05NodeInput, List.length_append, List.length_ofFn,
    encodeLE_length, profile, role]

def rp05NodeKey (bound : Nat) (largeEnough : 249 ≤ bound)
    (left right : DigestRegister) : Rp05OtherRawInput bound :=
  rp05OtherRawKey bound (rp05NodeInput left right)
    (by rw [rp05_node_input_length]; exact largeEnough)
    (by rw [rp05_node_input_length]; decide)

theorem rp05_node_key_is_literal_input (bound : Nat)
    (largeEnough : 249 ≤ bound) (left right : DigestRegister) :
    rp05RawBytes (.inr (rp05NodeKey bound largeEnough left right)) =
      rp05NodeInput left right :=
  rp05_other_raw_key_preserves_bytes _ _ _ _

/-- One read per parent pair, preserving the left/right order. -/
def rp05ParentLevel (bound : Nat) (largeEnough : 249 ≤ bound) :
    (count : Nat) → (Fin (2 * count) → DigestRegister) →
      NonleafProgram (Rp05OtherRawInput bound) (Fin count → DigestRegister)
  | 0, _ => .done Fin.elim0
  | count + 1, labels =>
      .read (rp05NodeKey bound largeEnough
        (labels ⟨0, by omega⟩) (labels ⟨1, by omega⟩)) fun parent =>
        NonleafProgram.bind
          (rp05ParentLevel bound largeEnough count
            (fun i => labels ⟨i.val + 2, by omega⟩))
          (fun parents => .done (Fin.cons parent parents))

def rp05MerkleLevels (bound : Nat) (largeEnough : 249 ≤ bound) :
    (depth : Nat) → (Fin (2 ^ depth) → DigestRegister) →
      NonleafProgram (Rp05OtherRawInput bound)
        (DigestRegister × List (List DigestRegister))
  | 0, labels => .done (labels ⟨0, by norm_num⟩, [List.ofFn labels])
  | depth + 1, labels =>
      NonleafProgram.bind
        (rp05ParentLevel bound largeEnough (2 ^ depth)
          (fun i => labels ⟨i.val, by
            simpa only [pow_succ, Nat.mul_comm] using i.isLt⟩))
        (fun parents =>
          NonleafProgram.bind
            (rp05MerkleLevels bound largeEnough depth parents)
            (fun result => .done (result.1, List.ofFn labels :: result.2)))

def rp05AllMerkleLevels (bound : Nat) (largeEnough : 249 ≤ bound)
    (labels : LeafIndex → DigestRegister) :
    NonleafProgram (Rp05OtherRawInput bound)
      (DigestRegister × List (List DigestRegister)) :=
  rp05MerkleLevels bound largeEnough 23 labels

/-- The unchanged rejection/early-stopping loop now reads only current
SMZA-framed counter keys in the corrected raw partition. -/
def rp05FieldXof (bound : Nat) (role : List CanonicalBytes.Byte) (words : List Nat)
    (bounded : 85 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 85 + role.length + 8 * words.length ≠ rp05LeafBytes)
    (requested : Nat) (countBound : requested ≤ 2 ^ 24) :
    NonleafProgram (Rp05OtherRawInput bound)
      (Option (List FieldWord)) :=
  sourceFieldReadLoop requested []
    (List.ofFn fun index : Fin (digestCallCap requested) =>
      rp05SourceCounterKey bound role words bounded notLeaf
        ⟨index.val, by
          have cap : digestCallCap requested ≤ 2 ^ 21 + 4 := by
            unfold digestCallCap
            split <;> omega
          exact lt_of_lt_of_le index.isLt (le_trans cap (by norm_num))⟩)

theorem rp05_field_xof_query_bound (bound : Nat) (role : List CanonicalBytes.Byte)
    (words : List Nat)
    (bounded : 85 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 85 + role.length + 8 * words.length ≠ rp05LeafBytes)
    (requested : Nat) (countBound : requested ≤ 2 ^ 24) :
    NonleafProgram.readCount
      (rp05FieldXof bound role words bounded notLeaf requested countBound) ≤
      digestCallCap requested :=
  (source_field_read_loop_count requested [] _).trans (by simp)

/-- Merkle build, root binding, q38 DECS and PIOP XOFs on one current
nonleaf address carrier.  Only pure field/word encoders are reused from the
old source; no historical SMZ9 oracle key survives here. -/
def rp05CurrentPrefinalShape (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24) :
    Q38PrefinalShape (Rp05OtherRawInput bound) :=
  let binding := statementWords statement
  let rootWords := fun root =>
    sourceSaltWords salt ++ sourceDigestWords root ++ binding
  let rootKey := fun root =>
    rp05SourceCounterKey bound SmallWoodTranscript.merkleRootDomain
      (rootWords root)
      (by simp only [rootWords, binding, sourceSaltWords, List.length_append,
        List.length_ofFn, source_digest_word_count, statement_word_count]
          have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
          rw [role]; omega)
      (by simp only [rootWords, binding, sourceSaltWords, List.length_append,
        List.length_ofFn, source_digest_word_count, statement_word_count]
          have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
          rw [role]; simp [rp05LeafBytes]) ⟨0, by norm_num⟩
  {
    build := rp05AllMerkleLevels bound (by omega) labels
    rootKey := rootKey
    decs := fun firstHash =>
      rp05FieldXof bound SmallWoodTranscript.decsCoefficientDomain
        (sourceDigestWords firstHash)
        (by rw [source_digest_word_count]
            have role : SmallWoodTranscript.decsCoefficientDomain.length = 41 := by decide
            rw [role]; omega)
        (by rw [source_digest_word_count]
            have role : SmallWoodTranscript.decsCoefficientDomain.length = 41 := by decide
            rw [role]; simp [rp05LeafBytes]) 700 (by norm_num)
    piopKey := fun hashMt reply =>
      let piopWords := sourceDigestWords hashMt ++ responseWords reply ++ binding
      rp05SourceCounterKey bound SmallWoodTranscript.piopInputDomain piopWords
        (by simp only [piopWords, binding, List.length_append,
          source_digest_word_count, response_word_count, statement_word_count]
            have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
            rw [role]; omega)
        (by simp only [piopWords, binding, List.length_append,
          source_digest_word_count, response_word_count, statement_word_count]
            have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
            rw [role]; simp [rp05LeafBytes]) ⟨0, by norm_num⟩
    piop := fun hashFpp =>
      rp05FieldXof bound SmallWoodTranscript.piopCoefficientDomain
        (sourceDigestWords hashFpp)
        (by rw [source_digest_word_count]
            have role : SmallWoodTranscript.piopCoefficientDomain.length = 41 := by decide
            rw [role]; omega)
        (by rw [source_digest_word_count]
            have role : SmallWoodTranscript.piopCoefficientDomain.length = 41 := by decide
            rw [role]; simp [rp05LeafBytes])
        (5 * dsl.width statement) widthBound
  }

def rp05CurrentPrefinal (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24) :
    NonleafProgram (Rp05OtherRawInput bound) (PrefinalResult × D) :=
  (rp05CurrentPrefinalShape bound largeEnough dsl statement salt labels
    widthBound).dynamic (decsReply values base masks)

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
