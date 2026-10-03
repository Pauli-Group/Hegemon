import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SemanticAssetMembership

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem full_candidate_auth_row (statement : V8PublicStatement) (witness : V8Witness)
    (row : Fin 155) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val (92 + row.val) =
      (sourceAuthRow statement witness (typedSourceFinals statement witness) row.val : F) := by
  change ((Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows
    (constructedAssignment statement witness (typedLiveInitialStates statement witness)
      (typedSourceTail statement witness)) lane.val).getD (92 + row.val) 0 : F) = _
  rw [constructed_as_auth_placement]
  exact congrArg (fun word : Nat => (word : F))
    (source_auth_global_lane_readback _ _ statement witness _
      (HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows.packed_prefix_length statement witness)
      row lane)

theorem full_candidate_auth_family (statement : V8PublicStatement) (witness : V8Witness)
    (family : AuthFamily) (index : Nat) (bound : index < family.width) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val (92 + family.base + index) =
      (authFamilyWord statement witness (typedSourceFinals statement witness) family index : F) :=
  congrArg (fun word : Nat => (word : F))
    (constructed_auth_family_readback statement witness (typedLiveInitialStates statement witness)
      (typedSourceTail statement witness) family index bound lane)

theorem zero_words_readback (words : List Nat) (zero : ZeroWords words) (index : Nat) :
    wordAt words index = 0 := by
  unfold wordAt
  cases found : words[index]? with
  | none => simp only [List.getD_eq_getElem?_getD, found, Option.getD_none]
  | some value =>
      have equal := zero value (List.mem_of_getElem? found)
      simp only [List.getD_eq_getElem?_getD, found, Option.getD_some, equal]

theorem zero_tag_readback (tags : List (List Nat)) (zero : ZeroSignerTags tags)
    (slot limb : Nat) : wordAt (tags.getD slot []) limb = 0 := by
  cases found : tags[slot]? with
  | none => simp [List.getD_eq_getElem?_getD, found, wordAt]
  | some tag =>
      have words := (zero.2 tag (List.mem_of_getElem? found)).2
      simp only [List.getD_eq_getElem?_getD, found, Option.getD_some]
      exact zero_words_readback tag words limb

theorem single_zero_openings (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (single : witness.authorization.mode = .singleKey) :
    ZeroAccumulator witness.authorization.current ∧ ZeroAccumulator witness.authorization.next ∧
      ZeroSignerTags witness.authorization.policySignerTags := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid, single] at auth
  exact ⟨auth.1,auth.2.1,auth.2.2.1⟩

theorem final_zero_next (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (finalMode : witness.authorization.mode = .finalThresholdSpend) :
    ZeroAccumulator witness.authorization.next := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid, finalMode] at auth
  exact auth.2.2.1

theorem single_scalar_zero (auth : V8AuthorizationWitness)
    (current : ZeroAccumulator auth.current) (next : ZeroAccumulator auth.next) (offset : Nat) :
    authScalar auth offset = 0 := by
  obtain ⟨_,_,_,_,ct,cs,cc,_,ca⟩ := current
  obtain ⟨_,_,_,_,_,_,nc,_,na⟩ := next
  have currentWords := zero_words_readback _ ca
  have nextWords := zero_words_readback _ na
  simp [authScalar,ct,cs,cc,nc,currentWords,nextWords]

theorem single_protected_row_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (single : witness.authorization.mode = .singleKey) (hashes : AuthHashFinals)
    (row : Nat) (lower : 46 ≤ row) (upper : row < 155) :
    sourceAuthRow statement witness hashes row = 0 := by
  obtain ⟨current,next,tags⟩ := single_zero_openings statement witness valid single
  have intent := zero_words_readback _ current.2.2.2.1
  have scalars := single_scalar_zero witness.authorization current next
  have tagWords := zero_tag_readback _ tags
  unfold sourceAuthRow
  simp only [if_neg (show ¬row < 3 by omega),if_neg (show ¬row < 5 by omega),
    if_neg (show ¬row < 13 by omega),if_neg (show ¬row < 18 by omega),
    if_neg (show ¬row < 25 by omega),if_neg (show ¬row < 32 by omega),
    if_neg (show ¬row < 39 by omega),if_neg (show ¬row < 46 by omega)]
  split_ifs <;> simp [authPolicyWord,authThresholdFlag,authSignerFlag,authCurrentCountFlag,
    authNextCountFlag,authMembership,authDistinctInverse,authBit,single,intent,scalars]
  simpa only [List.getD_eq_getElem?_getD] using tagWords ((row - 104) / 5) ((row - 104) % 5)

theorem mode_boolean (mode : V8AuthorizationMode) (index : Fin 3) :
    (authModeFlag mode index.val : F) * ((authModeFlag mode index.val : F) - 1) = 0 := by
  cases mode <;> fin_cases index <;> norm_num [authModeFlag,authBit]

theorem mode_one_hot (mode : V8AuthorizationMode) :
    (authModeFlag mode 0 : F) + (authModeFlag mode 1 : F) + (authModeFlag mode 2 : F) - 1 = 0 := by
  cases mode <;> norm_num [authModeFlag,authBit]


end HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
