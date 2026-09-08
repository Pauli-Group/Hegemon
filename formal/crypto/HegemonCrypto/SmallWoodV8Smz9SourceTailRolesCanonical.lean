import HegemonCrypto.SmallWoodV8Smz9SourceTailReadbacks

/-! Canonicality of source role rows 2..8 and Boolean row 11 only.
Every auxiliary is computed internally by the unchanged sourceAux function.
No range, successful evaluator, accepted-packed or arbitrary-auxiliary premise.
Canonicality and Boolean values do not imply nonzero role obligations,
checked arithmetic refinement or full relation acceptance. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldNormalize fieldSub)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem boolean_word_canonical (value : Nat) (boolean : BooleanWord value) :
    value < fieldModulus := by
  rcases boolean with rfl | rfl <;> decide

theorem source_unit_word_boolean (limb : Nat) : BooleanWord (sourceUnitWord limb) := by
  unfold sourceUnitWord
  split_ifs <;> simp [BooleanWord]

theorem source_unit_word_canonical (limb : Nat) : sourceUnitWord limb < fieldModulus :=
  boolean_word_canonical _ (source_unit_word_boolean limb)

theorem source_normalize_canonical (value : Nat) : fieldNormalize value < fieldModulus :=
  Nat.mod_lt _ (by decide)

theorem source_sub_canonical (left right : Nat) : fieldSub left right < fieldModulus :=
  source_normalize_canonical _

theorem valid_stable_intent_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords digestWords statement.stablecoin.actionIntent := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,intent,_⟩ := valid.1
  exact intent

theorem valid_selected_spend_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Nat) :
    wordAt (selectedTransactionSpendKey statement witness) limb < fieldModulus := by
  unfold selectedTransactionSpendKey
  split_ifs
  · exact auth_exact_words_getD (valid_input_spend_words_exact statement witness valid 0 (by decide)) limb
  · exact auth_exact_words_getD (valid_input_spend_words_exact statement witness valid 1 (by decide)) limb
  · simp only [wordAt, List.getD_eq_getElem?_getD, List.getElem?_replicate]
    split_ifs <;> simp only [Option.getD_some, Option.getD_none] <;> decide

theorem valid_commitment_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role limb : Nat) :
    sourceCommitmentWord witness.stablecoin role limb < fieldModulus := by
  unfold sourceCommitmentWord
  split_ifs
  · exact auth_exact_words_getD (valid_stable_words_exact statement witness valid) _
  · decide

theorem valid_stable_role_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role limb : Nat) :
    sourceStableRoleWord statement.stablecoin witness.stablecoin role limb < fieldModulus := by
  unfold sourceStableRoleWord
  dsimp only
  split_ifs
  all_goals first
    | exact source_unit_word_canonical limb
    | exact valid_commitment_word_canonical statement witness valid _ _
    | exact source_sub_canonical _ _
    | exact source_normalize_canonical _
    | exact auth_exact_words_getD (valid_stable_words_exact statement witness valid) _
    | exact auth_exact_words_getD (valid_stable_intent_exact statement witness valid) _
    | decide

theorem valid_role_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (hashCanonical : HashFinalsCanonical hashes) (role limb : Nat) :
    sourceRoleWord statement witness hashes role limb < fieldModulus := by
  have auth := valid_auth_typed_source_canonical statement witness valid
  unfold sourceRoleWord
  split_ifs
  all_goals first
    | exact valid_stable_role_word_canonical statement witness valid _ _
    | exact source_unit_word_canonical limb
    | exact valid_selected_spend_word_canonical statement witness valid limb
    | exact auth_hash_word_canonical hashes hashCanonical _ _
    | exact auth.1.1 limb
    | exact auth.2.2 (role - 24) (by omega) limb

theorem valid_tail_role_rows_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (hashCanonical : HashFinalsCanonical hashes) (row : Fin 7) (lane : Fin 64) :
    sourceTailWord statement witness hashes (2 + row.val) lane.val < fieldModulus := by
  have readback := source_tail_family_readback statement witness hashes .roleDifference
    row.val lane.val row.isLt
  dsimp only [TailFamily.base, tailFamilyWord] at readback
  rw [readback]
  exact valid_role_word_canonical statement witness valid hashes hashCanonical lane.val row.val

theorem boolean_getD (words : List Nat) (allBoolean : ∀ value, value ∈ words → BooleanWord value)
    (index : Nat) : BooleanWord (words.getD index 0) := by
  cases found : words[index]? with
  | none => simp only [List.getD_eq_getElem?_getD, found, Option.getD_none]; exact Or.inl rfl
  | some value =>
      simp only [List.getD_eq_getElem?_getD, found, Option.getD_some]
      exact allBoolean value (List.mem_of_getElem? found)

theorem source_time_carry_boolean (left right extra : Nat) :
    BooleanWord (sourceTimeCarry left right extra) := by
  have bound : sourceTimeCarry left right extra < 2 := Nat.mod_lt _ (by decide)
  unfold BooleanWord
  omega

def AuxiliaryBooleanFields (aux : SourceAux) : Prop :=
  (∀ index, BooleanWord (aux.pathBits index)) ∧ BooleanWord aux.sameEpoch ∧
  (∀ index, BooleanWord (aux.decimalBits index)) ∧
  (∀ index, BooleanWord (aux.decimalSlackBits index)) ∧
  (∀ index, BooleanWord (aux.collateral.borrows index)) ∧
  ∀ index, BooleanWord (aux.timeCarries index)

/-- All computed auxiliary flags are Boolean even for arbitrary source inputs. -/
theorem actual_source_aux_boolean (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness) :
    AuxiliaryBooleanFields (sourceAux stablePublic witness) := by
  by_cases disabled : stablePublic.direction = .disabled
  · simp [sourceAux, disabled, AuxiliaryBooleanFields, disabledSourceAux, BooleanWord]
  · unfold AuxiliaryBooleanFields
    simp only [sourceAux, if_neg disabled]
    refine ⟨fun i => source_bit_boolean _ i, ?_, fun i => source_bit_boolean _ i,
      fun i => source_bit_boolean _ i, ?_, ?_⟩
    · split <;> simp [BooleanWord]
    · intro i
      split
      · exact source_borrow_boolean _ _ (i + 1)
      · exact Or.inl rfl
    · intro i
      split
      · apply boolean_getD
        intro value member
        simp only [List.mem_cons, List.not_mem_nil, or_false] at member
        rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl
        all_goals first
          | exact source_time_carry_boolean _ _ _
          | split_ifs <;> first | exact source_time_carry_boolean _ _ _ | exact Or.inl rfl
      · exact Or.inl rfl

theorem stable_zero_word (witness : V8StablecoinWitness) (zero : StableZeroWords witness.words)
    (index : Nat) : stableWitnessWord witness index = 0 := by
  cases found : witness.words[index]? with
  | none => simp only [stableWitnessWord, List.getD_eq_getElem?_getD, found, Option.getD_none]
  | some value =>
      have isZero : value = 0 := of_decide_eq_true
        ((List.all_eq_true.mp zero) value (List.mem_of_getElem? found))
      simp only [stableWitnessWord, List.getD_eq_getElem?_getD, found, Option.getD_some, isZero]

def ConfigBooleanFields (witness : V8StablecoinWitness) : Prop :=
  BooleanWord (decodeV8StablecoinConfig witness).active ∧
  BooleanWord (decodeV8StablecoinConfig witness).retiredPresent ∧
  BooleanWord (decodeV8StablecoinConfig witness).attestationDisputed ∧
  BooleanWord (decodeV8StablecoinConfig witness).attestationPresent

theorem canonical_encoding_config_boolean (witness : V8StablecoinWitness)
    (canonical : CanonicalV8StablecoinWitnessEncoding witness) : ConfigBooleanFields witness := by
  obtain ⟨_,_,_,active,retired,_,_,_,disputed,present,_⟩ := canonical
  exact ⟨active,retired,disputed,present⟩

theorem valid_config_boolean (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) : ConfigBooleanFields witness.stablecoin := by
  have transition : exactV8StableTransition (derivedRelationContext statement)
      statement.stablecoin witness.stablecoin := valid.2.2.2.2
  cases direction : statement.stablecoin.direction with
  | disabled =>
      simp only [exactV8StableTransition, direction] at transition
      obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,zero⟩ := transition
      exact ⟨Or.inl (stable_zero_word _ zero 2), Or.inl (stable_zero_word _ zero 4),
        Or.inl (stable_zero_word _ zero 21), Or.inl (stable_zero_word _ zero 22)⟩
  | mint =>
      simp only [exactV8StableTransition, direction] at transition
      exact canonical_encoding_config_boolean _ transition.1
  | burn =>
      simp only [exactV8StableTransition, direction] at transition
      exact canonical_encoding_config_boolean _ transition.1

/-- All 53 source Boolean values are 0 or 1, using the actual computed aux. -/
theorem valid_source_boolean_values_boolean (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ∀ value, value ∈ sourceBooleanValues statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin) → BooleanWord value := by
  have config := valid_config_boolean statement witness valid
  have aux := actual_source_aux_boolean statement.stablecoin witness.stablecoin
  intro value member
  simp only [sourceBooleanValues, List.mem_append] at member
  rcases member with ((((((header | path) | epoch) | decimals) | slack) | borrow) | carry) | ranges
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at header
    rcases header with rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · cases statement.stablecoin.direction <;> simp [BooleanWord]
    · split_ifs <;> simp [BooleanWord]
    · split_ifs <;> simp [BooleanWord]
    · exact config.1
    · exact config.2.1
    · exact config.2.2.1
    · exact config.2.2.2
  · obtain ⟨i,rfl⟩ := List.mem_ofFn.mp path
    exact aux.1 i.val
  · simp only [List.mem_singleton] at epoch
    rw [epoch]
    exact aux.2.1
  · obtain ⟨i,rfl⟩ := List.mem_ofFn.mp decimals
    exact aux.2.2.1 i.val
  · obtain ⟨i,rfl⟩ := List.mem_ofFn.mp slack
    exact aux.2.2.2.1 i.val
  · obtain ⟨i,rfl⟩ := List.mem_ofFn.mp borrow
    exact aux.2.2.2.2.1 i.val
  · obtain ⟨i,rfl⟩ := List.mem_ofFn.mp carry
    exact aux.2.2.2.2.2 i.val
  · obtain ⟨entry,_,rfl⟩ := List.mem_map.mp ranges
    exact source_bit_boolean _ _

theorem valid_tail_boolean_row_boolean (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) (lane : Nat) :
    BooleanWord (sourceTailWord statement witness hashes 11 lane) := by
  rw [source_tail_at_11]
  exact boolean_getD _ (valid_source_boolean_values_boolean statement witness valid) lane

theorem valid_tail_boolean_row_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) (lane : Fin 64) :
    sourceTailWord statement witness hashes 11 lane.val < fieldModulus :=
  boolean_word_canonical _ (valid_tail_boolean_row_boolean statement witness valid hashes lane.val)


end HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
