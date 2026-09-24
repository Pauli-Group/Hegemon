import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SourceEarlyReservedRoots
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoin

/-!
Source-level support for the exact 135 actual CSR rows in families
36/38/40/41/42/43/45. The disjoint 210 live-role rows of family 47 are
coordinator-owned. All nontrivial semantic premises below are derived from
ExactV8RelationSemanticValid; none assume acceptance or a desired row identity.
This module does not itself claim membership or zero residuals for CSR rows.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem typed_stable_transition (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    exactV8StableTransition (derivedRelationContext statement)
      statement.stablecoin witness.stablecoin := valid.2.2.2.2

theorem typed_disabled_source_words_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (disabled : statement.stablecoin.direction = .disabled) :
    StableZeroWords witness.stablecoin.words := by
  have transition := typed_stable_transition statement witness valid
  simp only [exactV8StableTransition, disabled] at transition
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,zero⟩ := transition
  exact zero

theorem typed_disabled_asset_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (disabled : statement.stablecoin.direction = .disabled) :
    statement.stablecoin.assetId = 0 := by
  have transition := typed_stable_transition statement witness valid
  simp only [exactV8StableTransition, disabled] at transition
  exact transition.2.2.1

theorem stable_source_disabled_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (disabled : statement.stablecoin.direction = .disabled) (slot : Fin 94) :
    stableSourceWord statement witness slot.val = 0 := by
  simp only [stableSourceWord, if_pos slot.isLt]
  exact HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds.stable_zero_word _
    (typed_disabled_source_words_zero statement witness valid disabled) _

theorem stable_source_reserved_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 18) :
    stableSourceWord statement witness (94 + slot.val) = 0 := by
  rw [stable_source_parent_readback statement witness slot.val slot.isLt]
  exact canonical_encoded_reserved_zero statement valid.1 slot

theorem typed_burn_issuer_secret_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (burn : statement.stablecoin.direction = .burn) :
    StableZeroWords (decodeV8StablecoinIssuerSecret witness.stablecoin) := by
  have transition := typed_stable_transition statement witness valid
  simp only [exactV8StableTransition, burn] at transition
  have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
  simp only [burn] at branch
  exact branch.1

theorem stable_source_nonmint_issuer_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonmint : statement.stablecoin.direction ≠ .mint) (limb : Fin 7) :
    stableSourceWord statement witness (83 + limb.val) = 0 := by
  cases mode : statement.stablecoin.direction with
  | disabled =>
      exact stable_source_disabled_zero statement witness valid mode ⟨83 + limb.val,by omega⟩
  | mint => exact False.elim (nonmint mode)
  | burn =>
      rw [stable_source_issuer_readback statement witness limb.val limb.isLt]
      have zero := typed_burn_issuer_secret_zero statement witness valid mode
      have member : stableWitnessWord witness.stablecoin (87 + limb.val) ∈
          decodeV8StablecoinIssuerSecret witness.stablecoin := by
        exact List.mem_map.mpr ⟨limb.val, List.mem_range.mpr limb.isLt, rfl⟩
      exact of_decide_eq_true (List.all_eq_true.mp zero _ member)

theorem typed_burn_issuer_authorization_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (burn : statement.stablecoin.direction = .burn) :
    StableZeroWords statement.stablecoin.issuerAuthorization := by
  have transition := typed_stable_transition statement witness valid
  simp only [exactV8StableTransition, burn] at transition
  have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
  simp only [burn] at branch
  exact branch.2.1

theorem stable_zero_words_getD (words : List Nat) (zero : StableZeroWords words) (index : Nat) :
    words.getD index 0 = 0 := by
  cases found : words[index]? with
  | none => simp only [List.getD_eq_getElem?_getD, found, Option.getD_none]
  | some value =>
      have valueZero : value = 0 :=
        of_decide_eq_true (List.all_eq_true.mp zero value (List.mem_of_getElem? found))
      simp only [List.getD_eq_getElem?_getD, found, Option.getD_some, valueZero]

/-- Uncast projections from the actual encoded public list. -/
theorem encoded_stable_public_scalars (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (encodePublicStatement statement).getD 83 0 = statement.stablecoin.direction.word ∧
    (encodePublicStatement statement).getD 84 0 = statement.stablecoin.assetId ∧
    (encodePublicStatement statement).getD 85 0 = statement.stablecoin.policyVersion ∧
    (encodePublicStatement statement).getD 86 0 = statement.stablecoin.magnitude := by
  exact ⟨by simpa [encodeStablecoinPublic] using encoded_stable_public_word statement valid.1 0,
    by simpa [encodeStablecoinPublic] using encoded_stable_public_word statement valid.1 1,
    by simpa [encodeStablecoinPublic] using encoded_stable_public_word statement valid.1 2,
    by simpa [encodeStablecoinPublic] using encoded_stable_public_word statement valid.1 3⟩

theorem encoded_stable_action_intent_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    (encodePublicStatement statement).getD (87 + limb.val) 0 =
      statement.stablecoin.actionIntent.getD limb.val 0 := by
  have intent := HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical.valid_stable_intent_exact
    statement witness valid
  have source := encoded_stable_public_word statement valid.1 (4 + limb.val)
  fin_cases limb <;>
    simpa [encodeStablecoinPublic, List.getD_eq_getElem?_getD,
      List.getElem?_append, List.length_append, intent.1, digestWords] using source

theorem encoded_stable_issuer_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    (encodePublicStatement statement).getD (113 + limb.val) 0 =
      statement.stablecoin.issuerAuthorization.getD limb.val 0 := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,intent,before,after,_⟩ := valid.1
  have source := encoded_stable_public_word statement valid.1 (30 + limb.val)
  fin_cases limb <;>
    simpa [encodeStablecoinPublic, List.getD_eq_getElem?_getD,
      List.getElem?_append, List.length_append, intent.1, before.1, after.1, digestWords] using source

theorem encoded_burn_issuer_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (burn : statement.stablecoin.direction = .burn) (limb : Fin 7) :
    (encodePublicStatement statement).getD (113 + limb.val) 0 = 0 := by
  rw [encoded_stable_issuer_word statement witness valid limb]
  exact stable_zero_words_getD _ (typed_burn_issuer_authorization_zero statement witness valid burn) _

theorem typed_stable_public_scalar_copies (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    stableSourceWord statement witness 0 = statement.stablecoin.assetId ∧
    stableSourceWord statement witness 1 = statement.stablecoin.policyVersion := by
  change stableWitnessWord witness.stablecoin 0 = statement.stablecoin.assetId ∧
    stableWitnessWord witness.stablecoin 1 = statement.stablecoin.policyVersion
  have transition := typed_stable_transition statement witness valid
  cases mode : statement.stablecoin.direction with
  | disabled =>
      simp only [exactV8StableTransition, mode] at transition
      obtain ⟨_,_,asset,policy,_,_,_,_,_,_,_,_,_,_,zero⟩ := transition
      exact ⟨(HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds.stable_zero_word _ zero 0).trans asset.symm,
        (HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds.stable_zero_word _ zero 1).trans policy.symm⟩
  | mint =>
      simp only [exactV8StableTransition, mode] at transition
      obtain ⟨_,_,_,_,_,_,_,_,_,_,asset,policy,_⟩ := transition
      exact ⟨asset.symm,policy.symm⟩
  | burn =>
      simp only [exactV8StableTransition, mode] at transition
      obtain ⟨_,_,_,_,_,_,_,_,_,_,asset,policy,_⟩ := transition
      exact ⟨asset.symm,policy.symm⟩

theorem stable_source_public_scalar_bridge (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    stableSourceWord statement witness slot.val =
      (encodePublicStatement statement).getD (84 + slot.val) 0 := by
  have typed := typed_stable_public_scalar_copies statement witness valid
  have encoded := encoded_stable_public_scalars statement witness valid
  fin_cases slot
  · exact typed.1.trans encoded.2.1.symm
  · exact typed.2.trans encoded.2.2.1.symm

theorem source_boolean_direction_values (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 0 0 =
      (if statement.stablecoin.direction = .mint then 1 else 0) +
      (if statement.stablecoin.direction = .burn then 1 else 0) ∧
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 1 0 =
      (if statement.stablecoin.direction = .mint then 1 else 0) ∧
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 2 0 =
      (if statement.stablecoin.direction = .burn then 1 else 0) := by
  exact ⟨rfl,rfl,rfl⟩

theorem source_boolean_direction_encoded (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (aux : SourceAux) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 0 0 =
      (if (encodePublicStatement statement).getD 83 0 = 1 then 1 else 0) +
      (if (encodePublicStatement statement).getD 83 0 = 2 then 1 else 0) ∧
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 1 0 =
      (if (encodePublicStatement statement).getD 83 0 = 1 then 1 else 0) ∧
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 2 0 =
      (if (encodePublicStatement statement).getD 83 0 = 2 then 1 else 0) := by
  rw [(encoded_stable_public_scalars statement witness valid).1]
  have values := source_boolean_direction_values statement witness aux
  cases mode : statement.stablecoin.direction <;>
    simpa [mode, StableDirection.word] using values

theorem source_boolean_path_projection (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (bit : Fin 4) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD (7 + bit.val) 0 =
      aux.pathBits bit.val := by
  fin_cases bit <;> rfl

theorem source_aux_asset_bit (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (bit : Nat) :
    (sourceAux statement.stablecoin witness.stablecoin).pathBits bit =
      sourceBit statement.stablecoin.assetId bit := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · rw [source_aux_disabled _ _ disabled, typed_disabled_asset_zero statement witness valid disabled]
    simp only [disabledSourceAux, sourceBit, Nat.zero_div, Nat.zero_mod]
  · simp only [sourceAux, if_neg disabled]

theorem source_boolean_asset_bit (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (bit : Fin 4) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin)).getD (7 + bit.val) 0 =
      sourceBit statement.stablecoin.assetId bit.val := by
  rw [source_boolean_path_projection, source_aux_asset_bit statement witness valid]

theorem source_boolean_asset_bit_encoded (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (bit : Fin 4) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin)).getD (7 + bit.val) 0 =
      sourceBit ((encodePublicStatement statement).getD 84 0) bit.val := by
  rw [(encoded_stable_public_scalars statement witness valid).2.1]
  exact source_boolean_asset_bit statement witness valid bit


end HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
