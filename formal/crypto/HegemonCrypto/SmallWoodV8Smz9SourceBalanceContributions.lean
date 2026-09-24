import HegemonCrypto.SmallWoodV8Smz9SourceEarlyStableAssetRoot

namespace HegemonCrypto.SmallWood.V8Smz9SourceBalanceRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def sourceNoteValue (witness : V8Witness) (note : Nat) : Nat :=
  if note < 2 then (witness.inputs.getD note default).note.value
  else (witness.outputs.getD (note - 2) default).note.value

def sourceNoteActive (witness : V8Witness) (note : Nat) : Nat :=
  if note < 2 then (witness.inputs.getD note default).active
  else (witness.outputs.getD (note - 2) default).active

def typedNoteContribution (witness : V8Witness) (asset note : Nat) : Nat :=
  if sourceNoteActive witness note = 1 ∧ sourceNoteAsset witness note = asset
  then sourceNoteValue witness note else 0

theorem canonical_assets (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    CanonicalBalanceAssets statement.balanceAssets := canonical.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1

theorem typed_source_note_flag (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) :
    (encodePublicStatement statement).getD note.val 0 = sourceNoteActive witness note.val := by
  by_cases input : note.val < 2
  · rw [encoded_input_flag statement valid.1 input]
    have real : note.val < witness.inputs.length := by rw [valid.2.1.1]; exact input
    simpa only [sourceNoteActive,if_pos input,List.getD_eq_getElem _ _ real] using
      (valid.2.1.2.2.1 note.val input).1.symm
  · have output : note.val - 2 < 2 := by omega
    have address : note.val = 2 + (note.val - 2) := by omega
    have real : note.val - 2 < witness.outputs.length := by rw [valid.2.1.2.1]; exact output
    rw [address,encoded_output_flag statement valid.1 output]
    simpa only [sourceNoteActive,if_neg (by omega : ¬2 + (note.val - 2) < 2),Nat.add_sub_cancel_left,List.getD_eq_getElem _ _ real] using
      (valid.2.1.2.2.2.1 (note.val - 2) output).1.symm

theorem typed_source_note_flag_boolean (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) :
    BooleanWord (sourceNoteActive witness note.val) := by
  have publicFlag := canonical_encoded_public_boolean statement valid.1
    (⟨note.val,by omega⟩ : Fin 7)
  have identity : publicBooleanIndex note.val = note.val := by
    have finite : ∀ n : Fin 4, publicBooleanIndex n.val = n.val := by decide
    exact finite note
  rw [identity,typed_source_note_flag statement witness valid note] at publicFlag
  exact publicFlag

noncomputable section

theorem canonical_public_assets_distinct (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    NonpaddingDistinct (fun index => encodedPublicField statement (54 + index))
      (balancePaddingAssetId : F) := by
  have distinct := canonical_balance_assets_nonpadding_distinct statement.balanceAssets (canonical_assets statement canonical)
  intro left right different leftReal rightReal equal
  simp only [encodedPublicField,encoded_balance_asset statement canonical left.isLt] at leftReal equal
  simp only [encodedPublicField,encoded_balance_asset statement canonical right.isLt] at rightReal equal
  exact distinct left right different leftReal rightReal equal

theorem typed_active_weight_indicator (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note slot : Fin 4)
    (active : sourceNoteActive witness note.val = 1) :
    sourceWeight (encodedPublicField statement) slot.val (sourceNoteAsset witness note.val : F) =
      if sourceNoteAsset witness note.val = wordAt statement.balanceAssets slot.val then 1 else 0 := by
  have facts := typed_source_note_asset_membership statement witness valid note
  rw [typed_source_note_flag statement witness valid note,active] at facts
  obtain ⟨assetCanonical,nonpadding,chosen,chosenBound,matched⟩ := facts.resolve_left (by decide)
  have member : ∃ selected : Fin 4,
      encodedPublicField statement (54 + selected.val) ≠ (balancePaddingAssetId : F) ∧
      (sourceNoteAsset witness note.val : F) = encodedPublicField statement (54 + selected.val) := by
    refine ⟨⟨chosen,chosenBound⟩,?_,?_⟩
    · simp only [encodedPublicField,encoded_balance_asset statement valid.1 chosenBound,matched]
      intro equal
      exact nonpadding (canonical_nat_cast_injective assetCanonical balance_padding_asset_id_is_canonical equal)
    · simp only [encodedPublicField,encoded_balance_asset statement valid.1 chosenBound,matched]
  have generic := interpolationWeight_eq_indicator
    (fun index => encodedPublicField statement (54 + index)) (balancePaddingAssetId : F)
    slot (sourceNoteAsset witness note.val : F) (canonical_public_assets_distinct statement valid.1) member
  rw [← sourceWeight_eq_interpolationWeight (encodedPublicField statement) slot] at generic
  have comparison : (sourceNoteAsset witness note.val : F) = encodedPublicField statement (54 + slot.val) ↔
      sourceNoteAsset witness note.val = wordAt statement.balanceAssets slot.val := by
    simp only [encodedPublicField,encoded_balance_asset statement valid.1 slot.isLt]
    exact ⟨canonical_nat_cast_injective assetCanonical
      ((canonical_assets statement valid.1).2.2.1 slot.val slot.isLt),
      congrArg (fun n : Nat => (n : F))⟩
  simpa only [comparison] using generic

theorem full_candidate_note_value_readback (statement : V8PublicStatement) (witness : V8Witness)
    (note : Fin 4) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val (valueRow note.val) =
      (sourceNoteValue witness note.val : F) := by
  have bound : valueRow note.val < 92 := by
    have finite : ∀ n : Fin 4, valueRow n.val < 92 := by decide
    exact finite note
  rw [full_candidate_raw_field_readback statement witness (⟨valueRow note.val,bound⟩ : Fin 92) lane]
  change (sourceWord statement witness (valueRow note.val) : F) = _
  fin_cases note <;> simp [valueRow,sourceWord,inputWord,outputWord,sourceNoteValue]

theorem full_candidate_note_asset_balance_readback (statement : V8PublicStatement) (witness : V8Witness)
    (note : Fin 4) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val (valueRow note.val + 1) =
      (sourceNoteAsset witness note.val : F) := by
  have row : valueRow note.val + 1 = (assetRootAt note.val).row := by
    have finite : ∀ n : Fin 4, valueRow n.val + 1 = (assetRootAt n.val).row := by decide
    exact finite note
  rw [row,full_candidate_note_asset_readback]

theorem full_candidate_source_contribution (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (note slot : Fin 4) :
    sourceContribution (encodedPublicField statement)
      (laneField (fullTypedSourceCandidate statement witness) lane.val) slot.val note.val =
      (typedNoteContribution witness (wordAt statement.balanceAssets slot.val) note.val : F) := by
  rw [sourceContribution,full_candidate_note_value_readback,full_candidate_note_asset_balance_readback]
  have flag : encodedPublicField statement note.val = (sourceNoteActive witness note.val : F) :=
    congrArg (fun n : Nat => (n : F)) (typed_source_note_flag statement witness valid note)
  rw [flag]
  rcases typed_source_note_flag_boolean statement witness valid note with inactive | active
  · simp only [typedNoteContribution,inactive,Nat.cast_zero,zero_mul,mul_zero,Nat.zero_ne_one,false_and,if_false]
  · rw [typed_active_weight_indicator statement witness valid note slot active]
    by_cases same : sourceNoteAsset witness note.val = wordAt statement.balanceAssets slot.val
    · simp only [typedNoteContribution,active,same,if_true,and_self,Nat.cast_one,one_mul]
    · simp only [typedNoteContribution,active,same,if_false,and_false,Nat.cast_one,one_mul,zero_mul,Nat.cast_zero]

theorem typed_input_sum_as_two_contributions (witness : V8Witness)
    (length : witness.inputs.length = 2) (asset : Nat) :
    inputValueForAsset witness asset =
      typedNoteContribution witness asset 0 + typedNoteContribution witness asset 1 := by
  obtain ⟨first,second,inputs⟩ := List.length_eq_two.mp length
  simp only [inputValueForAsset,typedNoteContribution,sourceNoteActive,sourceNoteAsset,sourceNoteValue,
    inputs,List.getD_cons_zero,List.getD_cons_succ,List.foldl_cons,List.foldl_nil,
    show 0 < 2 by decide,show 1 < 2 by decide,if_true,Nat.zero_add]
  exact two_step_conditional_sum _ _ _ _

theorem typed_output_sum_as_two_contributions (witness : V8Witness)
    (length : witness.outputs.length = 2) (asset : Nat) :
    outputValueForAsset witness asset =
      typedNoteContribution witness asset 2 + typedNoteContribution witness asset 3 := by
  obtain ⟨first,second,outputs⟩ := List.length_eq_two.mp length
  simp only [outputValueForAsset,typedNoteContribution,sourceNoteActive,sourceNoteAsset,sourceNoteValue,
    outputs,List.getD_cons_zero,List.getD_cons_succ,List.foldl_cons,List.foldl_nil,
    show ¬2 < 2 by decide,show ¬3 < 2 by decide,if_false,show 2 - 2 = 0 by decide,
    show 3 - 2 = 1 by decide,Nat.zero_add]
  exact two_step_conditional_sum _ _ _ _

theorem full_candidate_source_delta (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (slot : Fin 4) :
    sourceDelta (encodedPublicField statement)
      (laneField (fullTypedSourceCandidate statement witness) lane.val) slot.val =
      (inputValueForAsset witness (wordAt statement.balanceAssets slot.val) : F) -
        (outputValueForAsset witness (wordAt statement.balanceAssets slot.val) : F) := by
  rw [sourceDelta,full_candidate_source_contribution statement witness valid lane ⟨0,by decide⟩ slot,
    full_candidate_source_contribution statement witness valid lane ⟨1,by decide⟩ slot,
    full_candidate_source_contribution statement witness valid lane ⟨2,by decide⟩ slot,
    full_candidate_source_contribution statement witness valid lane ⟨3,by decide⟩ slot,
    typed_input_sum_as_two_contributions witness valid.2.1.1,
    typed_output_sum_as_two_contributions witness valid.2.1.2.1]
  simp only [Nat.cast_add,sub_sub]


end
end HegemonCrypto.SmallWood.V8Smz9SourceBalanceRoots
