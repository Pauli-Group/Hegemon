import HegemonCrypto.SmallWoodV8Smz9SourceEarlyCiphertextRoots
import HegemonCrypto.SmallWoodV8Smz9SourceEarlyStablePublicRoots

namespace HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

open Hegemon.Transaction.Poseidon2V8RelationProgram (FieldExpression)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def sourceNoteAsset (witness : V8Witness) (note : Nat) : Nat :=
  if note < 2 then (witness.inputs.getD note default).note.assetId
  else (witness.outputs.getD (note - 2) default).note.assetId

theorem typed_input_asset_membership (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    flagAt statement.inputFlags slot.val = 0 ∨
      (witness.inputs.getD slot.val default).note.assetId < fieldModulus ∧
      (witness.inputs.getD slot.val default).note.assetId ≠ balancePaddingAssetId ∧
      ∃ asset, asset < 4 ∧ wordAt statement.balanceAssets asset =
        (witness.inputs.getD slot.val default).note.assetId := by
  have input := valid.2.1.2.2.1 slot.val slot.isLt
  change _ ∧ (if (witness.inputs.getD slot.val default).active = 0 then _ else _) at input
  by_cases inactive : (witness.inputs.getD slot.val default).active = 0
  · exact Or.inl (input.1.symm.trans inactive)
  · rw [if_neg inactive] at input
    have selectors := input.2.2.2.2.2.2.2
    change OneHotSelectorForAsset (witness.inputs.getD slot.val default).active
      (witness.inputs.getD slot.val default).note
      (witness.inputs.getD slot.val default).balanceSelectors statement.balanceAssets at selectors
    rw [OneHotSelectorForAsset,if_neg inactive] at selectors
    obtain ⟨asset,bound,_,equal⟩ := selectors.2.2.2
    exact Or.inr ⟨input.2.1.2.1,input.2.1.2.2.1,asset,bound,equal⟩

theorem typed_output_asset_membership (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    flagAt statement.outputFlags slot.val = 0 ∨
      (witness.outputs.getD slot.val default).note.assetId < fieldModulus ∧
      (witness.outputs.getD slot.val default).note.assetId ≠ balancePaddingAssetId ∧
      ∃ asset, asset < 4 ∧ wordAt statement.balanceAssets asset =
        (witness.outputs.getD slot.val default).note.assetId := by
  have output := valid.2.1.2.2.2.1 slot.val slot.isLt
  change _ ∧ (if (witness.outputs.getD slot.val default).active = 0 then _ else _) at output
  by_cases inactive : (witness.outputs.getD slot.val default).active = 0
  · exact Or.inl (output.1.symm.trans inactive)
  · rw [if_neg inactive] at output
    have selectors := output.2.2
    change OneHotSelectorForAsset (witness.outputs.getD slot.val default).active
      (witness.outputs.getD slot.val default).note
      (witness.outputs.getD slot.val default).balanceSelectors statement.balanceAssets at selectors
    rw [OneHotSelectorForAsset,if_neg inactive] at selectors
    obtain ⟨asset,bound,_,equal⟩ := selectors.2.2.2
    exact Or.inr ⟨output.2.1.2.1,output.2.1.2.2.1,asset,bound,equal⟩

theorem typed_source_note_asset_membership (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) :
    (encodePublicStatement statement).getD note.val 0 = 0 ∨
      sourceNoteAsset witness note.val < fieldModulus ∧
      sourceNoteAsset witness note.val ≠ balancePaddingAssetId ∧
      ∃ slot, slot < 4 ∧ wordAt statement.balanceAssets slot = sourceNoteAsset witness note.val := by
  by_cases input : note.val < 2
  · rw [encoded_input_flag statement valid.1 input]
    simpa only [sourceNoteAsset,if_pos input] using
      typed_input_asset_membership statement witness valid ⟨note.val,input⟩
  · have output : note.val - 2 < 2 := by omega
    have address : note.val = 2 + (note.val - 2) := by omega
    rw [address,encoded_output_flag statement valid.1 output]
    simpa only [sourceNoteAsset,if_neg (by omega : ¬2 + (note.val - 2) < 2),
      Nat.add_sub_cancel_left] using typed_output_asset_membership statement witness valid ⟨note.val - 2,output⟩

def noteAssetRootIndex (note : Nat) : Nat := [63,96,97,104].getD note 0

theorem exact_note_asset_root_indices (note : Fin 4) :
    (assetRootAt note.val).row < 92 ∧
    exactNonlinearRoots[noteAssetRootIndex note.val]? = some (assetRootAt note.val).root := by
  have finite : ∀ note : Fin 4, (assetRootAt note.val).row < 92 ∧
      exactNonlinearRoots[noteAssetRootIndex note.val]? = some (assetRootAt note.val).root := by decide
  exact finite note

noncomputable section

theorem matching_asset_factors_zero (asset : F) (candidates : Nat → F)
    (matchSlot : ∃ slot, slot < 4 ∧ candidates slot = asset)
    (nonpadding : asset ≠ (balancePaddingAssetId : F)) :
    ((assetFactor asset (candidates 0) * assetFactor asset (candidates 1)) *
      assetFactor asset (candidates 2)) * assetFactor asset (candidates 3) = 0 := by
  obtain ⟨slot,bound,matched⟩ := matchSlot
  have zero : assetFactor asset (candidates slot) = 0 := by simp [assetFactor,matched,nonpadding]
  have cases : slot = 0 ∨ slot = 1 ∨ slot = 2 ∨ slot = 3 := by omega
  rcases cases with rfl | rfl | rfl | rfl <;> simp only [zero,zero_mul,mul_zero]

theorem full_candidate_note_asset_readback (statement : V8PublicStatement) (witness : V8Witness)
    (note : Fin 4) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val (assetRootAt note.val).row =
      (sourceNoteAsset witness note.val : F) := by
  rw [full_candidate_raw_field_readback statement witness
    (⟨(assetRootAt note.val).row,(exact_note_asset_root_indices note).1⟩ : Fin 92) lane]
  change (sourceWord statement witness (assetRootAt note.val).row : F) = _
  fin_cases note <;> simp [assetRootAt,assetRoots,sourceWord,inputWord,outputWord,sourceNoteAsset]

theorem full_candidate_note_asset_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (note : Fin 4) :
    (exactNonlinearRoots[noteAssetRootIndex note.val]?).map
      (fieldAt exactNonlinearExpressions (encodedPublicField statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [(exact_note_asset_root_indices note).2,Option.map_some,
    actual_asset_root_formula _ (asset_root_at_valid note.isLt).1,
    (asset_root_at_valid note.isLt).2,full_candidate_note_asset_readback]
  rcases typed_source_note_asset_membership statement witness valid note with inactive | member
  · simp only [encodedPublicField,inactive,Nat.cast_zero,zero_mul]
  · have nonpadding : (sourceNoteAsset witness note.val : F) ≠ (balancePaddingAssetId : F) := by
      intro equal
      exact member.2.1 (canonical_nat_cast_injective member.1 balance_padding_asset_id_is_canonical equal)
    have matched : ∃ slot, slot < 4 ∧ encodedPublicField statement (54 + slot) =
        (sourceNoteAsset witness note.val : F) := by
      obtain ⟨slot,bound,equal⟩ := member.2.2
      exact ⟨slot,bound,by simp only [encodedPublicField,encoded_balance_asset statement valid.1 bound,equal]⟩
    have zero := matching_asset_factors_zero (sourceNoteAsset witness note.val : F)
      (fun slot => encodedPublicField statement (54 + slot)) matched nonpadding
    change some (_ * _) = some 0
    rw [zero,mul_zero]









end
end HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
