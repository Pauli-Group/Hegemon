import HegemonCrypto.SmallWoodV8Smz9SourceDenseMaterialization
import HegemonCrypto.SmallWoodV8Smz9SemanticBalance

namespace HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance

/-- The seven actual private/public dense-range inputs, in source loop order. -/
def typedSourceValues (statement : V8PublicStatement) (witness : V8Witness) : SourceValues :=
  orderedSourceValues
    (witness.inputs.getD 0 default).note.value
    (witness.inputs.getD 1 default).note.value
    (witness.outputs.getD 0 default).note.value
    (witness.outputs.getD 1 default).note.value
    ((encodePublicStatement statement).getD 44 0)
    ((encodePublicStatement statement).getD 46 0)
    ((encodePublicStatement statement).getD 62 0)

theorem typed_input_value_bounded (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    (witness.inputs.getD slot.val default).note.value < 2 ^ 61 := by
  have input := valid.2.1.2.2.1 slot.val slot.isLt
  change _ ∧ (if (witness.inputs.getD slot.val default).active = 0 then
    ZeroInputWitness (witness.inputs.getD slot.val default) else _) at input
  split at input
  · rw [input.2.2.2.2.1.1]
    decide
  · exact input.2.1.1

theorem typed_output_value_bounded (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    (witness.outputs.getD slot.val default).note.value < 2 ^ 61 := by
  have output := valid.2.1.2.2.2.1 slot.val slot.isLt
  change _ ∧ (if (witness.outputs.getD slot.val default).active = 0 then
    ZeroOutputWitness (witness.outputs.getD slot.val default) else _) at output
  split at output
  · rw [output.2.2.1.1]
    decide
  · exact output.2.1.1

theorem typed_source_values_bounded (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ValuesBounded (typedSourceValues statement witness) := by
  have input0 := typed_input_value_bounded statement witness valid ⟨0, by decide⟩
  have input1 := typed_input_value_bounded statement witness valid ⟨1, by decide⟩
  have output0 := typed_output_value_bounded statement witness valid ⟨0, by decide⟩
  have output1 := typed_output_value_bounded statement witness valid ⟨1, by decide⟩
  have public44 := encoded_balance_scalar statement valid.1 (index := 0) (by decide)
  have public46 := encoded_balance_scalar statement valid.1 (index := 2) (by decide)
  have public62 := encoded_compatibility_scalar statement valid.1 (index := 4) (by decide)
  obtain ⟨_, _, _, _, _, _, _, _, _, _, feeBound, _, magnitudeZero, _, _,
    compatibility, _⟩ := valid.1
  have issuanceBound := compatibility.2.2.1
  intro slot
  fin_cases slot
  · exact input0
  · exact input1
  · exact output0
  · exact output1
  · change (encodePublicStatement statement).getD 44 0 < 2 ^ 61
    rw [public44]
    exact feeBound
  · change (encodePublicStatement statement).getD 46 0 < 2 ^ 61
    rw [public46]
    change statement.valueBalanceMagnitude < 2 ^ 61
    rw [magnitudeZero]
    decide
  · change (encodePublicStatement statement).getD 62 0 < 2 ^ 61
    rw [public62]
    change statement.compatibility.issuanceMagnitude < 2 ^ 61
    norm_num only [stablecoinValueBound, Nat.reducePow] at issuanceBound ⊢
    omega

theorem valid_typed_dense_cells_canonical (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness)
    (slot : Nat) :
    sourceDenseCell (typedSourceValues statement witness) slot <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus :=
  source_dense_cells_canonical _ (typed_source_values_bounded statement witness valid) slot

theorem valid_typed_dense_top_equations (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness)
    (lane : Nat) :
    let top : V8Smz9SemanticDenseRange.F :=
      sourceDenseCell (typedSourceValues statement witness) (256 + lane)
    top * (top - 1) = 0 :=
  source_dense_top_equations _ (typed_source_values_bounded statement witness valid) lane


end HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization
