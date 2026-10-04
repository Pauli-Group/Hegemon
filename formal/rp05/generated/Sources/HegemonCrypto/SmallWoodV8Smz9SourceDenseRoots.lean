import HegemonCrypto.SmallWoodV8Smz9SourceDenseTyped
import HegemonCrypto.SmallWoodV8Smz9SemanticAssetMembership

/-!
Forward zero evaluation of the actual generated dense nonlinear roots.
The witness is an explicit dense-block embedding. No accepted-witness,
evaluator-success, coefficient-equality, or desired-root-zero premise occurs.
This is a field interpretation of the source DAG, not extracted Rust.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SourceDenseRoots

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

noncomputable section

theorem actual_dense_radix_four_root_formula (pub rows : Nat → F)
    (slot : Nat) (slotBound : slot < 4) :
    fieldAt exactNonlinearExpressions pub rows (1183 + 6 * slot) =
      rows (247 + slot) * (rows (247 + slot) - 1) *
        (rows (247 + slot) - 2) * (rows (247 + slot) - 3) := by
  obtain ⟨sourceNode, subOneNode, subTwoNode, subThreeNode,
    mulOneNode, mulTwoNode, rootNode, _⟩ := exact_dense_radix_four_nodes slot slotBound
  have one := actual_node_field_equation pub rows exact_nonlinear_small_constant_nodes.1
  have two := actual_node_field_equation pub rows exact_nonlinear_small_constant_nodes.2.1
  have three := actual_node_field_equation pub rows exact_nonlinear_small_constant_nodes.2.2
  have source := actual_node_field_equation pub rows sourceNode
  have subOne := actual_node_field_equation pub rows subOneNode
  have subTwo := actual_node_field_equation pub rows subTwoNode
  have subThree := actual_node_field_equation pub rows subThreeNode
  have mulOne := actual_node_field_equation pub rows mulOneNode
  have mulTwo := actual_node_field_equation pub rows mulTwoNode
  have root := actual_node_field_equation pub rows rootNode
  simp only [expressionField, Nat.cast_one, Nat.cast_ofNat] at one two three source subOne subTwo subThree mulOne mulTwo root
  rw [source, one] at subOne
  rw [source, two] at subTwo
  rw [source, three] at subThree
  rw [source, subOne] at mulOne
  rw [subTwo, mulOne] at mulTwo
  rw [subThree, mulTwo] at root
  exact root.trans (by ring)

theorem actual_dense_top_root_formula (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 1203 = rows 251 * (rows 251 - 1) := by
  have valid := exact_boolean_witness_roots_valid
    (⟨251, 1202, 1203⟩ : BooleanWitnessRoot) (by decide)
  obtain ⟨_, sourceNode, minusNode, rootNode, _⟩ := valid
  have one := actual_node_field_equation pub rows exact_nonlinear_small_constant_nodes.1
  have source := actual_node_field_equation pub rows sourceNode
  have minus := actual_node_field_equation pub rows minusNode
  have root := actual_node_field_equation pub rows rootNode
  simp only [expressionField, Nat.cast_one] at one source minus root
  rw [source, one] at minus
  rw [source, minus] at root
  exact root

/-- Global lane rows read from an explicitly placed dense block. -/
def denseLaneFieldRows (before after : List Nat) (values : SourceValues)
    (lane : Fin 64) : Nat → F :=
  fun row => ((packedWitnessLaneRows (embedSourceDense before after values) lane.val).getD row 0 : F)

theorem dense_lane_field_readback (before after : List Nat) (values : SourceValues)
    (prefixLength : before.length = 15808) (row : Fin 5) (lane : Fin 64) :
    denseLaneFieldRows before after values lane (247 + row.val) =
      (sourceDenseCell values (row.val * 64 + lane.val) : F) := by
  unfold denseLaneFieldRows
  rw [source_dense_global_lane_readback before after values prefixLength row lane]
  rfl

theorem source_dense_actual_digit_root_zero (before after : List Nat)
    (values : SourceValues) (prefixLength : before.length = 15808)
    (pub : Nat → F) (lane : Fin 64) (slot : Fin 4) :
    fieldAt exactNonlinearExpressions pub (denseLaneFieldRows before after values lane)
      (1183 + 6 * slot.val) = 0 := by
  rw [actual_dense_radix_four_root_formula pub _ slot.val slot.isLt]
  have row : slot.val < 5 := by omega
  rw [dense_lane_field_readback before after values prefixLength ⟨slot.val, row⟩ lane]
  exact source_dense_digit_equations values (slot.val * 64 + lane.val) (by omega)

theorem source_dense_actual_top_root_zero (before after : List Nat)
    (values : SourceValues) (prefixLength : before.length = 15808)
    (bounded : ValuesBounded values) (pub : Nat → F) (lane : Fin 64) :
    fieldAt exactNonlinearExpressions pub (denseLaneFieldRows before after values lane)
      1203 = 0 := by
  rw [actual_dense_top_root_formula]
  have readback := dense_lane_field_readback before after values prefixLength
    (⟨4, by decide⟩ : Fin 5) lane
  change denseLaneFieldRows before after values lane 251 =
    (sourceDenseCell values (256 + lane.val) : F) at readback
  rw [readback]
  exact source_dense_top_equations values bounded lane.val

/-- All four generated low-row roots and the generated top root, in all 64 lanes. -/
theorem source_dense_all_actual_roots_zero (before after : List Nat)
    (values : SourceValues) (prefixLength : before.length = 15808)
    (bounded : ValuesBounded values) (pub : Nat → F) :
    ∀ lane : Fin 64,
      (∀ slot : Fin 4,
        fieldAt exactNonlinearExpressions pub (denseLaneFieldRows before after values lane)
          (1183 + 6 * slot.val) = 0) ∧
      fieldAt exactNonlinearExpressions pub (denseLaneFieldRows before after values lane)
        1203 = 0 := by
  intro lane
  exact ⟨fun slot => source_dense_actual_digit_root_zero before after values prefixLength pub lane slot,
    source_dense_actual_top_root_zero before after values prefixLength bounded pub lane⟩

/-- Typed semantic validity supplies input ranges; it does not assume program acceptance. -/
theorem valid_typed_dense_actual_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (before after : List Nat) (prefixLength : before.length = 15808) :
    ∀ lane : Fin 64,
      (∀ slot : Fin 4,
        fieldAt exactNonlinearExpressions
          (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (denseLaneFieldRows before after (typedSourceValues statement witness) lane)
          (1183 + 6 * slot.val) = 0) ∧
      fieldAt exactNonlinearExpressions
        (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (denseLaneFieldRows before after (typedSourceValues statement witness) lane) 1203 = 0 := by
  exact source_dense_all_actual_roots_zero before after (typedSourceValues statement witness)
    prefixLength (typed_source_values_bounded statement witness valid) _


end
end HegemonCrypto.SmallWood.V8Smz9SourceDenseRoots
