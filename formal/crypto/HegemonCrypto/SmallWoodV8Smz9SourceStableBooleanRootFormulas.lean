import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoin
import HegemonCrypto.SmallWoodV8Smz9SourceTailRolesCanonical

/-! The generated stable Boolean and radix-four roots, interpreted by the actual
field-expression DAG. Root indices and descriptor kinds are checked explicitly. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableBooleanRoots

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem actual_stable_boolean_root_identity :
    exactNonlinearRoots[805]? = some 8130 ∧
    exactNonlinearIdentities[805]? =
      some ⟨1025,[805,0,0,0],"stable.boolean_row"⟩ := by decide

theorem actual_stable_radix_root_identities (slot : Fin 23) :
    exactNonlinearRoots[807 + slot.val]? = some (8138 + 6 * slot.val) ∧
    exactNonlinearIdentities[807 + slot.val]? =
      some ⟨1025,[807 + slot.val,slot.val,slot.val,0],"stable.radix4_row"⟩ := by
  have all : ∀ s : Fin 23,
      exactNonlinearRoots[807 + s.val]? = some (8138 + 6 * s.val) ∧
      exactNonlinearIdentities[807 + s.val]? =
        some ⟨1025,[807 + s.val,s.val,s.val,0],"stable.radix4_row"⟩ := by decide
  exact all slot

noncomputable section

theorem actual_stable_boolean_root_formula (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 8130 = rows 658 * (rows 658 - 1) := by
  have valid := exact_boolean_witness_roots_valid
    (⟨658,8129,8130⟩ : BooleanWitnessRoot) (by decide)
  obtain ⟨_,sourceNode,minusNode,rootNode,_⟩ := valid
  have one := actual_node_field_equation pub rows exact_nonlinear_small_constant_nodes.1
  have source := actual_node_field_equation pub rows sourceNode
  have minus := actual_node_field_equation pub rows minusNode
  have root := actual_node_field_equation pub rows rootNode
  simp only [expressionField,Nat.cast_one] at one source minus root
  rw [source,one] at minus
  rw [source,minus] at root
  exact root

theorem actual_stable_radix_four_root_formula (pub rows : Nat → F) (slot : Fin 23) :
    fieldAt exactNonlinearExpressions pub rows (8138 + 6 * slot.val) =
      rows (663 + slot.val) * (rows (663 + slot.val) - 1) *
        (rows (663 + slot.val) - 2) * (rows (663 + slot.val) - 3) := by
  obtain ⟨sourceNode,subOneNode,subTwoNode,subThreeNode,mulOneNode,mulTwoNode,rootNode,_⟩ :=
    exact_stable_radix_four_nodes slot.val slot.isLt
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
  simp only [expressionField,Nat.cast_one,Nat.cast_ofNat] at one two three source subOne subTwo subThree mulOne mulTwo root
  rw [source,one] at subOne
  rw [source,two] at subTwo
  rw [source,three] at subThree
  rw [source,subOne] at mulOne
  rw [subTwo,mulOne] at mulTwo
  rw [subThree,mulTwo] at root
  exact root.trans (by ring)

theorem boolean_word_field_equation (word : Nat) (boolean : BooleanWord word) :
    (word : F) * ((word : F) - 1) = 0 := by
  rcases boolean with rfl | rfl <;> simp

theorem radix_four_field_equation (word : Nat) (bound : word < 4) :
    (word : F) * ((word : F) - 1) * ((word : F) - 2) * ((word : F) - 3) = 0 := by
  interval_cases word <;> norm_num


end
end HegemonCrypto.SmallWood.V8Smz9SourceStableBooleanRoots
