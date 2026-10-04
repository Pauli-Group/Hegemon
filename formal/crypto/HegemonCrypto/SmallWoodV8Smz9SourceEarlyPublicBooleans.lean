import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SemanticBalance

namespace HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical (boolean_getD)
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def publicBooleanIndex (slot : Nat) : Nat := [0,1,2,3,45,58,61].getD slot 0

theorem exact_public_boolean_nodes (slot : Fin 7) :
    publicBooleanIndex slot.val < 120 ∧
    exactNonlinearExpressions[810 + 2 * slot.val]? =
      some (.sub (4 + publicBooleanIndex slot.val) 1) ∧
    exactNonlinearExpressions[811 + 2 * slot.val]? =
      some (.mul (4 + publicBooleanIndex slot.val) (810 + 2 * slot.val)) ∧
    exactNonlinearRoots[slot.val]? = some (811 + 2 * slot.val) ∧
    exactNonlinearIdentities[slot.val]? =
      some ⟨1025,[slot.val,slot.val,0,0],"base.public_boolean"⟩ := by
  have finite : ∀ s : Fin 7,
      publicBooleanIndex s.val < 120 ∧
      exactNonlinearExpressions[810 + 2 * s.val]? = some (.sub (4 + publicBooleanIndex s.val) 1) ∧
      exactNonlinearExpressions[811 + 2 * s.val]? = some (.mul (4 + publicBooleanIndex s.val) (810 + 2 * s.val)) ∧
      exactNonlinearRoots[s.val]? = some (811 + 2 * s.val) ∧
      exactNonlinearIdentities[s.val]? = some ⟨1025,[s.val,s.val,0,0],"base.public_boolean"⟩ := by decide
  exact finite slot

theorem canonical_encoded_public_boolean (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) (slot : Fin 7) :
    BooleanWord ((encodePublicStatement statement).getD (publicBooleanIndex slot.val) 0) := by
  have inputs := canonical.2.2.1
  have outputs := canonical.2.2.2.1
  have publicFacts := canonical
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,sign,_,_,_,compatibility,_⟩ := publicFacts
  fin_cases slot
  · change BooleanWord ((encodePublicStatement statement).getD 0 0)
    rw [encoded_input_flag statement canonical (by decide : 0 < 2)]
    exact boolean_getD _ inputs 0
  · change BooleanWord ((encodePublicStatement statement).getD 1 0)
    rw [encoded_input_flag statement canonical (by decide : 1 < 2)]
    exact boolean_getD _ inputs 1
  · change BooleanWord ((encodePublicStatement statement).getD (2 + 0) 0)
    rw [encoded_output_flag statement canonical (by decide : 0 < 2)]
    exact boolean_getD _ outputs 0
  · change BooleanWord ((encodePublicStatement statement).getD (2 + 1) 0)
    rw [encoded_output_flag statement canonical (by decide : 1 < 2)]
    exact boolean_getD _ outputs 1
  · change BooleanWord ((encodePublicStatement statement).getD (44 + 1) 0)
    rw [encoded_balance_scalar statement canonical (by decide : 1 < 3)]
    change BooleanWord statement.valueBalanceSign
    rw [sign]
    exact Or.inl rfl
  · change BooleanWord ((encodePublicStatement statement).getD (58 + 0) 0)
    rw [encoded_compatibility_scalar statement canonical (by decide : 0 < 5)]
    exact compatibility.1
  · change BooleanWord ((encodePublicStatement statement).getD (58 + 3) 0)
    rw [encoded_compatibility_scalar statement canonical (by decide : 3 < 5)]
    exact compatibility.2.1

noncomputable section

def encodedPublicField (statement : V8PublicStatement) : Nat → F :=
  fun index => ((encodePublicStatement statement).getD index 0 : F)

theorem actual_public_boolean_root_formula (pub rows : Nat → F) (slot : Fin 7) :
    fieldAt exactNonlinearExpressions pub rows (811 + 2 * slot.val) =
      pub (publicBooleanIndex slot.val) * (pub (publicBooleanIndex slot.val) - 1) := by
  obtain ⟨bound,minusNode,rootNode,_,_⟩ := exact_public_boolean_nodes slot
  have source := actual_source_public pub rows bound
  have one := (actual_source_constants pub rows).2.1
  have minus := actual_node_field_equation pub rows minusNode
  have root := actual_node_field_equation pub rows rootNode
  simp only [expressionField] at minus root
  rw [source,one] at minus
  rw [source,minus] at root
  exact root

theorem boolean_field_zero (word : Nat) (boolean : BooleanWord word) :
    (word : F) * ((word : F) - 1) = 0 := by
  rcases boolean with rfl | rfl <;> simp

theorem full_candidate_public_boolean_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (slot : Fin 7) :
    (exactNonlinearRoots[slot.val]?).map
      (fieldAt exactNonlinearExpressions (encodedPublicField statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [(exact_public_boolean_nodes slot).2.2.2.1,Option.map_some,actual_public_boolean_root_formula]
  exact congrArg some (boolean_field_zero _ (canonical_encoded_public_boolean statement valid.1 slot))

/-- A concrete non-Boolean public input does not satisfy the actual generated root. -/
theorem public_boolean_two_negative_control (rows : Nat → F) :
    fieldAt exactNonlinearExpressions (fun _ => 2) rows 811 = 2 := by
  have formula := actual_public_boolean_root_formula (fun _ => 2) rows (⟨0,by decide⟩ : Fin 7)
  norm_num at formula ⊢
  exact formula








end
end HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
