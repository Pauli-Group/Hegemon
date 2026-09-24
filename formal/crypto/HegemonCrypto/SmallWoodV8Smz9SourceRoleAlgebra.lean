import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SemanticBalance

namespace HegemonCrypto.SmallWood.V8Smz9SourceRoleAlgebra

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (FieldExpression fieldInverse)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance (source_inverse_cast)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def firstNonzeroSeven (words : Nat → Nat) : Nat :=
  if words 0 ≠ 0 then 0 else if words 1 ≠ 0 then 1 else
  if words 2 ≠ 0 then 2 else if words 3 ≠ 0 then 3 else
  if words 4 ≠ 0 then 4 else if words 5 ≠ 0 then 5 else 6

theorem first_nonzero_bound (words : Nat → Nat) : firstNonzeroSeven words < 7 := by
  unfold firstNonzeroSeven
  split_ifs <;> decide

theorem first_nonzero_selected (words : Nat → Nat)
    (nonzero : ∃ limb : Fin 7, words limb.val ≠ 0) :
    words (firstNonzeroSeven words) ≠ 0 := by
  unfold firstNonzeroSeven
  split_ifs with h0 h1 h2 h3 h4 h5
  · exact h0
  · exact h1
  · exact h2
  · exact h3
  · exact h4
  · exact h5
  · obtain ⟨limb, present⟩ := nonzero
    have possibilities : limb.val = 0 ∨ limb.val = 1 ∨ limb.val = 2 ∨
        limb.val = 3 ∨ limb.val = 4 ∨ limb.val = 5 ∨ limb.val = 6 := by omega
    rcases possibilities with equal | equal | equal | equal | equal | equal | equal
    all_goals simp_all

theorem actual_source_selector_is_first (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (role : Nat) :
    sourceRoleSelector statement witness hashes role =
      firstNonzeroSeven (sourceRoleWord statement witness hashes role) := rfl

theorem canonical_inverse_cast (word : Nat) (canonical : word < fieldModulus) :
    (fieldInverse word : F) = (word : F)⁻¹ := by
  have value : (word : F).val = word := ZMod.val_natCast_of_lt canonical
  rw [← value, source_inverse_cast, ZMod.natCast_zmod_val]

theorem canonical_nonzero_cast (word : Nat) (canonical : word < fieldModulus)
    (nonzero : word ≠ 0) : (word : F) ≠ 0 := by
  intro zero
  exact nonzero (canonical_nat_cast_injective canonical (by decide) zero)

theorem selected_inverse_equation (words : Nat → Nat)
    (canonical : ∀ limb : Fin 7, words limb.val < fieldModulus)
    (nonzero : ∃ limb : Fin 7, words limb.val ≠ 0) :
    (fieldInverse (words (firstNonzeroSeven words)) : F) *
      (words (firstNonzeroSeven words) : F) = 1 := by
  have bound := canonical ⟨firstNonzeroSeven words, first_nonzero_bound words⟩
  rw [canonical_inverse_cast _ bound]
  exact inv_mul_cancel₀ (canonical_nonzero_cast _ bound (first_nonzero_selected words nonzero))



def roleHighExpressions : List FieldExpression :=
  [.sub 780 1,
   .mul 780 7998,
   .sub 780 2,
   .mul 7999 8000,
   .sub 780 829,
   .mul 8001 8002,
   .sub 780 1460,
   .mul 8003 8004,
   .sub 780 1463,
   .mul 8005 8006,
   .sub 780 1466,
   .mul 8007 8008,
   .sub 0 1,
   .mul 7998 8000,
   .sub 0 2,
   .mul 8010 8012,
   .mul 8002 8011,
   .sub 0 829,
   .mul 8013 8015,
   .mul 8004 8014,
   .sub 0 1460,
   .mul 8016 8018,
   .mul 8006 8017,
   .sub 0 1463,
   .mul 8019 8021,
   .mul 8008 8020,
   .sub 0 1466,
   .mul 8022 8024,
   .inverse 8025,
   .mul 8023 8026,
   .mul 773 8027,
   .mul 780 8000,
   .sub 1 2,
   .mul 8002 8029,
   .sub 1 829,
   .mul 8030 8032,
   .mul 8004 8031,
   .sub 1 1460,
   .mul 8033 8035,
   .mul 8006 8034,
   .sub 1 1463,
   .mul 8036 8038,
   .mul 8008 8037,
   .sub 1 1466,
   .mul 8039 8041,
   .inverse 8042,
   .mul 8040 8043,
   .mul 774 8044,
   .add 8028 8045,
   .sub 2 1,
   .mul 2 8047,
   .mul 7999 8002,
   .sub 2 829,
   .mul 8048 8050,
   .mul 8004 8049,
   .sub 2 1460,
   .mul 8051 8053,
   .mul 8006 8052,
   .sub 2 1463,
   .mul 8054 8056,
   .mul 8008 8055,
   .sub 2 1466,
   .mul 8057 8059,
   .inverse 8060,
   .mul 8058 8061,
   .mul 775 8062,
   .add 8046 8063,
   .sub 829 1,
   .mul 829 8065,
   .sub 829 2,
   .mul 8066 8067,
   .mul 8001 8004,
   .sub 829 1460,
   .mul 8068 8070,
   .mul 8006 8069,
   .sub 829 1463,
   .mul 8071 8073,
   .mul 8008 8072,
   .sub 829 1466,
   .mul 8074 8076,
   .inverse 8077,
   .mul 8075 8078,
   .mul 776 8079,
   .add 8064 8080,
   .sub 1460 1,
   .mul 1460 8082,
   .sub 1460 2,
   .mul 8083 8084,
   .sub 1460 829,
   .mul 8085 8086,
   .mul 8003 8006,
   .sub 1460 1463,
   .mul 8087 8089,
   .mul 8008 8088,
   .sub 1460 1466,
   .mul 8090 8092,
   .inverse 8093,
   .mul 8091 8094,
   .mul 777 8095,
   .add 8081 8096,
   .sub 1463 1,
   .mul 1463 8098,
   .sub 1463 2,
   .mul 8099 8100,
   .sub 1463 829,
   .mul 8101 8102,
   .sub 1463 1460,
   .mul 8103 8104,
   .mul 8005 8008,
   .sub 1463 1466,
   .mul 8105 8107,
   .inverse 8108,
   .mul 8106 8109,
   .mul 778 8110,
   .add 8097 8111,
   .sub 1466 1,
   .mul 1466 8113,
   .sub 1466 2,
   .mul 8114 8115,
   .sub 1466 829,
   .mul 8116 8117,
   .sub 1466 1460,
   .mul 8118 8119,
   .sub 1466 1463,
   .mul 8120 8121,
   .inverse 8122,
   .mul 8007 8123,
   .mul 779 8124,
   .add 8112 8125,
   .mul 781 8126,
   .sub 8127 1]

theorem role_high_source_exact :
    (exactNonlinearExpressions.drop 7998).take 131 = roleHighExpressions := by decide

theorem role_high_node (offset : Fin 131) :
    exactNonlinearExpressions[7998 + offset.val]? =
      some (roleHighExpressions.getD offset.val (.constant 0)) := by
  have equality := congrArg (fun program : List FieldExpression => program[offset.val]?) role_high_source_exact
  have length : roleHighExpressions.length = 131 := by decide
  have bound : offset.val < roleHighExpressions.length := by rw [length]; exact offset.isLt
  have right : roleHighExpressions[offset.val]? =
      some (roleHighExpressions.getD offset.val (.constant 0)) := by
    simp only [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem bound, Option.getD_some]
  simpa only [List.getElem?_take, if_pos offset.isLt, List.getElem?_drop] using equality.trans right

theorem actual_role_root_indices :
    exactNonlinearRoots[803]? = some 8009 ∧ exactNonlinearRoots[804]? = some 8128 := by decide

noncomputable section

def roleSelectorPolynomial (selector : F) : F :=
  ((((((selector * (selector - (1 : F))) * (selector - (2 : F))) * (selector - (3 : F))) * (selector - (4 : F))) * (selector - (5 : F))) * (selector - (6 : F)))

def roleSelectedPolynomial (selector : F) (word : Nat → F) : F :=
  ((((((((word 0) * (((selector - (6 : F)) * ((selector - (5 : F)) * ((selector - (4 : F)) * ((selector - (3 : F)) * ((selector - (1 : F)) * (selector - (2 : F))))))) * ((((((((0 : F) - (1 : F)) * ((0 : F) - (2 : F))) * ((0 : F) - (3 : F))) * ((0 : F) - (4 : F))) * ((0 : F) - (5 : F))) * ((0 : F) - (6 : F))))⁻¹)) + ((word 1) * (((selector - (6 : F)) * ((selector - (5 : F)) * ((selector - (4 : F)) * ((selector - (3 : F)) * (selector * (selector - (2 : F))))))) * (((((((1 : F) - (2 : F)) * ((1 : F) - (3 : F))) * ((1 : F) - (4 : F))) * ((1 : F) - (5 : F))) * ((1 : F) - (6 : F))))⁻¹))) + ((word 2) * (((selector - (6 : F)) * ((selector - (5 : F)) * ((selector - (4 : F)) * ((selector * (selector - (1 : F))) * (selector - (3 : F)))))) * (((((((2 : F) * ((2 : F) - (1 : F))) * ((2 : F) - (3 : F))) * ((2 : F) - (4 : F))) * ((2 : F) - (5 : F))) * ((2 : F) - (6 : F))))⁻¹))) + ((word 3) * (((selector - (6 : F)) * ((selector - (5 : F)) * (((selector * (selector - (1 : F))) * (selector - (2 : F))) * (selector - (4 : F))))) * (((((((3 : F) * ((3 : F) - (1 : F))) * ((3 : F) - (2 : F))) * ((3 : F) - (4 : F))) * ((3 : F) - (5 : F))) * ((3 : F) - (6 : F))))⁻¹))) + ((word 4) * (((selector - (6 : F)) * ((((selector * (selector - (1 : F))) * (selector - (2 : F))) * (selector - (3 : F))) * (selector - (5 : F)))) * (((((((4 : F) * ((4 : F) - (1 : F))) * ((4 : F) - (2 : F))) * ((4 : F) - (3 : F))) * ((4 : F) - (5 : F))) * ((4 : F) - (6 : F))))⁻¹))) + ((word 5) * ((((((selector * (selector - (1 : F))) * (selector - (2 : F))) * (selector - (3 : F))) * (selector - (4 : F))) * (selector - (6 : F))) * (((((((5 : F) * ((5 : F) - (1 : F))) * ((5 : F) - (2 : F))) * ((5 : F) - (3 : F))) * ((5 : F) - (4 : F))) * ((5 : F) - (6 : F))))⁻¹))) + ((word 6) * ((((((selector * (selector - (1 : F))) * (selector - (2 : F))) * (selector - (3 : F))) * (selector - (4 : F))) * (selector - (5 : F))) * (((((((6 : F) * ((6 : F) - (1 : F))) * ((6 : F) - (2 : F))) * ((6 : F) - (3 : F))) * ((6 : F) - (4 : F))) * ((6 : F) - (5 : F))))⁻¹)))

theorem actual_role_root_formulas (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 8009 = roleSelectorPolynomial (rows 656) ∧
    fieldAt exactNonlinearExpressions pub rows 8128 =
      rows 657 * roleSelectedPolynomial (rows 656) (fun limb => rows (649 + limb)) - 1 := by
  have n0 : fieldAt exactNonlinearExpressions pub rows 0 = (0 : F) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[0]? = some (.constant 0) by decide))
  have n1 : fieldAt exactNonlinearExpressions pub rows 1 = (1 : F) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[1]? = some (.constant 1) by decide))
  have n2 : fieldAt exactNonlinearExpressions pub rows 2 = (2 : F) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[2]? = some (.constant 2) by decide))
  have n773 : fieldAt exactNonlinearExpressions pub rows 773 = rows 649 := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[773]? = some (.witnessRow 649) by decide))
  have n774 : fieldAt exactNonlinearExpressions pub rows 774 = rows 650 := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[774]? = some (.witnessRow 650) by decide))
  have n775 : fieldAt exactNonlinearExpressions pub rows 775 = rows 651 := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[775]? = some (.witnessRow 651) by decide))
  have n776 : fieldAt exactNonlinearExpressions pub rows 776 = rows 652 := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[776]? = some (.witnessRow 652) by decide))
  have n777 : fieldAt exactNonlinearExpressions pub rows 777 = rows 653 := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[777]? = some (.witnessRow 653) by decide))
  have n778 : fieldAt exactNonlinearExpressions pub rows 778 = rows 654 := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[778]? = some (.witnessRow 654) by decide))
  have n779 : fieldAt exactNonlinearExpressions pub rows 779 = rows 655 := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[779]? = some (.witnessRow 655) by decide))
  have n780 : fieldAt exactNonlinearExpressions pub rows 780 = rows 656 := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[780]? = some (.witnessRow 656) by decide))
  have n781 : fieldAt exactNonlinearExpressions pub rows 781 = rows 657 := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[781]? = some (.witnessRow 657) by decide))
  have n829 : fieldAt exactNonlinearExpressions pub rows 829 = (3 : F) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[829]? = some (.constant 3) by decide))
  have n1460 : fieldAt exactNonlinearExpressions pub rows 1460 = (4 : F) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[1460]? = some (.constant 4) by decide))
  have n1463 : fieldAt exactNonlinearExpressions pub rows 1463 = (5 : F) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[1463]? = some (.constant 5) by decide))
  have n1466 : fieldAt exactNonlinearExpressions pub rows 1466 = (6 : F) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows ((show exactNonlinearExpressions[1466]? = some (.constant 6) by decide))
  have n7998 : fieldAt exactNonlinearExpressions pub rows 7998 = (fieldAt exactNonlinearExpressions pub rows 780) - (fieldAt exactNonlinearExpressions pub rows 1) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[7998]? = some (.sub 780 1) by
        simpa [roleHighExpressions] using role_high_node ⟨0, by decide⟩)
  have n7999 : fieldAt exactNonlinearExpressions pub rows 7999 = (fieldAt exactNonlinearExpressions pub rows 780) * (fieldAt exactNonlinearExpressions pub rows 7998) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[7999]? = some (.mul 780 7998) by
        simpa [roleHighExpressions] using role_high_node ⟨1, by decide⟩)
  have n8000 : fieldAt exactNonlinearExpressions pub rows 8000 = (fieldAt exactNonlinearExpressions pub rows 780) - (fieldAt exactNonlinearExpressions pub rows 2) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8000]? = some (.sub 780 2) by
        simpa [roleHighExpressions] using role_high_node ⟨2, by decide⟩)
  have n8001 : fieldAt exactNonlinearExpressions pub rows 8001 = (fieldAt exactNonlinearExpressions pub rows 7999) * (fieldAt exactNonlinearExpressions pub rows 8000) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8001]? = some (.mul 7999 8000) by
        simpa [roleHighExpressions] using role_high_node ⟨3, by decide⟩)
  have n8002 : fieldAt exactNonlinearExpressions pub rows 8002 = (fieldAt exactNonlinearExpressions pub rows 780) - (fieldAt exactNonlinearExpressions pub rows 829) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8002]? = some (.sub 780 829) by
        simpa [roleHighExpressions] using role_high_node ⟨4, by decide⟩)
  have n8003 : fieldAt exactNonlinearExpressions pub rows 8003 = (fieldAt exactNonlinearExpressions pub rows 8001) * (fieldAt exactNonlinearExpressions pub rows 8002) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8003]? = some (.mul 8001 8002) by
        simpa [roleHighExpressions] using role_high_node ⟨5, by decide⟩)
  have n8004 : fieldAt exactNonlinearExpressions pub rows 8004 = (fieldAt exactNonlinearExpressions pub rows 780) - (fieldAt exactNonlinearExpressions pub rows 1460) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8004]? = some (.sub 780 1460) by
        simpa [roleHighExpressions] using role_high_node ⟨6, by decide⟩)
  have n8005 : fieldAt exactNonlinearExpressions pub rows 8005 = (fieldAt exactNonlinearExpressions pub rows 8003) * (fieldAt exactNonlinearExpressions pub rows 8004) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8005]? = some (.mul 8003 8004) by
        simpa [roleHighExpressions] using role_high_node ⟨7, by decide⟩)
  have n8006 : fieldAt exactNonlinearExpressions pub rows 8006 = (fieldAt exactNonlinearExpressions pub rows 780) - (fieldAt exactNonlinearExpressions pub rows 1463) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8006]? = some (.sub 780 1463) by
        simpa [roleHighExpressions] using role_high_node ⟨8, by decide⟩)
  have n8007 : fieldAt exactNonlinearExpressions pub rows 8007 = (fieldAt exactNonlinearExpressions pub rows 8005) * (fieldAt exactNonlinearExpressions pub rows 8006) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8007]? = some (.mul 8005 8006) by
        simpa [roleHighExpressions] using role_high_node ⟨9, by decide⟩)
  have n8008 : fieldAt exactNonlinearExpressions pub rows 8008 = (fieldAt exactNonlinearExpressions pub rows 780) - (fieldAt exactNonlinearExpressions pub rows 1466) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8008]? = some (.sub 780 1466) by
        simpa [roleHighExpressions] using role_high_node ⟨10, by decide⟩)
  have n8009 : fieldAt exactNonlinearExpressions pub rows 8009 = (fieldAt exactNonlinearExpressions pub rows 8007) * (fieldAt exactNonlinearExpressions pub rows 8008) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8009]? = some (.mul 8007 8008) by
        simpa [roleHighExpressions] using role_high_node ⟨11, by decide⟩)
  have n8010 : fieldAt exactNonlinearExpressions pub rows 8010 = (fieldAt exactNonlinearExpressions pub rows 0) - (fieldAt exactNonlinearExpressions pub rows 1) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8010]? = some (.sub 0 1) by
        simpa [roleHighExpressions] using role_high_node ⟨12, by decide⟩)
  have n8011 : fieldAt exactNonlinearExpressions pub rows 8011 = (fieldAt exactNonlinearExpressions pub rows 7998) * (fieldAt exactNonlinearExpressions pub rows 8000) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8011]? = some (.mul 7998 8000) by
        simpa [roleHighExpressions] using role_high_node ⟨13, by decide⟩)
  have n8012 : fieldAt exactNonlinearExpressions pub rows 8012 = (fieldAt exactNonlinearExpressions pub rows 0) - (fieldAt exactNonlinearExpressions pub rows 2) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8012]? = some (.sub 0 2) by
        simpa [roleHighExpressions] using role_high_node ⟨14, by decide⟩)
  have n8013 : fieldAt exactNonlinearExpressions pub rows 8013 = (fieldAt exactNonlinearExpressions pub rows 8010) * (fieldAt exactNonlinearExpressions pub rows 8012) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8013]? = some (.mul 8010 8012) by
        simpa [roleHighExpressions] using role_high_node ⟨15, by decide⟩)
  have n8014 : fieldAt exactNonlinearExpressions pub rows 8014 = (fieldAt exactNonlinearExpressions pub rows 8002) * (fieldAt exactNonlinearExpressions pub rows 8011) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8014]? = some (.mul 8002 8011) by
        simpa [roleHighExpressions] using role_high_node ⟨16, by decide⟩)
  have n8015 : fieldAt exactNonlinearExpressions pub rows 8015 = (fieldAt exactNonlinearExpressions pub rows 0) - (fieldAt exactNonlinearExpressions pub rows 829) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8015]? = some (.sub 0 829) by
        simpa [roleHighExpressions] using role_high_node ⟨17, by decide⟩)
  have n8016 : fieldAt exactNonlinearExpressions pub rows 8016 = (fieldAt exactNonlinearExpressions pub rows 8013) * (fieldAt exactNonlinearExpressions pub rows 8015) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8016]? = some (.mul 8013 8015) by
        simpa [roleHighExpressions] using role_high_node ⟨18, by decide⟩)
  have n8017 : fieldAt exactNonlinearExpressions pub rows 8017 = (fieldAt exactNonlinearExpressions pub rows 8004) * (fieldAt exactNonlinearExpressions pub rows 8014) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8017]? = some (.mul 8004 8014) by
        simpa [roleHighExpressions] using role_high_node ⟨19, by decide⟩)
  have n8018 : fieldAt exactNonlinearExpressions pub rows 8018 = (fieldAt exactNonlinearExpressions pub rows 0) - (fieldAt exactNonlinearExpressions pub rows 1460) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8018]? = some (.sub 0 1460) by
        simpa [roleHighExpressions] using role_high_node ⟨20, by decide⟩)
  have n8019 : fieldAt exactNonlinearExpressions pub rows 8019 = (fieldAt exactNonlinearExpressions pub rows 8016) * (fieldAt exactNonlinearExpressions pub rows 8018) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8019]? = some (.mul 8016 8018) by
        simpa [roleHighExpressions] using role_high_node ⟨21, by decide⟩)
  have n8020 : fieldAt exactNonlinearExpressions pub rows 8020 = (fieldAt exactNonlinearExpressions pub rows 8006) * (fieldAt exactNonlinearExpressions pub rows 8017) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8020]? = some (.mul 8006 8017) by
        simpa [roleHighExpressions] using role_high_node ⟨22, by decide⟩)
  have n8021 : fieldAt exactNonlinearExpressions pub rows 8021 = (fieldAt exactNonlinearExpressions pub rows 0) - (fieldAt exactNonlinearExpressions pub rows 1463) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8021]? = some (.sub 0 1463) by
        simpa [roleHighExpressions] using role_high_node ⟨23, by decide⟩)
  have n8022 : fieldAt exactNonlinearExpressions pub rows 8022 = (fieldAt exactNonlinearExpressions pub rows 8019) * (fieldAt exactNonlinearExpressions pub rows 8021) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8022]? = some (.mul 8019 8021) by
        simpa [roleHighExpressions] using role_high_node ⟨24, by decide⟩)
  have n8023 : fieldAt exactNonlinearExpressions pub rows 8023 = (fieldAt exactNonlinearExpressions pub rows 8008) * (fieldAt exactNonlinearExpressions pub rows 8020) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8023]? = some (.mul 8008 8020) by
        simpa [roleHighExpressions] using role_high_node ⟨25, by decide⟩)
  have n8024 : fieldAt exactNonlinearExpressions pub rows 8024 = (fieldAt exactNonlinearExpressions pub rows 0) - (fieldAt exactNonlinearExpressions pub rows 1466) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8024]? = some (.sub 0 1466) by
        simpa [roleHighExpressions] using role_high_node ⟨26, by decide⟩)
  have n8025 : fieldAt exactNonlinearExpressions pub rows 8025 = (fieldAt exactNonlinearExpressions pub rows 8022) * (fieldAt exactNonlinearExpressions pub rows 8024) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8025]? = some (.mul 8022 8024) by
        simpa [roleHighExpressions] using role_high_node ⟨27, by decide⟩)
  have n8026 : fieldAt exactNonlinearExpressions pub rows 8026 = (fieldAt exactNonlinearExpressions pub rows 8025)⁻¹ := by
    simpa only [expressionField, source_inverse_cast] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8026]? = some (.inverse 8025) by
        simpa [roleHighExpressions] using role_high_node ⟨28, by decide⟩)
  have n8027 : fieldAt exactNonlinearExpressions pub rows 8027 = (fieldAt exactNonlinearExpressions pub rows 8023) * (fieldAt exactNonlinearExpressions pub rows 8026) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8027]? = some (.mul 8023 8026) by
        simpa [roleHighExpressions] using role_high_node ⟨29, by decide⟩)
  have n8028 : fieldAt exactNonlinearExpressions pub rows 8028 = (fieldAt exactNonlinearExpressions pub rows 773) * (fieldAt exactNonlinearExpressions pub rows 8027) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8028]? = some (.mul 773 8027) by
        simpa [roleHighExpressions] using role_high_node ⟨30, by decide⟩)
  have n8029 : fieldAt exactNonlinearExpressions pub rows 8029 = (fieldAt exactNonlinearExpressions pub rows 780) * (fieldAt exactNonlinearExpressions pub rows 8000) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8029]? = some (.mul 780 8000) by
        simpa [roleHighExpressions] using role_high_node ⟨31, by decide⟩)
  have n8030 : fieldAt exactNonlinearExpressions pub rows 8030 = (fieldAt exactNonlinearExpressions pub rows 1) - (fieldAt exactNonlinearExpressions pub rows 2) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8030]? = some (.sub 1 2) by
        simpa [roleHighExpressions] using role_high_node ⟨32, by decide⟩)
  have n8031 : fieldAt exactNonlinearExpressions pub rows 8031 = (fieldAt exactNonlinearExpressions pub rows 8002) * (fieldAt exactNonlinearExpressions pub rows 8029) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8031]? = some (.mul 8002 8029) by
        simpa [roleHighExpressions] using role_high_node ⟨33, by decide⟩)
  have n8032 : fieldAt exactNonlinearExpressions pub rows 8032 = (fieldAt exactNonlinearExpressions pub rows 1) - (fieldAt exactNonlinearExpressions pub rows 829) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8032]? = some (.sub 1 829) by
        simpa [roleHighExpressions] using role_high_node ⟨34, by decide⟩)
  have n8033 : fieldAt exactNonlinearExpressions pub rows 8033 = (fieldAt exactNonlinearExpressions pub rows 8030) * (fieldAt exactNonlinearExpressions pub rows 8032) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8033]? = some (.mul 8030 8032) by
        simpa [roleHighExpressions] using role_high_node ⟨35, by decide⟩)
  have n8034 : fieldAt exactNonlinearExpressions pub rows 8034 = (fieldAt exactNonlinearExpressions pub rows 8004) * (fieldAt exactNonlinearExpressions pub rows 8031) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8034]? = some (.mul 8004 8031) by
        simpa [roleHighExpressions] using role_high_node ⟨36, by decide⟩)
  have n8035 : fieldAt exactNonlinearExpressions pub rows 8035 = (fieldAt exactNonlinearExpressions pub rows 1) - (fieldAt exactNonlinearExpressions pub rows 1460) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8035]? = some (.sub 1 1460) by
        simpa [roleHighExpressions] using role_high_node ⟨37, by decide⟩)
  have n8036 : fieldAt exactNonlinearExpressions pub rows 8036 = (fieldAt exactNonlinearExpressions pub rows 8033) * (fieldAt exactNonlinearExpressions pub rows 8035) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8036]? = some (.mul 8033 8035) by
        simpa [roleHighExpressions] using role_high_node ⟨38, by decide⟩)
  have n8037 : fieldAt exactNonlinearExpressions pub rows 8037 = (fieldAt exactNonlinearExpressions pub rows 8006) * (fieldAt exactNonlinearExpressions pub rows 8034) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8037]? = some (.mul 8006 8034) by
        simpa [roleHighExpressions] using role_high_node ⟨39, by decide⟩)
  have n8038 : fieldAt exactNonlinearExpressions pub rows 8038 = (fieldAt exactNonlinearExpressions pub rows 1) - (fieldAt exactNonlinearExpressions pub rows 1463) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8038]? = some (.sub 1 1463) by
        simpa [roleHighExpressions] using role_high_node ⟨40, by decide⟩)
  have n8039 : fieldAt exactNonlinearExpressions pub rows 8039 = (fieldAt exactNonlinearExpressions pub rows 8036) * (fieldAt exactNonlinearExpressions pub rows 8038) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8039]? = some (.mul 8036 8038) by
        simpa [roleHighExpressions] using role_high_node ⟨41, by decide⟩)
  have n8040 : fieldAt exactNonlinearExpressions pub rows 8040 = (fieldAt exactNonlinearExpressions pub rows 8008) * (fieldAt exactNonlinearExpressions pub rows 8037) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8040]? = some (.mul 8008 8037) by
        simpa [roleHighExpressions] using role_high_node ⟨42, by decide⟩)
  have n8041 : fieldAt exactNonlinearExpressions pub rows 8041 = (fieldAt exactNonlinearExpressions pub rows 1) - (fieldAt exactNonlinearExpressions pub rows 1466) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8041]? = some (.sub 1 1466) by
        simpa [roleHighExpressions] using role_high_node ⟨43, by decide⟩)
  have n8042 : fieldAt exactNonlinearExpressions pub rows 8042 = (fieldAt exactNonlinearExpressions pub rows 8039) * (fieldAt exactNonlinearExpressions pub rows 8041) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8042]? = some (.mul 8039 8041) by
        simpa [roleHighExpressions] using role_high_node ⟨44, by decide⟩)
  have n8043 : fieldAt exactNonlinearExpressions pub rows 8043 = (fieldAt exactNonlinearExpressions pub rows 8042)⁻¹ := by
    simpa only [expressionField, source_inverse_cast] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8043]? = some (.inverse 8042) by
        simpa [roleHighExpressions] using role_high_node ⟨45, by decide⟩)
  have n8044 : fieldAt exactNonlinearExpressions pub rows 8044 = (fieldAt exactNonlinearExpressions pub rows 8040) * (fieldAt exactNonlinearExpressions pub rows 8043) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8044]? = some (.mul 8040 8043) by
        simpa [roleHighExpressions] using role_high_node ⟨46, by decide⟩)
  have n8045 : fieldAt exactNonlinearExpressions pub rows 8045 = (fieldAt exactNonlinearExpressions pub rows 774) * (fieldAt exactNonlinearExpressions pub rows 8044) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8045]? = some (.mul 774 8044) by
        simpa [roleHighExpressions] using role_high_node ⟨47, by decide⟩)
  have n8046 : fieldAt exactNonlinearExpressions pub rows 8046 = (fieldAt exactNonlinearExpressions pub rows 8028) + (fieldAt exactNonlinearExpressions pub rows 8045) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8046]? = some (.add 8028 8045) by
        simpa [roleHighExpressions] using role_high_node ⟨48, by decide⟩)
  have n8047 : fieldAt exactNonlinearExpressions pub rows 8047 = (fieldAt exactNonlinearExpressions pub rows 2) - (fieldAt exactNonlinearExpressions pub rows 1) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8047]? = some (.sub 2 1) by
        simpa [roleHighExpressions] using role_high_node ⟨49, by decide⟩)
  have n8048 : fieldAt exactNonlinearExpressions pub rows 8048 = (fieldAt exactNonlinearExpressions pub rows 2) * (fieldAt exactNonlinearExpressions pub rows 8047) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8048]? = some (.mul 2 8047) by
        simpa [roleHighExpressions] using role_high_node ⟨50, by decide⟩)
  have n8049 : fieldAt exactNonlinearExpressions pub rows 8049 = (fieldAt exactNonlinearExpressions pub rows 7999) * (fieldAt exactNonlinearExpressions pub rows 8002) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8049]? = some (.mul 7999 8002) by
        simpa [roleHighExpressions] using role_high_node ⟨51, by decide⟩)
  have n8050 : fieldAt exactNonlinearExpressions pub rows 8050 = (fieldAt exactNonlinearExpressions pub rows 2) - (fieldAt exactNonlinearExpressions pub rows 829) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8050]? = some (.sub 2 829) by
        simpa [roleHighExpressions] using role_high_node ⟨52, by decide⟩)
  have n8051 : fieldAt exactNonlinearExpressions pub rows 8051 = (fieldAt exactNonlinearExpressions pub rows 8048) * (fieldAt exactNonlinearExpressions pub rows 8050) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8051]? = some (.mul 8048 8050) by
        simpa [roleHighExpressions] using role_high_node ⟨53, by decide⟩)
  have n8052 : fieldAt exactNonlinearExpressions pub rows 8052 = (fieldAt exactNonlinearExpressions pub rows 8004) * (fieldAt exactNonlinearExpressions pub rows 8049) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8052]? = some (.mul 8004 8049) by
        simpa [roleHighExpressions] using role_high_node ⟨54, by decide⟩)
  have n8053 : fieldAt exactNonlinearExpressions pub rows 8053 = (fieldAt exactNonlinearExpressions pub rows 2) - (fieldAt exactNonlinearExpressions pub rows 1460) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8053]? = some (.sub 2 1460) by
        simpa [roleHighExpressions] using role_high_node ⟨55, by decide⟩)
  have n8054 : fieldAt exactNonlinearExpressions pub rows 8054 = (fieldAt exactNonlinearExpressions pub rows 8051) * (fieldAt exactNonlinearExpressions pub rows 8053) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8054]? = some (.mul 8051 8053) by
        simpa [roleHighExpressions] using role_high_node ⟨56, by decide⟩)
  have n8055 : fieldAt exactNonlinearExpressions pub rows 8055 = (fieldAt exactNonlinearExpressions pub rows 8006) * (fieldAt exactNonlinearExpressions pub rows 8052) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8055]? = some (.mul 8006 8052) by
        simpa [roleHighExpressions] using role_high_node ⟨57, by decide⟩)
  have n8056 : fieldAt exactNonlinearExpressions pub rows 8056 = (fieldAt exactNonlinearExpressions pub rows 2) - (fieldAt exactNonlinearExpressions pub rows 1463) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8056]? = some (.sub 2 1463) by
        simpa [roleHighExpressions] using role_high_node ⟨58, by decide⟩)
  have n8057 : fieldAt exactNonlinearExpressions pub rows 8057 = (fieldAt exactNonlinearExpressions pub rows 8054) * (fieldAt exactNonlinearExpressions pub rows 8056) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8057]? = some (.mul 8054 8056) by
        simpa [roleHighExpressions] using role_high_node ⟨59, by decide⟩)
  have n8058 : fieldAt exactNonlinearExpressions pub rows 8058 = (fieldAt exactNonlinearExpressions pub rows 8008) * (fieldAt exactNonlinearExpressions pub rows 8055) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8058]? = some (.mul 8008 8055) by
        simpa [roleHighExpressions] using role_high_node ⟨60, by decide⟩)
  have n8059 : fieldAt exactNonlinearExpressions pub rows 8059 = (fieldAt exactNonlinearExpressions pub rows 2) - (fieldAt exactNonlinearExpressions pub rows 1466) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8059]? = some (.sub 2 1466) by
        simpa [roleHighExpressions] using role_high_node ⟨61, by decide⟩)
  have n8060 : fieldAt exactNonlinearExpressions pub rows 8060 = (fieldAt exactNonlinearExpressions pub rows 8057) * (fieldAt exactNonlinearExpressions pub rows 8059) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8060]? = some (.mul 8057 8059) by
        simpa [roleHighExpressions] using role_high_node ⟨62, by decide⟩)
  have n8061 : fieldAt exactNonlinearExpressions pub rows 8061 = (fieldAt exactNonlinearExpressions pub rows 8060)⁻¹ := by
    simpa only [expressionField, source_inverse_cast] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8061]? = some (.inverse 8060) by
        simpa [roleHighExpressions] using role_high_node ⟨63, by decide⟩)
  have n8062 : fieldAt exactNonlinearExpressions pub rows 8062 = (fieldAt exactNonlinearExpressions pub rows 8058) * (fieldAt exactNonlinearExpressions pub rows 8061) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8062]? = some (.mul 8058 8061) by
        simpa [roleHighExpressions] using role_high_node ⟨64, by decide⟩)
  have n8063 : fieldAt exactNonlinearExpressions pub rows 8063 = (fieldAt exactNonlinearExpressions pub rows 775) * (fieldAt exactNonlinearExpressions pub rows 8062) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8063]? = some (.mul 775 8062) by
        simpa [roleHighExpressions] using role_high_node ⟨65, by decide⟩)
  have n8064 : fieldAt exactNonlinearExpressions pub rows 8064 = (fieldAt exactNonlinearExpressions pub rows 8046) + (fieldAt exactNonlinearExpressions pub rows 8063) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8064]? = some (.add 8046 8063) by
        simpa [roleHighExpressions] using role_high_node ⟨66, by decide⟩)
  have n8065 : fieldAt exactNonlinearExpressions pub rows 8065 = (fieldAt exactNonlinearExpressions pub rows 829) - (fieldAt exactNonlinearExpressions pub rows 1) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8065]? = some (.sub 829 1) by
        simpa [roleHighExpressions] using role_high_node ⟨67, by decide⟩)
  have n8066 : fieldAt exactNonlinearExpressions pub rows 8066 = (fieldAt exactNonlinearExpressions pub rows 829) * (fieldAt exactNonlinearExpressions pub rows 8065) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8066]? = some (.mul 829 8065) by
        simpa [roleHighExpressions] using role_high_node ⟨68, by decide⟩)
  have n8067 : fieldAt exactNonlinearExpressions pub rows 8067 = (fieldAt exactNonlinearExpressions pub rows 829) - (fieldAt exactNonlinearExpressions pub rows 2) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8067]? = some (.sub 829 2) by
        simpa [roleHighExpressions] using role_high_node ⟨69, by decide⟩)
  have n8068 : fieldAt exactNonlinearExpressions pub rows 8068 = (fieldAt exactNonlinearExpressions pub rows 8066) * (fieldAt exactNonlinearExpressions pub rows 8067) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8068]? = some (.mul 8066 8067) by
        simpa [roleHighExpressions] using role_high_node ⟨70, by decide⟩)
  have n8069 : fieldAt exactNonlinearExpressions pub rows 8069 = (fieldAt exactNonlinearExpressions pub rows 8001) * (fieldAt exactNonlinearExpressions pub rows 8004) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8069]? = some (.mul 8001 8004) by
        simpa [roleHighExpressions] using role_high_node ⟨71, by decide⟩)
  have n8070 : fieldAt exactNonlinearExpressions pub rows 8070 = (fieldAt exactNonlinearExpressions pub rows 829) - (fieldAt exactNonlinearExpressions pub rows 1460) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8070]? = some (.sub 829 1460) by
        simpa [roleHighExpressions] using role_high_node ⟨72, by decide⟩)
  have n8071 : fieldAt exactNonlinearExpressions pub rows 8071 = (fieldAt exactNonlinearExpressions pub rows 8068) * (fieldAt exactNonlinearExpressions pub rows 8070) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8071]? = some (.mul 8068 8070) by
        simpa [roleHighExpressions] using role_high_node ⟨73, by decide⟩)
  have n8072 : fieldAt exactNonlinearExpressions pub rows 8072 = (fieldAt exactNonlinearExpressions pub rows 8006) * (fieldAt exactNonlinearExpressions pub rows 8069) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8072]? = some (.mul 8006 8069) by
        simpa [roleHighExpressions] using role_high_node ⟨74, by decide⟩)
  have n8073 : fieldAt exactNonlinearExpressions pub rows 8073 = (fieldAt exactNonlinearExpressions pub rows 829) - (fieldAt exactNonlinearExpressions pub rows 1463) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8073]? = some (.sub 829 1463) by
        simpa [roleHighExpressions] using role_high_node ⟨75, by decide⟩)
  have n8074 : fieldAt exactNonlinearExpressions pub rows 8074 = (fieldAt exactNonlinearExpressions pub rows 8071) * (fieldAt exactNonlinearExpressions pub rows 8073) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8074]? = some (.mul 8071 8073) by
        simpa [roleHighExpressions] using role_high_node ⟨76, by decide⟩)
  have n8075 : fieldAt exactNonlinearExpressions pub rows 8075 = (fieldAt exactNonlinearExpressions pub rows 8008) * (fieldAt exactNonlinearExpressions pub rows 8072) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8075]? = some (.mul 8008 8072) by
        simpa [roleHighExpressions] using role_high_node ⟨77, by decide⟩)
  have n8076 : fieldAt exactNonlinearExpressions pub rows 8076 = (fieldAt exactNonlinearExpressions pub rows 829) - (fieldAt exactNonlinearExpressions pub rows 1466) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8076]? = some (.sub 829 1466) by
        simpa [roleHighExpressions] using role_high_node ⟨78, by decide⟩)
  have n8077 : fieldAt exactNonlinearExpressions pub rows 8077 = (fieldAt exactNonlinearExpressions pub rows 8074) * (fieldAt exactNonlinearExpressions pub rows 8076) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8077]? = some (.mul 8074 8076) by
        simpa [roleHighExpressions] using role_high_node ⟨79, by decide⟩)
  have n8078 : fieldAt exactNonlinearExpressions pub rows 8078 = (fieldAt exactNonlinearExpressions pub rows 8077)⁻¹ := by
    simpa only [expressionField, source_inverse_cast] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8078]? = some (.inverse 8077) by
        simpa [roleHighExpressions] using role_high_node ⟨80, by decide⟩)
  have n8079 : fieldAt exactNonlinearExpressions pub rows 8079 = (fieldAt exactNonlinearExpressions pub rows 8075) * (fieldAt exactNonlinearExpressions pub rows 8078) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8079]? = some (.mul 8075 8078) by
        simpa [roleHighExpressions] using role_high_node ⟨81, by decide⟩)
  have n8080 : fieldAt exactNonlinearExpressions pub rows 8080 = (fieldAt exactNonlinearExpressions pub rows 776) * (fieldAt exactNonlinearExpressions pub rows 8079) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8080]? = some (.mul 776 8079) by
        simpa [roleHighExpressions] using role_high_node ⟨82, by decide⟩)
  have n8081 : fieldAt exactNonlinearExpressions pub rows 8081 = (fieldAt exactNonlinearExpressions pub rows 8064) + (fieldAt exactNonlinearExpressions pub rows 8080) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8081]? = some (.add 8064 8080) by
        simpa [roleHighExpressions] using role_high_node ⟨83, by decide⟩)
  have n8082 : fieldAt exactNonlinearExpressions pub rows 8082 = (fieldAt exactNonlinearExpressions pub rows 1460) - (fieldAt exactNonlinearExpressions pub rows 1) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8082]? = some (.sub 1460 1) by
        simpa [roleHighExpressions] using role_high_node ⟨84, by decide⟩)
  have n8083 : fieldAt exactNonlinearExpressions pub rows 8083 = (fieldAt exactNonlinearExpressions pub rows 1460) * (fieldAt exactNonlinearExpressions pub rows 8082) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8083]? = some (.mul 1460 8082) by
        simpa [roleHighExpressions] using role_high_node ⟨85, by decide⟩)
  have n8084 : fieldAt exactNonlinearExpressions pub rows 8084 = (fieldAt exactNonlinearExpressions pub rows 1460) - (fieldAt exactNonlinearExpressions pub rows 2) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8084]? = some (.sub 1460 2) by
        simpa [roleHighExpressions] using role_high_node ⟨86, by decide⟩)
  have n8085 : fieldAt exactNonlinearExpressions pub rows 8085 = (fieldAt exactNonlinearExpressions pub rows 8083) * (fieldAt exactNonlinearExpressions pub rows 8084) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8085]? = some (.mul 8083 8084) by
        simpa [roleHighExpressions] using role_high_node ⟨87, by decide⟩)
  have n8086 : fieldAt exactNonlinearExpressions pub rows 8086 = (fieldAt exactNonlinearExpressions pub rows 1460) - (fieldAt exactNonlinearExpressions pub rows 829) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8086]? = some (.sub 1460 829) by
        simpa [roleHighExpressions] using role_high_node ⟨88, by decide⟩)
  have n8087 : fieldAt exactNonlinearExpressions pub rows 8087 = (fieldAt exactNonlinearExpressions pub rows 8085) * (fieldAt exactNonlinearExpressions pub rows 8086) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8087]? = some (.mul 8085 8086) by
        simpa [roleHighExpressions] using role_high_node ⟨89, by decide⟩)
  have n8088 : fieldAt exactNonlinearExpressions pub rows 8088 = (fieldAt exactNonlinearExpressions pub rows 8003) * (fieldAt exactNonlinearExpressions pub rows 8006) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8088]? = some (.mul 8003 8006) by
        simpa [roleHighExpressions] using role_high_node ⟨90, by decide⟩)
  have n8089 : fieldAt exactNonlinearExpressions pub rows 8089 = (fieldAt exactNonlinearExpressions pub rows 1460) - (fieldAt exactNonlinearExpressions pub rows 1463) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8089]? = some (.sub 1460 1463) by
        simpa [roleHighExpressions] using role_high_node ⟨91, by decide⟩)
  have n8090 : fieldAt exactNonlinearExpressions pub rows 8090 = (fieldAt exactNonlinearExpressions pub rows 8087) * (fieldAt exactNonlinearExpressions pub rows 8089) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8090]? = some (.mul 8087 8089) by
        simpa [roleHighExpressions] using role_high_node ⟨92, by decide⟩)
  have n8091 : fieldAt exactNonlinearExpressions pub rows 8091 = (fieldAt exactNonlinearExpressions pub rows 8008) * (fieldAt exactNonlinearExpressions pub rows 8088) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8091]? = some (.mul 8008 8088) by
        simpa [roleHighExpressions] using role_high_node ⟨93, by decide⟩)
  have n8092 : fieldAt exactNonlinearExpressions pub rows 8092 = (fieldAt exactNonlinearExpressions pub rows 1460) - (fieldAt exactNonlinearExpressions pub rows 1466) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8092]? = some (.sub 1460 1466) by
        simpa [roleHighExpressions] using role_high_node ⟨94, by decide⟩)
  have n8093 : fieldAt exactNonlinearExpressions pub rows 8093 = (fieldAt exactNonlinearExpressions pub rows 8090) * (fieldAt exactNonlinearExpressions pub rows 8092) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8093]? = some (.mul 8090 8092) by
        simpa [roleHighExpressions] using role_high_node ⟨95, by decide⟩)
  have n8094 : fieldAt exactNonlinearExpressions pub rows 8094 = (fieldAt exactNonlinearExpressions pub rows 8093)⁻¹ := by
    simpa only [expressionField, source_inverse_cast] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8094]? = some (.inverse 8093) by
        simpa [roleHighExpressions] using role_high_node ⟨96, by decide⟩)
  have n8095 : fieldAt exactNonlinearExpressions pub rows 8095 = (fieldAt exactNonlinearExpressions pub rows 8091) * (fieldAt exactNonlinearExpressions pub rows 8094) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8095]? = some (.mul 8091 8094) by
        simpa [roleHighExpressions] using role_high_node ⟨97, by decide⟩)
  have n8096 : fieldAt exactNonlinearExpressions pub rows 8096 = (fieldAt exactNonlinearExpressions pub rows 777) * (fieldAt exactNonlinearExpressions pub rows 8095) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8096]? = some (.mul 777 8095) by
        simpa [roleHighExpressions] using role_high_node ⟨98, by decide⟩)
  have n8097 : fieldAt exactNonlinearExpressions pub rows 8097 = (fieldAt exactNonlinearExpressions pub rows 8081) + (fieldAt exactNonlinearExpressions pub rows 8096) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8097]? = some (.add 8081 8096) by
        simpa [roleHighExpressions] using role_high_node ⟨99, by decide⟩)
  have n8098 : fieldAt exactNonlinearExpressions pub rows 8098 = (fieldAt exactNonlinearExpressions pub rows 1463) - (fieldAt exactNonlinearExpressions pub rows 1) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8098]? = some (.sub 1463 1) by
        simpa [roleHighExpressions] using role_high_node ⟨100, by decide⟩)
  have n8099 : fieldAt exactNonlinearExpressions pub rows 8099 = (fieldAt exactNonlinearExpressions pub rows 1463) * (fieldAt exactNonlinearExpressions pub rows 8098) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8099]? = some (.mul 1463 8098) by
        simpa [roleHighExpressions] using role_high_node ⟨101, by decide⟩)
  have n8100 : fieldAt exactNonlinearExpressions pub rows 8100 = (fieldAt exactNonlinearExpressions pub rows 1463) - (fieldAt exactNonlinearExpressions pub rows 2) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8100]? = some (.sub 1463 2) by
        simpa [roleHighExpressions] using role_high_node ⟨102, by decide⟩)
  have n8101 : fieldAt exactNonlinearExpressions pub rows 8101 = (fieldAt exactNonlinearExpressions pub rows 8099) * (fieldAt exactNonlinearExpressions pub rows 8100) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8101]? = some (.mul 8099 8100) by
        simpa [roleHighExpressions] using role_high_node ⟨103, by decide⟩)
  have n8102 : fieldAt exactNonlinearExpressions pub rows 8102 = (fieldAt exactNonlinearExpressions pub rows 1463) - (fieldAt exactNonlinearExpressions pub rows 829) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8102]? = some (.sub 1463 829) by
        simpa [roleHighExpressions] using role_high_node ⟨104, by decide⟩)
  have n8103 : fieldAt exactNonlinearExpressions pub rows 8103 = (fieldAt exactNonlinearExpressions pub rows 8101) * (fieldAt exactNonlinearExpressions pub rows 8102) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8103]? = some (.mul 8101 8102) by
        simpa [roleHighExpressions] using role_high_node ⟨105, by decide⟩)
  have n8104 : fieldAt exactNonlinearExpressions pub rows 8104 = (fieldAt exactNonlinearExpressions pub rows 1463) - (fieldAt exactNonlinearExpressions pub rows 1460) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8104]? = some (.sub 1463 1460) by
        simpa [roleHighExpressions] using role_high_node ⟨106, by decide⟩)
  have n8105 : fieldAt exactNonlinearExpressions pub rows 8105 = (fieldAt exactNonlinearExpressions pub rows 8103) * (fieldAt exactNonlinearExpressions pub rows 8104) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8105]? = some (.mul 8103 8104) by
        simpa [roleHighExpressions] using role_high_node ⟨107, by decide⟩)
  have n8106 : fieldAt exactNonlinearExpressions pub rows 8106 = (fieldAt exactNonlinearExpressions pub rows 8005) * (fieldAt exactNonlinearExpressions pub rows 8008) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8106]? = some (.mul 8005 8008) by
        simpa [roleHighExpressions] using role_high_node ⟨108, by decide⟩)
  have n8107 : fieldAt exactNonlinearExpressions pub rows 8107 = (fieldAt exactNonlinearExpressions pub rows 1463) - (fieldAt exactNonlinearExpressions pub rows 1466) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8107]? = some (.sub 1463 1466) by
        simpa [roleHighExpressions] using role_high_node ⟨109, by decide⟩)
  have n8108 : fieldAt exactNonlinearExpressions pub rows 8108 = (fieldAt exactNonlinearExpressions pub rows 8105) * (fieldAt exactNonlinearExpressions pub rows 8107) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8108]? = some (.mul 8105 8107) by
        simpa [roleHighExpressions] using role_high_node ⟨110, by decide⟩)
  have n8109 : fieldAt exactNonlinearExpressions pub rows 8109 = (fieldAt exactNonlinearExpressions pub rows 8108)⁻¹ := by
    simpa only [expressionField, source_inverse_cast] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8109]? = some (.inverse 8108) by
        simpa [roleHighExpressions] using role_high_node ⟨111, by decide⟩)
  have n8110 : fieldAt exactNonlinearExpressions pub rows 8110 = (fieldAt exactNonlinearExpressions pub rows 8106) * (fieldAt exactNonlinearExpressions pub rows 8109) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8110]? = some (.mul 8106 8109) by
        simpa [roleHighExpressions] using role_high_node ⟨112, by decide⟩)
  have n8111 : fieldAt exactNonlinearExpressions pub rows 8111 = (fieldAt exactNonlinearExpressions pub rows 778) * (fieldAt exactNonlinearExpressions pub rows 8110) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8111]? = some (.mul 778 8110) by
        simpa [roleHighExpressions] using role_high_node ⟨113, by decide⟩)
  have n8112 : fieldAt exactNonlinearExpressions pub rows 8112 = (fieldAt exactNonlinearExpressions pub rows 8097) + (fieldAt exactNonlinearExpressions pub rows 8111) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8112]? = some (.add 8097 8111) by
        simpa [roleHighExpressions] using role_high_node ⟨114, by decide⟩)
  have n8113 : fieldAt exactNonlinearExpressions pub rows 8113 = (fieldAt exactNonlinearExpressions pub rows 1466) - (fieldAt exactNonlinearExpressions pub rows 1) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8113]? = some (.sub 1466 1) by
        simpa [roleHighExpressions] using role_high_node ⟨115, by decide⟩)
  have n8114 : fieldAt exactNonlinearExpressions pub rows 8114 = (fieldAt exactNonlinearExpressions pub rows 1466) * (fieldAt exactNonlinearExpressions pub rows 8113) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8114]? = some (.mul 1466 8113) by
        simpa [roleHighExpressions] using role_high_node ⟨116, by decide⟩)
  have n8115 : fieldAt exactNonlinearExpressions pub rows 8115 = (fieldAt exactNonlinearExpressions pub rows 1466) - (fieldAt exactNonlinearExpressions pub rows 2) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8115]? = some (.sub 1466 2) by
        simpa [roleHighExpressions] using role_high_node ⟨117, by decide⟩)
  have n8116 : fieldAt exactNonlinearExpressions pub rows 8116 = (fieldAt exactNonlinearExpressions pub rows 8114) * (fieldAt exactNonlinearExpressions pub rows 8115) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8116]? = some (.mul 8114 8115) by
        simpa [roleHighExpressions] using role_high_node ⟨118, by decide⟩)
  have n8117 : fieldAt exactNonlinearExpressions pub rows 8117 = (fieldAt exactNonlinearExpressions pub rows 1466) - (fieldAt exactNonlinearExpressions pub rows 829) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8117]? = some (.sub 1466 829) by
        simpa [roleHighExpressions] using role_high_node ⟨119, by decide⟩)
  have n8118 : fieldAt exactNonlinearExpressions pub rows 8118 = (fieldAt exactNonlinearExpressions pub rows 8116) * (fieldAt exactNonlinearExpressions pub rows 8117) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8118]? = some (.mul 8116 8117) by
        simpa [roleHighExpressions] using role_high_node ⟨120, by decide⟩)
  have n8119 : fieldAt exactNonlinearExpressions pub rows 8119 = (fieldAt exactNonlinearExpressions pub rows 1466) - (fieldAt exactNonlinearExpressions pub rows 1460) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8119]? = some (.sub 1466 1460) by
        simpa [roleHighExpressions] using role_high_node ⟨121, by decide⟩)
  have n8120 : fieldAt exactNonlinearExpressions pub rows 8120 = (fieldAt exactNonlinearExpressions pub rows 8118) * (fieldAt exactNonlinearExpressions pub rows 8119) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8120]? = some (.mul 8118 8119) by
        simpa [roleHighExpressions] using role_high_node ⟨122, by decide⟩)
  have n8121 : fieldAt exactNonlinearExpressions pub rows 8121 = (fieldAt exactNonlinearExpressions pub rows 1466) - (fieldAt exactNonlinearExpressions pub rows 1463) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8121]? = some (.sub 1466 1463) by
        simpa [roleHighExpressions] using role_high_node ⟨123, by decide⟩)
  have n8122 : fieldAt exactNonlinearExpressions pub rows 8122 = (fieldAt exactNonlinearExpressions pub rows 8120) * (fieldAt exactNonlinearExpressions pub rows 8121) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8122]? = some (.mul 8120 8121) by
        simpa [roleHighExpressions] using role_high_node ⟨124, by decide⟩)
  have n8123 : fieldAt exactNonlinearExpressions pub rows 8123 = (fieldAt exactNonlinearExpressions pub rows 8122)⁻¹ := by
    simpa only [expressionField, source_inverse_cast] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8123]? = some (.inverse 8122) by
        simpa [roleHighExpressions] using role_high_node ⟨125, by decide⟩)
  have n8124 : fieldAt exactNonlinearExpressions pub rows 8124 = (fieldAt exactNonlinearExpressions pub rows 8007) * (fieldAt exactNonlinearExpressions pub rows 8123) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8124]? = some (.mul 8007 8123) by
        simpa [roleHighExpressions] using role_high_node ⟨126, by decide⟩)
  have n8125 : fieldAt exactNonlinearExpressions pub rows 8125 = (fieldAt exactNonlinearExpressions pub rows 779) * (fieldAt exactNonlinearExpressions pub rows 8124) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8125]? = some (.mul 779 8124) by
        simpa [roleHighExpressions] using role_high_node ⟨127, by decide⟩)
  have n8126 : fieldAt exactNonlinearExpressions pub rows 8126 = (fieldAt exactNonlinearExpressions pub rows 8112) + (fieldAt exactNonlinearExpressions pub rows 8125) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8126]? = some (.add 8112 8125) by
        simpa [roleHighExpressions] using role_high_node ⟨128, by decide⟩)
  have n8127 : fieldAt exactNonlinearExpressions pub rows 8127 = (fieldAt exactNonlinearExpressions pub rows 781) * (fieldAt exactNonlinearExpressions pub rows 8126) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8127]? = some (.mul 781 8126) by
        simpa [roleHighExpressions] using role_high_node ⟨129, by decide⟩)
  have n8128 : fieldAt exactNonlinearExpressions pub rows 8128 = (fieldAt exactNonlinearExpressions pub rows 8127) - (fieldAt exactNonlinearExpressions pub rows 1) := by
    simpa only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8128]? = some (.sub 8127 1) by
        simpa [roleHighExpressions] using role_high_node ⟨130, by decide⟩)
  constructor <;> simp only [roleSelectorPolynomial, roleSelectedPolynomial,
    n0, n1, n2, n773, n774, n775, n776, n777, n778, n779, n780, n781, n829, n1460, n1463, n1466, n7998, n7999, n8000, n8001, n8002, n8003, n8004, n8005, n8006, n8007, n8008, n8009, n8010, n8011, n8012, n8013, n8014, n8015, n8016, n8017, n8018, n8019, n8020, n8021, n8022, n8023, n8024, n8025, n8026, n8027, n8028, n8029, n8030, n8031, n8032, n8033, n8034, n8035, n8036, n8037, n8038, n8039, n8040, n8041, n8042, n8043, n8044, n8045, n8046, n8047, n8048, n8049, n8050, n8051, n8052, n8053, n8054, n8055, n8056, n8057, n8058, n8059, n8060, n8061, n8062, n8063, n8064, n8065, n8066, n8067, n8068, n8069, n8070, n8071, n8072, n8073, n8074, n8075, n8076, n8077, n8078, n8079, n8080, n8081, n8082, n8083, n8084, n8085, n8086, n8087, n8088, n8089, n8090, n8091, n8092, n8093, n8094, n8095, n8096, n8097, n8098, n8099, n8100, n8101, n8102, n8103, n8104, n8105, n8106, n8107, n8108, n8109, n8110, n8111, n8112, n8113, n8114, n8115, n8116, n8117, n8118, n8119, n8120, n8121, n8122, n8123, n8124, n8125, n8126, n8127, n8128]

theorem selector_polynomial_zero (selected : Fin 7) :
    roleSelectorPolynomial (selected.val : F) = 0 := by
  fin_cases selected <;> norm_num [roleSelectorPolynomial]

theorem selection_polynomial_readback (selected : Fin 7) (word : Nat → F) :
    roleSelectedPolynomial (selected.val : F) word = word selected.val := by
  have n36 : (36 : F) ≠ 0 := canonical_nonzero_cast 36 (by decide) (by decide)
  have n48 : (48 : F) ≠ 0 := canonical_nonzero_cast 48 (by decide) (by decide)
  have n120 : (120 : F) ≠ 0 := canonical_nonzero_cast 120 (by decide) (by decide)
  have n720 : (720 : F) ≠ 0 := canonical_nonzero_cast 720 (by decide) (by decide)
  fin_cases selected <;> norm_num [roleSelectedPolynomial]
  all_goals simp only [mul_inv_cancel₀ n36, mul_inv_cancel₀ n48,
    mul_inv_cancel₀ n120, mul_inv_cancel₀ n720, mul_one]

end


end HegemonCrypto.SmallWood.V8Smz9SourceRoleAlgebra
