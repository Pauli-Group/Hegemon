import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness
import HegemonCrypto.SmallWoodV8Smz9SemanticInterpolation
import Mathlib.FieldTheory.Finite.Basic

/-!
Derive the unchanged integer per-asset balance semantics from the actual four
HGV8RP03 balance roots. Source interpolation weights must be proved to select
the admitted, distinct, nonpadding public assets; field equality is then lifted
using independently proved 61-bit bounds. No balance hypothesis is introduced.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticBalance

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (FieldExpression fieldInverse fieldNormalize)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
  (AssetRoot assetRootAt assetRoots asset_root_at_valid assetFactor actual_node_field_equation
    admitted_public_lengths encoded_balance_asset admitted_input_flag_one admitted_output_flag_one)
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
  (admitted_public_input_flag admitted_public_output_flag)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
  (fieldAt expressionField fieldAt_refines_source canonical_getD)
open HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem source_inverse_cast (value : F) : (fieldInverse value.val : F) = value⁻¹ := by
  have normalized : fieldNormalize value.val = value.val := by
    exact Nat.mod_eq_of_lt value.val_lt
  by_cases zero : value = 0
  · subst value
    simp [fieldInverse, fieldNormalize]
  · have valNonzero : value.val ≠ 0 := by
      intro valZero
      apply zero
      rw [← ZMod.natCast_zmod_val value, valZero]
      rfl
    rw [fieldInverse, normalized, if_neg valNonzero]
    have castPower : (fieldNormalize
          (value.val ^ (Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus - 2)) : F) =
        value ^ (Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus - 2) := by
      change (((value.val ^
          (Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus - 2)) %
          Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus : Nat) : F) = _
      simp only [ZMod.natCast_mod, Nat.cast_pow, ZMod.natCast_zmod_val]
    rw [castPower]
    apply mul_right_cancel₀ zero
    rw [inv_mul_cancel₀ zero, ← pow_succ]
    have exponent : Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus - 2 + 1 =
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus - 1 := by decide
    rw [exponent]
    exact ZMod.pow_card_sub_one_eq_one zero

def otherSlots (slot : Nat) : List Nat :=
  [[1, 2, 3], [0, 2, 3], [0, 1, 3], [0, 1, 2]].getD slot []

def interpolationTriple (pub : Nat → F) (slot : Nat) (asset : F) : F :=
  (assetFactor asset (pub (54 + (otherSlots slot).getD 0 0)) *
    assetFactor asset (pub (54 + (otherSlots slot).getD 1 0))) *
    assetFactor asset (pub (54 + (otherSlots slot).getD 2 0))

def sourceWeight (pub : Nat → F) (slot : Nat) (asset : F) : F :=
  if pub (54 + slot) = (balancePaddingAssetId : F) then 0
  else interpolationTriple pub slot asset * (interpolationTriple pub slot (pub (54 + slot)))⁻¹

def sortedMulExpression (left right : Nat) : FieldExpression :=
  .mul (min left right) (max left right)

theorem actual_sorted_mul (pub rows : Nat → F) {node left right : Nat}
    (found : exactNonlinearExpressions[node]? = some (sortedMulExpression left right)) :
    fieldAt exactNonlinearExpressions pub rows node =
      fieldAt exactNonlinearExpressions pub rows left *
        fieldAt exactNonlinearExpressions pub rows right := by
  have equation := actual_node_field_equation pub rows found
  rcases le_total left right with ordered | ordered
  · simpa only [sortedMulExpression, Nat.min_eq_left ordered, Nat.max_eq_right ordered,
      expressionField] using equation
  · simpa only [sortedMulExpression, Nat.min_eq_right ordered, Nat.max_eq_left ordered,
      expressionField, mul_comm] using equation

theorem actual_source_constants (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 0 = 0 ∧
    fieldAt exactNonlinearExpressions pub rows 1 = 1 ∧
    fieldAt exactNonlinearExpressions pub rows 905 = (balancePaddingAssetId : F) := by
  refine ⟨?_, ?_, ?_⟩
  · simpa only [expressionField, Nat.cast_zero] using actual_node_field_equation pub rows
      (node := 0) (expression := .constant 0) (by decide)
  · simpa only [expressionField, Nat.cast_one] using actual_node_field_equation pub rows
      (node := 1) (expression := .constant 1) (by decide)
  · simpa only [expressionField] using actual_node_field_equation pub rows
      (node := 905) (expression := .constant balancePaddingAssetId) (by decide)

theorem actual_source_public (pub rows : Nat → F) {index : Nat} (bound : index < 120) :
    fieldAt exactNonlinearExpressions pub rows (4 + index) = pub index := by
  have nodes : ∀ i : Fin 120,
      exactNonlinearExpressions[4 + i.val]? = some (.publicWord i.val) := by decide
  simpa only [expressionField] using actual_node_field_equation pub rows (nodes ⟨index, bound⟩)

structure DenominatorSource where
  slot : Nat
  differences : List Nat
  factors : List Nat
  product01 : Nat
  denominator : Nat
  inverse : Nat
deriving DecidableEq, Repr, Inhabited

def denominatorSources : List DenominatorSource :=
  [⟨0, [1050, 1052, 1055], [1051, 1053, 1056], 1054, 1057, 1060⟩,
   ⟨1, [1063, 1065, 1068], [1064, 1066, 1069], 1067, 1070, 1073⟩,
   ⟨2, [1076, 1078, 1081], [1077, 1079, 1082], 1080, 1083, 1085⟩,
   ⟨3, [1088, 1090, 1093], [1089, 1091, 1094], 1092, 1095, 1096⟩]

def DenominatorSource.Valid (entry : DenominatorSource) : Prop :=
  entry.slot < 4 ∧
    (∀ factor, factor ∈ List.range 3 →
      (otherSlots entry.slot).getD factor 0 < 4 ∧
      exactNonlinearExpressions[entry.differences.getD factor 0]? =
        some (.sub (58 + entry.slot) (58 + (otherSlots entry.slot).getD factor 0)) ∧
      exactNonlinearExpressions[entry.factors.getD factor 0]? =
        some (.selectEqual (58 + (otherSlots entry.slot).getD factor 0) 905 1
          (entry.differences.getD factor 0))) ∧
    exactNonlinearExpressions[entry.product01]? =
      some (sortedMulExpression (entry.factors.getD 0 0) (entry.factors.getD 1 0)) ∧
    exactNonlinearExpressions[entry.denominator]? =
      some (sortedMulExpression entry.product01 (entry.factors.getD 2 0)) ∧
    exactNonlinearExpressions[entry.inverse]? = some (.inverse entry.denominator)

instance (entry : DenominatorSource) : Decidable entry.Valid := by
  unfold DenominatorSource.Valid
  infer_instance

theorem exact_denominator_sources_valid : ∀ entry, entry ∈ denominatorSources → entry.Valid := by
  have checked : denominatorSources.all (fun entry => decide entry.Valid) = true := by decide
  simpa only [List.all_eq_true, decide_eq_true_eq] using checked

theorem actual_denominator_formula (entry : DenominatorSource) (valid : entry.Valid)
    (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows entry.denominator =
      interpolationTriple pub entry.slot (pub (54 + entry.slot)) ∧
    fieldAt exactNonlinearExpressions pub rows entry.inverse =
      (interpolationTriple pub entry.slot (pub (54 + entry.slot)))⁻¹ := by
  obtain ⟨slotBound, factorNodes, productNode, denominatorNode, inverseNode⟩ := valid
  have constants := actual_source_constants pub rows
  have slotPublic : fieldAt exactNonlinearExpressions pub rows (58 + entry.slot) =
      pub (54 + entry.slot) := by
    simpa only [← Nat.add_assoc, Nat.reduceAdd] using
      actual_source_public pub rows (index := 54 + entry.slot) (by omega)
  have factors : ∀ factor, factor < 3 →
      fieldAt exactNonlinearExpressions pub rows (entry.factors.getD factor 0) =
        assetFactor (pub (54 + entry.slot))
          (pub (54 + (otherSlots entry.slot).getD factor 0)) := by
    intro factor bound
    obtain ⟨otherBound, differenceNode, factorNode⟩ :=
      factorNodes factor (List.mem_range.mpr bound)
    have otherPublic : fieldAt exactNonlinearExpressions pub rows
        (58 + (otherSlots entry.slot).getD factor 0) =
        pub (54 + (otherSlots entry.slot).getD factor 0) := by
      simpa only [← Nat.add_assoc, Nat.reduceAdd] using actual_source_public pub rows
        (index := 54 + (otherSlots entry.slot).getD factor 0) (by omega)
    have difference := actual_node_field_equation pub rows differenceNode
    have selected := actual_node_field_equation pub rows factorNode
    simp only [expressionField] at difference selected
    rw [slotPublic, otherPublic] at difference
    simpa only [assetFactor, otherPublic, constants.2.2, constants.2.1, difference] using selected
  have product := actual_sorted_mul pub rows productNode
  have denominator := actual_sorted_mul pub rows denominatorNode
  rw [product, factors 0 (by decide), factors 1 (by decide), factors 2 (by decide)] at denominator
  have inverse := actual_node_field_equation pub rows inverseNode
  simp only [expressionField, source_inverse_cast] at inverse
  exact ⟨denominator, inverse.trans (congrArg Inv.inv denominator)⟩

def denominatorSourceAt (slot : Nat) : DenominatorSource := denominatorSources.getD slot default

theorem denominator_source_at_valid {slot : Nat} (bound : slot < 4) :
    (denominatorSourceAt slot).Valid ∧ (denominatorSourceAt slot).slot = slot := by
  have cases : slot = 0 ∨ slot = 1 ∨ slot = 2 ∨ slot = 3 := by omega
  rcases cases with rfl | rfl | rfl | rfl <;>
    exact ⟨exact_denominator_sources_valid _ (by simp [denominatorSourceAt, denominatorSources]), rfl⟩

theorem actual_asset_factor_formula (entry : AssetRoot) (valid : entry.Valid)
    (pub rows : Nat → F) {slot : Nat} (bound : slot < 4) :
    fieldAt exactNonlinearExpressions pub rows (entry.selectors.getD slot 0) =
      assetFactor (rows entry.row) (pub (54 + slot)) := by
  obtain ⟨_, _, _, oneNode, paddingNode, _, rowNode, slotNodes, _, _, _, _, _⟩ := valid
  obtain ⟨publicNode, differenceNode, selectorNode⟩ := slotNodes slot (List.mem_range.mpr bound)
  have one := actual_node_field_equation pub rows oneNode
  have padding := actual_node_field_equation pub rows paddingNode
  have row := actual_node_field_equation pub rows rowNode
  have pubValue := actual_node_field_equation pub rows publicNode
  have difference := actual_node_field_equation pub rows differenceNode
  have selected := actual_node_field_equation pub rows selectorNode
  simp only [expressionField, Nat.cast_one] at one padding row pubValue difference selected
  rw [row, pubValue] at difference
  simpa only [assetFactor, pubValue, padding, one, difference] using selected

structure WeightSource where
  note : Nat
  slot : Nat
  product01 : Nat
  numerator : Nat
  scaled : Nat
  weight : Nat
deriving DecidableEq, Repr, Inhabited

def weightSources : List WeightSource :=
  [⟨0, 0, 1058, 1059, 1061, 1062⟩, ⟨0, 1, 1071, 1072, 1074, 1075⟩,
   ⟨0, 2, 909, 1084, 1086, 1087⟩, ⟨0, 3, 909, 912, 1097, 1098⟩,
   ⟨1, 0, 1101, 1102, 1103, 1104⟩, ⟨1, 1, 1105, 1106, 1107, 1108⟩,
   ⟨1, 2, 985, 1109, 1110, 1111⟩, ⟨1, 3, 985, 988, 1112, 1113⟩,
   ⟨2, 0, 1117, 1118, 1119, 1120⟩, ⟨2, 1, 1121, 1122, 1123, 1124⟩,
   ⟨2, 2, 997, 1125, 1126, 1127⟩, ⟨2, 3, 997, 1000, 1128, 1129⟩,
   ⟨3, 0, 1133, 1134, 1135, 1136⟩, ⟨3, 1, 1137, 1138, 1139, 1140⟩,
   ⟨3, 2, 1016, 1141, 1142, 1143⟩, ⟨3, 3, 1016, 1019, 1144, 1145⟩]

def WeightSource.Valid (entry : WeightSource) : Prop :=
  let selectors := (assetRootAt entry.note).selectors
  let others := otherSlots entry.slot
  entry.note < 4 ∧ entry.slot < 4 ∧
    (∀ factor, factor ∈ List.range 3 → others.getD factor 0 < 4) ∧
    exactNonlinearExpressions[entry.product01]? =
      some (sortedMulExpression (selectors.getD (others.getD 0 0) 0)
        (selectors.getD (others.getD 1 0) 0)) ∧
    exactNonlinearExpressions[entry.numerator]? =
      some (sortedMulExpression entry.product01 (selectors.getD (others.getD 2 0) 0)) ∧
    exactNonlinearExpressions[entry.scaled]? =
      some (sortedMulExpression entry.numerator (denominatorSourceAt entry.slot).inverse) ∧
    exactNonlinearExpressions[entry.weight]? =
      some (.selectEqual (58 + entry.slot) 905 0 entry.scaled)

instance (entry : WeightSource) : Decidable entry.Valid := by
  unfold WeightSource.Valid
  infer_instance

theorem exact_weight_sources_valid : ∀ entry, entry ∈ weightSources → entry.Valid := by
  have checked : weightSources.all (fun entry => decide entry.Valid) = true := by decide
  simpa only [List.all_eq_true, decide_eq_true_eq] using checked

theorem actual_source_weight_formula (entry : WeightSource) (valid : entry.Valid)
    (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows entry.weight =
      sourceWeight pub entry.slot (rows (assetRootAt entry.note).row) := by
  obtain ⟨noteBound, slotBound, otherBounds, productNode, numeratorNode, scaledNode, weightNode⟩ := valid
  have assetValid := (asset_root_at_valid noteBound).1
  have denominatorValid := denominator_source_at_valid slotBound
  have denominator := actual_denominator_formula (denominatorSourceAt entry.slot)
    denominatorValid.1 pub rows
  rw [denominatorValid.2] at denominator
  have factors : ∀ factor, factor < 3 →
      fieldAt exactNonlinearExpressions pub rows
        ((assetRootAt entry.note).selectors.getD ((otherSlots entry.slot).getD factor 0) 0) =
        assetFactor (rows (assetRootAt entry.note).row)
          (pub (54 + (otherSlots entry.slot).getD factor 0)) := by
    intro factor bound
    exact actual_asset_factor_formula _ assetValid pub rows (otherBounds factor (List.mem_range.mpr bound))
  have product := actual_sorted_mul pub rows productNode
  have numerator := actual_sorted_mul pub rows numeratorNode
  rw [product, factors 0 (by decide), factors 1 (by decide), factors 2 (by decide)] at numerator
  have scaled := actual_sorted_mul pub rows scaledNode
  rw [numerator, denominator.2] at scaled
  have constants := actual_source_constants pub rows
  have slotPublic : fieldAt exactNonlinearExpressions pub rows (58 + entry.slot) =
      pub (54 + entry.slot) := by
    simpa only [← Nat.add_assoc, Nat.reduceAdd] using
      actual_source_public pub rows (index := 54 + entry.slot) (by omega)
  have weight := actual_node_field_equation pub rows weightNode
  simpa only [expressionField, sourceWeight, interpolationTriple,
    slotPublic, constants.2.2, constants.1, scaled] using weight

def weightSourceAt (note slot : Nat) : WeightSource := weightSources.getD (4 * note + slot) default

theorem weight_source_at_valid {note slot : Nat} (noteBound : note < 4) (slotBound : slot < 4) :
    (weightSourceAt note slot).Valid ∧
      (weightSourceAt note slot).note = note ∧ (weightSourceAt note slot).slot = slot := by
  have checked : ∀ n s : Fin 4,
      weightSourceAt n.val s.val ∈ weightSources ∧
        (weightSourceAt n.val s.val).note = n.val ∧
        (weightSourceAt n.val s.val).slot = s.val := by decide
  have entry := checked ⟨note, noteBound⟩ ⟨slot, slotBound⟩
  exact ⟨exact_weight_sources_valid _ entry.1, entry.2⟩

def valueRow (note : Nat) : Nat := [0, 34, 68, 80].getD note 0
def flagValueNode (note : Nat) : Nat := [1099, 1114, 1130, 1146].getD note 0

theorem value_row_source {note : Nat} (bound : note < 4) :
    (assetRootAt note).row = valueRow note + 1 ∧
    valueRow note * 64 = densePrivateAddress note ∧
    valueRow note < 686 ∧
    exactNonlinearExpressions[124 + valueRow note]? = some (.witnessRow (valueRow note)) ∧
    exactNonlinearExpressions[flagValueNode note]? =
      some (sortedMulExpression (4 + note) (124 + valueRow note)) := by
  have checked : ∀ n : Fin 4,
      (assetRootAt n.val).row = valueRow n.val + 1 ∧
      valueRow n.val * 64 = densePrivateAddress n.val ∧
      valueRow n.val < 686 ∧
      exactNonlinearExpressions[124 + valueRow n.val]? = some (.witnessRow (valueRow n.val)) ∧
      exactNonlinearExpressions[flagValueNode n.val]? =
        some (sortedMulExpression (4 + n.val) (124 + valueRow n.val)) := by decide
  exact checked ⟨note, bound⟩

theorem actual_weight_source_at_formula (pub rows : Nat → F) {note slot : Nat}
    (noteBound : note < 4) (slotBound : slot < 4) :
    fieldAt exactNonlinearExpressions pub rows (weightSourceAt note slot).weight =
      sourceWeight pub slot (rows (valueRow note + 1)) := by
  have valid := weight_source_at_valid noteBound slotBound
  have formula := actual_source_weight_formula _ valid.1 pub rows
  simpa only [valid.2.1, valid.2.2, (value_row_source noteBound).1] using formula

theorem actual_flag_value_formula (pub rows : Nat → F) {note : Nat} (bound : note < 4) :
    fieldAt exactNonlinearExpressions pub rows (flagValueNode note) = pub note * rows (valueRow note) := by
  have source := value_row_source bound
  have value := actual_node_field_equation pub rows source.2.2.2.1
  have flag := actual_source_public pub rows (index := note) (by omega)
  have product := actual_sorted_mul pub rows source.2.2.2.2
  simpa only [expressionField, flag, value] using product

structure BalanceRootSource where
  slot : Nat
  contributions : List Nat
  inputSum : Nat
  firstSub : Nat
  delta : Nat
  expected : Nat
  root : Nat
deriving DecidableEq, Repr, Inhabited

def balanceRootSources : List BalanceRootSource :=
  [⟨0, [1100, 1115, 1131, 1147], 1116, 1132, 1148, 1049, 1149⟩,
   ⟨1, [1150, 1151, 1153, 1155], 1152, 1154, 1156, 1158, 1159⟩,
   ⟨2, [1160, 1161, 1163, 1165], 1162, 1164, 1166, 1167, 1168⟩,
   ⟨3, [1169, 1170, 1172, 1174], 1171, 1173, 1175, 1176, 1177⟩]

def BalanceRootSource.Valid (entry : BalanceRootSource) : Prop :=
  entry.slot < 4 ∧
    (∀ note, note ∈ List.range 4 →
      exactNonlinearExpressions[entry.contributions.getD note 0]? =
        some (sortedMulExpression (weightSourceAt note entry.slot).weight (flagValueNode note))) ∧
    exactNonlinearExpressions[entry.inputSum]? =
      some (.add (entry.contributions.getD 0 0) (entry.contributions.getD 1 0)) ∧
    exactNonlinearExpressions[entry.firstSub]? =
      some (.sub entry.inputSum (entry.contributions.getD 2 0)) ∧
    exactNonlinearExpressions[entry.delta]? =
      some (.sub entry.firstSub (entry.contributions.getD 3 0)) ∧
    exactNonlinearExpressions[entry.root]? = some (.sub entry.delta entry.expected) ∧
    entry.root ∈ exactNonlinearRoots

instance (entry : BalanceRootSource) : Decidable entry.Valid := by
  unfold BalanceRootSource.Valid
  infer_instance

theorem exact_balance_root_sources_valid : ∀ entry, entry ∈ balanceRootSources → entry.Valid := by
  have checked : balanceRootSources.all (fun entry => decide entry.Valid) = true := by decide
  simpa only [List.all_eq_true, decide_eq_true_eq] using checked

def sourceContribution (pub rows : Nat → F) (slot note : Nat) : F :=
  sourceWeight pub slot (rows (valueRow note + 1)) * (pub note * rows (valueRow note))

def sourceDelta (pub rows : Nat → F) (slot : Nat) : F :=
  (sourceContribution pub rows slot 0 + sourceContribution pub rows slot 1) -
    sourceContribution pub rows slot 2 - sourceContribution pub rows slot 3

theorem actual_balance_root_formula (entry : BalanceRootSource) (valid : entry.Valid)
    (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows entry.root =
      sourceDelta pub rows entry.slot - fieldAt exactNonlinearExpressions pub rows entry.expected := by
  obtain ⟨slotBound, contributionNodes, sumNode, firstSubNode, deltaNode, rootNode, _⟩ := valid
  have contributions : ∀ note, note < 4 →
      fieldAt exactNonlinearExpressions pub rows (entry.contributions.getD note 0) =
        sourceContribution pub rows entry.slot note := by
    intro note bound
    have product := actual_sorted_mul pub rows (contributionNodes note (List.mem_range.mpr bound))
    simpa only [sourceContribution, actual_weight_source_at_formula pub rows bound slotBound,
      actual_flag_value_formula pub rows bound] using product
  have sum := actual_node_field_equation pub rows sumNode
  have first := actual_node_field_equation pub rows firstSubNode
  have delta := actual_node_field_equation pub rows deltaNode
  have root := actual_node_field_equation pub rows rootNode
  simp only [expressionField] at sum first delta root
  rw [delta, first, sum, contributions 0 (by decide), contributions 1 (by decide),
    contributions 2 (by decide), contributions 3 (by decide)] at root
  exact root

def balanceRootSourceAt (slot : Nat) : BalanceRootSource := balanceRootSources.getD slot default

theorem balance_root_source_at_valid {slot : Nat} (bound : slot < 4) :
    (balanceRootSourceAt slot).Valid ∧ (balanceRootSourceAt slot).slot = slot ∧
    (if slot = 0 then (balanceRootSourceAt slot).expected = 1049 else
      exactNonlinearExpressions[(balanceRootSourceAt slot).expected]? =
        some (.selectEqual (58 + slot) 63 1157 0)) := by
  have checked : ∀ s : Fin 4,
      balanceRootSourceAt s.val ∈ balanceRootSources ∧
      (balanceRootSourceAt s.val).slot = s.val ∧
      (if s.val = 0 then (balanceRootSourceAt s.val).expected = 1049 else
        exactNonlinearExpressions[(balanceRootSourceAt s.val).expected]? =
          some (.selectEqual (58 + s.val) 63 1157 0)) := by decide
  have entry := checked ⟨slot, bound⟩
  exact ⟨exact_balance_root_sources_valid _ entry.1, entry.2⟩

def signedFieldValue (sign magnitude : F) : F := magnitude - magnitude * (sign + sign)

theorem actual_expected_common_terms (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 1049 =
      pub 44 - signedFieldValue (pub 45) (pub 46) ∧
    fieldAt exactNonlinearExpressions pub rows 1157 =
      fieldAt exactNonlinearExpressions pub rows 832 * signedFieldValue (pub 61) (pub 62) := by
  have p44 := actual_source_public pub rows (index := 44) (by decide)
  have p45 := actual_source_public pub rows (index := 45) (by decide)
  have p46 := actual_source_public pub rows (index := 46) (by decide)
  have p61 := actual_source_public pub rows (index := 61) (by decide)
  have p62 := actual_source_public pub rows (index := 62) (by decide)
  have n1043 := actual_node_field_equation pub rows (node := 1043) (expression := .add 49 49) (by decide)
  have n1044 := actual_node_field_equation pub rows (node := 1044) (expression := .mul 50 1043) (by decide)
  have n1045 := actual_node_field_equation pub rows (node := 1045) (expression := .sub 50 1044) (by decide)
  have n1046 := actual_node_field_equation pub rows (node := 1046) (expression := .add 65 65) (by decide)
  have n1047 := actual_node_field_equation pub rows (node := 1047) (expression := .mul 66 1046) (by decide)
  have n1048 := actual_node_field_equation pub rows (node := 1048) (expression := .sub 66 1047) (by decide)
  have n1049 := actual_node_field_equation pub rows (node := 1049) (expression := .sub 48 1045) (by decide)
  have n1157 := actual_node_field_equation pub rows (node := 1157) (expression := .mul 832 1048) (by decide)
  simp only [expressionField] at n1043 n1044 n1045 n1046 n1047 n1048 n1049 n1157
  constructor
  · simpa only [signedFieldValue, n1045, n1044, n1043, p44, p45, p46] using n1049
  · simpa only [signedFieldValue, n1048, n1047, n1046, p61, p62] using n1157

def sourceExpected (pub : Nat → F) (slot : Nat) : F :=
  if slot = 0 then pub 44 - signedFieldValue (pub 45) (pub 46)
  else if pub (54 + slot) = pub 59 then pub 58 * signedFieldValue (pub 61) (pub 62) else 0

theorem accepted_source_root_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {root : Nat} (member : root ∈ exactNonlinearRoots) :
    fieldAt exactNonlinearExpressions (fun index => (publicWords.getD index 0 : F))
      (fun row => ((Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0).getD row 0 : F))
      root = 0 := by
  obtain ⟨values, evaluated, zero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 0 (by decide)) member
  have source := fieldAt_refines_source hgv8rp03ProgramComponents.nonlinearExecutable
    publicWords (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0)
    values V8Smz9ProgramCanonicality.hgv8rp03_nonlinear_expression_program_is_canonical evaluated root
    (V8Smz9ProgramCanonicality.hgv8rp03_nonlinear_expression_program_is_canonical.2 _ member)
  change fieldAt exactNonlinearExpressions _ _ root = (values.getD root 0 : F) at source
  rw [source]
  simp only [List.getD_eq_getElem?_getD, zero, Option.getD_some, Nat.cast_zero]

theorem accepted_source_enabled {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    fieldAt exactNonlinearExpressions (fun index => (publicWords.getD index 0 : F))
      (fun row => ((Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0).getD row 0 : F))
      832 = (publicWords.getD 58 0 : F) := by
  let pub := fun index => (publicWords.getD index 0 : F)
  let rows := fun row =>
    ((Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0).getD row 0 : F)
  have rootZero := accepted_source_root_zero accepted (root := 835) (by decide)
  have root := actual_node_field_equation pub rows (node := 835) (expression := .sub 62 832) (by decide)
  have flag := actual_source_public pub rows (index := 58) (by decide)
  simp only [expressionField, flag] at root
  have equal : pub 58 - fieldAt exactNonlinearExpressions pub rows 832 = 0 := root.symm.trans rootZero
  exact (sub_eq_zero.mp equal).symm

theorem accepted_source_balance_equation {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    sourceDelta (fun index => (publicWords.getD index 0 : F))
      (fun row => ((Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0).getD row 0 : F))
      slot = sourceExpected (fun index => (publicWords.getD index 0 : F)) slot := by
  let pub := fun index => (publicWords.getD index 0 : F)
  let rows := fun row =>
    ((Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0).getD row 0 : F)
  have entry := balance_root_source_at_valid bound
  have rootMember := entry.1.2.2.2.2.2.2
  have rootZero := accepted_source_root_zero accepted rootMember
  have formula := actual_balance_root_formula (balanceRootSourceAt slot) entry.1 pub rows
  rw [entry.2.1] at formula
  have delta := sub_eq_zero.mp (formula.symm.trans rootZero)
  have expected : fieldAt exactNonlinearExpressions pub rows (balanceRootSourceAt slot).expected =
      sourceExpected pub slot := by
    have common := actual_expected_common_terms pub rows
    by_cases native : slot = 0
    · have target := entry.2.2
      rw [if_pos native] at target
      simpa only [sourceExpected, if_pos native, target] using common.1
    · have target := entry.2.2
      rw [if_neg native] at target
      have selected := actual_node_field_equation pub rows target
      have asset : fieldAt exactNonlinearExpressions pub rows (58 + slot) = pub (54 + slot) := by
        simpa only [← Nat.add_assoc, Nat.reduceAdd] using
          actual_source_public pub rows (index := 54 + slot) (by omega)
      have stableAsset := actual_source_public pub rows (index := 59) (by decide)
      have enabled : fieldAt exactNonlinearExpressions pub rows 832 = pub 58 := accepted_source_enabled accepted
      have constants := actual_source_constants pub rows
      simpa only [expressionField, sourceExpected, if_neg native, asset, stableAsset,
        common.2, enabled, constants.1] using selected
  exact delta.trans expected

theorem encoded_balance_scalar (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    {index : Nat} (bound : index < 3) :
    (encodePublicStatement statement).getD (44 + index) 0 =
      [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude].getD index 0 := by
  obtain ⟨inputLength, outputLength, nullifierLength, commitmentLength,
    ciphertextLength, _, _⟩ := admitted_public_lengths statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags ++ statement.nullifiers.flatten ++
    statement.commitments.flatten ++ statement.ciphertextCommitments.flatten
  have prefixLength : publicPrefix.length = 44 := by
    simp [publicPrefix, inputLength, outputLength, nullifierLength, commitmentLength, ciphertextLength]
  have encoded : encodePublicStatement statement = publicPrefix ++
      ([statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
        (statement.merkleRoot ++ statement.balanceAssets ++ encodeCompatibility statement.compatibility ++
          [statement.version, statement.cryptoSuite] ++ encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  simp only [Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ (by simpa only [List.length_cons, List.length_nil] using bound)]

theorem encoded_compatibility_scalar (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    {index : Nat} (bound : index < 5) :
    (encodePublicStatement statement).getD (58 + index) 0 =
      [statement.compatibility.enabled, statement.compatibility.assetId,
        statement.compatibility.policyVersion, statement.compatibility.issuanceSign,
        statement.compatibility.issuanceMagnitude].getD index 0 := by
  obtain ⟨inputLength, outputLength, nullifierLength, commitmentLength,
    ciphertextLength, rootLength, assetLength⟩ := admitted_public_lengths statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags ++ statement.nullifiers.flatten ++
    statement.commitments.flatten ++ statement.ciphertextCommitments.flatten ++
    [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
    statement.merkleRoot ++ statement.balanceAssets
  have prefixLength : publicPrefix.length = 58 := by
    simp [publicPrefix, inputLength, outputLength, nullifierLength, commitmentLength,
      ciphertextLength, rootLength, assetLength]
  have encoded : encodePublicStatement statement = publicPrefix ++
      ([statement.compatibility.enabled, statement.compatibility.assetId,
        statement.compatibility.policyVersion, statement.compatibility.issuanceSign,
        statement.compatibility.issuanceMagnitude] ++
        (statement.compatibility.reservedLegacyCommitments.flatten ++
          [statement.version, statement.cryptoSuite] ++ encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement, encodeCompatibility, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  simp only [Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ (by simpa only [List.length_cons, List.length_nil] using bound)]

theorem admitted_balance_public_fields {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    publicWords.getD 44 0 = statement.fee ∧ publicWords.getD 45 0 = 0 ∧
    publicWords.getD 46 0 = 0 ∧
    publicWords.getD 58 0 = statement.compatibility.enabled ∧
    publicWords.getD 59 0 = statement.compatibility.assetId ∧
    publicWords.getD 61 0 = statement.compatibility.issuanceSign ∧
    publicWords.getD 62 0 = statement.compatibility.issuanceMagnitude := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, signZero, magnitudeZero, _⟩ := domain.2.1
  rw [← domain.1]
  exact ⟨encoded_balance_scalar statement domain.2.1 (index := 0) (by decide),
    (encoded_balance_scalar statement domain.2.1 (index := 1) (by decide)).trans signZero,
    (encoded_balance_scalar statement domain.2.1 (index := 2) (by decide)).trans magnitudeZero,
    encoded_compatibility_scalar statement domain.2.1 (index := 0) (by decide),
    encoded_compatibility_scalar statement domain.2.1 (index := 1) (by decide),
    encoded_compatibility_scalar statement domain.2.1 (index := 3) (by decide),
    encoded_compatibility_scalar statement domain.2.1 (index := 4) (by decide)⟩

theorem admitted_balance_asset {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    publicWords.getD (54 + slot) 0 = wordAt statement.balanceAssets slot := by
  rw [← domain.1]
  exact encoded_balance_asset statement domain.2.1 bound

theorem admitted_raw_note_flag_one {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {note : Nat} (bound : note < 4) (active : publicWords.getD note 0 ≠ 0) :
    publicWords.getD note 0 = 1 := by
  by_cases input : note < 2
  · have flag := admitted_public_input_flag domain input
    rw [flag] at active ⊢
    exact admitted_input_flag_one statement domain.2.1 input active
  · have outputBound : note - 2 < 2 := by omega
    have index : 2 + (note - 2) = note := by omega
    have flag := admitted_public_output_flag domain outputBound
    rw [index] at flag
    rw [flag] at active ⊢
    exact admitted_output_flag_one statement domain.2.1 outputBound active

theorem interpolationTriple_eq_numerator (pub : Nat → F) (slot : Fin 4) (asset : F) :
    interpolationTriple pub slot.val asset =
      interpolationNumerator (fun index => pub (54 + index)) (balancePaddingAssetId : F) slot asset := by
  rw [interpolationNumerator_eq_three_factors]
  have cases : slot = 0 ∨ slot = 1 ∨ slot = 2 ∨ slot = 3 := by
    have bound := slot.isLt
    omega
  rcases cases with rfl | rfl | rfl | rfl <;> rfl

theorem sourceWeight_eq_interpolationWeight (pub : Nat → F) (slot : Fin 4) (asset : F) :
    sourceWeight pub slot.val asset =
      interpolationWeight (fun index => pub (54 + index)) (balancePaddingAssetId : F) slot asset := by
  simp only [sourceWeight, interpolationWeight, interpolationTriple_eq_numerator]

theorem admitted_public_asset_field_distinct {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    NonpaddingDistinct (fun index => (publicWords.getD (54 + index) 0 : F))
      (balancePaddingAssetId : F) := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, assets, _⟩ := domain.2.1
  have distinct := canonical_balance_assets_nonpadding_distinct statement.balanceAssets assets
  intro left right different leftReal rightReal equal
  dsimp only at leftReal rightReal equal
  rw [admitted_balance_asset domain left.isLt] at leftReal equal
  rw [admitted_balance_asset domain right.isLt] at rightReal equal
  exact distinct left right different leftReal rightReal equal

theorem packed_lane_zero_row (packed : List Nat) {row : Nat} (bound : row < 686) :
    (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0).getD row 0 =
      packedWord packed (row * 64) := by
  simp [Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows,
    Hegemon.Transaction.Poseidon2V8RelationProgram.relationRowCount,
    Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor,
    List.getD_eq_getElem?_getD, bound, packedWord]

theorem accepted_lane_note_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {note word : Nat} (noteBound : note < 4) (wordBound : word < 2) :
    (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0).getD
      (valueRow note + word) 0 = spongeSourceWord packed (noteBridgeCall note) word := by
  have valueRowBound : valueRow note ≤ 80 := by
    have checked : ∀ n : Fin 4, valueRow n.val ≤ 80 := by decide
    exact checked ⟨note, noteBound⟩
  have address : (valueRow note + word) * 64 = densePrivateAddress note + 64 * word := by
    rw [Nat.add_mul, (value_row_source noteBound).2.1, Nat.mul_comm word 64]
  rw [packed_lane_zero_row packed (by omega), address]
  exact (accepted_note_source_bridge accepted noteBound wordBound).symm

theorem admitted_active_weight_indicator {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {note slot : Nat} (noteBound : note < 4) (slotBound : slot < 4)
    (active : publicWords.getD note 0 = 1) :
    sourceWeight (fun index => (publicWords.getD index 0 : F)) slot
      ((projectNote packed (noteBridgeCall note)).assetId : F) =
      if (projectNote packed (noteBridgeCall note)).assetId = publicWords.getD (54 + slot) 0
        then 1 else 0 := by
  have distinct := admitted_public_asset_field_distinct domain
  obtain ⟨chosen, chosenBound, nonpadding, matched⟩ :=
    V8Smz9SemanticAssetMembership.accepted_active_note_asset_member domain.2.2 noteBound active
  have member : ∃ selected : Fin 4,
      (publicWords.getD (54 + selected.val) 0 : F) ≠ (balancePaddingAssetId : F) ∧
      ((projectNote packed (noteBridgeCall note)).assetId : F) =
        (publicWords.getD (54 + selected.val) 0 : F) := by
    refine ⟨⟨chosen, chosenBound⟩, ?_, congrArg (fun value : Nat => (value : F)) matched⟩
    intro equal
    exact nonpadding (canonical_nat_cast_injective
      (canonical_getD publicWords domain.2.2.1.2 _) (by decide) equal)
  have generic := interpolationWeight_eq_indicator
    (fun index => (publicWords.getD (54 + index) 0 : F)) (balancePaddingAssetId : F)
    ⟨slot, slotBound⟩ ((projectNote packed (noteBridgeCall note)).assetId : F) distinct member
  rw [← sourceWeight_eq_interpolationWeight (fun index => (publicWords.getD index 0 : F))
    ⟨slot, slotBound⟩] at generic
  by_cases same : (projectNote packed (noteBridgeCall note)).assetId = publicWords.getD (54 + slot) 0
  · simpa only [same, if_pos rfl] using generic
  · have fieldDifferent : ((projectNote packed (noteBridgeCall note)).assetId : F) ≠
        (publicWords.getD (54 + slot) 0 : F) := by
      intro equal
      exact same (canonical_nat_cast_injective
        (project_note_field_shape domain.2.2.2.1 _).1
        (canonical_getD publicWords domain.2.2.1.2 _) equal)
    simpa only [if_neg same, if_neg fieldDifferent] using generic

def noteContribution (publicWords packed : List Nat) (asset note : Nat) : Nat :=
  if publicWords.getD note 0 = 1 ∧ (projectNote packed (noteBridgeCall note)).assetId = asset
  then (projectNote packed (noteBridgeCall note)).value else 0

theorem admitted_source_contribution {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {note slot : Nat} (noteBound : note < 4) (slotBound : slot < 4) :
    sourceContribution (fun index => (publicWords.getD index 0 : F))
      (fun row => ((Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0).getD row 0 : F))
      slot note = (noteContribution publicWords packed (wordAt statement.balanceAssets slot) note : F) := by
  have value := accepted_lane_note_word domain.2.2 noteBound (word := 0) (by decide)
  have asset := accepted_lane_note_word domain.2.2 noteBound (word := 1) (by decide)
  have publicAsset := admitted_balance_asset domain slotBound
  simp only [Nat.add_zero] at value
  unfold sourceContribution
  dsimp only
  rw [value, asset]
  change sourceWeight (fun index => (publicWords.getD index 0 : F)) slot
      ((projectNote packed (noteBridgeCall note)).assetId : F) *
      ((publicWords.getD note 0 : F) * ((projectNote packed (noteBridgeCall note)).value : F)) = _
  by_cases inactive : publicWords.getD note 0 = 0
  · simp only [noteContribution, inactive, Nat.cast_zero, zero_mul, mul_zero,
      zero_ne_one, false_and, if_false]
  · have active := admitted_raw_note_flag_one domain noteBound inactive
    rw [admitted_active_weight_indicator domain noteBound slotBound active]
    rw [publicAsset]
    by_cases same : (projectNote packed (noteBridgeCall note)).assetId = wordAt statement.balanceAssets slot
    · simp only [noteContribution, active, same, if_pos, and_self, Nat.cast_one, one_mul]
    · simp only [noteContribution, active, same, if_false, and_false,
        Nat.cast_one, one_mul, zero_mul, Nat.cast_zero]

theorem note_contribution_bound {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (asset : Nat) {note : Nat} (bound : note < 4) :
    noteContribution publicWords packed asset note < 2 ^ 61 := by
  unfold noteContribution
  split
  · exact accepted_project_note_value_bound accepted bound
  · decide

def noteInputSum (publicWords packed : List Nat) (asset : Nat) : Nat :=
  noteContribution publicWords packed asset 0 + noteContribution publicWords packed asset 1

def noteOutputSum (publicWords packed : List Nat) (asset : Nat) : Nat :=
  noteContribution publicWords packed asset 2 + noteContribution publicWords packed asset 3

theorem admitted_source_delta {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    sourceDelta (fun index => (publicWords.getD index 0 : F))
      (fun row => ((Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0).getD row 0 : F)) slot =
      (noteInputSum publicWords packed (wordAt statement.balanceAssets slot) : F) -
        (noteOutputSum publicWords packed (wordAt statement.balanceAssets slot) : F) := by
  rw [sourceDelta, admitted_source_contribution domain (by decide : 0 < 4) bound,
    admitted_source_contribution domain (by decide : 1 < 4) bound,
    admitted_source_contribution domain (by decide : 2 < 4) bound,
    admitted_source_contribution domain (by decide : 3 < 4) bound]
  simp only [noteInputSum, noteOutputSum, Nat.cast_add, sub_sub]

theorem two_step_conditional_sum (first second : Prop) [Decidable first] [Decidable second]
    (left right : Nat) :
    (if second then (if first then left else 0) + right else (if first then left else 0)) =
      (if first then left else 0) + (if second then right else 0) := by
  by_cases hFirst : first <;> by_cases hSecond : second <;> simp [hFirst, hSecond]

theorem admitted_input_sum_is_typed {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (asset : Nat) :
    inputValueForAsset (projectTypedWitness statement packed) asset = noteInputSum publicWords packed asset := by
  have flag0 := admitted_public_input_flag domain (input := 0) (by decide)
  have flag1 := admitted_public_input_flag domain (input := 1) (by decide)
  have note0 : projectNote packed (noteBridgeCall 0) = (projectInput statement packed 0).note := rfl
  have note1 : projectNote packed (noteBridgeCall 1) = (projectInput statement packed 1).note := rfl
  have active0 : flagAt statement.inputFlags 0 = (projectInput statement packed 0).active := rfl
  have active1 : flagAt statement.inputFlags 1 = (projectInput statement packed 1).active := rfl
  have range : List.range 2 = [0, 1] := rfl
  simp only [inputValueForAsset, projectTypedWitness, range, List.map_cons, List.map_nil,
    List.foldl_cons, List.foldl_nil, noteInputSum, noteContribution, flag0, flag1,
    note0, note1, active0, active1, Nat.zero_add]
  exact two_step_conditional_sum _ _ _ _

theorem admitted_output_sum_is_typed {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (asset : Nat) :
    outputValueForAsset (projectTypedWitness statement packed) asset = noteOutputSum publicWords packed asset := by
  have flag0 := admitted_public_output_flag domain (output := 0) (by decide)
  have flag1 := admitted_public_output_flag domain (output := 1) (by decide)
  have note0 : projectNote packed (noteBridgeCall 2) = (projectOutput statement packed 0).note := rfl
  have note1 : projectNote packed (noteBridgeCall 3) = (projectOutput statement packed 1).note := rfl
  have active0 : flagAt statement.outputFlags 0 = (projectOutput statement packed 0).active := rfl
  have active1 : flagAt statement.outputFlags 1 = (projectOutput statement packed 1).active := rfl
  have range : List.range 2 = [0, 1] := rfl
  simp only [outputValueForAsset, projectTypedWitness, range,
    List.map_cons, List.map_nil, List.foldl_cons, List.foldl_nil,
    noteOutputSum, noteContribution, flag0, flag1, note0, note1, active0, active1, Nat.zero_add]
  exact two_step_conditional_sum _ _ _ _

theorem admitted_native_slot_iff {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    wordAt statement.balanceAssets slot = nativeAssetId ↔ slot = 0 := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, assets, _⟩ := domain.2.1
  constructor
  · intro native
    by_contra nonzero
    have positive : 0 < slot := by omega
    have firstReal : wordAt statement.balanceAssets 0 ≠ balancePaddingAssetId := by
      rw [assets.2.1]
      decide
    have slotReal : wordAt statement.balanceAssets slot ≠ balancePaddingAssetId := by
      rw [native]
      decide
    have ordered := assets.2.2.2.1 0 slot positive bound firstReal slotReal
    rw [assets.2.1, native] at ordered
    exact Nat.lt_irrefl _ ordered
  · rintro rfl
    exact assets.2.1

def typedExpectedField (statement : V8PublicStatement) (asset : Nat) : F :=
  if asset = nativeAssetId then (statement.fee : F)
  else if statement.compatibility.enabled = 1 ∧ statement.compatibility.assetId = asset then
    if statement.compatibility.issuanceSign = 1 then -(statement.compatibility.issuanceMagnitude : F)
    else (statement.compatibility.issuanceMagnitude : F)
  else 0

theorem admitted_expected_field {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    sourceExpected (fun index => (publicWords.getD index 0 : F)) slot =
      typedExpectedField statement (wordAt statement.balanceAssets slot) := by
  have fields := admitted_balance_public_fields domain
  have asset := admitted_balance_asset domain bound
  have nativeIff := admitted_native_slot_iff domain bound
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, compatibility, _⟩ := domain.2.1
  by_cases native : wordAt statement.balanceAssets slot = nativeAssetId
  · have slotZero := nativeIff.mp native
    rw [sourceExpected, if_pos slotZero, typedExpectedField, if_pos native,
      fields.1, fields.2.1, fields.2.2.1]
    simp [signedFieldValue]
  · have slotNonzero : slot ≠ 0 := by
      intro zero
      exact native (nativeIff.mpr zero)
    have comparison : ((wordAt statement.balanceAssets slot : Nat) : F) =
        (statement.compatibility.assetId : F) ↔
        statement.compatibility.assetId = wordAt statement.balanceAssets slot := by
      constructor
      · intro equal
        have slotCanonical : wordAt statement.balanceAssets slot < fieldModulus := by
          rw [← asset]
          exact canonical_getD publicWords domain.2.2.1.2 _
        have stableCanonical : statement.compatibility.assetId < fieldModulus := by
          rw [← fields.2.2.2.2.1]
          exact canonical_getD publicWords domain.2.2.1.2 _
        exact (canonical_nat_cast_injective slotCanonical stableCanonical equal).symm
      · intro equal
        rw [equal]
    simp only [sourceExpected, if_neg slotNonzero, asset, fields.2.2.2.1,
      fields.2.2.2.2.1, fields.2.2.2.2.2.1, fields.2.2.2.2.2.2,
      typedExpectedField, if_neg native, comparison]
    rcases compatibility.1 with disabled | enabled
    · simp [disabled]
    · rw [enabled]
      by_cases matching : statement.compatibility.assetId = wordAt statement.balanceAssets slot
      · simp only [matching, if_true, and_self, Nat.cast_one, one_mul]
        rcases compatibility.2.1 with signZero | signOne
        · simp [signedFieldValue, signZero]
        · simp only [signedFieldValue, signOne, if_true, Nat.cast_one]
          ring
      · simp [matching]

theorem admitted_typed_field_balance {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    (inputValueForAsset (projectTypedWitness statement packed) (wordAt statement.balanceAssets slot) : F) -
      (outputValueForAsset (projectTypedWitness statement packed) (wordAt statement.balanceAssets slot) : F) =
      typedExpectedField statement (wordAt statement.balanceAssets slot) := by
  have equation := accepted_source_balance_equation domain.2.2 bound
  rw [admitted_source_delta domain bound, admitted_expected_field domain bound] at equation
  simpa only [admitted_input_sum_is_typed domain, admitted_output_sum_is_typed domain] using equation

theorem admitted_typed_value_sum_bounds {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (asset : Nat) :
    inputValueForAsset (projectTypedWitness statement packed) asset < 2 ^ 62 ∧
    outputValueForAsset (projectTypedWitness statement packed) asset < 2 ^ 62 := by
  rw [admitted_input_sum_is_typed domain, admitted_output_sum_is_typed domain]
  have first := note_contribution_bound domain.2.2 asset (note := 0) (by decide)
  have second := note_contribution_bound domain.2.2 asset (note := 1) (by decide)
  have third := note_contribution_bound domain.2.2 asset (note := 2) (by decide)
  have fourth := note_contribution_bound domain.2.2 asset (note := 3) (by decide)
  unfold noteInputSum noteOutputSum
  constructor <;> omega

theorem pair_sum_extra_canonical {pair extra : Nat} (pairBound : pair < 2 ^ 62)
    (extraBound : extra < 2 ^ 61) : pair + extra < fieldModulus := by
  change pair + extra < 18446744069414584321
  omega

/-- Full unchanged per-asset natural-number conservation, derived from the actual roots. -/
theorem admitted_packed_project_typed_witness_balance {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    V8BalanceValid statement (projectTypedWitness statement packed) := by
  intro slot bound
  change wordAt statement.balanceAssets slot = balancePaddingAssetId ∨ _
  by_cases padding : wordAt statement.balanceAssets slot = balancePaddingAssetId
  · exact Or.inl padding
  · right
    have equation := admitted_typed_field_balance domain bound
    have sums := admitted_typed_value_sum_bounds domain (wordAt statement.balanceAssets slot)
    obtain ⟨_, _, _, _, _, _, _, _, _, _, feeBound, _, _, _, _, compatibility, _⟩ := domain.2.1
    have feeRange : statement.fee < 2 ^ 61 := feeBound
    have magnitudeRange : statement.compatibility.issuanceMagnitude < 2 ^ 61 := by
      have bounded := compatibility.2.2.1
      change statement.compatibility.issuanceMagnitude < 2 ^ 56 at bounded
      omega
    have inputCanonical : inputValueForAsset (projectTypedWitness statement packed)
        (wordAt statement.balanceAssets slot) < fieldModulus := by
      have bound := pair_sum_extra_canonical sums.1 (extra := 0) (by decide)
      simpa only [Nat.add_zero] using bound
    have outputCanonical : outputValueForAsset (projectTypedWitness statement packed)
        (wordAt statement.balanceAssets slot) < fieldModulus := by
      have bound := pair_sum_extra_canonical sums.2 (extra := 0) (by decide)
      simpa only [Nat.add_zero] using bound
    by_cases native : wordAt statement.balanceAssets slot = nativeAssetId
    · rw [if_pos native]
      simp only [typedExpectedField, if_pos native] at equation
      apply canonical_nat_cast_injective inputCanonical (pair_sum_extra_canonical sums.2 feeRange)
      rw [Nat.cast_add]
      linear_combination equation
    · rw [if_neg native]
      simp only [typedExpectedField, if_neg native] at equation
      by_cases stable : statement.compatibility.enabled = 1 ∧
          statement.compatibility.assetId = wordAt statement.balanceAssets slot
      · rw [if_pos stable]
        rw [if_pos stable] at equation
        by_cases mint : statement.compatibility.issuanceSign = 1
        · rw [if_pos mint]
          rw [if_pos mint] at equation
          apply canonical_nat_cast_injective (pair_sum_extra_canonical sums.1 magnitudeRange) outputCanonical
          rw [Nat.cast_add]
          linear_combination equation
        · rw [if_neg mint]
          rw [if_neg mint] at equation
          apply canonical_nat_cast_injective inputCanonical (pair_sum_extra_canonical sums.2 magnitudeRange)
          rw [Nat.cast_add]
          linear_combination equation
      · rw [if_neg stable]
        rw [if_neg stable] at equation
        exact canonical_nat_cast_injective inputCanonical outputCanonical (sub_eq_zero.mp equation)

end HegemonCrypto.SmallWood.V8Smz9SemanticBalance
