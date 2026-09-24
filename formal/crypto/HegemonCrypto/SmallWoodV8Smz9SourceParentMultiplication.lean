import HegemonCrypto.SmallWoodV8Smz9SourceMulResiduals
import HegemonCrypto.SmallWoodV8Smz9SourceRoleAlgebra
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoin

namespace HegemonCrypto.SmallWood.V8Smz9SourceParentMultiplication

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldInverse)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SourceMulResiduals
open HegemonCrypto.SmallWood.V8Smz9SourceRoleAlgebra
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem source_config_retirement (statement : V8PublicStatement) (witness : V8Witness) :
    stableSourceWord statement witness 3 = (decodeV8StablecoinConfig witness.stablecoin).enabledAt ∧
    stableSourceWord statement witness 4 = (decodeV8StablecoinConfig witness.stablecoin).retiredPresent ∧
    stableSourceWord statement witness 5 = (decodeV8StablecoinConfig witness.stablecoin).retiredAt := by
  exact ⟨rfl,rfl,rfl⟩

theorem source_retirement_projections (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) :
    (sourceNumericValues aux).getD 2 0 = aux.retirementOrderGap ∧
    (sourceNumericValues aux).getD 3 0 = aux.retirementHeightGap ∧
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 27 0 = aux.timeCarries 1 ∧
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 28 0 = aux.timeCarries 2 := by
  simp [sourceNumericValues, sourceBooleanValues, List.ofFn_succ]

theorem encoded_parent_height (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    wordAt (encodePublicStatement statement) 94 = statement.stablecoin.parentHeight := by
  change (encodePublicStatement statement).getD (83 + 11) 0 = _
  rw [encoded_stable_public_word statement valid.1]
  have intent : statement.stablecoin.actionIntent.length = 7 :=
    (valid_stable_intent_exact statement witness valid).1
  simp only [encodeStablecoinPublic, List.append_assoc]
  simp only [List.cons_append, List.nil_append, List.getD_cons_succ]
  rw [List.getD_append_right _ _ _ _ (by omega), intent]
  rfl

theorem typed_retired_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (decodeV8StablecoinConfig witness.stablecoin).retiredPresent = 0 →
      (decodeV8StablecoinConfig witness.stablecoin).retiredAt = 0 := by
  have transition : exactV8StableTransition (derivedRelationContext statement)
      statement.stablecoin witness.stablecoin := valid.2.2.2.2
  cases mode : statement.stablecoin.direction with
  | disabled =>
      simp only [exactV8StableTransition, mode] at transition
      obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,zero⟩ := transition
      intro _
      exact HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds.stable_zero_word _ zero 5
  | mint =>
      simp only [exactV8StableTransition, mode] at transition
      obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,retired⟩ := transition.1
      exact retired
  | burn =>
      simp only [exactV8StableTransition, mode] at transition
      obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,retired⟩ := transition.1
      exact retired

theorem typed_selected_carry_bound (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 6) :
    (sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)).getD
      ([23,28,29,35,40,41].getD lane.val 0) 0 ≤ limbBase - 2 := by
  have bounds := valid_numeric_input_bounds statement witness valid
  have left := actual_left_mul3_bounds statement witness bounds
  have right := actual_right_mul3_bounds statement witness bounds
  fin_cases lane <;>
    simp only [List.getD_cons_zero, List.getD_cons_succ] <;>
    simpa only [sourceNumericValues, SourceMul3.rangeValues, List.ofFn_succ,
      List.cons_append, List.nil_append, List.getD_cons_zero, List.getD_cons_succ] using
      (by first | exact left.c0 | exact left.c1 | exact left.c2 |
        exact right.c0 | exact right.c1 | exact right.c2)

theorem typed_carry_inverse (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 6) :
    let left := limbBase - 1 - (sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)).getD
      ([23,28,29,35,40,41].getD lane.val 0) 0
    (left : F) * ((if statement.stablecoin.direction = .mint then fieldInverse left else 0) : Nat) =
      ((if statement.stablecoin.direction = .mint then 1 else 0) : Nat) := by
  dsimp only
  by_cases mint : statement.stablecoin.direction = .mint
  · simp only [if_pos mint, Nat.cast_one]
    have carry := typed_selected_carry_bound statement witness valid lane
    have canonical : limbBase - 1 - (sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)).getD
        ([23,28,29,35,40,41].getD lane.val 0) 0 < fieldModulus :=
      lt_of_le_of_lt (Nat.sub_le _ _) (by decide)
    have nonzero : limbBase - 1 - (sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)).getD
        ([23,28,29,35,40,41].getD lane.val 0) 0 ≠ 0 := by norm_num [limbBase] at carry ⊢; omega
    rw [canonical_inverse_cast _ canonical]
    exact mul_inv_cancel₀ (canonical_nonzero_cast _ canonical nonzero)
  · simp [mint]

theorem actual_retirement_carries (statement : V8PublicStatement) (witness : V8Witness)
    (mint : statement.stablecoin.direction = .mint)
    (retired : (decodeV8StablecoinConfig witness.stablecoin).retiredPresent = 1) :
    let aux := sourceAux statement.stablecoin witness.stablecoin
    aux.timeCarries 1 = sourceTimeCarry (decodeV8StablecoinConfig witness.stablecoin).enabledAt aux.retirementOrderGap 1 ∧
    aux.timeCarries 2 = sourceTimeCarry statement.stablecoin.parentHeight aux.retirementHeightGap 1 := by
  simp [sourceAux, mint, retired]

theorem inactive_retirement_data (statement : V8PublicStatement) (witness : V8Witness)
    (inactive : ¬(statement.stablecoin.direction = .mint ∧
      (decodeV8StablecoinConfig witness.stablecoin).retiredPresent = 1)) :
    let aux := sourceAux statement.stablecoin witness.stablecoin
    aux.retirementOrderGap = 0 ∧ aux.retirementHeightGap = 0 ∧
      aux.timeCarries 1 = 0 ∧ aux.timeCarries 2 = 0 := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · simp [sourceAux, disabled, disabledSourceAux]
  by_cases mint : statement.stablecoin.direction = .mint
  · have retired : (decodeV8StablecoinConfig witness.stablecoin).retiredPresent ≠ 1 := by tauto
    simp [sourceAux, mint, retired]
  · simp [sourceAux, disabled, mint]

theorem typed_retirement_residuals (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (mint : statement.stablecoin.direction = .mint)
    (retired : (decodeV8StablecoinConfig witness.stablecoin).retiredPresent = 1) :
    let config := decodeV8StablecoinConfig witness.stablecoin
    let aux := sourceAux statement.stablecoin witness.stablecoin
    (sourceLowResidual config.enabledAt aux.retirementOrderGap config.retiredAt (aux.timeCarries 1) : F) = 0 ∧
    (sourceHighResidual config.enabledAt aux.retirementOrderGap config.retiredAt (aux.timeCarries 1) : F) = 0 ∧
    (sourceLowResidual statement.stablecoin.parentHeight aux.retirementHeightGap config.retiredAt (aux.timeCarries 2) : F) = 0 ∧
    (sourceHighResidual statement.stablecoin.parentHeight aux.retirementHeightGap config.retiredAt (aux.timeCarries 2) : F) = 0 := by
  have active : statement.stablecoin.direction ≠ .disabled := by rw [mint]; decide
  have checked := valid_source_aux_checked_arithmetic statement witness valid active
  have equalities := (checked.2.2.2.2.2 mint).2.1 retired
  have carries := actual_retirement_carries statement witness mint retired
  have canonical : (decodeV8StablecoinConfig witness.stablecoin).retiredAt < fieldModulus :=
    lt_trans (valid_numeric_input_bounds statement witness valid).retiredAt (by decide)
  dsimp only
  rw [carries.1, carries.2]
  exact ⟨source_low_residual_zero _ _ _ equalities.1,
    source_high_residual_zero _ _ _ equalities.1 canonical,
    source_low_residual_zero _ _ _ equalities.2,
    source_high_residual_zero _ _ _ equalities.2 canonical⟩

theorem typed_source_carry_multiplication (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Nat)
    (lower : 18 ≤ lane) (upper : lane < 24) :
    let tuple := sourceMultiplication statement witness (sourceAux statement.stablecoin witness.stablecoin) lane
    (tuple.a : F) * (tuple.b : F) = (tuple.c : F) := by
  simp only [sourceMultiplication, if_neg (show ¬lane < 18 by omega), if_pos upper]
  have equation := typed_carry_inverse statement witness valid ⟨lane - 18,by omega⟩
  by_cases mint : statement.stablecoin.direction = .mint
  · simpa only [if_pos mint, if_true] using equation
  · simp only [if_neg mint, show ¬(0:Nat)=1 by decide, if_false, Nat.cast_zero, mul_zero]

theorem typed_source_retired_helper_multiplication (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    let tuple := sourceMultiplication statement witness (sourceAux statement.stablecoin witness.stablecoin) 24
    (tuple.a : F) * (tuple.b : F) = (tuple.c : F) := by
  have config := source_config_retirement statement witness
  have retiredBoolean := (valid_config_boolean statement witness valid).2.1
  simp only [sourceMultiplication, show ¬(24:Nat)<18 by decide, show ¬(24:Nat)<24 by decide,
    if_false, if_true]
  rw [config.2.1, config.2.2]
  rcases retiredBoolean with zero | one
  · simp only [zero, typed_retired_zero statement witness valid zero, Nat.cast_zero, mul_zero]
  · simp only [one, Nat.sub_self, Nat.cast_zero, zero_mul]

theorem four_zero_field_getD (a b c d index : Nat)
    (ha : (a : F) = 0) (hb : (b : F) = 0) (hc : (c : F) = 0) (hd : (d : F) = 0) :
    ([a,b,c,d].getD index 0 : F) = 0 := by
  cases index with
  | zero => exact ha
  | succ index => cases index with
    | zero => exact hb
    | succ index => cases index with
      | zero => exact hc
      | succ index => cases index with
        | zero => exact hd
        | succ index => simp

theorem typed_source_retirement_multiplication (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Nat)
    (lower : 25 ≤ lane) (upper : lane < 29) :
    let tuple := sourceMultiplication statement witness (sourceAux statement.stablecoin witness.stablecoin) lane
    (tuple.a : F) * (tuple.b : F) = (tuple.c : F) := by
  have config := source_config_retirement statement witness
  have projections := source_retirement_projections statement witness (sourceAux statement.stablecoin witness.stablecoin)
  have retiredBoolean := (valid_config_boolean statement witness valid).2.1
  simp only [sourceMultiplication, if_neg (show ¬lane < 18 by omega),
    if_neg (show ¬lane < 24 by omega), if_neg (show lane ≠ 24 by omega), if_pos upper]
  rw [config.1,config.2.1,config.2.2,projections.1,projections.2.1,projections.2.2.1,projections.2.2.2,
    encoded_parent_height statement witness valid]
  by_cases mint : statement.stablecoin.direction = .mint
  · simp only [if_pos mint, Nat.one_mul]
    rcases retiredBoolean with zero | one
    · simp only [zero, Nat.cast_zero, zero_mul]
    · have residuals := typed_retirement_residuals statement witness valid mint one
      simp only [one, Nat.cast_one, one_mul, Nat.cast_zero]
      exact four_zero_field_getD _ _ _ _ _ residuals.1 residuals.2.1 residuals.2.2.1 residuals.2.2.2
  · simp only [if_neg mint, Nat.cast_zero, zero_mul]

theorem typed_source_inactive_retirement_multiplication (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Nat) (lower : 29 ≤ lane) (upper : lane < 33) :
    let tuple := sourceMultiplication statement witness (sourceAux statement.stablecoin witness.stablecoin) lane
    (tuple.a : F) * (tuple.b : F) = (tuple.c : F) := by
  have config := source_config_retirement statement witness
  have projections := source_retirement_projections statement witness (sourceAux statement.stablecoin witness.stablecoin)
  simp only [sourceMultiplication, if_neg (show ¬lane < 18 by omega),
    if_neg (show ¬lane < 24 by omega), if_neg (show lane ≠ 24 by omega),
    if_neg (show ¬lane < 29 by omega), if_pos upper]
  rw [config.2.1, projections.1,projections.2.1,projections.2.2.1,projections.2.2.2]
  by_cases active : statement.stablecoin.direction = .mint ∧
      (decodeV8StablecoinConfig witness.stablecoin).retiredPresent = 1
  · simp only [if_pos active.1, active.2, Nat.one_mul, Nat.sub_self, Nat.cast_zero, zero_mul]
  · have zeros := inactive_retirement_data statement witness active
    have cases : lane = 29 ∨ lane = 30 ∨ lane = 31 ∨ lane = 32 := by omega
    rcases cases with rfl | rfl | rfl | rfl <;>
      simp only [zeros.1,zeros.2.1,zeros.2.2.1,zeros.2.2.2,
        Nat.reduceSub, List.getD_cons_zero,List.getD_cons_succ, Nat.cast_zero, mul_zero]

theorem typed_source_parent_multiplication_equation (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Nat) (notBase : 18 ≤ lane) :
    let tuple := sourceMultiplication statement witness (sourceAux statement.stablecoin witness.stablecoin) lane
    (tuple.a : F) * (tuple.b : F) = (tuple.c : F) := by
  by_cases low24 : lane < 24
  · exact typed_source_carry_multiplication statement witness valid lane notBase low24
  by_cases at24 : lane = 24
  · subst lane
    exact typed_source_retired_helper_multiplication statement witness valid
  by_cases low29 : lane < 29
  · exact typed_source_retirement_multiplication statement witness valid lane (by omega) low29
  by_cases low33 : lane < 33
  · exact typed_source_inactive_retirement_multiplication statement witness lane (by omega) low33
  simp only [sourceMultiplication, if_neg (show ¬lane < 18 by omega),
    if_neg low24, if_neg at24, if_neg low29, if_neg low33, Nat.cast_zero, mul_zero]







end HegemonCrypto.SmallWood.V8Smz9SourceParentMultiplication
