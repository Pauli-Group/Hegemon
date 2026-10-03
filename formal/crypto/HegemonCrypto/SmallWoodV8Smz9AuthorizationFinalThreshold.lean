import HegemonCrypto.SmallWoodV8Smz9AuthorizationCanonical

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationFinalThreshold

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle
open HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonical
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

/-- The current approval-count scalar is encoded by count flags 1 through 6;
flag zero has coefficient zero and is intentionally outside `weightedSix`. -/
def countScalarSource : WeightedScalarSource :=
  ⟨154, 183, 278, 307, 1547, 1548, 1549, 1550, 1460, 1551, 1552,
    1463, 1553, 1554, 1466, 1555, 1556, 1557, 1558⟩

theorem exact_count_scalar_data : countScalarSource.Valid := by decide

theorem accepted_current_raw_count_weighted {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    authorizationRawWord packed 154 = weightedSix packed 183 := by
  exact accepted_raw_scalar_weighted accepted mode countScalarSource exact_count_scalar_data (by
    intro index bound
    have shifted : index + 1 < 7 := by omega
    change BooleanWord (authorizationRawWord packed (183 + index))
    simpa only [show 183 + index = 182 + (index + 1) by omega] using
      accepted_count_flag_boolean accepted mode shifted)

theorem accepted_current_approval_count_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (projectAuthorization packed).current.approvalCount = authorizationRawWord packed 154 := by
  have source := accepted_current_opening_source_word accepted (word := 16) (by decide)
  simpa [projectAuthorization, projectAccumulator] using source

/-- Sum of the one-hot `(threshold, approvalCount)` combinations for which the
approval count is strictly below the threshold. -/
def finalBelowThreshold (packed : List Nat) : Nat :=
  authorizationRawWord packed 170 * authorizationRawWord packed 182 +
    authorizationRawWord packed 171 *
      (authorizationRawWord packed 182 + authorizationRawWord packed 183) +
    authorizationRawWord packed 172 *
      (authorizationRawWord packed 182 + authorizationRawWord packed 183 +
        authorizationRawWord packed 184) +
    authorizationRawWord packed 173 *
      (authorizationRawWord packed 182 + authorizationRawWord packed 183 +
        authorizationRawWord packed 184 + authorizationRawWord packed 185) +
    authorizationRawWord packed 174 *
      (authorizationRawWord packed 182 + authorizationRawWord packed 183 +
        authorizationRawWord packed 184 + authorizationRawWord packed 185 +
        authorizationRawWord packed 186) +
    authorizationRawWord packed 175 *
      (authorizationRawWord packed 182 + authorizationRawWord packed 183 +
        authorizationRawWord packed 184 + authorizationRawWord packed 185 +
        authorizationRawWord packed 186 + authorizationRawWord packed 187)

theorem accepted_final_below_threshold_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) :
    finalBelowThreshold packed = 0 := by
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := 1999) (by decide) (by decide)
  have gate := equations 218 (.witnessRow 94) (by decide)
  have modeAddress : authorizationRawWord packed 94 = authorizationWord packed 2 :=
    authorization_raw_mode_word packed 2
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 94 < 686), modeAddress,
    accepted_final_mode_word accepted mode, Nat.cast_one] at gate
  have t0 := equations 294 (.witnessRow 170) (by decide)
  have t1 := equations 295 (.witnessRow 171) (by decide)
  have t2 := equations 296 (.witnessRow 172) (by decide)
  have t3 := equations 297 (.witnessRow 173) (by decide)
  have t4 := equations 298 (.witnessRow 174) (by decide)
  have t5 := equations 299 (.witnessRow 175) (by decide)
  have c0 := equations 306 (.witnessRow 182) (by decide)
  have c1 := equations 307 (.witnessRow 183) (by decide)
  have c2 := equations 308 (.witnessRow 184) (by decide)
  have c3 := equations 309 (.witnessRow 185) (by decide)
  have c4 := equations 310 (.witnessRow 186) (by decide)
  have c5 := equations 311 (.witnessRow 187) (by decide)
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 170 < 686)] at t0
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 171 < 686)] at t1
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 172 < 686)] at t2
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 173 < 686)] at t3
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 174 < 686)] at t4
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 175 < 686)] at t5
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 182 < 686)] at c0
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 183 < 686)] at c1
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 184 < 686)] at c2
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 185 < 686)] at c3
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 186 < 686)] at c4
  simp only [expressionField,
    authorization_lane_zero_word packed (by decide : 187 < 686)] at c5
  have prefix1 := equations 1539 (.add 306 307) (by decide)
  have prefix2 := equations 1540 (.add 308 1539) (by decide)
  have prefix3 := equations 1541 (.add 309 1540) (by decide)
  have prefix4 := equations 1542 (.add 310 1541) (by decide)
  have prefix5 := equations 1543 (.add 311 1542) (by decide)
  simp only [expressionField, c0, c1] at prefix1
  simp only [expressionField, c2, prefix1] at prefix2
  simp only [expressionField, c3, prefix2] at prefix3
  simp only [expressionField, c4, prefix3] at prefix4
  simp only [expressionField, c5, prefix4] at prefix5
  have v0 := equations 1988 (.mul 294 306) (by decide)
  have v1 := equations 1989 (.mul 295 1539) (by decide)
  have a1 := equations 1990 (.add 1988 1989) (by decide)
  have v2 := equations 1991 (.mul 296 1540) (by decide)
  have a2 := equations 1992 (.add 1990 1991) (by decide)
  have v3 := equations 1993 (.mul 297 1541) (by decide)
  have a3 := equations 1994 (.add 1992 1993) (by decide)
  have v4 := equations 1995 (.mul 298 1542) (by decide)
  have a4 := equations 1996 (.add 1994 1995) (by decide)
  have v5 := equations 1997 (.mul 299 1543) (by decide)
  have total := equations 1998 (.add 1996 1997) (by decide)
  have root := equations 1999 (.mul 218 1998) (by decide)
  simp only [expressionField, t0, c0] at v0
  simp only [expressionField, t1, prefix1] at v1
  simp only [expressionField, v0, v1] at a1
  simp only [expressionField, t2, prefix2] at v2
  simp only [expressionField, a1, v2] at a2
  simp only [expressionField, t3, prefix3] at v3
  simp only [expressionField, a2, v3] at a3
  simp only [expressionField, t4, prefix4] at v4
  simp only [expressionField, a3, v4] at a4
  simp only [expressionField, t5, prefix5] at v5
  simp only [expressionField, a4, v5] at total
  simp only [expressionField, gate, total, one_mul] at root
  have fieldZero : (finalBelowThreshold packed : F) = 0 := by
    simpa only [finalBelowThreshold, Nat.cast_add, Nat.cast_mul,
      add_assoc, add_comm, add_left_comm] using root.symm.trans rootZero
  have thresholdBoolean : ∀ index, index < 6 →
      BooleanWord (authorizationRawWord packed (170 + index)) := by
    intro index bound
    have notSingle : projectAuthorizationMode packed ≠ .singleKey := by
      simp only [mode]
      decide
    exact accepted_threshold_flag_boolean accepted notSingle bound
  have countBoolean : ∀ index, index < 6 →
      BooleanWord (authorizationRawWord packed (182 + index)) := by
    intro index bound
    have notSingle : projectAuthorizationMode packed ≠ .singleKey := by
      simp only [mode]
      decide
    exact accepted_count_flag_boolean accepted notSingle (by omega)
  have upper : finalBelowThreshold packed ≤ 21 := by
    have leOne (value : Nat) (boolean : BooleanWord value) : value ≤ 1 := by
      rcases boolean with rfl | rfl <;> omega
    have t0le := leOne _ (thresholdBoolean 0 (by decide))
    have t1le := leOne _ (thresholdBoolean 1 (by decide))
    have t2le := leOne _ (thresholdBoolean 2 (by decide))
    have t3le := leOne _ (thresholdBoolean 3 (by decide))
    have t4le := leOne _ (thresholdBoolean 4 (by decide))
    have t5le := leOne _ (thresholdBoolean 5 (by decide))
    have c0le := leOne _ (countBoolean 0 (by decide))
    have c1le := leOne _ (countBoolean 1 (by decide))
    have c2le := leOne _ (countBoolean 2 (by decide))
    have c3le := leOne _ (countBoolean 3 (by decide))
    have c4le := leOne _ (countBoolean 4 (by decide))
    have c5le := leOne _ (countBoolean 5 (by decide))
    have p0 := Nat.mul_le_mul t0le c0le
    have p1 := Nat.mul_le_mul t1le (Nat.add_le_add c0le c1le)
    have p2 := Nat.mul_le_mul t2le
      (Nat.add_le_add (Nat.add_le_add c0le c1le) c2le)
    have p3 := Nat.mul_le_mul t3le
      (Nat.add_le_add (Nat.add_le_add (Nat.add_le_add c0le c1le) c2le) c3le)
    have p4 := Nat.mul_le_mul t4le
      (Nat.add_le_add
        (Nat.add_le_add (Nat.add_le_add (Nat.add_le_add c0le c1le) c2le) c3le) c4le)
    have p5 := Nat.mul_le_mul t5le
      (Nat.add_le_add (Nat.add_le_add
        (Nat.add_le_add (Nat.add_le_add (Nat.add_le_add c0le c1le) c2le) c3le) c4le) c5le)
    simp only [Nat.reduceAdd, Nat.one_mul] at p0 p1 p2 p3 p4 p5
    unfold finalBelowThreshold
    omega
  apply canonical_nat_cast_injective ?_ (by decide) fieldZero
  have modulus : 21 < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by decide
  omega

theorem final_threshold_arithmetic (packed : List Nat)
    (thresholdSum : authorizationRawSum packed 170 6 = 1)
    (countSum : authorizationRawSum packed 182 7 = 1)
    (below : finalBelowThreshold packed = 0)
    (thresholdBoolean : ∀ index, index < 6 → BooleanWord (authorizationRawWord packed (170 + index))) :
    weightedSix packed 170 ≤ weightedSix packed 183 := by
  have t0 := thresholdBoolean 0 (by decide)
  have t1 := thresholdBoolean 1 (by decide)
  have t2 := thresholdBoolean 2 (by decide)
  have t3 := thresholdBoolean 3 (by decide)
  have t4 := thresholdBoolean 4 (by decide)
  have t5 := thresholdBoolean 5 (by decide)
  simp only [authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
    List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
    Nat.add_zero, zero_add] at thresholdSum countSum
  rcases t0 with t0 | t0 <;> rcases t1 with t1 | t1 <;>
    rcases t2 with t2 | t2 <;> rcases t3 with t3 | t3 <;>
    rcases t4 with t4 | t4 <;> rcases t5 with t5 | t5 <;>
    simp [weightedSix, finalBelowThreshold, *] at * <;> omega

theorem accepted_final_approval_count_ge_threshold {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) :
    (projectAuthorization packed).current.threshold ≤
      (projectAuthorization packed).current.approvalCount := by
  have notSingle : projectAuthorizationMode packed ≠ .singleKey := by
    simp only [mode]
    decide
  rw [accepted_current_threshold_source accepted,
    accepted_threshold_raw_weighted accepted notSingle,
    accepted_current_approval_count_source accepted,
    accepted_current_raw_count_weighted accepted notSingle]
  exact final_threshold_arithmetic packed
    (accepted_threshold_flags_sum_one accepted notSingle)
    (accepted_count_flags_sum_one accepted notSingle)
    (accepted_final_below_threshold_zero accepted mode)
    (by intro index bound; exact accepted_threshold_flag_boolean accepted notSingle bound)


end HegemonCrypto.SmallWood.V8Smz9AuthorizationFinalThreshold
