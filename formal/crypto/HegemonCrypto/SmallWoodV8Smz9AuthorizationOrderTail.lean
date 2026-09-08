import HegemonCrypto.SmallWoodV8Smz9AuthorizationCanonical

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationOrderTail

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

def thresholdTooLarge (packed : List Nat) : Nat :=
  authorizationRawWord packed 171 * authorizationRawWord packed 176 +
    authorizationRawWord packed 172 *
      (authorizationRawWord packed 176 + authorizationRawWord packed 177) +
    authorizationRawWord packed 173 *
      (authorizationRawWord packed 176 + authorizationRawWord packed 177 +
        authorizationRawWord packed 178) +
    authorizationRawWord packed 174 *
      (authorizationRawWord packed 176 + authorizationRawWord packed 177 +
        authorizationRawWord packed 178 + authorizationRawWord packed 179) +
    authorizationRawWord packed 175 *
      (authorizationRawWord packed 176 + authorizationRawWord packed 177 +
        authorizationRawWord packed 178 + authorizationRawWord packed 179 +
        authorizationRawWord packed 180)

theorem accepted_threshold_too_large_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    thresholdTooLarge packed = 0 := by
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := 1517) (by decide) (by decide)
  have gateOne := authorization_trace_gate_one accepted equations (Or.inr ⟨rfl, mode⟩)
  have t1 := equations 295 (.witnessRow 171) (by decide)
  have t2 := equations 296 (.witnessRow 172) (by decide)
  have t3 := equations 297 (.witnessRow 173) (by decide)
  have t4 := equations 298 (.witnessRow 174) (by decide)
  have t5 := equations 299 (.witnessRow 175) (by decide)
  have s0 := equations 300 (.witnessRow 176) (by decide)
  have s1 := equations 301 (.witnessRow 177) (by decide)
  have s2 := equations 302 (.witnessRow 178) (by decide)
  have s3 := equations 303 (.witnessRow 179) (by decide)
  have s4 := equations 304 (.witnessRow 180) (by decide)
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 171 < 686)] at t1
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 172 < 686)] at t2
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 173 < 686)] at t3
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 174 < 686)] at t4
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 175 < 686)] at t5
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 176 < 686)] at s0
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 177 < 686)] at s1
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 178 < 686)] at s2
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 179 < 686)] at s3
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 180 < 686)] at s4
  have p1 := equations 1489 (.add 300 301) (by decide)
  have p2 := equations 1490 (.add 302 1489) (by decide)
  have p3 := equations 1491 (.add 303 1490) (by decide)
  have p4 := equations 1492 (.add 304 1491) (by decide)
  have v1 := equations 1508 (.mul 295 300) (by decide)
  have v2 := equations 1509 (.mul 296 1489) (by decide)
  have a2 := equations 1510 (.add 1508 1509) (by decide)
  have v3 := equations 1511 (.mul 297 1490) (by decide)
  have a3 := equations 1512 (.add 1510 1511) (by decide)
  have v4 := equations 1513 (.mul 298 1491) (by decide)
  have a4 := equations 1514 (.add 1512 1513) (by decide)
  have v5 := equations 1515 (.mul 299 1492) (by decide)
  have total := equations 1516 (.add 1514 1515) (by decide)
  have root := equations 1517 (.mul 1234 1516) (by decide)
  simp only [expressionField, s0, s1] at p1
  simp only [expressionField, s2, p1] at p2
  simp only [expressionField, s3, p2] at p3
  simp only [expressionField, s4, p3] at p4
  simp only [expressionField, t1, s0] at v1
  simp only [expressionField, t2, p1] at v2
  simp only [expressionField, v1, v2] at a2
  simp only [expressionField, t3, p2] at v3
  simp only [expressionField, a2, v3] at a3
  simp only [expressionField, t4, p3] at v4
  simp only [expressionField, a3, v4] at a4
  simp only [expressionField, t5, p4] at v5
  simp only [expressionField, a4, v5] at total
  simp only [expressionField, gateOne, one_mul, total] at root
  have fieldZero : (thresholdTooLarge packed : F) = 0 := by
    simpa only [thresholdTooLarge, Nat.cast_add, Nat.cast_mul,
      add_assoc, add_comm, add_left_comm] using
      root.symm.trans rootZero
  have thresholdBoolean : ∀ index, index < 6 →
      BooleanWord (authorizationRawWord packed (170 + index)) := by
    intro index bound
    exact accepted_threshold_flag_boolean accepted mode bound
  have upper : thresholdTooLarge packed ≤ 25 := by
    have t1b := thresholdBoolean 1 (by decide)
    have t2b := thresholdBoolean 2 (by decide)
    have t3b := thresholdBoolean 3 (by decide)
    have t4b := thresholdBoolean 4 (by decide)
    have t5b := thresholdBoolean 5 (by decide)
    have signerBoolean : ∀ index, index < 6 →
        BooleanWord (authorizationRawWord packed (176 + index)) := by
      intro index bound
      exact accepted_signer_flag_boolean accepted mode bound
    have leOne (value : Nat) (boolean : BooleanWord value) : value ≤ 1 := by
      rcases boolean with rfl | rfl <;> omega
    have t1le := leOne _ t1b
    have t2le := leOne _ t2b
    have t3le := leOne _ t3b
    have t4le := leOne _ t4b
    have t5le := leOne _ t5b
    have s0le := leOne _ (signerBoolean 0 (by decide))
    have s1le := leOne _ (signerBoolean 1 (by decide))
    have s2le := leOne _ (signerBoolean 2 (by decide))
    have s3le := leOne _ (signerBoolean 3 (by decide))
    have s4le := leOne _ (signerBoolean 4 (by decide))
    norm_num at t1le t2le t3le t4le t5le s0le s1le s2le s3le s4le
    have p1 := Nat.mul_le_mul t1le s0le
    have p2 := Nat.mul_le_mul t2le (Nat.add_le_add s0le s1le)
    have p3 := Nat.mul_le_mul t3le
      (Nat.add_le_add (Nat.add_le_add s0le s1le) s2le)
    have p4 := Nat.mul_le_mul t4le
      (Nat.add_le_add (Nat.add_le_add (Nat.add_le_add s0le s1le) s2le) s3le)
    have p5 := Nat.mul_le_mul t5le
      (Nat.add_le_add
        (Nat.add_le_add (Nat.add_le_add (Nat.add_le_add s0le s1le) s2le) s3le) s4le)
    unfold thresholdTooLarge
    omega
  apply canonical_nat_cast_injective ?_ (by decide) fieldZero
  have modulus : 25 < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by decide
  omega

theorem accepted_threshold_le_signer_count {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    (projectAuthorization packed).current.threshold ≤
      (projectAuthorization packed).current.signerCount := by
  have thresholdSource := accepted_current_threshold_source accepted
  have signerSource := accepted_current_signer_count_source accepted
  have thresholdValue := accepted_threshold_raw_weighted accepted mode
  have signerValue := accepted_signer_raw_weighted accepted mode
  have thresholdSum := accepted_threshold_flags_sum_one accepted mode
  have signerSum := accepted_signer_flags_sum_one accepted mode
  have tooLarge := accepted_threshold_too_large_zero accepted mode
  have t0 := accepted_threshold_flag_boolean accepted mode (index := 0) (by decide)
  have t1 := accepted_threshold_flag_boolean accepted mode (index := 1) (by decide)
  have t2 := accepted_threshold_flag_boolean accepted mode (index := 2) (by decide)
  have t3 := accepted_threshold_flag_boolean accepted mode (index := 3) (by decide)
  have t4 := accepted_threshold_flag_boolean accepted mode (index := 4) (by decide)
  have t5 := accepted_threshold_flag_boolean accepted mode (index := 5) (by decide)
  simp only [authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
    List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
    Nat.add_zero, zero_add] at thresholdSum signerSum
  rw [thresholdSource, thresholdValue, signerSource, signerValue]
  rcases t0 with t0 | t0 <;> rcases t1 with t1 | t1 <;>
    rcases t2 with t2 | t2 <;> rcases t3 with t3 | t3 <;>
    rcases t4 with t4 | t4 <;> rcases t5 with t5 | t5 <;>
    simp [weightedSix, thresholdTooLarge, *] at * <;> omega

theorem accepted_signer_suffix_sum {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) {slot : Nat} (slotBound : slot < 6) :
    (slot < (projectAuthorization packed).current.signerCount →
      authorizationRawSum packed (176 + slot) (6 - slot) = 1) ∧
    ((projectAuthorization packed).current.signerCount ≤ slot →
      authorizationRawSum packed (176 + slot) (6 - slot) = 0) := by
  have source := accepted_current_signer_count_source accepted
  have value := accepted_signer_raw_weighted accepted mode
  have sum := accepted_signer_flags_sum_one accepted mode
  rw [source, value]
  constructor <;> intro comparison <;> interval_cases slot <;>
    simp only [authorizationRawSum, weightedSix, List.range_succ, List.range_zero,
      List.map_append, List.map_cons, List.map_nil, List.sum_append, List.sum_cons,
      List.sum_nil, Nat.add_zero, zero_add, Nat.reduceAdd, Nat.reduceSub]
      at sum comparison ⊢ <;> omega

def signerSuffixNode (slot : Nat) : Nat := [1493, 1617, 1626, 1634, 1641, 305].getD slot 0
def signerInactiveNode (slot : Nat) : Nat := [1608, 1618, 1627, 1635, 1642, 1648].getD slot 0
def approvedScaledNode (slot : Nat) : Nat := [1607, 1613, 1623, 1632, 1640, 1647].getD slot 0
def approvedInactiveRoot (slot : Nat) : Nat := [1609, 1619, 1628, 1636, 1643, 1649].getD slot 0

theorem accepted_signer_suffix_trace {publicWords packed values : List Nat}
    (equations : FieldTraceEquations publicWords
      (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0)
      values exactNonlinearExpressions) {slot : Nat} (slotBound : slot < 6) :
    (values.getD (signerSuffixNode slot) 0 : F) =
      (authorizationRawSum packed (176 + slot) (6 - slot) : F) := by
  have rows : ∀ index, index < 6 →
      (values.getD (300 + index) 0 : F) =
        (authorizationRawWord packed (176 + index) : F) := by
    intro index bound
    have lane := authorization_lane_zero_word packed (row := 176 + index) (by omega)
    simpa only [expressionField, lane] using
      equations (300 + index) (.witnessRow (176 + index)) (by
        interval_cases index <;> decide)
  have s0 := rows 0 (by decide)
  have s1 := rows 1 (by decide)
  have s2 := rows 2 (by decide)
  have s3 := rows 3 (by decide)
  have s4 := rows 4 (by decide)
  have s5 := rows 5 (by decide)
  simp only [Nat.add_zero] at s0
  have all1 := equations 1489 (.add 300 301) (by decide)
  have all2 := equations 1490 (.add 302 1489) (by decide)
  have all3 := equations 1491 (.add 303 1490) (by decide)
  have all4 := equations 1492 (.add 304 1491) (by decide)
  have all5 := equations 1493 (.add 305 1492) (by decide)
  have tail11 := equations 1614 (.add 301 302) (by decide)
  have tail12 := equations 1615 (.add 303 1614) (by decide)
  have tail13 := equations 1616 (.add 304 1615) (by decide)
  have tail14 := equations 1617 (.add 305 1616) (by decide)
  have tail21 := equations 1624 (.add 302 303) (by decide)
  have tail22 := equations 1625 (.add 304 1624) (by decide)
  have tail23 := equations 1626 (.add 305 1625) (by decide)
  have tail31 := equations 1633 (.add 303 304) (by decide)
  have tail32 := equations 1634 (.add 305 1633) (by decide)
  have tail41 := equations 1641 (.add 304 305) (by decide)
  simp only [expressionField, s0, s1] at all1
  simp only [expressionField, s2, all1] at all2
  simp only [expressionField, s3, all2] at all3
  simp only [expressionField, s4, all3] at all4
  simp only [expressionField, s5, all4] at all5
  simp only [expressionField, s1, s2] at tail11
  simp only [expressionField, s3, tail11] at tail12
  simp only [expressionField, s4, tail12] at tail13
  simp only [expressionField, s5, tail13] at tail14
  simp only [expressionField, s2, s3] at tail21
  simp only [expressionField, s4, tail21] at tail22
  simp only [expressionField, s5, tail22] at tail23
  simp only [expressionField, s3, s4] at tail31
  simp only [expressionField, s5, tail31] at tail32
  simp only [expressionField, s4, s5] at tail41
  interval_cases slot
  · change (values.getD 1493 0 : F) = (authorizationRawSum packed 176 6 : F)
    simpa only [authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
      List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
      Nat.add_zero, zero_add, Nat.reduceAdd, Nat.cast_add, Nat.cast_zero,
      add_zero, add_assoc, add_comm, add_left_comm] using all5
  · change (values.getD 1617 0 : F) = (authorizationRawSum packed 177 5 : F)
    simpa only [authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
      List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
      Nat.add_zero, zero_add, Nat.reduceAdd, Nat.cast_add, Nat.cast_zero,
      add_zero, add_assoc, add_comm, add_left_comm] using tail14
  · change (values.getD 1626 0 : F) = (authorizationRawSum packed 178 4 : F)
    simpa only [authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
      List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
      Nat.add_zero, zero_add, Nat.reduceAdd, Nat.cast_add, Nat.cast_zero,
      add_zero, add_assoc, add_comm, add_left_comm] using tail23
  · change (values.getD 1634 0 : F) = (authorizationRawSum packed 179 3 : F)
    simpa only [authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
      List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
      Nat.add_zero, zero_add, Nat.reduceAdd, Nat.cast_add, Nat.cast_zero,
      add_zero, add_assoc, add_comm, add_left_comm] using tail32
  · change (values.getD 1641 0 : F) = (authorizationRawSum packed 180 2 : F)
    simpa only [authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
      List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
      Nat.add_zero, zero_add, Nat.reduceAdd, Nat.cast_add, Nat.cast_zero,
      add_zero, add_assoc, add_comm, add_left_comm] using tail41
  · change (values.getD 305 0 : F) = (authorizationRawSum packed 181 1 : F)
    simpa only [authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
      List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
      Nat.add_zero, zero_add, Nat.reduceAdd, Nat.cast_add, Nat.cast_zero,
      add_zero] using s5

theorem accepted_signer_inactive_trace_one {publicWords packed values : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey)
    (equations : FieldTraceEquations publicWords
      (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0)
      values exactNonlinearExpressions) {slot : Nat}
    (inactive : (projectAuthorization packed).current.signerCount ≤ slot)
    (slotBound : slot < 6) :
    (values.getD (signerInactiveNode slot) 0 : F) = 1 := by
  have suffixZero := (accepted_signer_suffix_sum accepted mode slotBound).2 inactive
  have suffix := accepted_signer_suffix_trace equations slotBound
  rw [suffixZero, Nat.cast_zero] at suffix
  have one := equations 1 (.constant 1) (by decide)
  have inactiveFound : exactNonlinearExpressions[signerInactiveNode slot]? =
      some (.sub 1 (signerSuffixNode slot)) := by
    interval_cases slot <;> decide
  have inactiveValue := equations (signerInactiveNode slot)
    (.sub 1 (signerSuffixNode slot)) inactiveFound
  simp only [expressionField, Nat.cast_one] at one
  simpa only [expressionField, one, suffix, sub_zero] using inactiveValue

theorem accepted_current_bitmap_inactive_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) {slot : Nat}
    (inactive : (projectAuthorization packed).current.signerCount ≤ slot)
    (slotBound : slot < signerCountMaximum) :
    wordAt (projectAuthorization packed).current.approvedSlots slot = 0 := by
  change slot < 6 at slotBound
  have exactNodes :
      exactNonlinearExpressions[signerInactiveNode slot]? = some (.sub 1 (signerSuffixNode slot)) ∧
      exactNonlinearExpressions[approvedScaledNode slot]? = some (.mul (279 + slot) 1234) ∧
      exactNonlinearExpressions[approvedInactiveRoot slot]? =
        some (.mul (approvedScaledNode slot) (signerInactiveNode slot)) ∧
      approvedInactiveRoot slot ∈ exactNonlinearRoots := by
    interval_cases slot <;> decide
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := approvedInactiveRoot slot) (by decide) exactNodes.2.2.2
  have gateOne := authorization_trace_gate_one accepted equations (Or.inr ⟨rfl, mode⟩)
  have inactiveValue := accepted_signer_inactive_trace_one accepted mode equations inactive slotBound
  have approvedRow := equations (279 + slot) (.witnessRow (155 + slot)) (by
    interval_cases slot <;> decide)
  have scaled := equations (approvedScaledNode slot) (.mul (279 + slot) 1234) exactNodes.2.1
  have root := equations (approvedInactiveRoot slot)
    (.mul (approvedScaledNode slot) (signerInactiveNode slot)) exactNodes.2.2.1
  simp only [expressionField, authorization_lane_zero_word packed (by omega : 155 + slot < 686)] at approvedRow
  simp only [expressionField, approvedRow, gateOne, mul_one] at scaled
  simp only [expressionField, scaled, inactiveValue, mul_one] at root
  have rawZero := canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
    (root.symm.trans rootZero)
  rw [accepted_current_bitmap_word accepted slotBound]
  exact rawZero

/-- Arithmetic core shared by current and next accumulator canonicality.  It is
kept independent of the trace proof so applications do not duplicate large
accepted-root proof terms for every concrete suffix slot. -/
theorem boolean_six_sum_le_count (count : Nat) (word : Nat → Nat)
    (countBound : count ≤ 6)
    (boolean : ∀ slot, slot < 6 → BooleanWord (word slot))
    (tail : ∀ slot, count ≤ slot → slot < 6 → word slot = 0) :
    word 0 + word 1 + word 2 + word 3 + word 4 + word 5 ≤ count := by
  have b0 := boolean 0 (by decide)
  have b1 := boolean 1 (by decide)
  have b2 := boolean 2 (by decide)
  have b3 := boolean 3 (by decide)
  have b4 := boolean 4 (by decide)
  have b5 := boolean 5 (by decide)
  have leOne (value : Nat) (isBoolean : BooleanWord value) : value ≤ 1 := by
    rcases isBoolean with rfl | rfl <;> omega
  have b0le : word 0 ≤ 1 := leOne _ b0
  have b1le : word 1 ≤ 1 := leOne _ b1
  have b2le : word 2 ≤ 1 := leOne _ b2
  have b3le : word 3 ≤ 1 := leOne _ b3
  have b4le : word 4 ≤ 1 := leOne _ b4
  have b5le : word 5 ≤ 1 := leOne _ b5
  by_cases c0 : count = 0
  · have z0 := tail 0 (by omega) (by decide)
    have z1 := tail 1 (by omega) (by decide)
    have z2 := tail 2 (by omega) (by decide)
    have z3 := tail 3 (by omega) (by decide)
    have z4 := tail 4 (by omega) (by decide)
    have z5 := tail 5 (by omega) (by decide)
    omega
  · by_cases c1 : count = 1
    · have z1 := tail 1 (by omega) (by decide)
      have z2 := tail 2 (by omega) (by decide)
      have z3 := tail 3 (by omega) (by decide)
      have z4 := tail 4 (by omega) (by decide)
      have z5 := tail 5 (by omega) (by decide)
      omega
    · by_cases c2 : count = 2
      · have z2 := tail 2 (by omega) (by decide)
        have z3 := tail 3 (by omega) (by decide)
        have z4 := tail 4 (by omega) (by decide)
        have z5 := tail 5 (by omega) (by decide)
        omega
      · by_cases c3 : count = 3
        · have z3 := tail 3 (by omega) (by decide)
          have z4 := tail 4 (by omega) (by decide)
          have z5 := tail 5 (by omega) (by decide)
          omega
        · by_cases c4 : count = 4
          · have z4 := tail 4 (by omega) (by decide)
            have z5 := tail 5 (by omega) (by decide)
            omega
          · by_cases c5 : count = 5
            · have z5 := tail 5 (by omega) (by decide)
              omega
            · omega

theorem accepted_current_raw_bitmap_sum_le_signer {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    authorizationRawSum packed 155 6 ≤
      (projectAuthorization packed).current.signerCount := by
  have boolean : ∀ slot, slot < 6 → BooleanWord (authorizationRawWord packed (155 + slot)) := by
    intro slot bound
    exact accepted_current_bitmap_boolean accepted mode bound
  have tail : ∀ slot, (projectAuthorization packed).current.signerCount ≤ slot → slot < 6 →
      authorizationRawWord packed (155 + slot) = 0 := by
    intro slot inactive bound
    have zero := accepted_current_bitmap_inactive_zero accepted mode inactive (by
      simpa only [signerCountMaximum] using bound)
    rw [accepted_current_bitmap_word accepted bound] at zero
    exact zero
  have signerBound := (accepted_non_single_signer_count_bounds accepted mode).2
  let count := (projectAuthorization packed).current.signerCount
  let word := fun slot => authorizationRawWord packed (155 + slot)
  have countBound : count ≤ 6 := by simpa [count, signerCountMaximum] using signerBound
  have wordsBound := boolean_six_sum_le_count count word countBound boolean tail
  simpa [authorizationRawSum, count, word, List.range_succ, Nat.add_assoc] using wordsBound

theorem accepted_current_approval_count_le_signer {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    (projectAuthorization packed).current.approvalCount ≤
      (projectAuthorization packed).current.signerCount := by
  have countSource := accepted_current_opening_source_word accepted (word := 16) (by decide)
  change spongeSourceWord packed 98 16 ≤ spongeSourceWord packed 98 15
  rw [countSource, accepted_current_raw_count accepted mode]
  simpa [projectAuthorization, projectAccumulator] using
    accepted_current_raw_bitmap_sum_le_signer accepted mode


end HegemonCrypto.SmallWood.V8Smz9AuthorizationOrderTail
