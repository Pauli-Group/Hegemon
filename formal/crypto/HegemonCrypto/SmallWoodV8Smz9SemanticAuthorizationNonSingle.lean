import HegemonCrypto.SmallWoodV8Smz9SemanticAuthorization
import Mathlib.Algebra.BigOperators.Fin

/-!
Non-single-key private authorization from actual HGV8RP03 roots and packed
coordinates. The checked single-key/source-opening prefix is a separate frozen
module. These results must not assume a canonical accumulator, an honest
lowering, or a detailed authorization receipt.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (FieldExpression packedWitnessLaneRows)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem authorization_raw_mode_word (packed : List Nat) (mode : Nat) :
    authorizationRawWord packed (92 + mode) = authorizationWord packed mode := by
  simp only [authorizationRawWord, authorizationWord,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.authorizationModeRow,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add]

theorem accepted_non_single_mode_sum {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    authorizationWord packed 1 + authorizationWord packed 2 = 1 := by
  rcases accepted_authorization_one_hot accepted with ⟨single, approval, finalMode⟩ |
      ⟨single, approval, finalMode⟩ | ⟨single, approval, finalMode⟩
  · exfalso
    apply mode
    simp only [authorizationWord] at single approval finalMode
    simp [projectAuthorizationMode, single, approval, finalMode]
  · omega
  · omega

def AuthorizationGateEnabled (packed : List Nat) (gate : Nat) : Prop :=
  (gate = 217 ∧ projectAuthorizationMode packed = .approvalStep) ∨
    (gate = 1234 ∧ projectAuthorizationMode packed ≠ .singleKey)

theorem authorization_trace_gate_one {publicWords packed values : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (equations : FieldTraceEquations publicWords (packedWitnessLaneRows packed 0)
      values exactNonlinearExpressions)
    {gate : Nat} (enabled : AuthorizationGateEnabled packed gate) :
    (values.getD gate 0 : F) = 1 := by
  have approval := equations 217 (.witnessRow 93) (by decide)
  have finalMode := equations 218 (.witnessRow 94) (by decide)
  have approvalAddress : authorizationRawWord packed 93 = authorizationWord packed 1 :=
    authorization_raw_mode_word packed 1
  have finalAddress : authorizationRawWord packed 94 = authorizationWord packed 2 :=
    authorization_raw_mode_word packed 2
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 93 < 686),
    approvalAddress] at approval
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 94 < 686),
    finalAddress] at finalMode
  rcases enabled with ⟨rfl, mode⟩ | ⟨rfl, mode⟩
  · simpa only [accepted_approval_mode_word accepted mode, Nat.cast_one] using approval
  · have gateEquation := equations 1234 (.add 217 218) (by decide)
    simp only [expressionField, approval, finalMode] at gateEquation
    have natural := congrArg (fun word : Nat => (word : F))
      (accepted_non_single_mode_sum accepted mode)
    exact gateEquation.trans (by simpa only [Nat.cast_add, Nat.cast_one] using natural)

structure AuthorizationBooleanSource where
  row : Nat
  gate : Nat
  root : Nat
deriving DecidableEq, Repr, Inhabited

def AuthorizationBooleanSource.Valid (entry : AuthorizationBooleanSource) : Prop :=
  entry.row < 686 ∧
    exactNonlinearExpressions[124 + entry.row]? = some (.witnessRow entry.row) ∧
    exactNonlinearExpressions[entry.root - 2]? = some (.sub (124 + entry.row) 1) ∧
    exactNonlinearExpressions[entry.root - 1]? = some (.mul (124 + entry.row) (entry.root - 2)) ∧
    exactNonlinearExpressions[entry.root]? = some (.mul entry.gate (entry.root - 1)) ∧
    entry.root ∈ exactNonlinearRoots

instance (entry : AuthorizationBooleanSource) : Decidable entry.Valid := by
  unfold AuthorizationBooleanSource.Valid
  infer_instance

def authorizationBooleanFamilySize (family : Nat) : Nat :=
  if family = 2 ∨ family = 3 then 7 else 6

def authorizationBooleanSourceAt (family index : Nat) : AuthorizationBooleanSource :=
  if family = 0 then ⟨170 + index, 1234, 1433 + 3 * index⟩
  else if family = 1 then ⟨176 + index, 1234, 1473 + 3 * index⟩
  else if family = 2 then ⟨182 + index, 1234, 1520 + 3 * index⟩
  else if family = 3 then ⟨189 + index, 217, 1561 + 3 * index⟩
  else if family = 4 then ⟨155 + index, 1234,
    [1606, 1612, 1622, 1631, 1639, 1646].getD index 0⟩
  else if family = 5 then ⟨162 + index, 217, 1659 + 5 * index⟩
  else ⟨226 + index, 217, 1728 + 3 * index⟩

def authorizationBooleanSources : List AuthorizationBooleanSource :=
  (List.range 7).flatMap (fun family =>
    (List.range (authorizationBooleanFamilySize family)).map (authorizationBooleanSourceAt family))

theorem exact_authorization_boolean_family0 : ∀ index : Fin 6,
    (authorizationBooleanSourceAt 0 index.val).Valid := by decide

theorem exact_authorization_boolean_family1 : ∀ index : Fin 6,
    (authorizationBooleanSourceAt 1 index.val).Valid := by decide

theorem exact_authorization_boolean_family2 : ∀ index : Fin 7,
    (authorizationBooleanSourceAt 2 index.val).Valid := by decide

theorem exact_authorization_boolean_family3 : ∀ index : Fin 7,
    (authorizationBooleanSourceAt 3 index.val).Valid := by decide

theorem exact_authorization_boolean_family4 : ∀ index : Fin 6,
    (authorizationBooleanSourceAt 4 index.val).Valid := by decide

theorem exact_authorization_boolean_family5 : ∀ index : Fin 6,
    (authorizationBooleanSourceAt 5 index.val).Valid := by decide

theorem exact_authorization_boolean_family6 : ∀ index : Fin 6,
    (authorizationBooleanSourceAt 6 index.val).Valid := by decide

theorem authorization_boolean_source_at_valid {family index : Nat}
    (familyBound : family < 7) (indexBound : index < authorizationBooleanFamilySize family) :
    (authorizationBooleanSourceAt family index).Valid := by
  have cases : family = 0 ∨ family = 1 ∨ family = 2 ∨ family = 3 ∨
      family = 4 ∨ family = 5 ∨ family = 6 := by omega
  rcases cases with rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · exact exact_authorization_boolean_family0 ⟨index, indexBound⟩
  · exact exact_authorization_boolean_family1 ⟨index, indexBound⟩
  · exact exact_authorization_boolean_family2 ⟨index, indexBound⟩
  · exact exact_authorization_boolean_family3 ⟨index, indexBound⟩
  · exact exact_authorization_boolean_family4 ⟨index, indexBound⟩
  · exact exact_authorization_boolean_family5 ⟨index, indexBound⟩
  · exact exact_authorization_boolean_family6 ⟨index, indexBound⟩

theorem exact_authorization_boolean_sources : ∀ entry, entry ∈ authorizationBooleanSources →
    entry.Valid := by
  intro entry member
  obtain ⟨family, familyMember, entryMember⟩ := List.mem_flatMap.mp member
  obtain ⟨index, indexMember, rfl⟩ := List.mem_map.mp entryMember
  exact authorization_boolean_source_at_valid (List.mem_range.mp familyMember)
    (List.mem_range.mp indexMember)

theorem accepted_authorization_boolean_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (entry : AuthorizationBooleanSource) (valid : entry.Valid)
    (enabled : AuthorizationGateEnabled packed entry.gate) :
    BooleanWord (authorizationRawWord packed entry.row) := by
  obtain ⟨rowBound, rowNode, differenceNode, productNode, rootNode, rootMember⟩ := valid
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := entry.root) (by decide) rootMember
  have gateOne := authorization_trace_gate_one accepted equations enabled
  have one := equations 1 (.constant 1) (by decide)
  have row := equations (124 + entry.row) (.witnessRow entry.row) rowNode
  have difference := equations (entry.root - 2) (.sub (124 + entry.row) 1) differenceNode
  have product := equations (entry.root - 1) (.mul (124 + entry.row) (entry.root - 2)) productNode
  have root := equations entry.root (.mul entry.gate (entry.root - 1)) rootNode
  simp only [expressionField, Nat.cast_one] at one
  simp only [expressionField, authorization_lane_zero_word packed rowBound] at row
  simp only [expressionField] at difference product root
  rw [gateOne, one_mul, product, difference, row, one] at root
  have zero : (authorizationRawWord packed entry.row : F) *
      ((authorizationRawWord packed entry.row : F) - 1) = 0 := root.symm.trans rootZero
  rcases mul_eq_zero.mp zero with zero | one
  · exact Or.inl (canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide) zero)
  · exact Or.inr (canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
      (sub_eq_zero.mp one))

theorem accepted_threshold_flag_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey)
    {index : Nat} (bound : index < 6) : BooleanWord (authorizationRawWord packed (170 + index)) := by
  exact accepted_authorization_boolean_source accepted (authorizationBooleanSourceAt 0 index)
    (authorization_boolean_source_at_valid (by decide) bound) (Or.inr ⟨rfl, mode⟩)

theorem accepted_signer_flag_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey)
    {index : Nat} (bound : index < 6) : BooleanWord (authorizationRawWord packed (176 + index)) := by
  exact accepted_authorization_boolean_source accepted (authorizationBooleanSourceAt 1 index)
    (authorization_boolean_source_at_valid (by decide) bound) (Or.inr ⟨rfl, mode⟩)

theorem accepted_count_flag_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey)
    {index : Nat} (bound : index < 7) : BooleanWord (authorizationRawWord packed (182 + index)) := by
  exact accepted_authorization_boolean_source accepted (authorizationBooleanSourceAt 2 index)
    (authorization_boolean_source_at_valid (by decide) bound) (Or.inr ⟨rfl, mode⟩)

theorem accepted_next_count_flag_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    {index : Nat} (bound : index < 7) : BooleanWord (authorizationRawWord packed (189 + index)) := by
  exact accepted_authorization_boolean_source accepted (authorizationBooleanSourceAt 3 index)
    (authorization_boolean_source_at_valid (by decide) bound) (Or.inl ⟨rfl, mode⟩)

theorem accepted_current_bitmap_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey)
    {index : Nat} (bound : index < 6) : BooleanWord (authorizationRawWord packed (155 + index)) := by
  exact accepted_authorization_boolean_source accepted (authorizationBooleanSourceAt 4 index)
    (authorization_boolean_source_at_valid (by decide) bound) (Or.inr ⟨rfl, mode⟩)

theorem accepted_next_bitmap_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    {index : Nat} (bound : index < 6) : BooleanWord (authorizationRawWord packed (162 + index)) := by
  exact accepted_authorization_boolean_source accepted (authorizationBooleanSourceAt 5 index)
    (authorization_boolean_source_at_valid (by decide) bound) (Or.inl ⟨rfl, mode⟩)

theorem accepted_membership_flag_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    {index : Nat} (bound : index < 6) : BooleanWord (authorizationRawWord packed (226 + index)) := by
  exact accepted_authorization_boolean_source accepted (authorizationBooleanSourceAt 6 index)
    (authorization_boolean_source_at_valid (by decide) bound) (Or.inl ⟨rfl, mode⟩)

def authorizationRawSum (packed : List Nat) (row count : Nat) : Nat :=
  ((List.range count).map (fun index => authorizationRawWord packed (row + index))).sum

theorem authorization_raw_sum_succ (packed : List Nat) (row count : Nat) :
    authorizationRawSum packed row (count + 1) =
      authorizationRawSum packed row count + authorizationRawWord packed (row + count) := by
  simp only [authorizationRawSum, List.range_succ, List.map_append, List.sum_append,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero]

theorem boolean_range_sum_le_count (words : Nat → Nat) (count : Nat)
    (boolean : ∀ index, index < count → BooleanWord (words index)) :
    ((List.range count).map words).sum ≤ count := by
  induction count with
  | zero => simp
  | succ count ih =>
      have prior := ih (by intro index bound; exact boolean index (by omega))
      have last := boolean count (by omega)
      simp only [List.range_succ, List.map_append, List.sum_append, List.map_cons,
        List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero]
      rcases last with last | last <;> omega

structure AuthorizationOneHotSource where
  row : Nat
  count : Nat
  sumStart : Nat
  gate : Nat
  root : Nat
deriving DecidableEq, Repr, Inhabited

def AuthorizationOneHotSource.Valid (entry : AuthorizationOneHotSource) : Prop :=
  2 ≤ entry.count ∧ entry.count ≤ 7 ∧ entry.row + entry.count ≤ 686 ∧
    (∀ index, index ∈ List.range entry.count →
      exactNonlinearExpressions[124 + (entry.row + index)]? = some (.witnessRow (entry.row + index))) ∧
    exactNonlinearExpressions[entry.sumStart]? =
      some (.add (124 + entry.row) (124 + (entry.row + 1))) ∧
    (∀ index, index ∈ List.range (entry.count - 2) →
      exactNonlinearExpressions[entry.sumStart + (index + 1)]? =
        some (.add (124 + (entry.row + (index + 2))) (entry.sumStart + index))) ∧
    exactNonlinearExpressions[entry.root - 1]? =
      some (.sub (entry.sumStart + (entry.count - 2)) 1) ∧
    exactNonlinearExpressions[entry.root]? = some (.mul entry.gate (entry.root - 1)) ∧
    entry.root ∈ exactNonlinearRoots

instance (entry : AuthorizationOneHotSource) : Decidable entry.Valid := by
  unfold AuthorizationOneHotSource.Valid
  infer_instance

def authorizationOneHotSourceAt (family : Nat) : AuthorizationOneHotSource :=
  if family = 0 then ⟨170, 6, 1449, 1234, 1455⟩
  else if family = 1 then ⟨176, 6, 1489, 1234, 1495⟩
  else if family = 2 then ⟨182, 7, 1539, 1234, 1546⟩
  else if family = 3 then ⟨189, 7, 1580, 217, 1587⟩
  else ⟨226, 6, 1744, 217, 1750⟩

theorem exact_authorization_one_hot_source {family : Nat} (bound : family < 5) :
    (authorizationOneHotSourceAt family).Valid := by
  have cases : family = 0 ∨ family = 1 ∨ family = 2 ∨ family = 3 ∨ family = 4 := by omega
  rcases cases with rfl | rfl | rfl | rfl | rfl <;> decide

theorem authorization_trace_one_hot_sum {publicWords packed values : List Nat}
    (equations : FieldTraceEquations publicWords (packedWitnessLaneRows packed 0)
      values exactNonlinearExpressions)
    (entry : AuthorizationOneHotSource) (valid : entry.Valid) :
    (values.getD (entry.sumStart + (entry.count - 2)) 0 : F) =
      (authorizationRawSum packed entry.row entry.count : F) := by
  obtain ⟨countLower, _, rowBound, rowNodes, firstNode, subsequentNodes, _, _, _⟩ := valid
  have rows : ∀ index, index < entry.count →
      (values.getD (124 + (entry.row + index)) 0 : F) =
        (authorizationRawWord packed (entry.row + index) : F) := by
    intro index bound
    have row := equations (124 + (entry.row + index)) (.witnessRow (entry.row + index))
      (rowNodes index (List.mem_range.mpr bound))
    simpa only [expressionField, authorization_lane_zero_word packed (by omega : entry.row + index < 686)] using row
  have partialSum : ∀ extra, extra + 2 ≤ entry.count →
      (values.getD (entry.sumStart + extra) 0 : F) =
        (authorizationRawSum packed entry.row (extra + 2) : F) := by
    intro extra
    induction extra with
    | zero =>
        intro bound
        have first := equations entry.sumStart
          (.add (124 + entry.row) (124 + (entry.row + 1))) firstNode
        have rowZero := rows 0 (by omega)
        have rowOne := rows 1 (by omega)
        simp only [Nat.add_zero] at rowZero
        simpa only [Nat.zero_add, Nat.add_zero, expressionField, rowZero, rowOne,
          authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
          List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
          Nat.cast_add, Nat.cast_zero, zero_add, add_zero] using first
    | succ extra ih =>
        intro bound
        have prior := ih (by omega)
        have next := equations (entry.sumStart + (extra + 1))
          (.add (124 + (entry.row + (extra + 2))) (entry.sumStart + extra))
          (subsequentNodes extra (List.mem_range.mpr (by omega)))
        have nextRow := rows (extra + 2) (by omega)
        simp only [expressionField, nextRow, prior] at next
        have size : extra + 1 + 2 = (extra + 2) + 1 := by omega
        have sumStep : (authorizationRawSum packed entry.row (extra + 1 + 2) : F) =
            (authorizationRawSum packed entry.row (extra + 2) : F) +
              (authorizationRawWord packed (entry.row + (extra + 2)) : F) := by
          rw [size, authorization_raw_sum_succ packed entry.row (extra + 2), Nat.cast_add]
        exact (next.trans (add_comm _ _)).trans sumStep.symm
  have final := partialSum (entry.count - 2) (by omega)
  have size : entry.count - 2 + 2 = entry.count := by omega
  simpa only [size] using final

theorem accepted_authorization_one_hot_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (entry : AuthorizationOneHotSource) (valid : entry.Valid)
    (enabled : AuthorizationGateEnabled packed entry.gate)
    (boolean : ∀ index, index < entry.count →
      BooleanWord (authorizationRawWord packed (entry.row + index))) :
    authorizationRawSum packed entry.row entry.count = 1 := by
  have small := valid.2.1
  have validCopy := valid
  obtain ⟨_, _, _, _, _, _, differenceNode, rootNode, rootMember⟩ := validCopy
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := entry.root) (by decide) rootMember
  have gateOne := authorization_trace_gate_one accepted equations enabled
  have sum := authorization_trace_one_hot_sum equations entry valid
  have one := equations 1 (.constant 1) (by decide)
  have difference := equations (entry.root - 1) (.sub (entry.sumStart + (entry.count - 2)) 1) differenceNode
  have root := equations entry.root (.mul entry.gate (entry.root - 1)) rootNode
  simp only [expressionField, Nat.cast_one] at one
  simp only [expressionField] at difference root
  rw [gateOne, one_mul, difference, sum, one] at root
  have fieldOne := sub_eq_zero.mp (root.symm.trans rootZero)
  have sumBound := boolean_range_sum_le_count
    (fun index => authorizationRawWord packed (entry.row + index)) entry.count boolean
  apply canonical_nat_cast_injective (right := 1) ?_ (by decide) fieldOne
  change authorizationRawSum packed entry.row entry.count ≤ entry.count at sumBound
  have modulusBound : 7 < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by decide
  omega

theorem accepted_threshold_flags_sum_one {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) : authorizationRawSum packed 170 6 = 1 := by
  exact accepted_authorization_one_hot_source accepted (authorizationOneHotSourceAt 0)
    (exact_authorization_one_hot_source (by decide)) (Or.inr ⟨rfl, mode⟩)
    (by intro index bound; exact accepted_threshold_flag_boolean accepted mode bound)

theorem accepted_signer_flags_sum_one {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) : authorizationRawSum packed 176 6 = 1 := by
  exact accepted_authorization_one_hot_source accepted (authorizationOneHotSourceAt 1)
    (exact_authorization_one_hot_source (by decide)) (Or.inr ⟨rfl, mode⟩)
    (by intro index bound; exact accepted_signer_flag_boolean accepted mode bound)

theorem accepted_count_flags_sum_one {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) : authorizationRawSum packed 182 7 = 1 := by
  exact accepted_authorization_one_hot_source accepted (authorizationOneHotSourceAt 2)
    (exact_authorization_one_hot_source (by decide)) (Or.inr ⟨rfl, mode⟩)
    (by intro index bound; exact accepted_count_flag_boolean accepted mode bound)

theorem accepted_next_count_flags_sum_one {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) : authorizationRawSum packed 189 7 = 1 := by
  exact accepted_authorization_one_hot_source accepted (authorizationOneHotSourceAt 3)
    (exact_authorization_one_hot_source (by decide)) (Or.inl ⟨rfl, mode⟩)
    (by intro index bound; exact accepted_next_count_flag_boolean accepted mode bound)

theorem accepted_membership_flags_sum_one {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) : authorizationRawSum packed 226 6 = 1 := by
  exact accepted_authorization_one_hot_source accepted (authorizationOneHotSourceAt 4)
    (exact_authorization_one_hot_source (by decide)) (Or.inl ⟨rfl, mode⟩)
    (by intro index bound; exact accepted_membership_flag_boolean accepted mode bound)

def AuthorizationDeltaSource (slot : Nat) : Prop :=
  exactNonlinearExpressions[279 + slot]? = some (.witnessRow (155 + slot)) ∧
    exactNonlinearExpressions[286 + slot]? = some (.witnessRow (162 + slot)) ∧
    exactNonlinearExpressions[350 + slot]? = some (.witnessRow (226 + slot)) ∧
    exactNonlinearExpressions[1696 + 5 * slot]? = some (.sub (286 + slot) (279 + slot)) ∧
    exactNonlinearExpressions[1697 + 5 * slot]? = some (.sub (1696 + 5 * slot) (350 + slot)) ∧
    exactNonlinearExpressions[1698 + 5 * slot]? = some (.mul 217 (1697 + 5 * slot)) ∧
    1698 + 5 * slot ∈ exactNonlinearRoots

instance (slot : Nat) : Decidable (AuthorizationDeltaSource slot) := by
  unfold AuthorizationDeltaSource
  infer_instance

theorem exact_authorization_delta_source {slot : Nat} (bound : slot < 6) :
    AuthorizationDeltaSource slot := by
  have checked : ∀ index : Fin 6, AuthorizationDeltaSource index.val := by decide
  exact checked ⟨slot, bound⟩

theorem accepted_approval_raw_bitmap_step {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    {slot : Nat} (bound : slot < 6) :
    authorizationRawWord packed (162 + slot) = authorizationRawWord packed (155 + slot) +
      authorizationRawWord packed (226 + slot) := by
  obtain ⟨currentNode, nextNode, memberNode, firstDifference, secondDifference, rootNode, rootMember⟩ :=
    exact_authorization_delta_source bound
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := 1698 + 5 * slot) (by decide) rootMember
  have gateOne := authorization_trace_gate_one accepted equations (Or.inl ⟨rfl, mode⟩)
  have current := equations (279 + slot) (.witnessRow (155 + slot)) currentNode
  have next := equations (286 + slot) (.witnessRow (162 + slot)) nextNode
  have member := equations (350 + slot) (.witnessRow (226 + slot)) memberNode
  have difference := equations (1696 + 5 * slot) (.sub (286 + slot) (279 + slot)) firstDifference
  have delta := equations (1697 + 5 * slot) (.sub (1696 + 5 * slot) (350 + slot)) secondDifference
  have root := equations (1698 + 5 * slot) (.mul 217 (1697 + 5 * slot)) rootNode
  simp only [expressionField, authorization_lane_zero_word packed (by omega : 155 + slot < 686)] at current
  simp only [expressionField, authorization_lane_zero_word packed (by omega : 162 + slot < 686)] at next
  simp only [expressionField, authorization_lane_zero_word packed (by omega : 226 + slot < 686)] at member
  simp only [expressionField] at difference delta root
  rw [gateOne, one_mul, delta, difference, next, current, member] at root
  have differenceEquality := sub_eq_zero.mp (root.symm.trans rootZero)
  have addition := congrArg
    (fun value : F => value + (authorizationRawWord packed (155 + slot) : F)) differenceEquality
  have fieldAddition : (authorizationRawWord packed (162 + slot) : F) =
      (authorizationRawWord packed (155 + slot) : F) +
        (authorizationRawWord packed (226 + slot) : F) := by
    rw [sub_add_cancel] at addition
    exact addition.trans (add_comm _ _)
  have notSingle : projectAuthorizationMode packed ≠ .singleKey := by simp only [mode]; decide
  have currentBoolean := accepted_current_bitmap_boolean accepted notSingle bound
  have memberBoolean := accepted_membership_flag_boolean accepted mode bound
  have small : authorizationRawWord packed (155 + slot) +
      authorizationRawWord packed (226 + slot) ≤ 2 := by
    rcases currentBoolean with currentBoolean | currentBoolean <;>
      rcases memberBoolean with memberBoolean | memberBoolean <;> omega
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) ?_
    (by simpa only [Nat.cast_add, authorizationRawWord] using fieldAddition)
  have fieldBound : 2 < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by decide
  omega

theorem accepted_current_bitmap_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {slot : Nat} (bound : slot < 6) :
    wordAt (projectAuthorization packed).current.approvedSlots slot =
      authorizationRawWord packed (155 + slot) := by
  have source := accepted_current_opening_source_word accepted (word := 17 + slot) (by omega)
  have address : 138 + (17 + slot) = 155 + slot := by omega
  simpa [projectAuthorization, projectAccumulator, wordAt, List.getD_eq_getElem?_getD,
    bound, address] using source

theorem accepted_next_bitmap_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    {slot : Nat} (bound : slot < 6) :
    wordAt (projectAuthorization packed).next.approvedSlots slot =
      authorizationRawWord packed (162 + slot) := by
  have source := accepted_next_opening_source_word accepted (word := 17 + slot) (by omega)
  have address : nextOpeningRawRow (17 + slot) = 162 + slot := by
    have notPrefix : ¬17 + slot < 16 := by omega
    simp only [nextOpeningRawRow, if_neg notPrefix]
    omega
  simpa [projectAuthorization, projectAccumulator, mode, wordAt, List.getD_eq_getElem?_getD,
    bound, address] using source

theorem accepted_approval_projected_bitmap_step {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    {slot : Nat} (bound : slot < 6) :
    wordAt (projectAuthorization packed).next.approvedSlots slot =
      wordAt (projectAuthorization packed).current.approvedSlots slot +
        authorizationRawWord packed (226 + slot) := by
  rw [accepted_current_bitmap_word accepted bound, accepted_next_bitmap_word accepted mode bound]
  exact accepted_approval_raw_bitmap_step accepted mode bound

def authorizationMembershipWords (packed : List Nat) : List Nat :=
  (List.range 6).map (fun slot => authorizationRawWord packed (226 + slot))

theorem authorization_membership_word (packed : List Nat) {slot : Nat} (bound : slot < 6) :
    (authorizationMembershipWords packed).getD slot 0 = authorizationRawWord packed (226 + slot) := by
  simp [authorizationMembershipWords, List.getD_eq_getElem?_getD, bound]

theorem changed_count_eq_membership_sum
    (current next membership : List Nat)
    (nextLength : next.length = current.length)
    (memberLength : membership.length = current.length)
    (boolean : ∀ index, index < current.length → BooleanWord (membership.getD index 0))
    (step : ∀ index, index < current.length →
      next.getD index 0 = current.getD index 0 + membership.getD index 0) :
    (List.zip current next).countP (fun pair => pair.1 ≠ pair.2) = membership.sum := by
  induction current generalizing next membership with
  | nil =>
      have nextNil : next = [] := List.eq_nil_of_length_eq_zero (by simpa using nextLength)
      have memberNil : membership = [] := List.eq_nil_of_length_eq_zero (by simpa using memberLength)
      simp [nextNil, memberNil]
  | cons currentHead currentTail ih =>
      cases next with
      | nil => simp at nextLength
      | cons nextHead nextTail =>
          cases membership with
          | nil => simp at memberLength
          | cons memberHead memberTail =>
              have nextTailLength : nextTail.length = currentTail.length := by simpa using nextLength
              have memberTailLength : memberTail.length = currentTail.length := by simpa using memberLength
              have headBoolean := boolean 0 (by simp)
              have headStep := step 0 (by simp)
              simp only [List.getD_cons_zero] at headBoolean headStep
              have tailBoolean : ∀ index, index < currentTail.length → BooleanWord (memberTail.getD index 0) := by
                intro index bound
                simpa only [List.getD_cons_succ] using boolean (index + 1) (by simp; omega)
              have tailStep : ∀ index, index < currentTail.length →
                  nextTail.getD index 0 = currentTail.getD index 0 + memberTail.getD index 0 := by
                intro index bound
                simpa only [List.getD_cons_succ] using step (index + 1) (by simp; omega)
              have tail := ih nextTail memberTail nextTailLength memberTailLength tailBoolean tailStep
              rcases headBoolean with zero | one
              · have equal : currentHead = nextHead := by omega
                rw [List.zip_cons_cons, List.countP_cons, tail]
                simp [equal, zero]
              · have different : currentHead ≠ nextHead := by omega
                rw [List.zip_cons_cons, List.countP_cons, tail]
                simp [different, one, Nat.add_comm]

theorem accepted_approval_bitmap_transition {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    changedApprovalSlots (projectAuthorization packed).current (projectAuthorization packed).next = 1 ∧
      noApprovalCleared (projectAuthorization packed).current (projectAuthorization packed).next := by
  have currentLength : (projectAuthorization packed).current.approvedSlots.length = 6 := by
    simp [projectAuthorization, projectAccumulator]
  have nextLength : (projectAuthorization packed).next.approvedSlots.length = 6 := by
    simp [projectAuthorization, projectAccumulator, mode]
  have memberLength : (authorizationMembershipWords packed).length = 6 := by
    simp [authorizationMembershipWords]
  constructor
  · have count := changed_count_eq_membership_sum
      (projectAuthorization packed).current.approvedSlots
      (projectAuthorization packed).next.approvedSlots (authorizationMembershipWords packed)
      (nextLength.trans currentLength.symm) (memberLength.trans currentLength.symm)
      (by
        intro index bound
        rw [currentLength] at bound
        rw [authorization_membership_word packed bound]
        exact accepted_membership_flag_boolean accepted mode bound)
      (by
        intro index bound
        rw [currentLength] at bound
        rw [authorization_membership_word packed bound]
        exact accepted_approval_projected_bitmap_step accepted mode bound)
    have sum := accepted_membership_flags_sum_one accepted mode
    exact count.trans sum
  · intro slot bound approved
    change slot < 6 at bound
    have step := accepted_approval_projected_bitmap_step accepted mode bound
    have nextBoolean : BooleanWord (wordAt (projectAuthorization packed).next.approvedSlots slot) := by
      rw [accepted_next_bitmap_word accepted mode bound]
      exact accepted_next_bitmap_boolean accepted mode bound
    rcases nextBoolean with zero | one <;> omega

def AuthorizationSignerSource (slot limb : Nat) : Prop :=
  exactNonlinearExpressions[350 + slot]? = some (.witnessRow (226 + slot)) ∧
    exactNonlinearExpressions[229 + limb]? = some (.witnessRow (105 + limb)) ∧
    exactNonlinearExpressions[320 + 5 * slot + limb]? = some (.witnessRow (196 + 5 * slot + limb)) ∧
    exactNonlinearExpressions[1694 + 5 * slot]? = some (.mul 217 (350 + slot)) ∧
    exactNonlinearExpressions[1752 + 11 * slot + 2 * limb]? =
      some (.sub (229 + limb) (320 + 5 * slot + limb)) ∧
    exactNonlinearExpressions[1753 + 11 * slot + 2 * limb]? =
      some (.mul (1694 + 5 * slot) (1752 + 11 * slot + 2 * limb)) ∧
    1753 + 11 * slot + 2 * limb ∈ exactNonlinearRoots

instance (slot limb : Nat) : Decidable (AuthorizationSignerSource slot limb) := by
  unfold AuthorizationSignerSource
  infer_instance

theorem exact_authorization_signer_slot0 : ∀ limb : Fin 5,
    AuthorizationSignerSource 0 limb.val := by decide

theorem exact_authorization_signer_slot1 : ∀ limb : Fin 5,
    AuthorizationSignerSource 1 limb.val := by decide

theorem exact_authorization_signer_slot2 : ∀ limb : Fin 5,
    AuthorizationSignerSource 2 limb.val := by decide

theorem exact_authorization_signer_slot3 : ∀ limb : Fin 5,
    AuthorizationSignerSource 3 limb.val := by decide

theorem exact_authorization_signer_slot4 : ∀ limb : Fin 5,
    AuthorizationSignerSource 4 limb.val := by decide

theorem exact_authorization_signer_slot5 : ∀ limb : Fin 5,
    AuthorizationSignerSource 5 limb.val := by decide

theorem exact_authorization_signer_source {slot limb : Nat} (slotBound : slot < 6) (limbBound : limb < 5) :
    AuthorizationSignerSource slot limb := by
  have cases : slot = 0 ∨ slot = 1 ∨ slot = 2 ∨ slot = 3 ∨ slot = 4 ∨ slot = 5 := by omega
  rcases cases with rfl | rfl | rfl | rfl | rfl | rfl
  · exact exact_authorization_signer_slot0 ⟨limb, limbBound⟩
  · exact exact_authorization_signer_slot1 ⟨limb, limbBound⟩
  · exact exact_authorization_signer_slot2 ⟨limb, limbBound⟩
  · exact exact_authorization_signer_slot3 ⟨limb, limbBound⟩
  · exact exact_authorization_signer_slot4 ⟨limb, limbBound⟩
  · exact exact_authorization_signer_slot5 ⟨limb, limbBound⟩

theorem accepted_approval_member_signer_limb {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    {slot limb : Nat} (slotBound : slot < 6) (limbBound : limb < 5)
    (membership : authorizationRawWord packed (226 + slot) = 1) :
    authorizationRawWord packed (196 + 5 * slot + limb) = authorizationRawWord packed (105 + limb) := by
  obtain ⟨memberNode, legacyNode, tagNode, scaledNode, differenceNode, rootNode, rootMember⟩ :=
    exact_authorization_signer_source slotBound limbBound
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := 1753 + 11 * slot + 2 * limb) (by decide) rootMember
  have modeOne := authorization_trace_gate_one accepted equations (Or.inl ⟨rfl, mode⟩)
  have member := equations (350 + slot) (.witnessRow (226 + slot)) memberNode
  have legacy := equations (229 + limb) (.witnessRow (105 + limb)) legacyNode
  have tag := equations (320 + 5 * slot + limb) (.witnessRow (196 + 5 * slot + limb)) tagNode
  have scaled := equations (1694 + 5 * slot) (.mul 217 (350 + slot)) scaledNode
  have difference := equations (1752 + 11 * slot + 2 * limb)
    (.sub (229 + limb) (320 + 5 * slot + limb)) differenceNode
  have root := equations (1753 + 11 * slot + 2 * limb)
    (.mul (1694 + 5 * slot) (1752 + 11 * slot + 2 * limb)) rootNode
  simp only [expressionField, authorization_lane_zero_word packed (by omega : 226 + slot < 686),
    membership, Nat.cast_one] at member
  simp only [expressionField, authorization_lane_zero_word packed (by omega : 105 + limb < 686)] at legacy
  simp only [expressionField, authorization_lane_zero_word packed (by omega : 196 + 5 * slot + limb < 686)] at tag
  simp only [expressionField] at scaled difference root
  rw [scaled, modeOne, member, one_mul, one_mul, difference, legacy, tag] at root
  have equality := sub_eq_zero.mp (root.symm.trans rootZero)
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) equality.symm

def authorizationRawLegacyTag (packed : List Nat) : List Nat :=
  (List.range 5).map (fun limb => authorizationRawWord packed (105 + limb))

def authorizationRawSignerTag (packed : List Nat) (slot : Nat) : List Nat :=
  (List.range 5).map (fun limb => authorizationRawWord packed (196 + 5 * slot + limb))

theorem project_authorization_signer_tag (packed : List Nat) {slot : Nat} (bound : slot < 6) :
    (projectAuthorization packed).policySignerTags.getD slot [] = authorizationRawSignerTag packed slot := by
  simp [projectAuthorization, authorizationRawSignerTag, authorizationRawWord,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.authorizationPolicyTagRow,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
    List.getD_eq_getElem?_getD, bound, Nat.mul_comm]

/-- The changed slot is source-bound to the five raw legacy-PRF tag words.
Exact primitive evaluation of those words is supplied by the hash-family lane. -/
theorem accepted_approval_raw_signer_bound {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    ApprovalSignerBound (authorizationRawLegacyTag packed) (projectAuthorization packed) := by
  intro slot bound changed
  change slot < 6 at bound
  have sourceChanged : authorizationRawWord packed (155 + slot) ≠ authorizationRawWord packed (162 + slot) := by
    simpa only [accepted_current_bitmap_word accepted bound,
      accepted_next_bitmap_word accepted mode bound] using changed
  have step := accepted_approval_raw_bitmap_step accepted mode bound
  have boolean := accepted_membership_flag_boolean accepted mode bound
  have membership : authorizationRawWord packed (226 + slot) = 1 := by
    rcases boolean with zero | one
    · exfalso
      apply sourceChanged
      omega
    · exact one
  have tag : authorizationRawSignerTag packed slot = authorizationRawLegacyTag packed := by
    apply List.map_congr_left
    intro limb member
    exact accepted_approval_member_signer_limb accepted mode bound (List.mem_range.mp member) membership
  rw [project_authorization_signer_tag packed bound, tag]
  simp [authorizationRawLegacyTag, signerTagWords]

structure AuthorizationBitmapCountSource where
  bitmapRow : Nat
  countRow : Nat
  sumStart : Nat
  gate : Nat
  root : Nat
deriving DecidableEq, Repr, Inhabited

def AuthorizationBitmapCountSource.Valid (entry : AuthorizationBitmapCountSource) : Prop :=
  entry.bitmapRow + 6 ≤ 686 ∧ entry.countRow < 686 ∧
    (∀ index, index ∈ List.range 6 →
      exactNonlinearExpressions[124 + (entry.bitmapRow + index)]? =
        some (.witnessRow (entry.bitmapRow + index))) ∧
    exactNonlinearExpressions[124 + entry.countRow]? = some (.witnessRow entry.countRow) ∧
    exactNonlinearExpressions[entry.sumStart]? =
      some (.add (124 + entry.bitmapRow) (124 + (entry.bitmapRow + 1))) ∧
    (∀ index, index ∈ List.range 4 →
      exactNonlinearExpressions[entry.sumStart + (index + 1)]? =
        some (.add (124 + (entry.bitmapRow + (index + 2))) (entry.sumStart + index))) ∧
    exactNonlinearExpressions[entry.root - 1]? =
      some (.sub (124 + entry.countRow) (entry.sumStart + 4)) ∧
    exactNonlinearExpressions[entry.root]? = some (.mul entry.gate (entry.root - 1)) ∧
    entry.root ∈ exactNonlinearRoots

instance (entry : AuthorizationBitmapCountSource) : Decidable entry.Valid := by
  unfold AuthorizationBitmapCountSource.Valid
  infer_instance

def currentBitmapCountSource : AuthorizationBitmapCountSource := ⟨155, 154, 1650, 1234, 1656⟩
def nextBitmapCountSource : AuthorizationBitmapCountSource := ⟨162, 161, 1687, 217, 1693⟩

theorem exact_current_bitmap_count_source : currentBitmapCountSource.Valid := by decide
theorem exact_next_bitmap_count_source : nextBitmapCountSource.Valid := by decide

theorem accepted_authorization_bitmap_count {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (entry : AuthorizationBitmapCountSource) (valid : entry.Valid)
    (enabled : AuthorizationGateEnabled packed entry.gate)
    (boolean : ∀ index, index < 6 → BooleanWord (authorizationRawWord packed (entry.bitmapRow + index))) :
    authorizationRawWord packed entry.countRow = authorizationRawSum packed entry.bitmapRow 6 := by
  obtain ⟨rowBound, countBound, rowNodes, countNode, firstNode, laterNodes, differenceNode, rootNode, rootMember⟩ := valid
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := entry.root) (by decide) rootMember
  have gateOne := authorization_trace_gate_one accepted equations enabled
  have rows : ∀ index, index < 6 →
      (values.getD (124 + (entry.bitmapRow + index)) 0 : F) =
        (authorizationRawWord packed (entry.bitmapRow + index) : F) := by
    intro index bound
    simpa only [expressionField,
      authorization_lane_zero_word packed (by omega : entry.bitmapRow + index < 686)] using
      equations (124 + (entry.bitmapRow + index)) (.witnessRow (entry.bitmapRow + index))
        (rowNodes index (List.mem_range.mpr bound))
  have row0 := rows 0 (by decide)
  have row1 := rows 1 (by decide)
  have row2 := rows 2 (by decide)
  have row3 := rows 3 (by decide)
  have row4 := rows 4 (by decide)
  have row5 := rows 5 (by decide)
  simp only [Nat.add_zero] at row0
  have sum0 := equations entry.sumStart
    (.add (124 + entry.bitmapRow) (124 + (entry.bitmapRow + 1))) firstNode
  have sum1 := equations (entry.sumStart + 1)
    (.add (124 + (entry.bitmapRow + 2)) entry.sumStart) (by simpa using laterNodes 0 (by simp))
  have sum2 := equations (entry.sumStart + 2)
    (.add (124 + (entry.bitmapRow + 3)) (entry.sumStart + 1)) (by simpa using laterNodes 1 (by simp))
  have sum3 := equations (entry.sumStart + 3)
    (.add (124 + (entry.bitmapRow + 4)) (entry.sumStart + 2)) (by simpa using laterNodes 2 (by simp))
  have sum4 := equations (entry.sumStart + 4)
    (.add (124 + (entry.bitmapRow + 5)) (entry.sumStart + 3)) (by simpa using laterNodes 3 (by simp))
  simp only [expressionField, row0, row1] at sum0
  simp only [expressionField, row2, sum0] at sum1
  simp only [expressionField, row3, sum1] at sum2
  simp only [expressionField, row4, sum2] at sum3
  simp only [expressionField, row5, sum3] at sum4
  have sum : (values.getD (entry.sumStart + 4) 0 : F) =
      (authorizationRawSum packed entry.bitmapRow 6 : F) := by
    simpa only [authorizationRawSum, List.range_succ, List.range_zero, List.map_append,
      List.map_cons, List.map_nil, List.sum_append, List.sum_cons, List.sum_nil,
      Nat.cast_add, Nat.cast_zero, Nat.add_zero, zero_add, add_zero,
      add_assoc, add_comm, add_left_comm] using sum4
  have count := equations (124 + entry.countRow) (.witnessRow entry.countRow) countNode
  have difference := equations (entry.root - 1) (.sub (124 + entry.countRow) (entry.sumStart + 4)) differenceNode
  have root := equations entry.root (.mul entry.gate (entry.root - 1)) rootNode
  simp only [expressionField, authorization_lane_zero_word packed countBound] at count
  simp only [expressionField] at difference root
  rw [gateOne, one_mul, difference, count, sum] at root
  have equality := sub_eq_zero.mp (root.symm.trans rootZero)
  have sumBound := boolean_range_sum_le_count
    (fun index => authorizationRawWord packed (entry.bitmapRow + index)) 6 boolean
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) ?_ equality
  change authorizationRawSum packed entry.bitmapRow 6 ≤ 6 at sumBound
  have fieldBound : 6 < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by decide
  omega

theorem accepted_current_raw_count {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    authorizationRawWord packed 154 = authorizationRawSum packed 155 6 := by
  exact accepted_authorization_bitmap_count accepted currentBitmapCountSource exact_current_bitmap_count_source
    (Or.inr ⟨rfl, mode⟩) (by intro index bound; exact accepted_current_bitmap_boolean accepted mode bound)

theorem accepted_next_raw_count {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    authorizationRawWord packed 161 = authorizationRawSum packed 162 6 := by
  exact accepted_authorization_bitmap_count accepted nextBitmapCountSource exact_next_bitmap_count_source
    (Or.inl ⟨rfl, mode⟩) (by intro index bound; exact accepted_next_bitmap_boolean accepted mode bound)

theorem accepted_approval_raw_count_increment {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    authorizationRawWord packed 161 = authorizationRawWord packed 154 + 1 := by
  have notSingle : projectAuthorizationMode packed ≠ .singleKey := by simp only [mode]; decide
  have mapped : (List.range 6).map (fun slot => authorizationRawWord packed (162 + slot)) =
      (List.range 6).map (fun slot => authorizationRawWord packed (155 + slot) +
        authorizationRawWord packed (226 + slot)) := by
    apply List.map_congr_left
    intro slot member
    exact accepted_approval_raw_bitmap_step accepted mode (List.mem_range.mp member)
  have sum : authorizationRawSum packed 162 6 =
      authorizationRawSum packed 155 6 + authorizationRawSum packed 226 6 := by
    unfold authorizationRawSum
    rw [mapped, List.sum_map_add]
  rw [accepted_next_raw_count accepted mode, sum,
    ← accepted_current_raw_count accepted notSingle, accepted_membership_flags_sum_one accepted mode]

theorem accepted_approval_count_increment {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    (projectAuthorization packed).next.approvalCount =
      (projectAuthorization packed).current.approvalCount + 1 := by
  have current := accepted_current_opening_source_word accepted (word := 16) (by decide)
  have next := accepted_next_opening_source_word accepted (word := 16) (by decide)
  change spongeSourceWord packed 98 16 = authorizationRawWord packed 154 at current
  change spongeSourceWord packed 101 16 = authorizationRawWord packed 161 at next
  simpa only [projectAuthorization, mode, if_true, projectAccumulator, current, next] using
    accepted_approval_raw_count_increment accepted mode

end HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle
