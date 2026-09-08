import HegemonCrypto.SmallWoodV8Smz9SourceBaseMultiplication
import HegemonCrypto.SmallWoodV8Smz9SourceParentMultiplication

namespace HegemonCrypto.SmallWood.V8Smz9SourceMultiplicationRoot

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceBaseMultiplication
open HegemonCrypto.SmallWood.V8Smz9SourceParentMultiplication
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem typed_source_multiplication_equation (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Nat) :
    TupleEquation (sourceMultiplication statement witness
      (sourceAux statement.stablecoin witness.stablecoin) lane) := by
  by_cases base : lane < 18
  · simpa only [sourceMultiplication, if_pos base] using
      typed_source_base_multiplication_equation statement witness valid lane
  · exact typed_source_parent_multiplication_equation statement witness valid lane (by omega)

/-- Exact root-list position, independently kernel reduced from the generated program. -/
theorem actual_multiplication_root_index : exactNonlinearRoots[806]? = some 8132 := by decide

noncomputable section

/-- Exact five-node dependency cone; row659 is numeric, factors are rows660 and661. -/
theorem actual_multiplication_root_formula (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 8132 = rows 660 * rows 661 - rows 662 := by
  have n784 : fieldAt exactNonlinearExpressions pub rows 784 = rows 660 := by
    simpa only [expressionField] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[784]? = some (.witnessRow 660) by decide)
  have n785 : fieldAt exactNonlinearExpressions pub rows 785 = rows 661 := by
    simpa only [expressionField] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[785]? = some (.witnessRow 661) by decide)
  have n786 : fieldAt exactNonlinearExpressions pub rows 786 = rows 662 := by
    simpa only [expressionField] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[786]? = some (.witnessRow 662) by decide)
  have n8131 : fieldAt exactNonlinearExpressions pub rows 8131 =
      fieldAt exactNonlinearExpressions pub rows 784 * fieldAt exactNonlinearExpressions pub rows 785 := by
    simpa only [expressionField] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8131]? = some (.mul 784 785) by decide)
  have n8132 : fieldAt exactNonlinearExpressions pub rows 8132 =
      fieldAt exactNonlinearExpressions pub rows 8131 - fieldAt exactNonlinearExpressions pub rows 786 := by
    simpa only [expressionField] using
      actual_node_field_equation pub rows (show exactNonlinearExpressions[8132]? = some (.sub 8131 786) by decide)
  rw [n8132,n8131,n784,n785,n786]

theorem full_candidate_multiplication_field_readbacks (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) :
    let tuple := sourceMultiplication statement witness (sourceAux statement.stablecoin witness.stablecoin) lane.val
    laneField (fullTypedSourceCandidate statement witness) lane.val 660 = (tuple.a : F) ∧
    laneField (fullTypedSourceCandidate statement witness) lane.val 661 = (tuple.b : F) ∧
    laneField (fullTypedSourceCandidate statement witness) lane.val 662 = (tuple.c : F) := by
  exact ⟨congrArg (fun word : Nat => (word : F))
      (full_candidate_tail_family_readback statement witness .multiplication 0 (by decide) lane),
    congrArg (fun word : Nat => (word : F))
      (full_candidate_tail_family_readback statement witness .multiplication 1 (by decide) lane),
    congrArg (fun word : Nat => (word : F))
      (full_candidate_tail_family_readback statement witness .multiplication 2 (by decide) lane)⟩

/-- Same actual packed candidate, all64 lanes, and fixed typed validity only. -/
theorem full_candidate_multiplication_root_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (publicWords : List Nat) (lane : Fin 64) :
    fieldAt exactNonlinearExpressions (fun index => (publicWords.getD index 0 : F))
      (laneField (fullTypedSourceCandidate statement witness) lane.val) 8132 = 0 := by
  have rows := full_candidate_multiplication_field_readbacks statement witness lane
  rw [actual_multiplication_root_formula, rows.1,rows.2.1,rows.2.2]
  exact sub_eq_zero.mpr (typed_source_multiplication_equation statement witness valid lane.val)

theorem full_candidate_actual_multiplication_root_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (publicWords : List Nat) (lane : Fin 64) :
    (exactNonlinearRoots[806]?).map
      (fieldAt exactNonlinearExpressions (fun index => (publicWords.getD index 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_multiplication_root_index, Option.map_some,
    full_candidate_multiplication_root_zero statement witness valid]

/-- Negative control: canonical factors alone do not establish their product row. -/
theorem incorrect_product_row_rejected : (1 : F) * 1 - 0 ≠ 0 := by norm_num

end









end HegemonCrypto.SmallWood.V8Smz9SourceMultiplicationRoot
