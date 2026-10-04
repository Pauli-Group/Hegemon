import HegemonCrypto.SmallWoodV8Smz9SourceAuthInputDAG

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthInputSelection

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (FieldExpression)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation encoded_input_flag)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInputDAG
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootTables
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

theorem actual_input_auth_formula (pub rows : Nat → F) (input : Fin 2) (word : Fin 5) :
    fieldAt exactNonlinearExpressions pub rows (inputAuthBase input.val word.val + 5) =
      rows (inputAuthOutRow input.val word.val) - pub input.val *
        (rows 92 * rows (105 + word.val) +
          (rows 93 * rows (inputAuthApprovalRow input.val word.val) +
            rows 94 * rows (inputAuthFinalRow input.val word.val))) := by
  have equations (index : Nat) (expression : FieldExpression)
      (member : (index, expression) ∈ inputAuthExpressions input.val word.val) :=
    actual_node_field_equation pub rows (of_decide_eq_true
      (List.all_eq_true.mp (input_auth_source_checked input word) (index, expression) member))
  have singleMode := equations 216 (.witnessRow 92) (by simp [inputAuthExpressions])
  have approvalMode := equations 217 (.witnessRow 93) (by simp [inputAuthExpressions])
  have finalMode := equations 218 (.witnessRow 94) (by simp [inputAuthExpressions])
  have flag := equations (4 + input.val) (.publicWord input.val) (by simp [inputAuthExpressions])
  have output := equations (124 + inputAuthOutRow input.val word.val)
    (.witnessRow (inputAuthOutRow input.val word.val)) (by simp [inputAuthExpressions])
  have legacy := equations (124 + (105 + word.val)) (.witnessRow (105 + word.val)) (by simp [inputAuthExpressions])
  have approval := equations (124 + inputAuthApprovalRow input.val word.val)
    (.witnessRow (inputAuthApprovalRow input.val word.val)) (by simp [inputAuthExpressions])
  have finalWord := equations (124 + inputAuthFinalRow input.val word.val)
    (.witnessRow (inputAuthFinalRow input.val word.val)) (by simp [inputAuthExpressions])
  have singleProduct := equations (1353 + 7 * word.val) (.mul 216 (124 + (105 + word.val)))
    (by simp [inputAuthExpressions])
  have approvalProduct := equations (inputAuthBase input.val word.val)
    (.mul 217 (124 + inputAuthApprovalRow input.val word.val)) (by simp [inputAuthExpressions])
  have finalProduct := equations (inputAuthBase input.val word.val + 1)
    (.mul 218 (124 + inputAuthFinalRow input.val word.val)) (by simp [inputAuthExpressions])
  have pair := equations (inputAuthBase input.val word.val + 2)
    (.add (inputAuthBase input.val word.val) (inputAuthBase input.val word.val + 1)) (by simp [inputAuthExpressions])
  have sum := equations (inputAuthBase input.val word.val + 3)
    (.add (1353 + 7 * word.val) (inputAuthBase input.val word.val + 2)) (by simp [inputAuthExpressions])
  have gated := equations (inputAuthBase input.val word.val + 4)
    (.mul (4 + input.val) (inputAuthBase input.val word.val + 3)) (by simp [inputAuthExpressions])
  have root := equations (inputAuthBase input.val word.val + 5)
    (.sub (124 + inputAuthOutRow input.val word.val) (inputAuthBase input.val word.val + 4)) (by simp [inputAuthExpressions])
  simp only [expressionField] at singleMode approvalMode finalMode flag output legacy approval finalWord singleProduct approvalProduct finalProduct pair sum gated root
  rw [output,gated,flag,sum,pair,singleProduct,approvalProduct,finalProduct,
    singleMode,approvalMode,finalMode,legacy,approval,finalWord] at root
  exact root

theorem typed_input_flag_boolean (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) :
    BooleanWord (flagAt statement.inputFlags input.val) := by
  have bound : input.val < statement.inputFlags.length := by
    rw [valid.1.1]
    exact input.isLt
  have present : statement.inputFlags[input.val]? =
      some (flagAt statement.inputFlags input.val) := by
    simp [flagAt,List.getD,bound]
  exact valid.1.2.2.1 _ (List.mem_of_getElem? present)

theorem source_input_auth_equation (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (input : Fin 2) (word : Fin 5) :
    (sourceAuthRow statement witness hashes (inputAuthOutRow input.val word.val - 92) : F) =
      (flagAt statement.inputFlags input.val : F) *
        ((sourceAuthRow statement witness hashes 0 : F) *
            (sourceAuthRow statement witness hashes (105 + word.val - 92) : F) +
          ((sourceAuthRow statement witness hashes 1 : F) *
              (sourceAuthRow statement witness hashes (inputAuthApprovalRow input.val word.val - 92) : F) +
            (sourceAuthRow statement witness hashes 2 : F) *
              (sourceAuthRow statement witness hashes (inputAuthFinalRow input.val word.val - 92) : F))) := by
  rcases typed_input_flag_boolean statement witness valid input with flag | flag
  all_goals cases mode : witness.authorization.mode <;> fin_cases input <;> fin_cases word
  all_goals dsimp only at flag
  all_goals simp [sourceAuthRow,authInputPrf,authInputKey,authModeFlag,authBit,
      inputAuthOutRow,inputAuthApprovalRow,inputAuthFinalRow,mode,flag]

theorem input_auth_rows_within_source (input : Fin 2) (word : Fin 5) :
    92 ≤ inputAuthOutRow input.val word.val ∧ inputAuthOutRow input.val word.val < 247 ∧
    92 ≤ inputAuthApprovalRow input.val word.val ∧ inputAuthApprovalRow input.val word.val < 247 ∧
    92 ≤ inputAuthFinalRow input.val word.val ∧ inputAuthFinalRow input.val word.val < 247 := by
  fin_cases input <;> fin_cases word <;> decide

theorem full_candidate_input_auth_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (word : Fin 5)
    (lane : Fin 64) :
    (exactNonlinearRoots[242 + 5 * input.val + word.val]?).map
      (fieldAt exactNonlinearExpressions (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_input_auth_root_position,Option.map_some,actual_input_auth_formula]
  have readback (row : Nat) (lower : 92 ≤ row) (upper : row < 247) :=
    full_candidate_auth_row statement witness ⟨row - 92,by omega⟩ lane
  have rowRead (row : Nat) (lower : 92 ≤ row) (upper : row < 247) :
      laneField (fullTypedSourceCandidate statement witness) lane.val row =
        (sourceAuthRow statement witness (typedSourceFinals statement witness) (row - 92) : F) := by
    simpa only [Nat.add_sub_of_le lower] using readback row lower upper
  have bounds := input_auth_rows_within_source input word
  rw [rowRead _ bounds.1 bounds.2.1,rowRead 92 (by decide) (by decide),
    rowRead _ (by omega) (by omega),rowRead 93 (by decide) (by decide),
    rowRead _ bounds.2.2.1 bounds.2.2.2.1,rowRead 94 (by decide) (by decide),
    rowRead _ bounds.2.2.2.2.1 bounds.2.2.2.2.2,
    encoded_input_flag statement valid.1 input.isLt]
  exact congrArg some (sub_eq_zero.mpr
    (source_input_auth_equation statement witness valid (typedSourceFinals statement witness) input word))

end


end HegemonCrypto.SmallWood.V8Smz9SourceAuthInputSelection
