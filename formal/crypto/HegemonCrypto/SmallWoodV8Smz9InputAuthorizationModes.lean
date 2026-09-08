import HegemonCrypto.SmallWoodV8Smz9SemanticAuthorization

namespace HegemonCrypto.SmallWood.V8Smz9SemanticEndpointInputModes

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (FieldExpression packedWitnessLaneRows)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def inputAuthOutRow (input word : Nat) : Nat :=
  if word = 0 then 95 + input else 96 + 4 * input + word

def inputAuthApprovalRow (input word : Nat) : Nat :=
  if input = 0 then (if word = 0 then 114 else 109 + word) else 105 + word

def inputAuthFinalRow (input word : Nat) : Nat :=
  if input = 0 then (if word = 0 then 128 else 123 + word)
  else (if word = 0 then 114 else 109 + word)

def inputAuthBase (input word : Nat) : Nat :=
  if input = 0 then 1354 + 7 * word else 1388 + 6 * word

def inputAuthExpressions (input word : Nat) : List (Nat × FieldExpression) :=
  let base := inputAuthBase input word
  [(216, .witnessRow 92), (217, .witnessRow 93), (218, .witnessRow 94),
    (4 + input, .publicWord input),
    (124 + inputAuthOutRow input word, .witnessRow (inputAuthOutRow input word)),
    (124 + (105 + word), .witnessRow (105 + word)),
    (124 + inputAuthApprovalRow input word, .witnessRow (inputAuthApprovalRow input word)),
    (124 + inputAuthFinalRow input word, .witnessRow (inputAuthFinalRow input word)),
    (1353 + 7 * word, .mul 216 (124 + (105 + word))),
    (base, .mul 217 (124 + inputAuthApprovalRow input word)),
    (base + 1, .mul 218 (124 + inputAuthFinalRow input word)),
    (base + 2, .add base (base + 1)),
    (base + 3, .add (1353 + 7 * word) (base + 2)),
    (base + 4, .mul (4 + input) (base + 3)),
    (base + 5, .sub (124 + inputAuthOutRow input word) (base + 4))]

theorem input_auth_source_checked (input : Fin 2) (word : Fin 5) :
    (inputAuthExpressions input.val word.val).all (fun pair =>
      decide (exactNonlinearExpressions[pair.1]? = some pair.2)) = true := by
  have checked : ∀ input : Fin 2, ∀ word : Fin 5,
      (inputAuthExpressions input.val word.val).all (fun pair =>
        decide (exactNonlinearExpressions[pair.1]? = some pair.2)) = true := by decide
  exact checked input word

theorem input_auth_root_checked (input : Fin 2) (word : Fin 5) :
    inputAuthBase input.val word.val + 5 ∈ exactNonlinearRoots := by
  have checked : ∀ input : Fin 2, ∀ word : Fin 5,
      inputAuthBase input.val word.val + 5 ∈ exactNonlinearRoots := by decide
  exact checked input word

theorem input_auth_rows_bound (input : Fin 2) (word : Fin 5) :
    inputAuthOutRow input.val word.val < 686 ∧
      inputAuthApprovalRow input.val word.val < 686 ∧
      inputAuthFinalRow input.val word.val < 686 := by
  have checked : ∀ input : Fin 2, ∀ word : Fin 5,
      inputAuthOutRow input.val word.val < 686 ∧
        inputAuthApprovalRow input.val word.val < 686 ∧
        inputAuthFinalRow input.val word.val < 686 := by decide
  exact checked input word

theorem input_authorization_raw_mode_word (packed : List Nat) (mode : Nat) :
    authorizationRawWord packed (92 + mode) = authorizationWord packed mode := by
  simp only [authorizationRawWord, authorizationWord,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.authorizationModeRow,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add]

/-- Actual nonlinear roots bind every input PRF/key word to its mode-selected source. -/
theorem accepted_input_authorization_mode_field {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (input : Fin 2) (word : Fin 5) :
    (authorizationRawWord packed (inputAuthOutRow input.val word.val) : F) =
      (publicWords.getD input.val 0 : F) *
        ((authorizationWord packed 0 : F) * (authorizationRawWord packed (105 + word.val) : F) +
          ((authorizationWord packed 1 : F) *
              (authorizationRawWord packed (inputAuthApprovalRow input.val word.val) : F) +
            (authorizationWord packed 2 : F) *
              (authorizationRawWord packed (inputAuthFinalRow input.val word.val) : F))) := by
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := inputAuthBase input.val word.val + 5) (by decide)
    (input_auth_root_checked input word)
  have source (index : Nat) (expression : FieldExpression)
      (member : (index, expression) ∈ inputAuthExpressions input.val word.val) :
      exactNonlinearExpressions[index]? = some expression := by
    exact of_decide_eq_true (List.all_eq_true.mp (input_auth_source_checked input word)
      (index, expression) member)
  have singleMode := equations 216 (.witnessRow 92) (source _ _ (by simp [inputAuthExpressions]))
  have approvalMode := equations 217 (.witnessRow 93) (source _ _ (by simp [inputAuthExpressions]))
  have finalMode := equations 218 (.witnessRow 94) (source _ _ (by simp [inputAuthExpressions]))
  have flag := equations (4 + input.val) (.publicWord input.val) (source _ _ (by simp [inputAuthExpressions]))
  have output := equations (124 + inputAuthOutRow input.val word.val)
    (.witnessRow (inputAuthOutRow input.val word.val)) (source _ _ (by simp [inputAuthExpressions]))
  have legacy := equations (124 + (105 + word.val)) (.witnessRow (105 + word.val))
    (source _ _ (by simp [inputAuthExpressions]))
  have approval := equations (124 + inputAuthApprovalRow input.val word.val)
    (.witnessRow (inputAuthApprovalRow input.val word.val)) (source _ _ (by simp [inputAuthExpressions]))
  have finalWord := equations (124 + inputAuthFinalRow input.val word.val)
    (.witnessRow (inputAuthFinalRow input.val word.val)) (source _ _ (by simp [inputAuthExpressions]))
  have singleProduct := equations (1353 + 7 * word.val) (.mul 216 (124 + (105 + word.val)))
    (source _ _ (by simp [inputAuthExpressions]))
  have approvalProduct := equations (inputAuthBase input.val word.val)
    (.mul 217 (124 + inputAuthApprovalRow input.val word.val))
    (source _ _ (by simp [inputAuthExpressions]))
  have finalProduct := equations (inputAuthBase input.val word.val + 1)
    (.mul 218 (124 + inputAuthFinalRow input.val word.val))
    (source _ _ (by simp [inputAuthExpressions]))
  have pair := equations (inputAuthBase input.val word.val + 2)
    (.add (inputAuthBase input.val word.val) (inputAuthBase input.val word.val + 1))
    (source _ _ (by simp [inputAuthExpressions]))
  have sum := equations (inputAuthBase input.val word.val + 3)
    (.add (1353 + 7 * word.val) (inputAuthBase input.val word.val + 2))
    (source _ _ (by simp [inputAuthExpressions]))
  have gated := equations (inputAuthBase input.val word.val + 4)
    (.mul (4 + input.val) (inputAuthBase input.val word.val + 3))
    (source _ _ (by simp [inputAuthExpressions]))
  have root := equations (inputAuthBase input.val word.val + 5)
    (.sub (124 + inputAuthOutRow input.val word.val) (inputAuthBase input.val word.val + 4))
    (source _ _ (by simp [inputAuthExpressions]))
  simp only [expressionField] at singleMode approvalMode finalMode flag output legacy approval finalWord singleProduct approvalProduct finalProduct pair sum gated root
  rw [authorization_lane_zero_word packed (by decide),
    show 92 = 92 + 0 by decide, input_authorization_raw_mode_word] at singleMode
  rw [authorization_lane_zero_word packed (by decide),
    show 93 = 92 + 1 by decide, input_authorization_raw_mode_word] at approvalMode
  rw [authorization_lane_zero_word packed (by decide),
    show 94 = 92 + 2 by decide, input_authorization_raw_mode_word] at finalMode
  rw [authorization_lane_zero_word packed (input_auth_rows_bound input word).1] at output
  rw [authorization_lane_zero_word packed (by omega : 105 + word.val < 686)] at legacy
  rw [authorization_lane_zero_word packed (input_auth_rows_bound input word).2.1] at approval
  rw [authorization_lane_zero_word packed (input_auth_rows_bound input word).2.2] at finalWord
  rw [rootZero, output, gated, flag, sum, pair, singleProduct, approvalProduct, finalProduct,
    singleMode, approvalMode, finalMode, legacy, approval, finalWord] at root
  exact sub_eq_zero.mp root.symm

theorem accepted_single_mode_words {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey) :
    authorizationWord packed 0 = 1 ∧ authorizationWord packed 1 = 0 ∧
      authorizationWord packed 2 = 0 := by
  have single := accepted_single_mode_word accepted mode
  rcases accepted_authorization_one_hot accepted with first | second | third
  · exact first
  · omega
  · omega

theorem accepted_active_single_input_authorization_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey)
    (input : Fin 2) (word : Fin 5) (active : publicWords.getD input.val 0 = 1) :
    authorizationRawWord packed (inputAuthOutRow input.val word.val) =
      authorizationRawWord packed (105 + word.val) := by
  have equality := accepted_input_authorization_mode_field accepted input word
  obtain ⟨single, approval, finalMode⟩ := accepted_single_mode_words accepted mode
  simp only [active, single, approval, finalMode, Nat.cast_one, Nat.cast_zero,
    one_mul, zero_mul, add_zero] at equality
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) equality


end HegemonCrypto.SmallWood.V8Smz9SemanticEndpointInputModes
