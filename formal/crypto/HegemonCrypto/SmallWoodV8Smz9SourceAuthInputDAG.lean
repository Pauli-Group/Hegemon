import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootTables

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthInputDAG
open Hegemon.Transaction.Poseidon2V8RelationProgram (FieldExpression)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option maxRecDepth 100000
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
def InputAuthSourceValid (input word : Nat) : Prop :=
  (inputAuthExpressions input word).all (fun pair =>
    decide (exactNonlinearExpressions[pair.1]? = some pair.2)) = true
instance (input word : Nat) : Decidable (InputAuthSourceValid input word) := by
  unfold InputAuthSourceValid
  infer_instance
theorem input0word0 : InputAuthSourceValid 0 0 := by decide
theorem input0word1 : InputAuthSourceValid 0 1 := by decide
theorem input0word2 : InputAuthSourceValid 0 2 := by decide
theorem input0word3 : InputAuthSourceValid 0 3 := by decide
theorem input0word4 : InputAuthSourceValid 0 4 := by decide
theorem input1word0 : InputAuthSourceValid 1 0 := by decide
theorem input1word1 : InputAuthSourceValid 1 1 := by decide
theorem input1word2 : InputAuthSourceValid 1 2 := by decide
theorem input1word3 : InputAuthSourceValid 1 3 := by decide
theorem input1word4 : InputAuthSourceValid 1 4 := by decide
theorem input_auth_source_checked (input : Fin 2) (word : Fin 5) :
    (inputAuthExpressions input.val word.val).all (fun pair =>
      decide (exactNonlinearExpressions[pair.1]? = some pair.2)) = true := by
  fin_cases input
  · fin_cases word
    · exact input0word0
    · exact input0word1
    · exact input0word2
    · exact input0word3
    · exact input0word4
  · fin_cases word
    · exact input1word0
    · exact input1word1
    · exact input1word2
    · exact input1word3
    · exact input1word4
theorem actual_input_auth_root_position (input : Fin 2) (word : Fin 5) :
    exactNonlinearRoots[242 + 5 * input.val + word.val]? =
      some (inputAuthBase input.val word.val + 5) := by
  fin_cases input <;> fin_cases word <;> decide
end HegemonCrypto.SmallWood.V8Smz9SourceAuthInputDAG
