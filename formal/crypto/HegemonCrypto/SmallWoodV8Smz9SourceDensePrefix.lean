import HegemonCrypto.SmallWoodV8Smz9SourceReplicatedRows
import HegemonCrypto.SmallWoodV8Smz9SourceDenseCsr

/-! Concrete first-92-row plus dense-block composition. The 155 authorization
rows between them and every row after the dense block remain arbitrary data.
All seven exact dense CSR residuals vanish on this explicit constructor; no
raw-cell binding, packed acceptance, or evaluator-success premise is supplied.
This remains a source-shaped natural/field model, not a full Rust lowerer. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceDensePrefix

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def beforeDense (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows : List Nat) : List Nat :=
  packedPrefix statement witness ++ authorizationRows

def composedAssignment (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows afterDense : List Nat) : List Nat :=
  embedSourceDense (beforeDense statement witness authorizationRows) afterDense
    (typedSourceValues statement witness)

theorem before_dense_length (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows : List Nat) (authLength : authorizationRows.length = 9920) :
    (beforeDense statement witness authorizationRows).length = 15808 := by
  simp only [beforeDense, List.length_append, packed_prefix_length, authLength]

theorem composed_as_placed_prefix (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows afterDense : List Nat) :
    composedAssignment statement witness authorizationRows afterDense =
      placePrefix statement witness
        (authorizationRows ++ (sourceDensePacked (typedSourceValues statement witness) ++ afterDense)) := by
  simp only [composedAssignment, embedSourceDense, beforeDense, placePrefix, List.append_assoc]

theorem composed_length (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows afterDense : List Nat) (authLength : authorizationRows.length = 9920) :
    (composedAssignment statement witness authorizationRows afterDense).length =
      16128 + afterDense.length := by
  simp only [composedAssignment, embedSourceDense, List.length_append,
    before_dense_length statement witness authorizationRows authLength, source_dense_packed_length]
  omega

theorem composed_full_length (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows afterDense : List Nat) (authLength : authorizationRows.length = 9920)
    (afterLength : afterDense.length = 27776) :
    (composedAssignment statement witness authorizationRows afterDense).length = 43904 := by
  rw [composed_length statement witness authorizationRows afterDense authLength, afterLength]

theorem composed_private_value_addresses (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows afterDense : List Nat) :
    (composedAssignment statement witness authorizationRows afterDense).getD 0 0 =
        (witness.inputs.getD 0 default).note.value ∧
    (composedAssignment statement witness authorizationRows afterDense).getD 2176 0 =
        (witness.inputs.getD 1 default).note.value ∧
    (composedAssignment statement witness authorizationRows afterDense).getD 4352 0 =
        (witness.outputs.getD 0 default).note.value ∧
    (composedAssignment statement witness authorizationRows afterDense).getD 5120 0 =
        (witness.outputs.getD 1 default).note.value := by
  rw [composed_as_placed_prefix]
  exact placed_private_value_addresses statement witness _

theorem composed_private_source_value (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows afterDense : List Nat) (value : Fin 7) (privateValue : value.val < 4) :
    (composedAssignment statement witness authorizationRows afterDense).getD
        (densePrivateAddress value.val) 0 = typedSourceValues statement witness value := by
  have addresses := composed_private_value_addresses statement witness authorizationRows afterDense
  fin_cases value <;> norm_num at privateValue
  · exact addresses.1
  · exact addresses.2.1
  · exact addresses.2.2.1
  · exact addresses.2.2.2

/-- The exact seven generated dense reconstruction entries, with their actual
coefficient DAG, now evaluate to zero on the explicitly composed assignment. -/
theorem composed_all_seven_actual_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows afterDense : List Nat) (authLength : authorizationRows.length = 9920)
    (value : Fin 7) :
    (exactCsrAttempts[15665 + value.val]?).map
        (actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (composedAssignment statement witness authorizationRows afterDense)) = some 0 := by
  unfold composedAssignment
  rw [source_dense_actual_csr_residual _ afterDense (typedSourceValues statement witness)
    (before_dense_length statement witness authorizationRows authLength) _ value]
  by_cases privateValue : value.val < 4
  · rw [if_pos privateValue]
    change some (((composedAssignment statement witness authorizationRows afterDense).getD
      (densePrivateAddress value.val) 0 : F) - (typedSourceValues statement witness value : F)) = some 0
    rw [composed_private_source_value statement witness authorizationRows afterDense value privateValue, sub_self]
  · rw [if_neg privateValue, typed_source_public_value statement witness value (by omega), sub_self]

theorem composed_authorization_unchanged (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows afterDense : List Nat) (index : Nat) (bound : index < authorizationRows.length) :
    (composedAssignment statement witness authorizationRows afterDense).getD (5888 + index) 0 =
      authorizationRows.getD index 0 := by
  rw [composed_as_placed_prefix, placed_tail_unchanged]
  simp only [List.getD_eq_getElem?_getD, List.getElem?_append_left bound]

theorem composed_after_dense_unchanged (statement : V8PublicStatement) (witness : V8Witness)
    (authorizationRows afterDense : List Nat) (authLength : authorizationRows.length = 9920)
    (index : Nat) :
    (composedAssignment statement witness authorizationRows afterDense).getD (16128 + index) 0 =
      afterDense.getD index 0 := by
  have beforeLength := before_dense_length statement witness authorizationRows authLength
  simp only [composedAssignment, embedSourceDense, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_right (by omega :
    (beforeDense statement witness authorizationRows).length ≤ 16128 + index)]
  have subtract : 16128 + index - (beforeDense statement witness authorizationRows).length =
      (sourceDensePacked (typedSourceValues statement witness)).length + index := by
    rw [source_dense_packed_length]
    omega
  rw [subtract, List.getElem?_append_right (by omega)]
  simp only [Nat.add_sub_cancel_left]


end HegemonCrypto.SmallWood.V8Smz9SourceDensePrefix
