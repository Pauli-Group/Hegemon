import SmzaRp05PairedHashDagFiniteSplit
import HegemonCrypto.SmallWoodV8Smz9ProgramPolynomials

/-! Field evaluation transport using the checked, bounded DAG chunks.  This
module deliberately does not import the monolithic `decide` aggregation. -/

namespace HegemonCrypto.SmallWood.SmzaRp05ChunkedDagRefinement

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

private theorem expressionField_mapped
    (pub rows current reference : Nat → Goldilocks)
    (expression : FieldExpression)
    (children : ∀ child, child ∈ expressionChildren expression →
      current child = reference (mappedNode child)) :
    expressionField pub rows current expression =
      expressionField pub rows reference
        (mappedExpression mappedNode expression) := by
  cases expression with
  | constant value => rfl
  | publicWord index => rfl
  | witnessRow row => rfl
  | add left right =>
      simp only [expressionField, mappedExpression]
      rw [children left (by simp [expressionChildren]),
        children right (by simp [expressionChildren])]
  | sub left right =>
      simp only [expressionField, mappedExpression]
      rw [children left (by simp [expressionChildren]),
        children right (by simp [expressionChildren])]
  | mul left right =>
      simp only [expressionField, mappedExpression]
      rw [children left (by simp [expressionChildren]),
        children right (by simp [expressionChildren])]
  | neg value =>
      simp only [expressionField, mappedExpression]
      rw [children value (by simp [expressionChildren])]
  | inverse value =>
      simp only [expressionField, mappedExpression]
      rw [children value (by simp [expressionChildren])]
  | selectEqual left right equal notEqual =>
      simp only [expressionField, mappedExpression]
      rw [children left (by simp [expressionChildren]),
        children right (by simp [expressionChildren]),
        children equal (by simp [expressionChildren]),
        children notEqual (by simp [expressionChildren])]
  | bit value bit =>
      simp only [expressionField, mappedExpression]
      rw [children value (by simp [expressionChildren])]

private theorem directed_edge_sound (node : Nat)
    (checked : directedEdgeCheck node = true) :
    ∃ expression,
      currentExpressions[node]? = some expression ∧
      referenceExpressions[mappedNode node]? =
        some (mappedExpression mappedNode expression) ∧
      ∀ child, child ∈ expressionChildren expression →
        supportedNode child ∧ child < node ∧ mappedNode child < mappedNode node := by
  unfold directedEdgeCheck at checked
  cases found : currentExpressions[node]? with
  | none => simp [found] at checked
  | some expression =>
      simp only [found, Bool.and_eq_true, decide_eq_true_eq,
        List.all_eq_true] at checked
      refine ⟨expression, rfl, checked.1, ?_⟩
      intro child member
      exact checked.2 child member

private theorem checked_supported (node : Nat) (supported : supportedNode node) :
    directedEdgeCheck node = true := by
  rcases supported with low | at1387 | at1390 | at1393 | high
  · exact SmzaRp05PairedHashDagData.checked_low node (Nat.zero_le _) low
  · subst node; exact SmzaRp05PairedHashDagData.checked_special_1387
  · subst node; exact SmzaRp05PairedHashDagData.checked_special_1390
  · subst node; exact SmzaRp05PairedHashDagData.checked_special_1393
  · exact SmzaRp05PairedHashDagData.checked_high node high.1 high.2

/-- The chunked opcode and edge checks prove field equality at every supported
node, including the 332 hash-root right-hand subgraphs. -/
theorem paired_fieldAt (pub rows : Nat → Goldilocks)
    (node : Nat) (supported : supportedNode node) :
    fieldAt currentExpressions pub rows node =
      fieldAt referenceExpressions pub rows (mappedNode node) := by
  induction node using Nat.strong_induction_on with
  | h node earlier =>
      obtain ⟨expression, currentFound, referenceFound, children⟩ :=
        directed_edge_sound node (checked_supported node supported)
      rw [fieldAt_eq, currentFound, fieldAt_eq, referenceFound]
      apply expressionField_mapped
      intro child member
      obtain ⟨childSupported, currentEarlier, referenceEarlier⟩ :=
        children child member
      simp only [if_pos currentEarlier, if_pos referenceEarlier]
      exact earlier child currentEarlier childSupported

end HegemonCrypto.SmallWood.SmzaRp05ChunkedDagRefinement
