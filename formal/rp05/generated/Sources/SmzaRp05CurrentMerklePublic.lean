import SmzaRp05AcceptedInputShape
import HegemonCrypto.SmallWoodV8Smz9ProgramPolynomials

/-!
# Current RP05 public Merkle-root gate (source-only)

The current parsed fixture places the two 32-level Merkle paths at calls
4..35 and 41..72. Its fourteen public-root CSR attempts are indexed by
`18241 + 7*input + limb` and copy the final digest through an active-input
gate into public words 47..53. The certificate below contains only finite
program syntax and exact membership; it has no witness-quantified semantic
field. A fixture-specific instance still needs to be generated and checked.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentMerklePublic

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation

set_option autoImplicit false

def currentMerkleCall (input : Fin 2) (level : Fin 32) : Nat :=
  if input.val = 0 then 4 + level.val else 41 + level.val

abbrev PublicRootCell := Fin 2 × Fin 7

/-- Exact active-input public-root CSR family of the selected RP05 program. -/
structure PublicRootCertificate (components : RelationProgramComponents) where
  canonical : ({ expressions := components.csrExpressions, roots := [] } :
    ExpressionProgram).Canonical true
  activeNode : Fin 2 → Nat
  targetNode : PublicRootCell → Nat
  activeRealizes : ∀ input, Realizes components.csrExpressions
    (activeNode input) (.publicInput input.val)
  targetRealizes : ∀ cell, Realizes components.csrExpressions
    (targetNode cell)
      (.mul (.publicInput cell.1.val) (.publicInput (47 + cell.2.val)))
  attempt : PublicRootCell → CsrExecutableAttempt
  member : ∀ cell, attempt cell ∈ components.csrAttempts
  attemptTerms : ∀ cell, (attempt cell).terms =
    [(hashFinalIndex (currentMerkleCall cell.1 ⟨31, by decide⟩)
      cell.2.val, activeNode cell.1)]
  attemptTarget : ∀ cell, (attempt cell).targetRoot = targetNode cell

theorem realizes_bound {expressions : List FieldExpression}
    {node : Nat} {term : SourceTerm}
    (realizes : Realizes expressions node term) :
    node < expressions.length := by
  induction realizes with
  | constant found => exact (List.getElem?_eq_some_iff.mp found).1
  | publicInput found => exact (List.getElem?_eq_some_iff.mp found).1
  | witness found => exact (List.getElem?_eq_some_iff.mp found).1
  | add found _ _ _ _ _ _ => exact (List.getElem?_eq_some_iff.mp found).1
  | sub found _ _ _ _ _ _ => exact (List.getElem?_eq_some_iff.mp found).1
  | mul found _ _ _ _ _ _ => exact (List.getElem?_eq_some_iff.mp found).1

theorem csr_node_value {components : RelationProgramComponents}
    (canonical : ({ expressions := components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical true)
    {publicWords values : List Nat}
    (evaluated : evalExpressionNodes publicWords [] components.csrExpressions =
      some values) {node : Nat} {term : SourceTerm}
    (realizes : Realizes components.csrExpressions node term) :
    (values.getD node 0 : Goldilocks) =
      term.eval (fun i => (publicWords.getD i 0 : Goldilocks)) (fun _ => 0) := by
  have source := fieldAt_refines_source
    ({ expressions := components.csrExpressions, roots := [] } : ExpressionProgram)
    publicWords [] values canonical evaluated node (realizes_bound realizes)
  rw [fieldAt_of_realizes realizes] at source
  simpa using source.symm

/-- From actual current packed acceptance and a checked finite CSR
certificate: active input's final Merkle call limb equals the corresponding
public anchor limb. The inactive branch is deliberately not claimed. -/
theorem accepted_active_public_merkle_word
    {components : RelationProgramComponents}
    (certificate : PublicRootCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 7)
    (active : publicWords.getD input.val 0 = 1) :
    packed.getD
      (hashFinalIndex (currentMerkleCall input ⟨31, by decide⟩) limb.val) 0 =
      publicWords.getD (47 + limb.val) 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have gate : (values.getD (certificate.activeNode input) 0 : Goldilocks) = 1 := by
    simpa only [SourceTerm.eval, active, Nat.cast_one] using
      csr_node_value certificate.canonical evaluated
        (certificate.activeRealizes input)
  have target :
      (values.getD (certificate.targetNode (input, limb)) 0 : Goldilocks) =
        (publicWords.getD (47 + limb.val) 0 : Goldilocks) := by
    simpa only [SourceTerm.eval, active, Nat.cast_one, one_mul] using
      csr_node_value certificate.canonical evaluated
        (certificate.targetRealizes (input, limb))
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (certificate.member (input, limb)))
  rw [certificate.attemptTerms (input, limb),
    certificate.attemptTarget (input, limb)] at equation
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, gate, target, one_mul, add_zero] at equation
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 _)
    (canonical_public_coordinate accepted.1
      (by change 47 + limb.val < 120; have := limb.isLt; omega)).2
    equation

end HegemonCrypto.SmallWood.SmzaRp05CurrentMerklePublic
