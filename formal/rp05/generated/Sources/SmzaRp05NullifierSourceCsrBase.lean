import SmzaRp05NullifierBinding
import SmzaRp05TypedRelation
import Hegemon.Transaction.Poseidon2Width16Kernel
import SmzaRp05NullifierSourceDirection

/-! Internal source chunk SmzaRp05NullifierSourceCsr. Original declaration bodies and statements are retained. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex inputDirectionRow)
open _root_.HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open _root_.HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open _root_.Hegemon.Transaction.Poseidon2Width16Kernel
open _root_.HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

private theorem realizes_bound {expressions : List FieldExpression}
    {node : Nat} {term : SourceTerm} (realizes : Realizes expressions node term) :
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

theorem position_terms_field
    (values packed : List Nat) (input : Fin 2) (powerNode : Nat → Nat)
    (powerValue : ∀ bit, bit < 32 →
      (values.getD (powerNode bit) 0 : Goldilocks) =
        -(2 ^ bit : Goldilocks)) :
    csrFieldSum values packed (positionTerms input powerNode) =
      -(projectPosition packed input.val : Goldilocks) := by
  have sum_map_neg (xs : List Goldilocks) :
      (xs.map fun value => -value).sum = -xs.sum := by
    induction xs with
    | nil => simp
    | cons head tail ih => simp only [List.map_cons, List.sum_cons, ih]; ring
  unfold csrFieldSum positionTerms
  simp only [List.map_map]
  calc
    ((List.range 32).map fun bit =>
      (values.getD (powerNode bit) 0 : Goldilocks) *
        (packed.getD (rawIndex (inputDirectionRow input.val bit)) 0 : Goldilocks)).sum =
      ((List.range 32).map fun bit =>
        -((2 ^ bit : Goldilocks) *
          (packed.getD (rawIndex (inputDirectionRow input.val bit)) 0 : Goldilocks))).sum := by
        congr 1
        apply List.map_congr_left
        intro bit member
        rw [powerValue bit (List.mem_range.mp member)]
        ring
    _ = -((List.range 32).map fun bit =>
          (2 ^ bit : Goldilocks) *
            (packed.getD (rawIndex (inputDirectionRow input.val bit)) 0 : Goldilocks)).sum := by
          let terms := (List.range 32).map fun bit =>
            (2 ^ bit : Goldilocks) *
              (packed.getD (rawIndex (inputDirectionRow input.val bit)) 0 : Goldilocks)
          change (terms.map fun value => -value).sum = -terms.sum
          exact sum_map_neg terms
    _ = -(projectPosition packed input.val : Goldilocks) := by
          unfold projectPosition directionWord packedWord
          have castSum (bits : List Nat) :
              (bits.map fun bit =>
                (2 ^ bit : Goldilocks) *
                  (packed.getD (rawIndex (inputDirectionRow input.val bit)) 0 : Goldilocks)).sum =
                (((bits.map fun bit =>
                  2 ^ bit * packed.getD (rawIndex (inputDirectionRow input.val bit)) 0).sum : Nat) : Goldilocks) := by
            induction bits with
            | nil => simp
            | cons bit bits ih =>
                simp only [List.map_cons, List.sum_cons, Nat.cast_add]
                rw [ih]
                congr 1
                norm_num
          exact congrArg (fun value : Goldilocks => -value) (castSum (List.range 32))

theorem csr_sum_append (values packed : List Nat)
    (left right : List (Nat × Nat)) :
    csrFieldSum values packed (left ++ right) =
      csrFieldSum values packed left + csrFieldSum values packed right := by
  unfold csrFieldSum
  rw [List.map_append, List.sum_append]

/-- Exact field equation forced by the current 32-cell nullifier CSR
certificate.  This includes the weighted position bits and note-rho sources,
not just the two hash calls. -/
theorem accepted_initial_cell_equation {components : RelationProgramComponents}
    (certificate : InitialCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (cell : InitialCell) :
    ∃ values, evalExpressionNodes publicWords [] components.csrExpressions =
        some values ∧
      csrFieldSum values packed
        (initialTerms certificate.oneNode certificate.negativeNode
          certificate.positiveNode
          certificate.powerNode cell) =
        (values.getD (certificate.constantNode cell) 0 : Goldilocks) := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (certificate.member cell))
  rw [certificate.attemptTerms cell, certificate.attemptTarget cell] at equation
  exact ⟨values, evaluated, equation⟩

/-- The exact two frames of the twelve-word source sponge. -/
def firstFrame (inputs : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 8 then _root_.Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD lane 0)
    else if lane = 8 then currentNullifierDomain
    else if lane = 9 then 12
    else if lane = 10 then poseidon2V8SpongeModeMarker
    else if lane = 15 then poseidon2V8SuiteMarker
    else 0

def lastFrame (inputs state : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 4 then
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd (state.getD lane 0)
        (inputs.getD (8 + lane) 0)
    else if lane = 11 then
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) 1
    else state.getD lane 0

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
