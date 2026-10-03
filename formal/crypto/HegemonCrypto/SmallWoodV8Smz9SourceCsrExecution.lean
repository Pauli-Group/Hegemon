import HegemonCrypto.SmallWoodV8Smz9CurrentSourceAcceptance
import HegemonCrypto.SmallWoodV8Smz9SourceDenseCsr

namespace HegemonCrypto.SmallWood.V8Smz9SourceCsrExecution

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9CurrentPublicContext
open HegemonCrypto.SmallWood.V8Smz9CurrentSourceAcceptance
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

noncomputable section

/--
  A generic raw-CSR supplier.  The residual premise is the actual DAG
  interpretation at the canonical publicValues coordinates; it is not an accepted
  program premise.  The conclusion is the executable CSR acceptance witness.
-/
theorem actual_residuals_supply_csr_execution
    (publicValues : List Nat) (witness : List Nat)
    (publicCanonical : CanonicalPublicWords publicValues)
    (witnessCanonical : CanonicalPackedWitness witness)
    (residuals : ∀ (entry : CsrExecutableAttempt), entry ∈ exactCsrAttempts →
      actualCsrResidual (fun index => (publicValues.getD index 0 : F)) witness entry = 0) :
    csrExecutableProgramAccepts exactCsrExpressions exactCsrAttempts publicValues witness := by
  have evaluated := canonical_public_expression_program_succeeds publicValues publicCanonical
  let values := publicExpressionValues publicValues
  have valuesCanonical := source_go_canonical publicValues [] [] values exactCsrExpressions
    (by simp) evaluated
  have valuesLength : values.length = exactCsrExpressions.length := by
    obtain ⟨result, succeeds, length⟩ := canonical_expression_program_resolves publicValues []
      { expressions := exactCsrExpressions, roots := [] } false
      (Nat.le_of_eq publicCanonical.1.symm) (by simp)
      hgv8rp03_csr_expression_program_is_canonical
    rw [evaluated] at succeeds
    have same : result = values := (Option.some.inj succeeds).symm
    simpa only [same] using length
  have coefficient_eq : ∀ (node : Nat), node < exactCsrExpressions.length →
      actualCsrCoefficients (fun index => (publicValues.getD index 0 : F)) node =
        (values.getD node 0 : F) := by
    intro node bound
    have bridge := fieldAt_refines_source
      { expressions := exactCsrExpressions, roots := [] }
      publicValues [] values exact_csr_is_canonical_with_rows evaluated node bound
    simpa [actualCsrCoefficients] using bridge
  refine ⟨values, evaluated, ?_⟩
  intro entry member
  obtain ⟨index, found⟩ := List.mem_iff_getElem?.mp member
  have canonical := hgv8rp03_program_is_canonical.2.2.2.2.2.2.2.2.2.2.2.1
    index entry found
  have coordinates := canonical.1.2.2.2.1
  change ∀ term, term ∈ entry.terms → term.1 < packedWitnessWordCount ∧
    term.2 < exactCsrExpressions.length at coordinates
  have targetBound : entry.targetRoot < exactCsrExpressions.length := canonical.1.2.2.2.2
  have residual := residuals entry member
  have terms_eq :
      entry.terms.map (fun term =>
        actualCsrCoefficients (fun index => (publicValues.getD index 0 : F)) term.2 *
          (witness.getD term.1 0 : F)) =
      entry.terms.map (fun term =>
        (values.getD term.2 0 : F) * (witness.getD term.1 0 : F)) := by
    apply List.map_congr_left
    intro term inTerms
    rw [coefficient_eq term.2 (coordinates term inTerms).2]
  have equation : csrFieldSum values witness entry.terms =
      (values.getD entry.targetRoot 0 : F) := by
    unfold actualCsrResidual actualCsrTerms at residual
    rw [sub_eq_zero] at residual
    rw [terms_eq, coefficient_eq entry.targetRoot targetBound] at residual
    exact residual
  apply field_csr_equation_supplies_source_acceptance values witness entry
  · intro term inTerms
    simpa only [witnessCanonical.1, valuesLength] using coordinates term inTerms
  · simpa only [valuesLength] using targetBound
  · exact valuesCanonical
  · exact equation

end
end HegemonCrypto.SmallWood.V8Smz9SourceCsrExecution
