import HegemonCrypto.SmallWoodV8Smz9SourceCsrEarlyComposition
import HegemonCrypto.SmallWoodV8Smz9SourceCsrMiddleComposition
import HegemonCrypto.SmallWoodV8Smz9SourceNumeric174Composition

/-! Whole-table CSR coverage, with every indexed equation interpreted using
the actual public coefficient DAG and the same complete source candidate. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceAllCsr
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood
open V8Smz9RelationProgramComponentsGenerated
open V8Smz9SourceCsrCompositionBase
open V8Smz9SourceCsrEarlyComposition
open V8Smz9SourceCsrMiddleComposition
open V8Smz9SourceNumeric174Composition
open V8Smz9SourceFullTypedCandidate
open V8Smz9SourceDenseCsr
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem actual_csr_table_length : exactCsrAttempts.length = 20605 :=
  exact_program_component_inventory.2.2.2.2.2.2.2.2.2

theorem full_candidate_all_20605_actual_csr_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 20605) :
    sourceCsrZero statement witness index.val := by
  by_cases early : index.val < 19168
  · exact full_candidate_all_19168_early_csr_zero statement witness valid ⟨index.val,early⟩
  by_cases middle : index.val < 20320
  · exact full_candidate_middle1152_csr_zero statement witness valid index.val (by omega) middle
  by_cases numeric : index.val < 20494
  · have zero : sourceCsrZero statement witness (20320+(index.val-20320)) :=
      full_candidate_actual_numeric174_zero statement witness valid ⟨index.val-20320,by omega⟩
    exact source_csr_reindex statement witness (by omega) zero
  · exact full_candidate_last111_csr_zero statement witness index.val (by omega) index.isLt

theorem full_candidate_all_actual_csr_residuals_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (entry : Hegemon.Transaction.Poseidon2V8RelationProgram.CsrExecutableAttempt)
    (member : entry ∈ exactCsrAttempts) :
    actualCsrResidual (sourceCsrPub statement) (fullTypedSourceCandidate statement witness) entry = 0 := by
  obtain ⟨index,bound,same⟩ := List.mem_iff_getElem.mp member
  have indexBound : index < 20605 := by rw [actual_csr_table_length] at bound; exact bound
  have found : exactCsrAttempts[index]? = some entry := by
    rw [List.getElem?_eq_getElem bound,same]
  have zero := full_candidate_all_20605_actual_csr_zero statement witness valid ⟨index,indexBound⟩
  change (exactCsrAttempts[index]?).map
    (actualCsrResidual (sourceCsrPub statement) (fullTypedSourceCandidate statement witness)) = some 0 at zero
  rw [found,Option.map_some] at zero
  exact Option.some.inj zero

end
end HegemonCrypto.SmallWood.V8Smz9SourceAllCsr

