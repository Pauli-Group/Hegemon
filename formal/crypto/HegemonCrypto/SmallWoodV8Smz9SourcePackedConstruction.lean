import HegemonCrypto.SmallWoodV8Smz9SourceAllCsr
import HegemonCrypto.SmallWoodV8Smz9SourceCsrExecution
import HegemonCrypto.SmallWoodV8Smz9SourceNonlinearExecution

/-! Complete forward construction from fixed typed semantic validity to the
actual packed Option interpreters. This is source construction, not an
accepted-proof extractor, native Rust equivalence or production authority. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourcePackedConstruction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood
open V8Smz9RelationProgramComponentsGenerated
open V8Smz9SourceFullTypedCandidate
open V8Smz9SourceCsrCompositionBase
open V8Smz9SourceAllCsr
open V8Smz9SourceCsrExecution
open V8Smz9SourceNonlinearExecution
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem full_candidate_complete_csr_interpreter_execution
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    csrExecutableProgramAccepts exactCsrExpressions exactCsrAttempts
      (encodePublicStatement statement) (fullTypedSourceCandidate statement witness) :=
  actual_residuals_supply_csr_execution _ _
    (typed_public_words_canonical statement witness valid)
    (full_candidate_canonical statement witness valid)
    (full_candidate_all_actual_csr_residuals_zero statement witness valid)

theorem full_candidate_actual_packed_source_acceptance
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    hgv8rp03ProgramComponents.AcceptsPacked (encodePublicStatement statement)
      (fullTypedSourceCandidate statement witness) := by
  refine ⟨typed_public_words_canonical statement witness valid,
    full_candidate_canonical statement witness valid,?_,
    full_candidate_complete_csr_interpreter_execution statement witness valid⟩
  intro lane bound
  exact full_candidate_nonlinear_source_accepts statement witness valid ⟨lane,bound⟩

theorem every_typed_valid_witness_has_constructed_packed_acceptance
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ∃ packed, packed = fullTypedSourceCandidate statement witness ∧
      packed.length = 43904 ∧
      hgv8rp03ProgramComponents.AcceptsPacked (encodePublicStatement statement) packed :=
  ⟨fullTypedSourceCandidate statement witness,rfl,full_candidate_length statement witness,
    full_candidate_actual_packed_source_acceptance statement witness valid⟩

theorem full_candidate_canonical_public_packed_domain
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    V8Smz9SemanticBinding.CanonicalPublicPackedDomain statement (encodePublicStatement statement)
      (fullTypedSourceCandidate statement witness) :=
  ⟨rfl,valid.1,full_candidate_actual_packed_source_acceptance statement witness valid⟩

end
end HegemonCrypto.SmallWood.V8Smz9SourcePackedConstruction
