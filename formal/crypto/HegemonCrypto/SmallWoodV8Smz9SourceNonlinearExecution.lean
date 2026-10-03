import HegemonCrypto.SmallWoodV8Smz9SourceAllNonlinear
import HegemonCrypto.SmallWoodV8Smz9CurrentSourceAcceptance

/-! The actual complete nonlinear interpreter succeeds from fixed typed
validity. CSR acceptance and the complete packed relation remain separate. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceNonlinearExecution
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9CurrentSourceAcceptance
open HegemonCrypto.SmallWood.V8Smz9SourceAllNonlinear
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows (typed_encoded_public_exact)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem full_candidate_nonlinear_source_accepts
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    hgv8rp03ProgramComponents.nonlinearExecutable.Accepts (encodePublicStatement statement)
      (packedWitnessLaneRows (fullTypedSourceCandidate statement witness) lane.val) := by
  apply field_roots_zero_supplies_source_acceptance
  · exact Nat.le_of_eq (typed_encoded_public_exact statement witness valid).1.symm
  · simp only [packedWitnessLaneRows,List.length_map,List.length_range,relationRowCount,le_refl]
  · exact hgv8rp03_nonlinear_expression_program_is_canonical
  · intro root member
    change root ∈ exactNonlinearRoots at member
    obtain ⟨index,bound,same⟩ := List.mem_iff_getElem.mp member
    have indexBound : index < 830 := by rw [actual_root_list_length] at bound; exact bound
    have found : exactNonlinearRoots[index]? = some root := by
      rw [List.getElem?_eq_getElem bound,same]
    have zero := full_candidate_all_830_actual_nonlinear_roots_zero statement witness valid lane ⟨index,indexBound⟩
    rw [found,Option.map_some] at zero
    exact Option.some.inj zero

theorem full_candidate_complete_nonlinear_interpreter_execution
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    ∃ values,
      evalExpressionNodes (encodePublicStatement statement)
        (packedWitnessLaneRows (fullTypedSourceCandidate statement witness) lane.val)
        exactNonlinearExpressions = some values ∧
      exactNonlinearRoots.map (fun root => values[root]?) = List.replicate 830 (some 0) := by
  obtain ⟨values,evaluated,zero⟩ := full_candidate_nonlinear_source_accepts statement witness valid lane
  refine ⟨values,evaluated,?_⟩
  simpa only [hgv8rp03ProgramComponents,actual_root_list_length,List.map_replicate] using zero

end
end HegemonCrypto.SmallWood.V8Smz9SourceNonlinearExecution
