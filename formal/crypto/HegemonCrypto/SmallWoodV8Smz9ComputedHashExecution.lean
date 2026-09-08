import HegemonCrypto.SmallWoodV8Smz9ComputedHashRoots
import HegemonCrypto.SmallWoodV8Smz9CurrentSourceAcceptance

/-! Interpreter corollary for the exact 332-root slice. This is not acceptance of
the other 498 nonlinear roots or of the full packed relation. The expression
list is the unchanged complete generated nonlinear program, not a new evaluator.
-/

namespace HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9CurrentSourceAcceptance
set_option Elab.async false
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
noncomputable section

def exactHashRootProgram : ExpressionProgram :=
  { expressions := exactNonlinearExpressions
    roots := (exactNonlinearRoots.drop 471).take 332 }

theorem exact_hash_root_program_canonical : exactHashRootProgram.Canonical true := by
  constructor
  · exact hgv8rp03_nonlinear_expression_program_is_canonical.1
  · intro root member
    exact hgv8rp03_nonlinear_expression_program_is_canonical.2 root
      (List.mem_of_mem_drop (List.mem_of_mem_take member))

theorem computed_hash_root_source_accepts (leading suffix : List Nat) (live : LiveInitialStates)
    (leadingLength : leading.length = 18112) (publicWords : List Nat)
    (publicLength : 120 ≤ publicWords.length) (lane : Nat) (hl : lane < 64) :
    exactHashRootProgram.Accepts publicWords (packedWitnessLaneRows (placeHashBlock leading live suffix) lane) := by
  apply field_roots_zero_supplies_source_acceptance
  · exact publicLength
  · simp only [packedWitnessLaneRows, List.length_map, List.length_range, relationRowCount, le_refl]
  · exact exact_hash_root_program_canonical
  · intro root member
    exact computed_block_exact_root_span_zero leading suffix live leadingLength publicWords lane hl root member

/-- One actual interpreter run gives zero at every member of the exact hash-root span. -/
theorem computed_hash_root_interpreter_execution (leading suffix : List Nat) (live : LiveInitialStates)
    (leadingLength : leading.length = 18112) (publicWords : List Nat)
    (publicLength : 120 ≤ publicWords.length) (lane : Nat) (hl : lane < 64) :
    ∃ values,
      evalExpressionNodes publicWords (packedWitnessLaneRows (placeHashBlock leading live suffix) lane)
        exactNonlinearExpressions = some values ∧
      ∀ root, root ∈ (exactNonlinearRoots.drop 471).take 332 → values[root]? = some 0 := by
  obtain ⟨values, evaluated, rootsZero⟩ := computed_hash_root_source_accepts
    leading suffix live leadingLength publicWords publicLength lane hl
  refine ⟨values, evaluated, ?_⟩
  intro root member
  have image : values[root]? ∈ exactHashRootProgram.roots.map (fun index => values[index]?) :=
    List.mem_map.mpr ⟨root, member, rfl⟩
  rw [rootsZero] at image
  simp only [List.mem_map, List.mem_replicate] at image
  obtain ⟨word, ⟨_, wordZero⟩, same⟩ := image
  simpa only [wordZero] using same.symm

end
end HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
