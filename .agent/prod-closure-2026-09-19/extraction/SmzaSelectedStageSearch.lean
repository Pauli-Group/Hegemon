import SmzaFixedAdviceBadCell
import HegemonCrypto.CmsAdaptiveClaimBridge
import HegemonCrypto.CmsFinitePhaseSystem

/-! Selected-stage search with an adaptive final claim. This uses the actual
finite CMS execution and its uniform-oracle simulation, not an assumed search
inequality. Other-stage fixed advice can parameterize every argument. The
live-VC label coupling and concrete role cardinalities remain separate inputs
to the complete SMZA theorem. In particular the bridge loss is not dropped. -/

namespace HegemonCrypto.SmallWood.SmzaSelectedStageSearch

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsLifting
open HegemonCrypto.CmsFinitePhaseSystem
open SmzaFixedAdviceBadCell

noncomputable section
set_option autoImplicit false

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output] [Inhabited Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

def selectedClaimEvent (bad : Input → Output → Prop)
    (selected : Workspace → Input × Output) : Workspace → Database Input Output → Prop :=
  AdaptiveClaimsEvent (fun workspace => bad (selected workspace).1 (selected workspace).2)
    (fun workspace => [selected workspace])

omit [Fintype Input] [DecidableEq Input] [Fintype Output] [DecidableEq Output]
  [AddCommGroup Output] [Inhabited Output] [Fintype Workspace] [DecidableEq Workspace] in
theorem selected_claim_implies_bad_cell (bad : Input → Output → Prop)
    (selected : Workspace → Input × Output) (workspace : Workspace)
    (database : Database Input Output)
    (accepted : selectedClaimEvent bad selected workspace database) : BadCell bad database := by
  exact ⟨(selected workspace).1, (selected workspace).2,
    accepted.2 (selected workspace) (by simp), accepted.1⟩

omit [Inhabited Output] [Fintype Phase] [DecidableEq Phase]
  [Fintype Workspace] [DecidableEq Workspace] in
theorem initial_bad_cell_project_zero (bad : Input → Output → Prop) (cap : Nat)
    (registers : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    project (BadCell bad) cap (partialRandomOracleState (Output := Output) ∅ registers) = 0 := by
  funext basis
  by_cases records : RecordsExactly (Output := Output) ∅ basis.database
  · have same := (records_exactly_empty_iff basis.database).mp records
    have outside : ¬ BadCell bad (empty : Database Input Output) := by
      rintro ⟨input, output, recorded, _⟩
      cases recorded
    simp [project, same, size_empty, outside]
  · simp [project, partialRandomOracleState, records]

/-- Uniform-oracle probability bound for any adaptively chosen final bad
complete-vector claim. There is no union factor over inputs or labels. -/
theorem selected_stage_oracle_search
    (system : CompletePhaseSystem Output Phase)
    (bad : Input → Output → Prop) (epsilon : Rat)
    (nonnegative : 0 ≤ epsilon)
    (perInput : ∀ input, outputEventProbability (bad input) ≤ epsilon)
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := Output) ∅ registers))
    (selected : Workspace → Input × Output) :
    normSquared (workspaceEventProjection (selectedClaimEvent bad selected)
      (totalOracleFamilyState (oracleFamilyRun system.system steps (fun _ => registers)))) ≤
      oracleLoss (databaseLoss steps.length (epsilon : ℝ))
        (1 / (Fintype.card Output : ℝ)) := by
  let blind := steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let initial := partialRandomOracleState (Output := Output) ∅ registers
  let finalState := rawRun system.system steps.length blind initial
  have capacity : blind.length ≤ steps.length := by simp [blind]
  have emptySupport : BoundedState 0 initial := partial_random_oracle_empty_bounded registers
  have bounded : BoundedState steps.length finalState := by
    exact raw_run_bounded_of_bounded system.system steps.length blind initial 0
      (by simpa using capacity) emptySupport
  have finalNormalized : Subnormalized finalState :=
    raw_run_subnormalized_of_bounded system.system steps.length blind initial 0
      (by simpa using capacity) emptySupport normalized
  have databaseBound : normSquared (project (BadCell bad) steps.length finalState) ≤
      databaseLoss steps.length (epsilon : ℝ) := by
    have result := implemented_raw_database_game_le_database_loss system.system
      (BadCell bad) steps.length blind initial
      (selected_stage_instability bad steps.length epsilon nonnegative perInput).toReal
      capacity emptySupport normalized (initial_bad_cell_project_zero bad steps.length registers)
    simpa only [blind, List.length_map] using result
  have result := adaptive_claims_probability_le finalState
    (oracleFamilyRun system.system steps (fun _ => registers))
    (compressed_run_is_uniform_random_oracle_purification
      system.system steps.length steps registers le_rfl)
    (fun workspace => bad (selected workspace).1 (selected workspace).2)
    (fun workspace => [selected workspace]) (fun _ => by simp) 1 (fun _ => by simp)
    (BadCell bad) (selected_claim_implies_bad_cell bad selected)
    steps.length bounded finalNormalized (databaseLoss steps.length (epsilon : ℝ)) databaseBound
  simpa only [Nat.cast_one, one_pow, one_mul, selectedClaimEvent] using result

theorem selected_stage_oracle_search_loose
    (system : CompletePhaseSystem Output Phase)
    (bad : Input → Output → Prop) (epsilon : Rat)
    (nonnegative : 0 ≤ epsilon)
    (perInput : ∀ input, outputEventProbability (bad input) ≤ epsilon)
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := Output) ∅ registers))
    (selected : Workspace → Input × Output) :
    normSquared (workspaceEventProjection (selectedClaimEvent bad selected)
      (totalOracleFamilyState (oracleFamilyRun system.system steps (fun _ => registers)))) ≤
      12 * (steps.length : ℝ)^2 * (epsilon : ℝ) + 2 / (Fintype.card Output : ℝ) := by
  have nonnegativeReal : (0 : ℝ) ≤ (epsilon : ℝ) := by exact_mod_cast nonnegative
  refine (selected_stage_oracle_search system bad epsilon nonnegative perInput
    steps registers normalized selected).trans ?_
  have result := oracle_loss_le_two_sum (databaseLoss steps.length (epsilon : ℝ))
    (1 / (Fintype.card Output : ℝ)) (by unfold databaseLoss; positivity) (by positivity)
  exact result.trans (by
    unfold databaseLoss
    ring_nf
    exact le_rfl)

end
end HegemonCrypto.SmallWood.SmzaSelectedStageSearch
