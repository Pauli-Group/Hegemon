import SmzaDynamicDatabaseSoundness

/-! Dynamic-label soundness on one actual initialized CMS/oracle execution.
There is no assumed distribution comparison with a uniform verifier challenge,
no supplied multi-stage quantum bound, and no equality between separately
postulated execution states.  The actual uniform-oracle purification and
adaptive-claims bridge are the checked CMS constructions. -/
namespace HegemonCrypto.SmallWood.SmzaDynamicOracleExecution

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsLifting
open HegemonCrypto.CmsFinitePhaseSystem
open SmzaDynamicDatabaseSoundness

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Input Output Phase Workspace Label : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output] [Inhabited Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

theorem initialized_dynamic_bad_zero
    (label : Database Input Output → Input → Label)
    (bad : Label → Input → Output → Prop) (cap : Nat)
    (registers : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    project (DynamicBad label bad) cap
      (partialRandomOracleState (Output := Output) ∅ registers) = 0 := by
  funext basis
  by_cases records : RecordsExactly (Output := Output) ∅ basis.database
  · have same := (records_exactly_empty_iff basis.database).mp records
    have outside : ¬ DynamicBad label bad (empty : Database Input Output) := by
      rintro ⟨input, output, recorded, _⟩
      cases recorded
    simp [project, same, size_empty, outside]
  · simp [project, partialRandomOracleState, records]

/-- Complete actual oracle execution, including an arbitrary adaptively
chosen final claim list.  The deterministic `included` obligation connects a
protocol's accepted failure to the concrete bad-database predicate. -/
theorem actual_dynamic_oracle_failure_bound
    (system : CompletePhaseSystem Output Phase)
    (label : Database Input Output → Input → Label)
    (bad : Label → Input → Output → Prop) (epsilon delta : Rat)
    (epsilonNonnegative : 0 ≤ epsilon) (deltaNonnegative : 0 ≤ delta)
    (perLabel : ∀ value input, outputEventProbability (bad value input) ≤ epsilon)
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (changes : ∀ database, size database < steps.length → ∀ queried,
      stepProbability (TrackedLabelChange label database queried) database queried ≤ delta)
    (registers : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := Output) ∅ registers))
    (enabled : Workspace → Prop) (claims : Workspace → List (Input × Output))
    (distinct : ∀ workspace, ((claims workspace).map Prod.fst).Nodup)
    (maxClaims : Nat) (claimBound : ∀ workspace, (claims workspace).length ≤ maxClaims)
    (included : ∀ workspace database,
      AdaptiveClaimsEvent enabled claims workspace database → DynamicBad label bad database) :
    normSquared (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
      (totalOracleFamilyState (oracleFamilyRun system.system steps (fun _ => registers)))) ≤
      oracleLoss (databaseLoss steps.length ((delta + epsilon : Rat) : ℝ))
        ((maxClaims : ℝ)^2 / (Fintype.card Output : ℝ)) := by
  let blind := steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let initial := partialRandomOracleState (Output := Output) ∅ registers
  let finalState := rawRun system.system steps.length blind initial
  have capacity : blind.length ≤ steps.length := by simp [blind]
  have emptySupport : BoundedState 0 initial := partial_random_oracle_empty_bounded registers
  have bounded : BoundedState steps.length finalState :=
    raw_run_bounded_of_bounded system.system steps.length blind initial 0
      (by simpa using capacity) emptySupport
  have finalNormalized : Subnormalized finalState :=
    raw_run_subnormalized_of_bounded system.system steps.length blind initial 0
      (by simpa using capacity) emptySupport normalized
  have instability := dynamic_bad_instability label bad steps.length epsilon delta
    epsilonNonnegative deltaNonnegative perLabel changes
  have databaseBound : normSquared (project (DynamicBad label bad) steps.length finalState) ≤
      databaseLoss steps.length ((delta + epsilon : Rat) : ℝ) := by
    have result := implemented_raw_database_game_le_database_loss system.system
      (DynamicBad label bad) steps.length blind initial instability.toReal
      capacity emptySupport normalized (initialized_dynamic_bad_zero label bad steps.length registers)
    simpa only [blind, List.length_map] using result
  have bridged := adaptive_claims_probability_le finalState
    (oracleFamilyRun system.system steps (fun _ => registers))
    (compressed_run_is_uniform_random_oracle_purification
      system.system steps.length steps registers le_rfl)
    enabled claims distinct maxClaims claimBound (DynamicBad label bad) included
    steps.length bounded finalNormalized
    (databaseLoss steps.length ((delta + epsilon : Rat) : ℝ)) databaseBound
  simpa only [div_eq_mul_inv, one_div, one_mul] using bridged

end
end HegemonCrypto.SmallWood.SmzaDynamicOracleExecution
