import SmzaRp05PhysicalReadTelescope
import SmzaRp05ScheduledRoleExecution
import SmzaRp05ConcreteSuffix

/-!
# One certified execution followed by its physical terminal reads

The pre-read amplitude is derived from the compiled common skeleton and its
exact query count. The reads are charged to the same lifetime cap, with all
answer branches retained. No post-read role probability is an input.

This is still the certified mathematical execution: it does not construct
`AcceptedFailureWitness` from the live Rust verifier or claim that arbitrary
earlier-table advice is the physical conditioned table.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ReadExecutionBound

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets SmzaRp04CompleteRawRoleCells
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05AdaptiveFilteredCollision SmzaRp05VectorReadCharge
open SmzaRp05PhysicalTerminalRead SmzaRp05SequentialReadCharge
open SmzaRp05RoleReadTotality SmzaRp05PhysicalReadTelescope
open SmzaRp05SuffixReadout
open SmzaRp04RawMcaSampling
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

/-- A precise query-count amplitude, before replacing that count by T. -/
theorem common_pre_read_role_amplitude
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (finishWithin : finish ≤ cap) (role : Role) :
    stateNorm (workspaceEventProjection (event (contexts role))
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) ≤
      (queries : ℝ) * Real.sqrt (6 * localBound (contexts role) cap) := by
  let actual := CertifiedPhysicalProgram.compilePhysical (contexts role)
    (CertifiedFor.program certified role)
  let compiled := ActualProgram.compile (contexts role) cap actual
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  have runEq : AdaptiveProgram.run compiled initial =
      PhysicalProgramSkeleton.run skeleton initial := by
    rw [← CertifiedPhysicalProgram.run_eq_compiled_physical]
    exact CertifiedFor.program_run_eq_skeleton certified role initial
  have bounded : BoundedState 0 initial := partial_random_oracle_empty_bounded registers
  have reached := AdaptiveProgram.run_bounded compiled bounded
  have amplitude := AdaptiveProgram.amplitude_telescope compiled initial bounded subnormalized
  rw [initialized_projection_zero (contexts role) cap registers,
    state_norm_zero, zero_add, ActualProgram.compile_total_leak] at amplitude
  rw [← workspace_event_eq_adaptive_project_of_bounded
    (event (contexts role)) cap _ (bounded_state_mono finishWithin reached), runEq] at amplitude
  exact amplitude

theorem common_run_bounded
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap start finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap start finish queries}
    (certified : CertifiedFor contexts skeleton) (role : Role)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState start state) :
    BoundedState finish (PhysicalProgramSkeleton.run skeleton state) := by
  rw [← CertifiedFor.program_run_eq_skeleton certified role]
  exact CertifiedPhysicalProgram.bounded_run (contexts role)
    (CertifiedFor.program certified role) bounded

/-- Recognized terminal challenge keys are standard-total after the common
certified skeleton. This turns the read theorem's totality premise into a
parser-recognition obligation on the actual scheduled keys. -/
theorem common_skeleton_standard_on_recognized_keys
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (keys : List Key)
    (recognized : ∀ key ∈ keys, ∃ query,
      parseStageQuery ((contexts .decsMatrix).keyBytes key) = some query) :
    StandardOn keys (PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
  have scheduled :=
    SmzaRp05ScheduledRoleExecution.certified_initial_run_standard_on_roles
      (contexts .decsMatrix) (CertifiedFor.program certified .decsMatrix)
      registers keys recognized
  rw [CertifiedFor.program_run_eq_skeleton certified .decsMatrix] at scheduled
  exact scheduled

/-- Concrete pulled batch schedules satisfy the parser premise of the
certified read-totality theorem. The batch-to-verifier refinement and
certification of the actual skeleton remain separate. -/
theorem common_skeleton_standard_on_pulled_schedule
    (model : SmzaRp05TracePrefixes.RelationModel)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (batch : List SmzaRp05ConcreteSuffix.ProofView)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : SmzaRp05TracePrefixes.TypedRoutes model Counter)
    (allAdvice : (role : Role) → SmzaRp05TracePrefixes.AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor
      (CertifiedFor.roleContexts model ns keyBytes counter routes allAdvice
        outerFuel innerFuel authorizedOf) skeleton)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    StandardOn (SmzaRp05ConcreteSuffix.pulledReadSchedule model ns batch keyBytes)
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
  exact common_skeleton_standard_on_recognized_keys certified registers _
    (by simpa [CertifiedFor.roleContexts] using
      (SmzaRp05ConcreteSuffix.pulled_read_schedule_recognized
        model ns batch keyBytes))

/-- The concrete plan's charged lifetime ledger supplies the exact
`queries + terminal reads ≤ cap` premise when earlier program queries are
included in prior touches. -/
theorem pulled_schedule_queries_within_cap
    (model : SmzaRp05TracePrefixes.RelationModel)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (batch : List SmzaRp05ConcreteSuffix.ProofView)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (injective : Function.Injective keyBytes)
    (queries priorTouches cap : Nat) (queriesLePrior : queries ≤ priorTouches)
    (charged : priorTouches +
      (SmzaRp05ConcreteSuffix.currentPlan model ns batch).keys.card ≤ cap) :
    queries +
      (SmzaRp05ConcreteSuffix.pulledReadSchedule model ns batch keyBytes).length ≤ cap := by
  have bound := SmzaRp05ConcreteSuffix.pulled_new_reads_lifetime_bound
    model ns batch keyBytes injective priorTouches cap charged
  omega

/-- The original queries and every terminal read share one cap. There is
no factor for the number of measurement outcomes or the pre-read norm loss. -/
theorem common_physical_read_role_mass_le
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (keys : List Key)
    (supportWithin : finish + keys.length ≤ cap)
    (queriesWithin : queries + keys.length ≤ cap)
    (total : StandardOn keys (PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))
    (role : Role) :
    (∑ answers : ReadAnswers (Input := Key) (VectorOutput Counter) keys,
      normSquared (workspaceEventProjection (event (contexts role))
        (physicalReadTrace keys answers (PhysicalProgramSkeleton.run skeleton
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))) ≤
      6 * (cap : ℝ)^2 * localBound (contexts role) cap := by
  let state := PhysicalProgramSkeleton.run skeleton
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  let charge := Real.sqrt (6 * localBound (contexts role) cap)
  have bounded : BoundedState finish state := common_run_bounded certified role _
    (partial_random_oracle_empty_bounded registers)
  have pre := common_pre_read_role_amplitude certified registers subnormalized
    (by omega) role
  have amplitude := physical_read_trace_role_amplitude_le keys finish cap state
    bounded total supportWithin (event (contexts role)) (localBound (contexts role) cap)
    (local_bound_nonnegative (contexts role) cap) (event_instability (contexts role) cap)
  have sourceNorm : stateNorm state ≤ 1 := by
    have sourceMass := CertifiedFor.common_run_subnormalized certified role subnormalized
    have normBound := state_norm_le_sqrt state (by norm_num) sourceMass
    simpa using normBound
  have chargeNonnegative : 0 ≤ charge := Real.sqrt_nonneg _
  have readCharge : (keys.length : ℝ) * charge * stateNorm state ≤
      (keys.length : ℝ) * charge := by
    nlinarith [mul_le_mul_of_nonneg_left sourceNorm
      (mul_nonneg (Nat.cast_nonneg keys.length) chargeNonnegative)]
  have count : (queries : ℝ) + keys.length ≤ cap := by exact_mod_cast queriesWithin
  have totalAmplitude :
      Real.sqrt (∑ answers : ReadAnswers (Input := Key) (VectorOutput Counter) keys,
        normSquared (workspaceEventProjection (event (contexts role))
          (physicalReadTrace keys answers state))) ≤ (cap : ℝ) * charge := by
    change _ ≤ _ + (keys.length : ℝ) * charge * stateNorm state at amplitude
    change stateNorm (workspaceEventProjection (event (contexts role)) state) ≤
      (queries : ℝ) * charge at pre
    nlinarith [mul_le_mul_of_nonneg_right count chargeNonnegative]
  have massNonnegative : 0 ≤
      ∑ answers : ReadAnswers (Input := Key) (VectorOutput Counter) keys,
        normSquared (workspaceEventProjection (event (contexts role))
          (physicalReadTrace keys answers state)) := by
    apply Finset.sum_nonneg
    intro answers _
    unfold normSquared
    exact Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _
  have squared := (sq_le_sq₀ (Real.sqrt_nonneg _) (by positivity)).2 totalAmplitude
  rw [Real.sq_sqrt massNonnegative, mul_pow,
    show charge^2 = 6 * localBound (contexts role) cap from
      Real.sq_sqrt (mul_nonneg (by norm_num) (local_bound_nonnegative _ _))] at squared
  nlinarith

/-- The physical post-read four-role budget follows from the one common
certified execution, rather than being a caller-supplied endpoint premise. -/
theorem common_physical_read_any_role_mass_le_terminal_loss
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    (selected : ∀ role, (contexts role).role = role)
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (counter : Counter) (keys : List Key)
    (supportWithin : finish + keys.length ≤ cap)
    (queriesWithin : queries + keys.length ≤ cap)
    (total : StandardOn keys (PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    (∑ answers : ReadAnswers (Input := Key) (VectorOutput Counter) keys,
      normSquared (workspaceEventProjection (CertifiedFor.anyContextRoleEvent contexts)
        (physicalReadTrace keys answers (PhysicalProgramSkeleton.run skeleton
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))) ≤
      (SmzaRp05SecurityLedger.terminalExtractionLoss cap : ℝ) := by
  let state := PhysicalProgramSkeleton.run skeleton
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  have bounded : BoundedState finish state := common_run_bounded certified .decsMatrix _
    (partial_random_oracle_empty_bounded registers)
  have union :
      (∑ answers : ReadAnswers (Input := Key) (VectorOutput Counter) keys,
        normSquared (workspaceEventProjection (CertifiedFor.anyContextRoleEvent contexts)
          (physicalReadTrace keys answers state))) ≤
      ∑ role : Role, ∑ answers : ReadAnswers (Input := Key) (VectorOutput Counter) keys,
        normSquared (workspaceEventProjection (event (contexts role))
          (physicalReadTrace keys answers state)) := by
    rw [Finset.sum_comm]
    apply Finset.sum_le_sum
    intro answers _
    have reached := bounded_state_mono supportWithin
      (physical_read_trace_bounded_add_length keys answers finish state bounded)
    have pointwise := CertifiedFor.any_context_role_event_mass_le_sum
      contexts cap (physicalReadTrace keys answers state)
    simp_rw [← workspace_event_eq_adaptive_project_of_bounded _ cap _ reached] at pointwise
    exact pointwise
  have sumBound :
      (∑ role : Role, ∑ answers : ReadAnswers (Input := Key) (VectorOutput Counter) keys,
        normSquared (workspaceEventProjection (event (contexts role))
          (physicalReadTrace keys answers state))) ≤
      ∑ role : Role,
        (6 * (cap : ℝ)^2 * (completeRoleLoss role : ℝ) +
          36 * (cap : ℝ)^3 / (2 : ℝ)^512) := by
    apply Finset.sum_le_sum
    intro role _
    have bound := common_physical_read_role_mass_le certified registers subnormalized
      keys supportWithin queriesWithin total role
    have coefficient : 6 * (cap : ℝ)^2 * localBound (contexts role) cap =
        6 * (cap : ℝ)^2 * (completeRoleLoss role : ℝ) +
          36 * (cap : ℝ)^3 / (2 : ℝ)^512 := by
      unfold localBound
      rw [selected role]
      push_cast
      ring_nf
    rwa [coefficient] at bound
  have ledger := SmzaRp05TerminalExtraction.common_terminal_rhs_le_terminal_extraction_loss
    counter cap 0 (Nat.zero_le cap) 0 (by norm_num) (by norm_num)
  simp only [Nat.cast_zero, mul_zero, zero_div, add_zero] at ledger
  exact union.trans (sumBound.trans ledger)

/-! The final bound below closes the read-charge/terminal-event composition
for the existing mathematical accepted-failure predicate. Its remaining
execution assumptions are explicit syntax certification and scheduled-key
physical totality, not a desired small failure probability. -/
theorem certified_physical_accepted_failure_below_130_bits
    (model : SmzaRp05TracePrefixes.RelationModel)
    (refinement : SmzaRp05AcceptedExtraction.RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : SmzaRp05TracePrefixes.TypedRoutes model Counter)
    (allAdvice : (role : Role) → SmzaRp05TracePrefixes.AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    {finish queries : Nat}
    (skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries)
    (certified : CertifiedFor
      (CertifiedFor.roleContexts model ns keyBytes counter routes allAdvice
        outerFuel innerFuel authorizedOf) skeleton)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (keys : List Key) (nodup : keys.Nodup)
    (supportWithin : finish + keys.length ≤ cap)
    (queriesWithin : queries + keys.length ≤ cap)
    (total : StandardOn keys (PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))
    (capWithin : cap ≤ 3 * 2^64) :
    SmzaRp05CurrentFinalEvent.acceptedPhysicalSelectedFailureMass model refinement
      ns keyBytes counter routes allAdvice outerFuel innerFuel cap authorizedOf
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) keys <
      1 / (2 : ℝ)^130 := by
  have roleBudget := common_physical_read_any_role_mass_le_terminal_loss
    (fun role => rfl) certified registers subnormalized counter keys
    supportWithin queriesWithin total
  have massBound := CertifiedFor.common_run_subnormalized certified .decsMatrix subnormalized
  exact SmzaRp05CurrentFinalEvent.accepted_physical_selected_failure_below_130_bits_of_role_budget
    model refinement ns keyBytes counter routes allAdvice outerFuel innerFuel
    cap cap authorizedOf _ keys nodup total (by omega) capWithin 1 massBound
    (by norm_num) (by simpa using roleBudget)

/-- The same certified mathematical endpoint with scheduled-read totality
derived from parser recognition, rather than supplied as a probability
assumption. Concrete verifier acceptance and oracle-derived advice remain
separate obligations. -/
theorem certified_physical_accepted_failure_below_130_bits_of_recognized_keys
    (model : SmzaRp05TracePrefixes.RelationModel)
    (refinement : SmzaRp05AcceptedExtraction.RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : SmzaRp05TracePrefixes.TypedRoutes model Counter)
    (allAdvice : (role : Role) → SmzaRp05TracePrefixes.AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    {finish queries : Nat}
    (skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries)
    (certified : CertifiedFor
      (CertifiedFor.roleContexts model ns keyBytes counter routes allAdvice
        outerFuel innerFuel authorizedOf) skeleton)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (keys : List Key) (nodup : keys.Nodup)
    (recognized : ∀ key ∈ keys, ∃ query,
      parseStageQuery (keyBytes key) = some query)
    (supportWithin : finish + keys.length ≤ cap)
    (queriesWithin : queries + keys.length ≤ cap)
    (capWithin : cap ≤ 3 * 2^64) :
    SmzaRp05CurrentFinalEvent.acceptedPhysicalSelectedFailureMass model refinement
      ns keyBytes counter routes allAdvice outerFuel innerFuel cap authorizedOf
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) keys <
      1 / (2 : ℝ)^130 := by
  have total := common_skeleton_standard_on_recognized_keys certified
    registers keys (by simpa [CertifiedFor.roleContexts] using recognized)
  exact certified_physical_accepted_failure_below_130_bits
    model refinement ns keyBytes counter routes allAdvice outerFuel innerFuel cap
    authorizedOf skeleton certified registers subnormalized keys nodup
    supportWithin queriesWithin total capWithin

end
end HegemonCrypto.SmallWood.SmzaRp05ReadExecutionBound
