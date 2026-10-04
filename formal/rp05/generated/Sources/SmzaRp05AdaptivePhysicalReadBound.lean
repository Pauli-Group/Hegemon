import SmzaRp05PhysicalReadTelescope
import SmzaRp05PhysicalAcceptedReplayBridge
import SmzaRp05ReadExecutionBound

/-!
# Adaptive physical read tree

Unlike a fixed terminal key list, the executable verifier program can choose
its next raw input from the preceding answer. The mass below sums every
physical answer branch with its own continuation. No branch is renormalized.
The bound is for a fixed diagonal event; oracle-derived advice and literal
Rust acceptance still require their separate same-execution composition.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AdaptivePhysicalReadBound

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05PhysicalTerminalRead SmzaRp05PhysicalReadSupport
open SmzaRp05PhysicalReadTelescope SmzaRp05VectorReadCharge
open SmzaRp05SequentialReadCharge SmzaRp05SuffixReadout
open SmzaRp05RoleReadTotality
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaChallengeStageTargets (Role)
open SmzaRp05ReadExecutionBound
open V8Smz9CoherentVectorMerkle
open SmzaRp04RawMcaSampling
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024

variable {Key Counter Work Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Work] [DecidableEq Work]

/-- A bound on the number of reads along every answer-dependent path. -/
def ReadsAtMost
    (decode : RawInput → Answer (Counter := Counter) → RawDigest) :
    Nat → Program Result → Prop
  | _, .done _ => True
  | 0, .read _ _ => False
  | depth + 1, .read raw next =>
      ∀ answer, ReadsAtMost decode depth (next (decode raw answer))

/-- Every answer-dependent continuation reads only from one scheduled key
list, although it may choose their order and repetition adaptively. -/
def ReadsWithinKeys (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (keys : List Key) :
    Program Result → Prop
  | .done _ => True
  | .read raw next =>
      encode raw ∈ keys ∧
        ∀ answer, ReadsWithinKeys encode decode keys (next (decode raw answer))

/-- Sum the unnormalised Born mass of one fixed event over every adaptive
physical read branch. The program's continuation may depend on the digest. -/
def adaptiveReadMass
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop) :
    Program Result → VectorCmsState (Key := Key) (Counter := Counter) (Work := Work) → ℝ
  | .done _, state => normSquared (workspaceEventProjection event state)
  | .read raw next, state =>
      ∑ answer : Answer (Counter := Counter),
        adaptiveReadMass encode decode event (next (decode raw answer))
          (physicalReadBranch (encode raw) answer state)

theorem adaptive_read_mass_nonnegative
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (program : Program Result)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    0 ≤ adaptiveReadMass encode decode event program state := by
  induction program generalizing state with
  | done result =>
      simp only [adaptiveReadMass]
      unfold normSquared
      exact Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _
  | read raw next ih =>
      simp only [adaptiveReadMass]
      exact Finset.sum_nonneg fun answer _ => ih (decode raw answer) _

/-- The executable interpreter has finitely many physical answer branches,
including when its continuation depends on each observed digest. -/
@[reducible] noncomputable def physicalBranchesFintype
    (decode : RawInput → Answer (Counter := Counter) → RawDigest) :
    (program : Program Result) →
      Fintype (SmzaRp05PhysicalAcceptedReplayLite.Branches decode program)
  | .done _ => by
      dsimp [SmzaRp05PhysicalAcceptedReplayLite.Branches]
      infer_instance
  | .read raw next => by
      letI (answer : Answer (Counter := Counter)) :
          Fintype (SmzaRp05PhysicalAcceptedReplayLite.Branches decode
            (next (decode raw answer))) :=
        physicalBranchesFintype decode (next (decode raw answer))
      dsimp [SmzaRp05PhysicalAcceptedReplayLite.Branches]
      infer_instance

/-- The recursively charged mass is exactly the finite sum of event mass on
the executable physical branch states. This connects the adaptive recurrence
to the concrete replay interpreter, not just to an abstract recurrence. -/
theorem adaptive_read_mass_eq_physical_branch_sum
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (program : Program Result)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    adaptiveReadMass encode decode event program state =
      letI := physicalBranchesFintype decode program
      ∑ branch : SmzaRp05PhysicalAcceptedReplayLite.Branches decode program,
        normSquared (workspaceEventProjection event
          (SmzaRp05PhysicalAcceptedReplayLite.physicalRun encode decode
            program branch state)) := by
  induction program generalizing state with
  | done result =>
      simp [adaptiveReadMass, SmzaRp05PhysicalAcceptedReplayLite.Branches,
        SmzaRp05PhysicalAcceptedReplayLite.physicalRun]
  | read raw next ih =>
      letI (answer : Answer (Counter := Counter)) :=
        physicalBranchesFintype decode (next (decode raw answer))
      letI := physicalBranchesFintype decode (Program.read raw next)
      simp only [adaptiveReadMass]
      change _ =
        ∑ branch : (answer : Answer (Counter := Counter)) ×
            SmzaRp05PhysicalAcceptedReplayLite.Branches decode
              (next (decode raw answer)),
          normSquared (workspaceEventProjection event
            (SmzaRp05PhysicalAcceptedReplayLite.physicalRun encode decode
              (Program.read raw next) branch state))
      rw [Fintype.sum_sigma]
      apply Finset.sum_congr rfl
      intro answer _
      simpa only [SmzaRp05PhysicalAcceptedReplayLite.physicalRun,
        SmzaRp05PhysicalAcceptedReplayBridge.physical_read_step_eq_branch]
        using (ih (decode raw answer)
          (physicalReadBranch (encode raw) answer state))

/-- Every adaptive branch's mass is computed on the exact terminal trace
with that branch's own key list and answers. -/
theorem adaptive_read_mass_eq_terminal_branch_sum
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (program : Program Result)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    adaptiveReadMass encode decode event program state =
      letI := physicalBranchesFintype decode program
      ∑ branch : SmzaRp05PhysicalAcceptedReplayLite.Branches decode program,
        normSquared (workspaceEventProjection event
          (physicalReadTrace
            (SmzaRp05PhysicalAcceptedReplayLite.branchKeys encode decode
              program branch)
            (SmzaRp05PhysicalAcceptedReplayBridge.toTerminalAnswers _
              (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers encode decode
                program branch)) state)) := by
  rw [adaptive_read_mass_eq_physical_branch_sum]
  simp_rw [SmzaRp05PhysicalAcceptedReplayBridge.physical_run_eq_terminal_trace]
theorem standard_total_physical_read_branch
    (selected : Key) (answer : Answer (Counter := Counter))
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (total : StandardTotal state) :
    StandardTotal (physicalReadBranch selected answer state) := by
  intro key
  rw [physical_read_branch_standard_view]
  exact total_at_coordinate_event_projection key selected answer
    (globalDecompress state) (total key)

/-- The adaptive read tree has the same homogeneous charge as a fixed list:
one local charge per maximum path read, not per branch or possible key. -/
theorem adaptive_read_role_amplitude_le
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (program : Program Result) (readBound : ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys program)
    (support cap : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState support state) (total : StandardOn keys state)
    (within : support + depth ≤ cap)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (instability : ∀ workspace, RealInstabilityBound (event workspace) cap loss) :
    Real.sqrt (adaptiveReadMass encode decode event program state) ≤
      stateNorm (workspaceEventProjection event state) +
        (depth : ℝ) * Real.sqrt (6 * loss) * stateNorm state := by
  induction depth generalizing program support state with
  | zero =>
      cases program with
      | done result =>
          simp only [adaptiveReadMass, Nat.cast_zero, zero_mul, add_zero]
          exact le_of_eq (sqrt_norm_squared_eq_state_norm _)
      | read raw next => exact False.elim readBound
  | succ depth ih =>
      cases program with
      | done result =>
          simp only [adaptiveReadMass]
          rw [sqrt_norm_squared_eq_state_norm]
          exact le_add_of_nonneg_right
            (mul_nonneg (mul_nonneg (Nat.cast_nonneg _) (Real.sqrt_nonneg _))
              (state_norm_nonnegative _))
      | read raw next =>
          let branch := fun answer : Answer (Counter := Counter) =>
            physicalReadBranch (encode raw) answer state
          let after := fun answer : Answer (Counter := Counter) =>
            Real.sqrt (adaptiveReadMass encode decode event
              (next (decode raw answer)) (branch answer))
          let before := fun answer : Answer (Counter := Counter) =>
            stateNorm (workspaceEventProjection event (branch answer))
          let source := fun answer : Answer (Counter := Counter) =>
            stateNorm (branch answer)
          have tailWithin : support + 1 + depth ≤ cap := by
            omega
          have localBound : ∀ answer,
              after answer ≤ before answer +
                ((depth : ℝ) * Real.sqrt (6 * loss)) * source answer := by
            intro answer
            exact ih (next (decode raw answer))
              (readBound answer)
              (keysWithin.2 answer) (support + 1) (branch answer)
              (SmzaRp05PhysicalReadSupport.physical_read_branch_bounded_succ
                (encode raw) answer support state bounded)
              (standard_on_physical_read_branch keys (encode raw) answer state total)
              tailWithin
          have aggregate := sqrt_sum_sq_le_of_pointwise after before source
            ((depth : ℝ) * Real.sqrt (6 * loss))
            (fun _ => Real.sqrt_nonneg _)
            (fun _ => state_norm_nonnegative _)
            (fun _ => state_norm_nonnegative _)
            (by positivity) localBound
          have afterSq : ∀ answer,
              after answer ^ 2 = adaptiveReadMass encode decode event
                (next (decode raw answer)) (branch answer) := by
            intro answer
            exact Real.sq_sqrt (adaptive_read_mass_nonnegative encode decode
              event _ _)
          have sourceSq : (∑ answer, source answer ^ 2) = normSquared state := by
            simp only [source, state_norm_sq_eq_norm_squared]
            exact sum_physical_read_branch_norm_squared_of_total_at
              (encode raw) state (total (encode raw) keysWithin.1)
          have beforeSq : (∑ answer, before answer ^ 2) =
              ∑ answer, normSquared (workspaceEventProjection event (branch answer)) := by
            simp only [before, state_norm_sq_eq_norm_squared]
          simp_rw [afterSq] at aggregate
          rw [sourceSq, beforeSq, sqrt_norm_squared_eq_state_norm] at aggregate
          have one := physical_read_role_amplitude_le_one_query_charge
            (encode raw) support state bounded (total (encode raw) keysWithin.1) event loss
            lossNonnegative (fun workspace => real_instability_restrict_cap
              (event workspace) (support + 1) cap loss (by omega)
              (instability workspace))
          change
            Real.sqrt (∑ answer : Answer (Counter := Counter),
              adaptiveReadMass encode decode event (next (decode raw answer))
                (branch answer)) ≤ _
          calc
            _ ≤ Real.sqrt (∑ answer,
                  normSquared (workspaceEventProjection event (branch answer))) +
                ((depth : ℝ) * Real.sqrt (6 * loss)) * stateNorm state :=
              aggregate
            _ ≤ (stateNorm (workspaceEventProjection event state) +
                  Real.sqrt (6 * loss) * stateNorm state) +
                ((depth : ℝ) * Real.sqrt (6 * loss)) * stateNorm state :=
              add_le_add_left one _
            _ = _ := by
              simp only [Nat.cast_add, Nat.cast_one]
              ring

/-- Squared, unnormalised Born-mass form of the adaptive read-tree bound. -/
theorem adaptive_read_role_mass_le
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (program : Program Result) (readBound : ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys program)
    (support cap : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState support state) (total : StandardOn keys state)
    (within : support + depth ≤ cap)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (instability : ∀ workspace, RealInstabilityBound (event workspace) cap loss) :
    adaptiveReadMass encode decode event program state ≤
      (stateNorm (workspaceEventProjection event state) +
        (depth : ℝ) * Real.sqrt (6 * loss) * stateNorm state)^2 := by
  have amplitude := adaptive_read_role_amplitude_le depth encode decode program
    readBound keys keysWithin support cap state bounded total within event loss
    lossNonnegative instability
  have rightNonnegative : 0 ≤
      stateNorm (workspaceEventProjection event state) +
        (depth : ℝ) * Real.sqrt (6 * loss) * stateNorm state :=
    add_nonneg (state_norm_nonnegative _)
      (mul_nonneg (mul_nonneg (Nat.cast_nonneg _) (Real.sqrt_nonneg _))
        (state_norm_nonnegative _))
  have squared := (sq_le_sq₀ (Real.sqrt_nonneg _) rightNonnegative).2 amplitude
  rwa [Real.sq_sqrt (adaptive_read_mass_nonnegative encode decode event program state)]
    at squared

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- The four-role union bound holds at the leaves of one *adaptive* physical
read tree. Every branch is charged on the same incoming state; no separate
postselected execution is inserted for a role. -/
theorem adaptive_read_any_role_mass_le_sum
    (depth : Nat)
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (program : Program Result) (readBound : ReadsAtMost decode depth program)
    (support cap : Nat)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (bounded : BoundedState support state) (within : support + depth ≤ cap) :
    adaptiveReadMass encode decode (CertifiedFor.anyContextRoleEvent contexts)
        program state ≤
      ∑ role : Role,
        adaptiveReadMass encode decode (event (contexts role)) program state := by
  induction depth generalizing program support state with
  | zero =>
      cases program with
      | done result =>
          have reached : BoundedState cap state :=
            bounded_state_mono (by omega) bounded
          have union := CertifiedFor.any_context_role_event_mass_le_sum
            contexts cap state
          rw [← workspace_event_eq_adaptive_project_of_bounded _ cap _ reached] at union
          simp_rw [← workspace_event_eq_adaptive_project_of_bounded _ cap _ reached]
            at union
          simpa only [adaptiveReadMass] using union
      | read raw next => exact False.elim readBound
  | succ depth ih =>
      cases program with
      | done result =>
          have reached : BoundedState cap state :=
            bounded_state_mono (by omega) bounded
          have union := CertifiedFor.any_context_role_event_mass_le_sum
            contexts cap state
          rw [← workspace_event_eq_adaptive_project_of_bounded _ cap _ reached] at union
          simp_rw [← workspace_event_eq_adaptive_project_of_bounded _ cap _ reached]
            at union
          simpa only [adaptiveReadMass] using union
      | read raw next =>
          simp only [adaptiveReadMass]
          calc
            _ ≤ ∑ answer : Answer (Counter := Counter),
                  ∑ role : Role,
                    adaptiveReadMass encode decode (event (contexts role))
                      (next (decode raw answer))
                      (physicalReadBranch (encode raw) answer state) := by
                apply Finset.sum_le_sum
                intro answer _
                exact ih (next (decode raw answer))
                  (readBound answer) (support + 1)
                  (physicalReadBranch (encode raw) answer state)
                  (SmzaRp05PhysicalReadSupport.physical_read_branch_bounded_succ
                    (encode raw) answer support state bounded) (by omega)
            _ = _ := Finset.sum_comm

/-- Certified common-execution charge followed by one answer-adaptive
physical read tree, for a fixed role context. -/
theorem common_adaptive_read_role_mass_le
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (depth : Nat) (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (program : Program Result) (readBound : ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys program)
    (supportWithin : finish + depth ≤ cap)
    (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys (PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))
    (role : Role) :
    adaptiveReadMass encode decode (event (contexts role)) program
        (PhysicalProgramSkeleton.run skeleton
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      6 * (cap : ℝ)^2 * localBound (contexts role) cap := by
  let state := PhysicalProgramSkeleton.run skeleton
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  let charge := Real.sqrt (6 * localBound (contexts role) cap)
  have bounded : BoundedState finish state := common_run_bounded certified role _
    (partial_random_oracle_empty_bounded registers)
  have pre := common_pre_read_role_amplitude certified registers subnormalized
    (by omega) role
  have amplitude := adaptive_read_role_amplitude_le depth encode decode program
    readBound keys keysWithin finish cap state bounded total supportWithin
    (event (contexts role)) (localBound (contexts role) cap)
    (local_bound_nonnegative (contexts role) cap)
    (event_instability (contexts role) cap)
  have sourceNorm : stateNorm state ≤ 1 := by
    have sourceMass := CertifiedFor.common_run_subnormalized certified role subnormalized
    have normBound := state_norm_le_sqrt state (by norm_num) sourceMass
    simpa using normBound
  have chargeNonnegative : 0 ≤ charge := Real.sqrt_nonneg _
  have readCharge : (depth : ℝ) * charge * stateNorm state ≤
      (depth : ℝ) * charge := by
    nlinarith [mul_le_mul_of_nonneg_left sourceNorm
      (mul_nonneg (Nat.cast_nonneg depth) chargeNonnegative)]
  have count : (queries : ℝ) + depth ≤ cap := by exact_mod_cast queriesWithin
  have totalAmplitude :
      Real.sqrt (adaptiveReadMass encode decode (event (contexts role))
        program state) ≤ (cap : ℝ) * charge := by
    change _ ≤ _ + (depth : ℝ) * charge * stateNorm state at amplitude
    change stateNorm (workspaceEventProjection (event (contexts role)) state) ≤
      (queries : ℝ) * charge at pre
    nlinarith [mul_le_mul_of_nonneg_right count chargeNonnegative]
  have squared := (sq_le_sq₀ (Real.sqrt_nonneg _) (by positivity)).2 totalAmplitude
  rw [Real.sq_sqrt (adaptive_read_mass_nonnegative encode decode
    (event (contexts role)) program state), mul_pow,
    show charge^2 = 6 * localBound (contexts role) cap from
      Real.sq_sqrt (mul_nonneg (by norm_num) (local_bound_nonnegative _ _))] at squared
  nlinarith

/-- The four fixed-context role events remain within the same terminal
extraction loss even when the physical read order and stopping path depend on
preceding answers. The prior advice context is fixed for this statement. -/
theorem common_adaptive_read_any_role_mass_le_terminal_loss
    {contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    (selected : ∀ role, (contexts role).role = role)
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (counter : Counter) (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (program : Program Result) (readBound : ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys program)
    (supportWithin : finish + depth ≤ cap)
    (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys (PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    adaptiveReadMass encode decode (CertifiedFor.anyContextRoleEvent contexts)
        program (PhysicalProgramSkeleton.run skeleton
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      (SmzaRp05SecurityLedger.terminalExtractionLoss cap : ℝ) := by
  let state := PhysicalProgramSkeleton.run skeleton
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  have bounded : BoundedState finish state := common_run_bounded certified .decsMatrix _
    (partial_random_oracle_empty_bounded registers)
  have union := adaptive_read_any_role_mass_le_sum depth contexts encode decode
    program readBound finish cap state bounded supportWithin
  have sumBound :
      (∑ role : Role,
        adaptiveReadMass encode decode (event (contexts role)) program state) ≤
      ∑ role : Role,
        (6 * (cap : ℝ)^2 * (completeRoleLoss role : ℝ) +
          36 * (cap : ℝ)^3 / (2 : ℝ)^512) := by
    apply Finset.sum_le_sum
    intro role _
    have bound := common_adaptive_read_role_mass_le certified registers
      subnormalized depth encode decode program readBound keys keysWithin
      supportWithin queriesWithin total role
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

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptivePhysicalReadBound
