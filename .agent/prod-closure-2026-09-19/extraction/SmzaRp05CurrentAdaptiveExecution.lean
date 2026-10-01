import SmzaRp05CurrentRoleLabels
import SmzaRp05AdaptiveKernelInstantiation

/-!
# Current RP05 role event on the adaptive CMS execution

The syntax below is the execution boundary: an `ActualProgram` is built from
ordinary vector-CMS queries, authorization marks, marked canonical-leaf
writes, authorization-preserving private kernels, and reversible database
copies.  `compile` derives every `CertifiedAdaptiveStep`; callers do not pass
an already-certified program or a final probability estimate.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAdaptiveExecution

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CanonicalBytes
open V8Smz9CoherentVectorMerkle
open SmzaRp04CompleteRawRoleCells
open SmzaRp05LeafNamespace SmzaRp05CurrentRoleLabels
open SmzaRp05TracePrefixes
open SmzaChallengeStageTargets SmzaRp04RawMcaSampling
open SmzaRp05FilteredReadback
open SmzaRp05AdaptiveFilteredCollision SmzaRp05AdaptiveKernelInstantiation

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000
set_option linter.unusedSectionVars false
set_option exponentiation.threshold 1024

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

abbrev Output := VectorOutput Counter
abbrev Work := RetainedWorkspace (Output (Counter := Counter)) BaseWork
abbrev CmsState := State Key (Output (Counter := Counter))
  (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork))

structure Context where
  model : RelationModel
  leafNamespace : SmzaRp05LeafNamespace.Namespace
  keyBytes : Key → V8SmzaOracleParser.RawInput
  counter : Counter
  routes : TypedRoutes model Counter
  role : Role
  advice : AllEarlierTables model role
  outerFuel : Nat
  innerFuel : Nat
  authorizedOf : BaseWork → Finset (List Byte)

def baseEvent (ctx : Context (Key := Key) (Counter := Counter)
    (BaseWork := BaseWork)) :
    AdaptiveEvent Key (Output (Counter := Counter)) BaseWork :=
  fun work database =>
    currentRoleEvent ctx.model ctx.leafNamespace ctx.keyBytes ctx.counter ctx.routes
      ctx.role ctx.advice ctx.outerFuel ctx.innerFuel (ctx.authorizedOf work) database

def event (ctx : Context (Key := Key) (Counter := Counter)
    (BaseWork := BaseWork)) :
    AdaptiveEvent Key (Output (Counter := Counter))
      (Work (Counter := Counter) (BaseWork := BaseWork)) :=
  ignoreRetained (baseEvent ctx)

def localBound (ctx : Context (Key := Key) (Counter := Counter)
    (BaseWork := BaseWork)) (cap : Nat) : ℝ :=
  (((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss ctx.role : Rat) : ℝ)

theorem local_bound_nonnegative
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) : 0 ≤ localBound ctx cap := by
  unfold localBound
  exact_mod_cast
    (add_nonneg (by positivity : (0 : Rat) ≤ (6 * cap : Rat) / (2^512 : Rat))
      (complete_role_loss_nonnegative ctx.role))

theorem event_instability
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) :
    ∀ workspace,
      RealInstabilityBound (event ctx workspace) cap (localBound ctx cap) := by
  intro workspace
  exact (current_role_instability ctx.model ctx.leafNamespace ctx.keyBytes ctx.counter
    ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel
    (ctx.authorizedOf workspace.2) cap).toReal

theorem base_event_mark_transport
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (source target : Basis Key (Output (Counter := Counter))
      (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork)))
    (statement : List Byte)
    (authorization : ctx.authorizedOf target.workspace.2 =
      insert statement (ctx.authorizedOf source.workspace.2))
    (sameDatabase : target.database = source.database)
    (after : event ctx target.workspace target.database) :
    event ctx source.workspace source.database := by
  unfold event ignoreRetained baseEvent at after ⊢
  rw [sameDatabase, authorization] at after
  apply current_role_mark_mono ctx.model ctx.leafNamespace ctx.keyBytes ctx.counter
    ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel
    (ctx.authorizedOf source.workspace.2) statement source.database
  convert after using 1
  exact Finset.ext (by intro x; simp)

theorem base_event_private_transport
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (source target : Basis Key (Output (Counter := Counter))
      (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork)))
    (sameAuthorization : ctx.authorizedOf source.workspace.2 =
      ctx.authorizedOf target.workspace.2)
    (sameDatabase : source.database = target.database)
    (after : event ctx target.workspace target.database) :
    event ctx source.workspace source.database := by
  unfold event ignoreRetained baseEvent at after ⊢
  simpa [sameAuthorization, sameDatabase] using after

theorem base_event_write_transport
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (source target : Basis Key (Output (Counter := Counter))
      (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork)))
    (key : Key) (statement : List Byte)
    (sameAuthorization : ctx.authorizedOf source.workspace.2 =
      ctx.authorizedOf target.workspace.2)
    (marked : statement ∈ ctx.authorizedOf target.workspace.2)
    (parsed : globalLeafStatement ctx.leafNamespace (ctx.keyBytes key) = some statement)
    (sameOutside : ∀ other, other ≠ key →
      source.database other = target.database other)
    (after : event ctx target.workspace target.database) :
    event ctx source.workspace source.database := by
  unfold event ignoreRetained baseEvent at after ⊢
  rw [sameAuthorization]
  exact (current_role_event_marked_write_iff ctx.model ctx.leafNamespace ctx.keyBytes
    ctx.counter ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel
    (ctx.authorizedOf target.workspace.2) statement marked key parsed
    source.database target.database sameOutside).mpr after

theorem base_event_coordinate_invariant_of_authorized
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (key : Key) (statement : List Byte)
    (marked : ∀ work, statement ∈ ctx.authorizedOf work)
    (parsed : globalLeafStatement ctx.leafNamespace (ctx.keyBytes key) = some statement) :
    CoordinateInvariant (baseEvent ctx) key := by
  intro work left right sameOutside
  exact current_role_event_marked_write_iff ctx.model ctx.leafNamespace ctx.keyBytes
    ctx.counter ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel
    (ctx.authorizedOf work) statement (marked work) key parsed left right sameOutside

/-! Each opcode contains physical localStep semantics and elementary operator
facts, never a bad-event probability or a certified adaptive step. -/
inductive Opcode
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) : Nat → Nat → Nat → Type _ where
  | query (occupied : Nat) (room : occupied < cap) :
      Opcode ctx cap occupied (occupied + 1) 1
  | privateKernel (budget : Nat) (within : budget ≤ cap)
      (transition : Basis Key (Output (Counter := Counter))
          (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork)) →
        Basis Key (Output (Counter := Counter))
          (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
      (localStep : ∀ source target, transition source target ≠ 0 →
        ctx.authorizedOf source.workspace.2 = ctx.authorizedOf target.workspace.2 ∧
        source.database = target.database)
      (contractive : ∀ state, stateNorm (kernelApply transition state) ≤ stateNorm state)
      (bounded : ∀ {state}, BoundedState budget state →
        BoundedState budget (kernelApply transition state)) :
      Opcode ctx cap budget budget 0
  | mark (budget : Nat) (within : budget ≤ cap)
      (transition : Basis Key (Output (Counter := Counter))
          (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork)) →
        Basis Key (Output (Counter := Counter))
          (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
      (localStep : ∀ source target, transition source target ≠ 0 →
        ∃ statement, ctx.authorizedOf target.workspace.2 =
          (insert statement (ctx.authorizedOf source.workspace.2) : Finset (List Byte)) ∧
          target.database = source.database)
      (contractive : ∀ state, stateNorm (kernelApply transition state) ≤ stateNorm state)
      (bounded : ∀ {state}, BoundedState budget state →
        BoundedState budget (kernelApply transition state)) :
      Opcode ctx cap budget budget 0
  | markedWrite (before after : Nat) (beforeWithin : before ≤ cap)
      (afterWithin : after ≤ cap)
      (transition : Basis Key (Output (Counter := Counter))
          (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork)) →
        Basis Key (Output (Counter := Counter))
          (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
      (localStep : ∀ source target, transition source target ≠ 0 →
        ∃ key statement,
          ctx.authorizedOf source.workspace.2 = ctx.authorizedOf target.workspace.2 ∧
          statement ∈ ctx.authorizedOf target.workspace.2 ∧
          globalLeafStatement ctx.leafNamespace (ctx.keyBytes key) = some statement ∧
          ∀ other, other ≠ key → source.database other = target.database other)
      (contractive : ∀ state, stateNorm (kernelApply transition state) ≤ stateNorm state)
      (bounded : ∀ {state}, BoundedState before state →
        BoundedState after (kernelApply transition state)) :
      Opcode ctx cap before after 0
  | copy (budget : Nat) (within : budget ≤ cap)
      (update : Database Key (Output (Counter := Counter)) →
        Work (Counter := Counter) (BaseWork := BaseWork) ≃
          Work (Counter := Counter) (BaseWork := BaseWork))
      (authorization : ∀ database workspace,
        ctx.authorizedOf ((update database).symm workspace).2 =
          ctx.authorizedOf workspace.2) :
      Opcode ctx cap budget budget 0
  | retainedWrite (occupied : Nat) (room : occupied < cap)
      (key : Key) (statement : List Byte)
      (marked : ∀ work, statement ∈ ctx.authorizedOf work)
      (parsed : globalLeafStatement ctx.leafNamespace (ctx.keyBytes key) = some statement)
      (fresh : Output (Counter := Counter)) :
      Opcode ctx cap occupied (occupied + 1) 0

namespace Opcode

def compile
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {before after charged : Nat}
    (opcode : Opcode ctx cap before after charged) :
      CertifiedAdaptiveStep (Phase := Output (Counter := Counter))
        (event ctx) (event ctx) cap before after := by
  cases opcode with
  | query room =>
      exact certifiedOrdinaryQueryStep vectorPhaseSystem (event ctx) cap before room
        (local_bound_nonnegative ctx cap) (event_instability ctx cap)
  | privateKernel within transition localStep contractive bounded =>
      exact certifiedKernelStep _ _ cap before before within within transition
        (fun source target nonzero afterEvent =>
          let facts := localStep source target nonzero
          base_event_private_transport ctx source target facts.1 facts.2 afterEvent)
        contractive bounded
  | mark within transition localStep contractive bounded =>
      exact certifiedKernelStep _ _ cap before before within within transition
        (fun source target nonzero afterEvent => by
          obtain ⟨statement, authorization, sameDatabase⟩ := localStep source target nonzero
          exact base_event_mark_transport ctx source target statement authorization
            sameDatabase afterEvent)
        contractive bounded
  | markedWrite after beforeWithin afterWithin transition localStep
      contractive bounded =>
      exact certifiedKernelStep _ _ cap before after beforeWithin afterWithin transition
        (fun source target nonzero afterEvent => by
          obtain ⟨key, statement, sameAuthorization, marked, parsed, sameOutside⟩ :=
            localStep source target nonzero
          exact base_event_write_transport ctx source target key statement
            sameAuthorization marked parsed sameOutside afterEvent)
        contractive bounded
  | copy within update authorization =>
      exact databaseControlledWorkspaceUpdateStep (event ctx) update
        (by
          intro database workspace
          unfold event ignoreRetained baseEvent
          rw [authorization database workspace])
        cap before within
  | retainedWrite room key statement marked parsed fresh =>
      exact vectorRetainedOldReplaceStep (baseEvent ctx) key
        (base_event_coordinate_invariant_of_authorized ctx key statement marked parsed)
        cap before room fresh

@[simp]
theorem compile_leak
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {before after charged : Nat}
    (opcode : Opcode ctx cap before after charged) :
    (compile ctx cap opcode).leak =
      (charged : ℝ) * Real.sqrt (6 * localBound ctx cap) := by
  cases opcode <;>
    simp [compile, certifiedOrdinaryQueryStep, certifiedKernelStep,
      databaseControlledWorkspaceUpdateStep, vectorRetainedOldReplaceStep,
      retainedOldReplaceStep, Real.sqrt_mul]

end Opcode

inductive ActualProgram
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) : Nat → Nat → Nat → Type _ where
  | nil (budget : Nat) : ActualProgram ctx cap budget budget 0
  | cons {start middle finish firstQueries remainingQueries}
      (first : Opcode ctx cap start middle firstQueries)
      (remaining : ActualProgram ctx cap middle finish remainingQueries) :
      ActualProgram ctx cap start finish (firstQueries + remainingQueries)

namespace ActualProgram

def compile
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {start finish queries : Nat} :
    ActualProgram ctx cap start finish queries →
      AdaptiveProgram (Phase := Output (Counter := Counter))
        cap (event ctx) start (event ctx) finish
  | .nil _ => .nil
  | .cons first remaining =>
      .cons (Opcode.compile ctx cap first) (compile ctx cap remaining)

theorem compile_total_leak
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {start finish queries : Nat}
    (program : ActualProgram ctx cap start finish queries) :
    AdaptiveProgram.totalLeak (compile ctx cap program) =
      (queries : ℝ) * Real.sqrt (6 * localBound ctx cap) := by
  induction program with
  | nil budget => simp [compile, AdaptiveProgram.totalLeak]
  | cons first remaining ih =>
      simp [compile, AdaptiveProgram.totalLeak, Opcode.compile_leak, ih]
      ring

end ActualProgram

theorem initialized_projection_zero
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    adaptiveProject (event ctx) cap
      (partialRandomOracleState (Output := Output (Counter := Counter)) ∅ registers) = 0 := by
  funext basis
  by_cases records : RecordsExactly
      (Output := Output (Counter := Counter)) ∅ basis.database
  · have same := (records_exactly_empty_iff basis.database).mp records
    have outside : ¬currentRoleEvent ctx.model ctx.leafNamespace ctx.keyBytes ctx.counter
        ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel
        (ctx.authorizedOf basis.workspace.2)
        (empty : Database Key (Output (Counter := Counter))) := by
      rintro ⟨key, output, recorded, _, _⟩
      cases recorded
    simp [adaptiveProject, event, ignoreRetained, baseEvent, same, outside]
  · simp [adaptiveProject, partialRandomOracleState, records]

/-- Final adaptive role-event endpoint.  Marks, private operations, X copies,
and marked writes are compiled internally as zero-leak steps; exactly
`queries` ordinary role/X queries are charged. -/
theorem current_adaptive_role_bad_mass_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (T finish queries : Nat)
    (program : ActualProgram ctx T 0 finish queries)
    (queriesLe : queries ≤ T)
    (registers : RegisterBasis (Input := Key)
      (Phase := Output (Counter := Counter))
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState
        (Output := Output (Counter := Counter)) ∅ registers)) :
    normSquared
        (adaptiveProject (event ctx) T
          (AdaptiveProgram.run (ActualProgram.compile ctx T program)
            (partialRandomOracleState
              (Output := Output (Counter := Counter)) ∅ registers))) ≤
      6 * (T : ℝ) ^ 2 * ((completeRoleLoss ctx.role : Rat) : ℝ) +
        36 * (T : ℝ) ^ 3 / (2^512 : ℝ) := by
  let initial := partialRandomOracleState
    (Output := Output (Counter := Counter)) ∅ registers
  have bounded : BoundedState 0 initial := partial_random_oracle_empty_bounded registers
  have counted := AdaptiveProgram.counted_query_probability_bound
    (ActualProgram.compile ctx T program) initial bounded subnormalized
    (local_bound_nonnegative ctx T) (initialized_projection_zero ctx T registers)
    (ActualProgram.compile_total_leak ctx T program)
  have castLe : (queries : ℝ) ≤ (T : ℝ) := by exact_mod_cast queriesLe
  have squares : (queries : ℝ) ^ 2 ≤ (T : ℝ) ^ 2 := by
    nlinarith [show (0 : ℝ) ≤ queries by positivity, show (0 : ℝ) ≤ T by positivity]
  calc
    _ ≤ 6 * (queries : ℝ) ^ 2 * localBound ctx T := by simpa [initial] using counted
    _ ≤ 6 * (T : ℝ) ^ 2 * localBound ctx T := by
      exact mul_le_mul_of_nonneg_right
        (mul_le_mul_of_nonneg_left squares (by norm_num))
        (local_bound_nonnegative ctx T)
    _ = 6 * (T : ℝ) ^ 2 * ((completeRoleLoss ctx.role : Rat) : ℝ) +
        36 * (T : ℝ) ^ 3 / (2^512 : ℝ) := by
      unfold localBound
      push_cast
      ring

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAdaptiveExecution
