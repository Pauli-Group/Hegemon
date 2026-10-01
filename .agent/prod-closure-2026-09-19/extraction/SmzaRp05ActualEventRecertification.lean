import SmzaRp05CurrentAdaptiveExecution

/-! Re-certify an existing physical program for a new counted role event.
The event may change; the executed kernels, query count, and state do not.
The specification contains local counting and support laws, never a supplied
execution probability. Concrete current-406 instances are checked separately. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ActualEventRecertification

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CmsOracleSimulation
open SmzaRp05AdaptiveFilteredCollision SmzaRp05AdaptiveKernelInstantiation
open SmzaRp05CurrentAdaptiveExecution SmzaRp05LeafNamespace
open SmzaRp05FilteredReadback
open V8Smz9CoherentVectorMerkle SmzaRp04RawMcaSampling

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

structure EventSpec
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) where
  base : Finset (List Byte) → Database Key (VectorOutput Counter) → Prop
  bound : ℝ
  bound_nonnegative : 0 ≤ bound
  instability : ∀ authorized, RealInstabilityBound (base authorized) cap bound
  mark_mono : ∀ authorized statement database,
    base (insert statement authorized) database → base authorized database
  marked_write : ∀ authorized statement, statement ∈ authorized → ∀ key,
    globalLeafStatement ctx.leafNamespace (ctx.keyBytes key) = some statement →
    ∀ left right, (∀ other, other ≠ key → left other = right other) →
      (base authorized left ↔ base authorized right)
  empty_false : ∀ authorized, ¬ base authorized empty

def baseEvent
    {ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    {cap : Nat} (spec : EventSpec ctx cap) :=
  fun work : BaseWork => spec.base (ctx.authorizedOf work)

def event
    {ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    {cap : Nat} (spec : EventSpec ctx cap) := ignoreRetained (baseEvent spec)

def compileOpcode
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) (spec : EventSpec ctx cap) {before after charged : Nat}
    (opcode : Opcode ctx cap before after charged) :
    CertifiedAdaptiveStep (Phase := VectorOutput Counter)
      (event spec) (event spec) cap before after := by
  cases opcode with
  | query room =>
      exact certifiedOrdinaryQueryStep vectorPhaseSystem (event spec) cap before room
        spec.bound_nonnegative (fun work => spec.instability (ctx.authorizedOf work.2))
  | privateKernel within transition localStep contractive bounded =>
      exact certifiedKernelStep _ _ cap before before within within transition
        (fun source target nonzero afterEvent => by
          obtain ⟨authorization, sameDatabase⟩ := localStep source target nonzero
          change spec.base (ctx.authorizedOf source.workspace.2) source.database
          change spec.base (ctx.authorizedOf target.workspace.2) target.database at afterEvent
          simpa only [authorization, sameDatabase] using afterEvent)
        contractive bounded
  | mark within transition localStep contractive bounded =>
      exact certifiedKernelStep _ _ cap before before within within transition
        (fun source target nonzero afterEvent => by
          obtain ⟨statement, authorization, sameDatabase⟩ := localStep source target nonzero
          change spec.base (ctx.authorizedOf source.workspace.2) source.database
          change spec.base (ctx.authorizedOf target.workspace.2) target.database at afterEvent
          rw [sameDatabase, authorization] at afterEvent
          exact spec.mark_mono _ statement _ afterEvent)
        contractive bounded
  | markedWrite after beforeWithin afterWithin transition localStep contractive bounded =>
      exact certifiedKernelStep _ _ cap before after beforeWithin afterWithin transition
        (fun source target nonzero afterEvent => by
          obtain ⟨key, statement, authorization, marked, parsed, sameOutside⟩ :=
            localStep source target nonzero
          change spec.base (ctx.authorizedOf source.workspace.2) source.database
          change spec.base (ctx.authorizedOf target.workspace.2) target.database at afterEvent
          rw [authorization]
          exact (spec.marked_write _ statement marked key parsed
            source.database target.database sameOutside).mpr afterEvent)
        contractive bounded
  | copy within update authorization =>
      exact databaseControlledWorkspaceUpdateStep (event spec) update
        (by
          intro database workspace
          unfold event ignoreRetained baseEvent
          rw [authorization database workspace])
        cap before within
  | retainedWrite room key statement marked parsed fresh =>
      exact vectorRetainedOldReplaceStep (baseEvent spec) key
        (fun workspace left right sameOutside =>
          spec.marked_write _ statement (marked workspace) key parsed left right sameOutside)
        cap before room fresh

/-- Re-certification changes no physical operation. -/
theorem compile_opcode_apply_eq
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) (spec : EventSpec ctx cap) {before after charged : Nat}
    (opcode : Opcode ctx cap before after charged) :
    (compileOpcode ctx cap spec opcode).apply = (Opcode.compile ctx cap opcode).apply := by
  cases opcode <;> rfl

theorem compile_opcode_leak
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) (spec : EventSpec ctx cap) {before after charged : Nat}
    (opcode : Opcode ctx cap before after charged) :
    (compileOpcode ctx cap spec opcode).leak =
      (charged : ℝ) * Real.sqrt (6 * spec.bound) := by
  cases opcode <;>
    simp [compileOpcode, certifiedOrdinaryQueryStep, certifiedKernelStep,
      databaseControlledWorkspaceUpdateStep, vectorRetainedOldReplaceStep,
      retainedOldReplaceStep, Real.sqrt_mul]

def compileProgram
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) (spec : EventSpec ctx cap) {start finish queries : Nat} :
    ActualProgram ctx cap start finish queries →
      AdaptiveProgram (Phase := VectorOutput Counter)
        cap (event spec) start (event spec) finish
  | .nil _ => .nil
  | .cons first remaining =>
      .cons (compileOpcode ctx cap spec first) (compileProgram ctx cap spec remaining)

/-- The recertified interpreter is exactly the existing interpreter. -/
theorem compile_program_run_eq
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) (spec : EventSpec ctx cap) {start finish queries : Nat}
    (program : ActualProgram ctx cap start finish queries)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    AdaptiveProgram.run (compileProgram ctx cap spec program) state =
      AdaptiveProgram.run (ActualProgram.compile ctx cap program) state := by
  induction program generalizing state with
  | nil budget => rfl
  | cons first remaining ih =>
      simp only [compileProgram, ActualProgram.compile, AdaptiveProgram.run,
        compile_opcode_apply_eq, ih]

theorem compile_program_total_leak
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) (spec : EventSpec ctx cap) {start finish queries : Nat}
    (program : ActualProgram ctx cap start finish queries) :
    AdaptiveProgram.totalLeak (compileProgram ctx cap spec program) =
      (queries : ℝ) * Real.sqrt (6 * spec.bound) := by
  induction program with
  | nil budget => simp [compileProgram, AdaptiveProgram.totalLeak]
  | cons first remaining ih =>
      simp only [compileProgram, AdaptiveProgram.totalLeak, compile_opcode_leak, ih,
        Nat.cast_add]
      ring

theorem initial_projection_zero
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) (spec : EventSpec ctx cap)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    adaptiveProject (event spec) cap
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) = 0 := by
  funext basis
  by_cases records : RecordsExactly (Output := VectorOutput Counter) ∅ basis.database
  · have same := (records_exactly_empty_iff basis.database).mp records
    have outside := spec.empty_false (ctx.authorizedOf basis.workspace.2)
    simp [adaptiveProject, event, ignoreRetained, baseEvent, same, outside]
  · simp [adaptiveProject, partialRandomOracleState, records]

/-- The new event bound is on the original physical execution, not on a
replacement program with a supplied simulation or terminal probability. -/
theorem actual_program_event_mass_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) (spec : EventSpec ctx cap) {finish queries : Nat}
    (program : ActualProgram ctx cap 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :
    normSquared (adaptiveProject (event spec) cap
      (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) ≤
      6 * (queries : ℝ)^2 * spec.bound := by
  have counted := AdaptiveProgram.counted_query_probability_bound
    (compileProgram ctx cap spec program)
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
    (partial_random_oracle_empty_bounded registers) normalized
    spec.bound_nonnegative (initial_projection_zero ctx cap spec registers)
    (compile_program_total_leak ctx cap spec program)
  rw [compile_program_run_eq] at counted
  exact counted

end
end HegemonCrypto.SmallWood.SmzaRp05ActualEventRecertification
