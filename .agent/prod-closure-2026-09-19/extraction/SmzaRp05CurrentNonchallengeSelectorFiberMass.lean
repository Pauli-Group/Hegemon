import SmzaRp05CurrentNonchallengeSelectorTransport
import SmzaRp05DependentAdviceEvent

/-! # Nonchallenge selector mass on actual fixed-table fibers

Selectors that inspect only the nonchallenge database view and the original
workspace can be transported through the existing fixed-table/active-state
isometry.  The mass identity below is the exact dependent-event disintegration
on one state; it does not introduce a new advice sample or normalize weights.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentNonchallengeSelectorFiberMass

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRoleDomainConditioning
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution
  (XKey ActiveDatabase ActiveMemory ActiveState FixedTable
    xView activeXView restrictActive mergeFixedActive restrict_merge_fixed_active
    fixedFiberToActive)
open SmzaRp05CurrentNonchallengeSelectorTransport
  (nonchallengeSelectorProjection active_nonchallenge_view_eq)
open SmzaRp05DependentAdviceEvent
  (dependentFixedEvent activeFiberEvent
    dependent_event_mass_eq_sum_active_event_masses)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

abbrev Output := VectorOutput Counter
abbrev Work := SmzaRp05CurrentAdaptiveExecution.Work
  (Counter := Counter) (BaseWork := BaseWork)
abbrev CmsState := State Key (Output (Counter := Counter))
  (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork))

/-- The selector read on an active database uses its exact full-database
completion by the fixed table.  The workspace is the original workspace
retained in `ActiveMemory`. -/
def activeNonchallengeSelectorEvent
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (select : (XKey keys → Option (Output (Counter := Counter))) →
      Work (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    ActiveMemory ctx → ActiveDatabase ctx blockCap → Prop :=
  fun memory active => select
    (activeXView ctx blockCap keys unrecognized active) memory.original.2.2

/-- On a fixed fiber, the active nonchallenge view is exactly the physical
database's X restriction. -/
theorem active_nonchallenge_selector_event_eq
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (select : (XKey keys → Option (Output (Counter := Counter))) →
      Work (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    activeFiberEvent ctx blockCap fixed
      (fun work database => select (xView keys database) work) =
    activeNonchallengeSelectorEvent ctx blockCap keys unrecognized select := by
  funext memory active
  change select (xView keys (mergeFixedActive ctx blockCap fixed active))
      memory.original.2.2 =
    select (activeXView ctx blockCap keys unrecognized active)
      memory.original.2.2
  have viewEq := active_nonchallenge_view_eq ctx blockCap keys unrecognized
    (mergeFixedActive ctx blockCap fixed active)
  simpa only [restrict_merge_fixed_active] using
    (congrArg (fun view => select view memory.original.2.2) viewEq.symm)

/-- Exact selected-event mass disintegration through the real active fibers.
The left side selects only states that have a complete fixed table, exactly
as the physical fixed-fiber partition requires. -/
theorem nonchallenge_selector_mass_eq_sum_active_fibers
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (select : (XKey keys → Option (Output (Counter := Counter))) →
      Work (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (workspaceEventProjection
      (dependentFixedEvent ctx blockCap
        (fun _ work database => select (xView keys database) work)) state) =
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (activeNonchallengeSelectorEvent ctx blockCap keys unrecognized select)
          (fixedFiberToActive ctx blockCap dummy fixed state)) := by
  rw [dependent_event_mass_eq_sum_active_event_masses]
  apply Finset.sum_congr rfl
  intro fixed _
  rw [active_nonchallenge_selector_event_eq]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentNonchallengeSelectorFiberMass
