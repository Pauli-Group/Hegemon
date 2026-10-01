import SmzaRp05Current406DependentPhysicalMass
import SmzaRp05CurrentFixedEarlierAdvice

/-! # Current-decoder fixed advice in the physical event-mass bound

The conditioned execution context's fixed advice uses the historical DECS
matrix map. This sibling keeps the fixed table and physical branch amplitudes
unchanged, but assigns earlier-table advice with the current deterministic
fixed-table decoder before applying the checked current-406 event law.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAdviceDependentPhysicalMass

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets SmzaRoleDomainConditioning
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ActualEventRecertification
open SmzaRp05Current406EventSpec SmzaRp05Current406ActiveFiberEvent
open SmzaRp05Current406PhysicalMass SmzaRp05CurrentFixedEarlierAdvice
open SmzaRp05ConditionedExecution SmzaRp05DependentAdviceEvent
open SmzaRp05AdaptiveRetainedAdviceTransport SmzaRp05ActualEventPhysicalMass
open SmzaRp05AdaptiveFilteredCollision SmzaRp05AdaptiveKernelInstantiation
open SmzaRp05CertifiedFiberCompiler SmzaRp05HomogeneousFiberSum
open SmzaRp05AdaptivePhysicalReadBound SmzaRp05RoleReadTotality
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9CoherentVectorMerkle

local notation "RawInput" => V8SmzaOracleParser.RawInput
local notation "RawDigest" => V8SmzaOracleParser.RawDigest

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 12000

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- Fixed-table context whose earlier advice is assigned by the current
decoder rather than the historical one. -/
def currentAdviceContextAtFixed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) :
    Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  { ctx with advice := currentFixedAdvice ctx blockCap fixed }

def currentAdviceFixedEvent
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) :
    SmzaRp05CurrentAdaptiveExecution.Work
      (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (VectorOutput Counter) → Prop :=
  fun work database =>
    current406Base (currentAdviceContextAtFixed ctx blockCap fixed)
      ((currentAdviceContextAtFixed ctx blockCap fixed).authorizedOf work.2)
      database

/-- Active context carrying current advice. The adaptive program still runs
on the original `activeContext`; the EventSpec base is independent of that
context's stored advice field. -/
def currentAdviceActiveContext
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) :
    Context (Key := ActiveKey ctx.role blockCap ctx.keyBytes)
      (Counter := Counter) (BaseWork := RoutedBaseMemory Key Counter BaseWork) :=
  { activeContext ctx blockCap fixed with
      advice := currentFixedAdvice ctx blockCap fixed }

def currentAdviceEventSpec
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) (cap : Nat) :
    EventSpec (activeContext ctx blockCap fixed) cap := by
  let adjusted := currentAdviceActiveContext ctx blockCap fixed
  let certified := current406EventSpec adjusted cap
  refine
    { base := certified.base
      bound := certified.bound
      bound_nonnegative := certified.bound_nonnegative
      instability := certified.instability
      mark_mono := certified.mark_mono
      marked_write := ?_
      empty_false := ?_ }
  · exact certified.marked_write
  · exact certified.empty_false

private theorem current_advice_fixed_fiber_event_eq_native
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (cap : Nat)
    :
    activeFiberEvent ctx blockCap fixed (currentAdviceFixedEvent ctx blockCap fixed)
      = fun memory active =>
      event (currentAdviceEventSpec ctx blockCap fixed cap)
        (activeMemoryEquiv ctx memory) active := by
  let adjusted := currentAdviceContextAtFixed ctx blockCap fixed
  funext memory active
  change current406Base adjusted (adjusted.authorizedOf memory.original.2.2.2)
      (mergeFixedActive adjusted blockCap fixed active) =
    currentRoleEvent406Explicit ctx.model ctx.leafNamespace
      (fun key : ActiveKey ctx.role blockCap ctx.keyBytes => ctx.keyBytes key.val)
      ctx.counter ctx.routes ctx.role (currentFixedAdvice ctx blockCap fixed)
      ctx.outerFuel ctx.innerFuel
      (ctx.authorizedOf memory.original.2.2.2) active
  simpa +instances [adjusted, currentAdviceContextAtFixed] using
    propext (current406_base_merged_iff_active adjusted blockCap fixed active
      (adjusted.authorizedOf memory.original.2.2.2))

/-- Exact disintegration for current deterministic advice. Each summand
retains the original physical branch amplitude. -/
theorem physical_current_advice_current406_mass_eq_fiber_sum
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (cap : Nat)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (suffix : Program Result)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    (letI := physicalBranchesFintype decode suffix
      ∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (dependentFixedEvent ctx blockCap
            (currentAdviceFixedEvent ctx blockCap))
          (otherRoleTransform ctx blockCap
            (physicalRun encode decode suffix branch state)))) =
      (letI := physicalBranchesFintype decode suffix
        ∑ fixed : FixedTable ctx blockCap, ∑ branch : Branches decode suffix,
          normSquared (workspaceEventProjection
            (fun memory database =>
              event (currentAdviceEventSpec ctx blockCap fixed cap)
                (activeMemoryEquiv ctx memory) database)
            (fixedFiberToActive ctx blockCap dummy fixed
              (otherRoleTransform ctx blockCap
                (physicalRun encode decode suffix branch state))))) := by
  letI := physicalBranchesFintype decode suffix
  have eventEq (fixed : FixedTable ctx blockCap) :
      activeFiberEvent ctx blockCap fixed (currentAdviceFixedEvent ctx blockCap fixed) =
        (fun memory database =>
          event (currentAdviceEventSpec ctx blockCap fixed cap)
            (activeMemoryEquiv ctx memory) database) := by
    funext memory database
    have native := current_advice_fixed_fiber_event_eq_native ctx blockCap fixed cap
    simpa [currentAdviceEventSpec] using congrFun (congrFun native memory) database
  calc
    (∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (dependentFixedEvent ctx blockCap
            (currentAdviceFixedEvent ctx blockCap))
          (otherRoleTransform ctx blockCap (physicalRun encode decode suffix branch state)))) =
      ∑ branch : Branches decode suffix, ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (activeFiberEvent ctx blockCap fixed
            (currentAdviceFixedEvent ctx blockCap fixed))
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap
              (physicalRun encode decode suffix branch state)))) := by
        simp_rw [dependent_event_mass_eq_sum_active_event_masses
          ctx blockCap dummy (currentAdviceFixedEvent ctx blockCap) _]
    _ = ∑ fixed : FixedTable ctx blockCap, ∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (fun memory database =>
            event (currentAdviceEventSpec ctx blockCap fixed cap)
              (activeMemoryEquiv ctx memory) database)
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap
              (physicalRun encode decode suffix branch state)))) := by
        rw [Finset.sum_comm]
        apply Finset.sum_congr rfl
        intro fixed _
        simp_rw [eventEq fixed]

/-- Current-advice physical mass is bounded by the existing certified-prefix
law. No new role-event probability premise is introduced. -/
theorem physical_current_advice_current406_mass_le_certified_prefix
    {contexts : Role → Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (role : Role) (blockCap : Role → Nat)
    (dummy : ActiveKey (contexts role).role blockCap (contexts role).keyBytes)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (suffix : Program Result) (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys (PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    (letI := physicalBranchesFintype decode suffix
      ∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (dependentFixedEvent (contexts role) blockCap
            (currentAdviceFixedEvent (contexts role) blockCap))
          (otherRoleTransform (contexts role) blockCap
            (physicalRun encode decode suffix branch
              (PhysicalProgramSkeleton.run skeleton
                (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))))) ≤
      (6 * (cap : ℝ)^2 * current406Bound (contexts role).role cap) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  rw [physical_current_advice_current406_mass_eq_fiber_sum
    (contexts role) blockCap dummy cap encode decode suffix _]
  let spec : ∀ fixed : FixedTable (contexts role) blockCap,
      EventSpec (activeContext (contexts role) blockCap fixed) cap :=
    fun fixed => currentAdviceEventSpec (contexts role) blockCap fixed cap
  have sameBound : ∀ fixed, (spec fixed).bound = current406Bound (contexts role).role cap := by
    intro fixed
    rfl
  exact sum_physical_fiber_event_mass_le_certified_prefix
    certified role blockCap dummy spec (current406Bound (contexts role).role cap)
    sameBound registers depth encode decode suffix readBound keys keysWithin
    supportWithin queriesWithin total

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAdviceDependentPhysicalMass
