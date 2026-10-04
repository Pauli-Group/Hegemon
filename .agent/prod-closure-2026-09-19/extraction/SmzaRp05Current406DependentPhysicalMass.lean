import SmzaRp05Current406PhysicalMass
import SmzaRp05Current406ActiveFiberEvent
import SmzaRp05AdaptiveRetainedAdviceTransport

/-! # Original-physical-mass transport for the current 406 event

Disintegrate the current 406 predicate by the fixed-table fiber actually
selected by the physical execution.  The checked active-fiber event equality
then identifies each term with the corresponding current-406 adaptive mass.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05Current406DependentPhysicalMass

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets
open SmzaRoleDomainConditioning
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ActualEventRecertification
open SmzaRp05ActualEventPhysicalMass SmzaRp05Current406EventSpec
open SmzaRp05ConditionedExecution SmzaRp05AdaptiveFilteredCollision
open SmzaRp05AdaptiveKernelInstantiation SmzaRp05CertifiedFiberCompiler
open SmzaRp05HomogeneousFiberSum V8Smz9CoherentVectorMerkle
open SmzaRp05AdaptivePhysicalReadBound SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05RoleReadTotality
open SmzaRp05DependentAdviceEvent SmzaRp05AdaptiveRetainedAdviceTransport
open SmzaRp05Current406PhysicalMass
open SmzaRp05Current406ActiveFiberEvent SmzaRp05ActualEventRecertification
open SmzaRp05ExecutableMerkleVerifier (Program)

local notation "RawInput" => V8SmzaOracleParser.RawInput
local notation "RawDigest" => V8SmzaOracleParser.RawDigest

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- The fixed-table summand is the literal current-406 base event, with
authorization read from the same physical workspace. -/
def current406FixedEvent
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap) :
    SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (VectorOutput Counter) → Prop :=
  fun work database => current406Base (contextAtFixed ctx blockCap fixed)
    ((contextAtFixed ctx blockCap fixed).authorizedOf work.2) database

/-- Sum of the current-406 dependent-event branch masses equals the exact
sum of certified current-406 active-fiber event masses.  This is an
unnormalized identity on the original physical branch amplitudes. -/
theorem physical_dependent_current406_mass_eq_fiber_sum
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
          (dependentFixedEvent ctx blockCap (current406FixedEvent ctx blockCap))
          (otherRoleTransform ctx blockCap (physicalRun encode decode suffix branch state)))) =
      (letI := physicalBranchesFintype decode suffix
        ∑ fixed : FixedTable ctx blockCap, ∑ branch : Branches decode suffix,
          normSquared (workspaceEventProjection
            (fun memory database =>
              SmzaRp05ActualEventRecertification.event
                (current406EventSpec (activeContext ctx blockCap fixed) cap)
                (activeMemoryEquiv ctx memory) database)
            (fixedFiberToActive ctx blockCap dummy fixed
              (otherRoleTransform ctx blockCap
                (physicalRun encode decode suffix branch state))))) := by
  letI := physicalBranchesFintype decode suffix
  have merged (fixed : FixedTable ctx blockCap) (active : ActiveDatabase ctx blockCap) :
      mergeFixedActive (contextAtFixed ctx blockCap fixed) blockCap fixed active =
        mergeFixedActive ctx blockCap fixed active := by
    funext key
    simp [mergeFixedActive, contextAtFixed]
  have eventEq (fixed : FixedTable ctx blockCap) :
      activeFiberEvent ctx blockCap fixed
        (current406FixedEvent ctx blockCap fixed) =
      fun memory database =>
        SmzaRp05ActualEventRecertification.event
          (current406EventSpec (activeContext ctx blockCap fixed) cap)
          (activeMemoryEquiv ctx memory) database := by
    funext memory database
    have fiberEq :
        activeFiberEvent ctx blockCap fixed (current406FixedEvent ctx blockCap fixed) memory =
          activeFiberEvent (contextAtFixed ctx blockCap fixed) blockCap fixed
            (current406FixedEvent ctx blockCap fixed) memory := by
      funext active
      simp [activeFiberEvent, current406FixedEvent, merged]
    have native := active_fiber_current406_base_eq_native
      (contextAtFixed ctx blockCap fixed) blockCap fixed memory
    dsimp +instances only [contextAtFixed] at native
    rw [fiberEq]
    simpa +instances [activeFiberEvent, current406FixedEvent,
      current406EventSpec, current406Base,
      contextAtFixed, activeContext, activeMemoryEquiv,
      SmzaRp05ActualEventRecertification.event,
      SmzaRp05ActualEventRecertification.baseEvent,
      SmzaRp05AdaptiveKernelInstantiation.ignoreRetained] using
      (congrFun native database)
  calc
    (∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (dependentFixedEvent ctx blockCap (current406FixedEvent ctx blockCap))
          (otherRoleTransform ctx blockCap (physicalRun encode decode suffix branch state)))) =
      ∑ branch : Branches decode suffix, ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (activeFiberEvent ctx blockCap fixed
            (current406FixedEvent ctx blockCap fixed))
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap
              (physicalRun encode decode suffix branch state)))) := by
        simp_rw [dependent_event_mass_eq_sum_active_event_masses
          ctx blockCap dummy (current406FixedEvent ctx blockCap) _]
    _ = ∑ fixed : FixedTable ctx blockCap, ∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (fun memory database =>
            SmzaRp05ActualEventRecertification.event
              (current406EventSpec (activeContext ctx blockCap fixed) cap)
              (activeMemoryEquiv ctx memory) database)
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap
              (physicalRun encode decode suffix branch state)))) := by
        rw [Finset.sum_comm]
        apply Finset.sum_congr rfl
        intro fixed _
        simp_rw [eventEq fixed]

/-- The original dependent current-406 event inherits the certified-prefix
bound without a caller-supplied role-event probability premise. -/
theorem physical_dependent_current406_mass_le_certified_prefix
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
            (current406FixedEvent (contexts role) blockCap))
          (otherRoleTransform (contexts role) blockCap
            (physicalRun encode decode suffix branch
              (PhysicalProgramSkeleton.run skeleton
                (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))))) ≤
      (6 * (cap : ℝ)^2 * current406Bound (contexts role).role cap) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  rw [physical_dependent_current406_mass_eq_fiber_sum
    (contexts role) blockCap dummy cap encode decode suffix _]
  exact sum_current406_physical_fiber_event_mass_le_certified_prefix
    certified role blockCap dummy registers depth encode decode suffix readBound keys
    keysWithin supportWithin queriesWithin total

end
end HegemonCrypto.SmallWood.SmzaRp05Current406DependentPhysicalMass
