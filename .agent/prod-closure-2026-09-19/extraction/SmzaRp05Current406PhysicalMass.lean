import SmzaRp05Current406EventSpec
import SmzaRp05ActualEventPhysicalMass

/-! A current-406 role-event specialization of the certified original
physical-fiber event-mass theorem. The event specification is reconstructed
for every fixed table from the selected active context; its bound is fixed
by the unchanged role, not supplied as an execution-probability premise. -/
namespace HegemonCrypto.SmallWood.SmzaRp05Current406PhysicalMass

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
open SmzaRp05ExecutableMerkleVerifier (Program)

local notation "RawInput" => V8SmzaOracleParser.RawInput
local notation "RawDigest" => V8SmzaOracleParser.RawDigest

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- Bound the sum of current-406 selected-role event masses over the original
physical branches and fixed tables. The physical skeleton and its certified
compiler are the only execution inputs; event instability is derived by the
current-406 `EventSpec`. -/
theorem sum_current406_physical_fiber_event_mass_le_certified_prefix
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
      ∑ fixed : FixedTable (contexts role) blockCap, ∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (fun memory database => event
            (current406EventSpec
              (activeContext (contexts role) blockCap fixed) cap)
            (activeMemoryEquiv (contexts role) memory) database)
          (fixedFiberToActive (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap
              (physicalRun encode decode suffix branch (PhysicalProgramSkeleton.run skeleton
                (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))))) ≤
      (6 * (cap : ℝ)^2 * current406Bound (contexts role).role cap) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  let spec : ∀ fixed : FixedTable (contexts role) blockCap,
      EventSpec (activeContext (contexts role) blockCap fixed) cap :=
    fun fixed => current406EventSpec (activeContext (contexts role) blockCap fixed) cap
  have sameBound : ∀ fixed, (spec fixed).bound = current406Bound (contexts role).role cap := by
    intro fixed
    rfl
  exact sum_physical_fiber_event_mass_le_certified_prefix
    certified role blockCap dummy spec (current406Bound (contexts role).role cap)
    sameBound registers depth encode decode suffix readBound keys keysWithin
    supportWithin queriesWithin total

end
end HegemonCrypto.SmallWood.SmzaRp05Current406PhysicalMass
