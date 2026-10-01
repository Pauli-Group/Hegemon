import SmzaRp05CurrentFilteredCollisionEventSpec
import SmzaRp05ActualEventPhysicalMass

/-! The current authorization-filtered raw-record collision event receives the
same original physical-fiber mass bound on the certified physical prefix. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFilteredCollisionPhysicalMass

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets SmzaRoleDomainConditioning
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ActualEventRecertification
open SmzaRp05ActualEventPhysicalMass SmzaRp05CurrentFilteredCollisionEventSpec
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

/-- Sum the filtered-collision event mass over fixed tables and actual answer
branches of the same certified physical prefix. The event is filtered by the
current authorization set, not the unfiltered raw-coordinate collision. -/
theorem sum_current_filtered_collision_physical_fiber_mass_le_certified_prefix
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
            (filteredCollisionEventSpec
              (activeContext (contexts role) blockCap fixed) cap)
            (activeMemoryEquiv (contexts role) memory) database)
          (fixedFiberToActive (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap
              (physicalRun encode decode suffix branch (PhysicalProgramSkeleton.run skeleton
                (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))))) ≤
      (6 * (cap : ℝ)^2 * (((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ)) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  let spec : ∀ fixed : FixedTable (contexts role) blockCap,
      EventSpec (activeContext (contexts role) blockCap fixed) cap :=
    fun fixed => filteredCollisionEventSpec
      (activeContext (contexts role) blockCap fixed) cap
  have sameBound : ∀ fixed,
      (spec fixed).bound = (((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ) := by
    intro fixed
    rfl
  exact sum_physical_fiber_event_mass_le_certified_prefix
    certified role blockCap dummy spec (((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ)
    sameBound registers depth encode decode suffix readBound keys keysWithin
    supportWithin queriesWithin total

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFilteredCollisionPhysicalMass
