import SmzaRp05OrdinarySoundnessExecution
import SmzaRp05CurrentFilteredCollisionPhysicalMass

/-! # Ordinary unprogrammed-prefix collision mass

Specialize the existing filtered-collision physical-fiber estimate to the
ordinary query/private-kernel syntax. Empty authorization is derived by the
ordinary execution module; no simulator programming certificate or final
accepted-soundness premise is introduced here.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05OrdinarySoundnessPhysicalMass

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets SmzaRoleDomainConditioning
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ActualEventRecertification
open SmzaRp05ActualEventPhysicalMass SmzaRp05CurrentFilteredCollisionEventSpec
open SmzaRp05ConditionedExecution SmzaRp05AdaptiveFilteredCollision
open SmzaRp05AdaptiveKernelInstantiation SmzaRp05CertifiedFiberCompiler
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05CurrentFilteredCollisionPhysicalMass
open SmzaRp05ConditionedEventJoin
open SmzaRp05HomogeneousFiberSum
open SmzaRp05AdaptivePhysicalReadBound SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05RoleReadTotality V8Smz9CoherentVectorMerkle
open SmzaRp05ExecutableMerkleVerifier (Program)

local notation "RawInput" => V8SmzaOracleParser.RawInput
local notation "RawDigest" => V8SmzaOracleParser.RawDigest

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxHeartbeats 1600000

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- The existing filtered-collision mass theorem specialized to an ordinary
unprogrammable prefix. The generated certificate and empty authorization are
internal; totals are stated on `ordinaryRun`, which is definitionally the
compiled physical execution. -/
theorem ordinary_filtered_collision_fiber_mass_le
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    {cap finish queries : Nat}
    (program : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (role : Role) (blockCap : Role → Nat)
    (dummy : ActiveKey (emptyAuthorizationContexts contexts role).role blockCap
      (emptyAuthorizationContexts contexts role).keyBytes)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (suffix : Program Result) (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys
      (ordinaryRun program
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    (letI := physicalBranchesFintype decode suffix
      ∑ fixed : FixedTable (emptyAuthorizationContexts contexts role) blockCap,
        ∑ branch : Branches decode suffix,
          normSquared (workspaceEventProjection
            (fun memory database => event
              (filteredCollisionEventSpec
                (activeContext (emptyAuthorizationContexts contexts role) blockCap fixed)
                cap)
              (activeMemoryEquiv (emptyAuthorizationContexts contexts role) memory)
              database)
            (fixedFiberToActive (emptyAuthorizationContexts contexts role) blockCap dummy fixed
              (otherRoleTransform (emptyAuthorizationContexts contexts role) blockCap
                (physicalRun encode decode suffix branch
                  (ordinaryRun program
                    (partialRandomOracleState
                      (Output := VectorOutput Counter) ∅ registers))))))) ≤
      (6 * (cap : ℝ)^2 * ((((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ)) *
        normSquared (partialRandomOracleState
          (Output := VectorOutput Counter) ∅ registers)) := by
  have total' := total
  rw [ordinaryRun_eq_compiled] at total'
  have physicalBound := sum_current_filtered_collision_physical_fiber_mass_le_certified_prefix
    (contexts := emptyAuthorizationContexts contexts)
    (skeleton := compileOrdinary program)
    (certified := compileOrdinary_certified contexts program)
    role blockCap dummy registers depth encode decode suffix readBound keys
    keysWithin supportWithin queriesWithin total'
  rw [ordinaryRun_eq_compiled]
  exact physicalBound

end
end HegemonCrypto.SmallWood.SmzaRp05OrdinarySoundnessPhysicalMass
