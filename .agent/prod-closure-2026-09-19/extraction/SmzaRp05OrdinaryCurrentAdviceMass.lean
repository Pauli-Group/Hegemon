import SmzaRp05OrdinarySoundnessExecution
import SmzaRp05OrdinarySoundnessStandardTotal
import SmzaRp05CurrentAdviceDependentPhysicalMass

/-! # Ordinary-prefix current-advice event mass

Specialize the current-decoder fixed-advice event bound to ordinary
unprogrammable prefixes. Standard-on totality is derived internally from the
initialized ordinary-run standard-total theorem, so callers supply no
probability or totality premise.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05OrdinaryCurrentAdviceMass

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets SmzaRoleDomainConditioning
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ActualEventRecertification
open SmzaRp05ConditionedExecution SmzaRp05OrdinarySoundnessExecution
open SmzaRp05OrdinarySoundnessStandardTotal
open SmzaRp05CurrentAdviceDependentPhysicalMass
open SmzaRp05Current406EventSpec
open SmzaRp05DependentAdviceEvent SmzaRp05AdaptivePhysicalReadBound
open SmzaRp05PhysicalAcceptedReplayLite SmzaRp05RoleReadTotality
open V8Smz9CoherentVectorMerkle
open SmzaRp05ExecutableMerkleVerifier (Program)

local notation "RawInput" => V8SmzaOracleParser.RawInput
local notation "RawDigest" => V8SmzaOracleParser.RawDigest

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxHeartbeats 1600000
set_option exponentiation.threshold 1024

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- Current-advice current-406 branch mass for an ordinary prefix. Empty
authorization and the standard-on totality proof are generated internally;
the estimate is on the unnormalized physical branch amplitudes. -/
theorem ordinary_current_advice_current406_mass_le
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
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap) :
    (letI := physicalBranchesFintype decode suffix
      ∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (dependentFixedEvent (emptyAuthorizationContexts contexts role) blockCap
            (currentAdviceFixedEvent (emptyAuthorizationContexts contexts role) blockCap))
          (otherRoleTransform (emptyAuthorizationContexts contexts role) blockCap
            (physicalRun encode decode suffix branch
              (ordinaryRun program
                (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))))) ≤
      (6 * (cap : ℝ)^2 *
        current406Bound (emptyAuthorizationContexts contexts role).role cap) *
        normSquared (partialRandomOracleState
          (Output := VectorOutput Counter) ∅ registers) := by
  have standardTotal := initialized_ordinary_run_standard_total program registers
  have total : StandardOn keys
      (ordinaryRun program
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
    intro key _
    exact standardTotal key
  have total' := total
  rw [ordinaryRun_eq_compiled] at total'
  have physicalBound := physical_current_advice_current406_mass_le_certified_prefix
    (contexts := emptyAuthorizationContexts contexts)
    (skeleton := compileOrdinary program)
    (certified := compileOrdinary_certified contexts program)
    role blockCap dummy registers depth encode decode suffix readBound keys
    keysWithin supportWithin queriesWithin total'
  simpa only [ordinaryRun_eq_compiled] using physicalBound

/-- Initialized numeric form with the current event coefficient expanded.
This remains scaled by the supplied input register norm, so it does not
silently assume normalized adversary registers. -/
theorem ordinary_current_advice_current406_mass_le_explicit
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
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap) :
    (letI := physicalBranchesFintype decode suffix
      ∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (dependentFixedEvent (emptyAuthorizationContexts contexts role) blockCap
            (currentAdviceFixedEvent (emptyAuthorizationContexts contexts role) blockCap))
          (otherRoleTransform (emptyAuthorizationContexts contexts role) blockCap
            (physicalRun encode decode suffix branch
              (ordinaryRun program
                (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))))) ≤
    (6 * (cap : ℝ)^2 *
        (((6 * cap : Rat) / (2 ^ 512 : Rat) +
          current406RoleLoss (emptyAuthorizationContexts contexts role).role : Rat) : ℝ) *
        normSquared (partialRandomOracleState
          (Output := VectorOutput Counter) ∅ registers)) := by
  simpa [current406Bound] using
    ordinary_current_advice_current406_mass_le contexts program role blockCap dummy
      registers depth encode decode suffix readBound keys keysWithin
      supportWithin queriesWithin

end
end HegemonCrypto.SmallWood.SmzaRp05OrdinaryCurrentAdviceMass
