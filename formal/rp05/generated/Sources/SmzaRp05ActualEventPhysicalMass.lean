import SmzaRp05ActualEventFiberMass
import SmzaRp05AdaptiveRetainedAdviceTotality
import SmzaRp05CertifiedFiberCompilerRun

/-! Event-specific bounds on the original physical answer branches.
The fixed-table and answer-branch sums retain their actual amplitudes;
neither a new advice distribution nor a final probability estimate is assumed. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ActualEventPhysicalMass

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05ConditionedExecution SmzaRp05CurrentAdaptiveExecution
open SmzaRp05AdaptiveFilteredCollision SmzaRp05DependentAdviceEvent
open SmzaRp05HomogeneousFiberSum SmzaRp05AdaptivePhysicalReadBound
open SmzaRp05RoleReadTotality SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05AdaptiveRetainedAdviceMass SmzaRp05AdaptiveRetainedAdviceTransport
open SmzaRp05AdaptiveRetainedAdviceTotality SmzaRp05ActualEventFiberMass
open SmzaRp05ConditionedEventJoin
open V8Smz9CoherentVectorMerkle
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

theorem sum_physical_fiber_event_mass_le_of_compiled_prefix
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (cap finish queries depth : Nat)
    (spec : ∀ fixed : FixedTable ctx blockCap,
      SmzaRp05ActualEventRecertification.EventSpec (activeContext ctx blockCap fixed) cap)
    (commonBound : ℝ) (sameBound : ∀ fixed, (spec fixed).bound = commonBound)
    (prefixProgram : ∀ fixed : FixedTable ctx blockCap,
      ActualProgram (activeContext ctx blockCap fixed) cap 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (prefixTransport : ∀ fixed,
      routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state) =
        AdaptiveProgram.run (ActualProgram.compile (activeContext ctx blockCap fixed) cap
          (prefixProgram fixed)) (partialRandomOracleState (Output := VectorOutput Counter) ∅
            (initialFiberRegisters ctx blockCap dummy registers)))
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (suffix : Program Result) (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys state) :
    (letI := physicalBranchesFintype decode suffix
      ∑ fixed : FixedTable ctx blockCap, ∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (fun memory database => SmzaRp05ActualEventRecertification.event (spec fixed)
            (activeMemoryEquiv ctx memory) database)
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap (physicalRun encode decode suffix branch state))))) ≤
      (6 * (cap : ℝ)^2 * commonBound) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  letI := physicalBranchesFintype decode suffix
  have transport (fixed : FixedTable ctx blockCap) :
      (∑ branch : Branches decode suffix,
        normSquared (workspaceEventProjection
          (fun memory database => SmzaRp05ActualEventRecertification.event (spec fixed)
            (activeMemoryEquiv ctx memory) database)
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap (physicalRun encode decode suffix branch state))))) =
      adaptiveReadMass (activeReadEncode ctx blockCap dummy encode) decode
        (SmzaRp05ActualEventRecertification.event (spec fixed))
        (compileFixedReads ctx blockCap fixed encode decode suffix)
        (routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state)) := by
    rw [original_physical_fiber_sum_eq_compiled_adaptive_mass,
      adaptive_read_mass_reindex]
    rfl
  simp_rw [transport, prefixTransport]
  apply sum_fixed_actual_event_suffix_mass_le ctx blockCap dummy cap finish queries depth
    spec commonBound sameBound prefixProgram registers
    (activeReadEncode ctx blockCap dummy encode) (fun _ => decode)
    (fun fixed => compileFixedReads ctx blockCap fixed encode decode suffix)
    (fun fixed => compile_fixed_reads_depth ctx blockCap fixed encode decode suffix depth readBound)
    (activeReadKeys ctx blockCap keys)
    (fun fixed => compile_fixed_reads_keys ctx blockCap dummy fixed encode decode suffix keys keysWithin)
    supportWithin queriesWithin
  intro fixed
  rw [← prefixTransport fixed]
  exact same_fiber_standard_on_active_schedule ctx blockCap dummy fixed keys state total

/-- Instantiate the prefix equality using the existing structural compiler
of the same physical program. -/
theorem sum_physical_fiber_event_mass_le_certified_prefix
    {contexts : Role → Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (role : Role) (blockCap : Role → Nat)
    (dummy : ActiveKey (contexts role).role blockCap (contexts role).keyBytes)
    (spec : ∀ fixed : FixedTable (contexts role) blockCap,
      SmzaRp05ActualEventRecertification.EventSpec
        (activeContext (contexts role) blockCap fixed) cap)
    (commonBound : ℝ) (sameBound : ∀ fixed, (spec fixed).bound = commonBound)
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
          (fun memory database => SmzaRp05ActualEventRecertification.event (spec fixed)
            (activeMemoryEquiv (contexts role) memory) database)
          (fixedFiberToActive (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap
              (physicalRun encode decode suffix branch (PhysicalProgramSkeleton.run skeleton
                (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))))) ≤
      (6 * (cap : ℝ)^2 * commonBound) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  exact sum_physical_fiber_event_mass_le_of_compiled_prefix (contexts role) blockCap dummy
    cap finish queries depth spec commonBound sameBound
    (SmzaRp05CertifiedFiberCompiler.compilePrefix certified role blockCap dummy)
    registers _
    (fun fixed => SmzaRp05CertifiedFiberCompiler.initial_run_eq_compiled_prefix
      certified role blockCap dummy fixed registers)
    encode decode suffix readBound keys keysWithin supportWithin queriesWithin total

end
end HegemonCrypto.SmallWood.SmzaRp05ActualEventPhysicalMass
