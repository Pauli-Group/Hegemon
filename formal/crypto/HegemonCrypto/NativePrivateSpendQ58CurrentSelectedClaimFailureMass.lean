import HegemonCrypto.NativePrivateSpendQ58CurrentConditionedBranchReadback
import SmzaRp05CurrentKnownClaimsFailureMass

/-! Unselected physical readback bounds diagonal selector loss. Source only. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSelectedClaimFailureMass
open scoped Classical
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaChallengeStageTargets (Role)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter encode decode)
end G
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims (live activeClaims fixedCompatible)
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end AC
namespace A
export NativePrivateSpendQ58ActiveEventProjection
  (ActiveKey FixedTable FullState Memory restrictFiber)
end A
namespace P
export NativePrivateSpendQ58PartitionTransport (conditioned)
end P
namespace X
export NativePrivateSpendQ58CurrentConditionedBranchReadback
  (eraseProgram eraseBranch activeEncode erased_branch_claims_are_actual_active_claims
   filtered_claims_at_native_root sparse_run_is_erased_actual_branch
   current_incompatible_conditioned_branch_is_zero)
export NativePrivateSpendQ58ActiveProgramTransport (physical_run_to_sparse_same_fiber)
end X
namespace K
export SmzaRp05CurrentKnownClaimsFailureMass
  (global_known_claims_failure_mass_le database_event_complement_mass_split)
export SmzaRp05CurrentPhysicalBranchClaimReadback (physical_branch_claim_known_at_standard)
export SmzaRp05CurrentPhysicalBranchClaims (workspace_event_mass_le_of_inclusion)
export SmzaRp05PartialReadout (claimFailureProjection KnownAt)
end K
noncomputable section
set_option autoImplicit false
private theorem zero_claim_failure_mass
    {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (claims : List (Input × Output)) (factor : ℝ) :
    normSquared (K.claimFailureProjection claims
      (0 : State Input Output Phase Workspace)) ≤
      factor * normSquared (0 : State Input Output Phase Workspace) := by
  have projectionZero : K.claimFailureProjection claims
      (0 : State Input Output Phase Workspace) = 0 := by
    funext basis
    simp only [K.claimFailureProjection, databaseEventProjection, Pi.zero_apply, ite_self]
  have normZero : normSquared (0 : State Input Output Phase Workspace) = 0 := by
    simp only [normSquared, Pi.zero_apply, Complex.normSq_zero, Finset.sum_const_zero]
  rw [projectionZero, normZero, mul_zero]

variable {Result Work : Type} [Fintype Work] [DecidableEq Work]

abbrev caps := AC.currentRoleCaps
def live (root : Program Result) (role : Role) := AC.live root role caps

structure Context (root : Program Result) (role : Role) (Work : Type) where
  dummy : A.ActiveKey (live root role)
  fixed : A.FixedTable (Counter := G.Counter) (live root role)
  branch : Branches G.decode root
  initial : A.FullState (Key := G.Key root) (Counter := G.Counter) (Work := Work)

variable {root : Program Result} {role : Role} (c : Context root role Work)
def conditioned := P.conditioned (live root role) c.fixed
  (physicalRun (G.encode root) G.decode root c.branch c.initial)
def sparse := A.restrictFiber (live root role) c.dummy c.fixed (conditioned c)
def claims := AC.activeClaims root role caps c.branch
abbrev recorded := ClaimsDatabaseEvent (claims c)
abbrev Selector (root : Program Result) (role : Role) (Work : Type) := A.Memory (Key := G.Key root) (Counter := G.Counter) (Work := Work) →
  Database (A.ActiveKey (live root role)) (VectorOutput G.Counter) → Prop
def selected (selector : Selector root role Work) :=
  workspaceEventProjection selector (sparse c)
def penalty := (((2 * (claims c).toFinset.card : Nat) : ℝ) /
  Fintype.card (VectorOutput G.Counter)) * normSquared (sparse c)

theorem unselected_failure_le :
    normSquared (K.claimFailureProjection (claims c) (sparse c)) ≤ penalty c := by
  by_cases compatible : AC.fixedCompatible root role caps c.fixed c.branch
  · let erased := X.eraseProgram root role caps c.fixed root
    let branch := X.eraseBranch root role caps c.fixed root c.branch compatible
    let initial := A.restrictFiber (live root role) c.dummy c.fixed
      (P.conditioned (live root role) c.fixed c.initial)
    have runEq : sparse c = physicalRun
        (X.activeEncode root role caps c.dummy) G.decode erased branch initial := by
      unfold sparse conditioned
      rw [X.physical_run_to_sparse_same_fiber]
      exact X.sparse_run_is_erased_actual_branch
        root role caps c.dummy c.fixed root c.branch compatible _
    have actual := X.erased_branch_claims_are_actual_active_claims
      root role caps c.dummy c.fixed root c.branch compatible
    rw [X.filtered_claims_at_native_root] at actual
    unfold penalty
    rw [runEq]
    apply K.global_known_claims_failure_mass_le
    intro claim member
    change claim ∈ AC.activeClaims root role caps c.branch at member
    rw [← actual] at member
    simpa only [K.KnownAt, SmzaRp05PhysicalAcceptedReplayLite.KnownAt] using
      K.physical_branch_claim_known_at_standard
      (X.activeEncode root role caps c.dummy) G.decode erased branch initial claim member
  · have zero : conditioned c = 0 := X.current_incompatible_conditioned_branch_is_zero
      root role caps c.fixed c.branch compatible c.initial
    have sparseZero : sparse c = 0 := by
      funext basis
      simp [sparse, zero, A.restrictFiber]
    rw [sparseZero]
    unfold penalty
    rw [sparseZero]
    have zeroBound := zero_claim_failure_mass
      (Input := A.ActiveKey (live root role))
      (Output := VectorOutput G.Counter)
      (Phase := VectorOutput G.Counter)
      (Workspace := A.Memory (Key := G.Key root) (Counter := G.Counter) (Work := Work))
      (claims c)
      (((2 * (claims c).toFinset.card : Nat) : ℝ) /
        Fintype.card (VectorOutput G.Counter))
    dsimp (config := { instances := true }) only
      [live, NativePrivateSpendQ58ActiveEventProjection.SparseState, OfNat.ofNat] at zeroBound ⊢
    with_reducible
      exact zeroBound

theorem current_selected_missing_claims_mass_le
    (selector : Selector root role Work) :
    normSquared (K.claimFailureProjection (claims c) (selected c selector)) ≤ penalty c := by
  calc
    _ ≤ normSquared (K.claimFailureProjection (claims c) (sparse c)) := by
      unfold selected K.claimFailureProjection normSquared databaseEventProjection workspaceEventProjection
      apply Finset.sum_le_sum
      intro basis _
      by_cases enabled : selector basis.workspace basis.database <;>
        by_cases missing : ¬ClaimsDatabaseEvent (claims c) basis.database <;>
        simp [enabled, missing, Complex.normSq_nonneg]
    _ ≤ penalty c := unselected_failure_le c

/-- Internal transport using a derived classifier implication. -/
theorem internal_selector_claims_mass_transport
    (selector event : Selector root role Work)
    (derived : ∀ memory database, selector memory database →
      recorded c database → event memory database) :
    normSquared (selected c selector) ≤
      normSquared (workspaceEventProjection event (sparse c)) + penalty c := by
  have split := K.database_event_complement_mass_split (recorded c) (selected c selector)
  have included : normSquared (databaseEventProjection (recorded c) (selected c selector)) ≤
      normSquared (workspaceEventProjection event (sparse c)) := by
    convert K.workspace_event_mass_le_of_inclusion
      (fun memory database => selector memory database ∧ recorded c database)
      event (sparse c) (by intro memory database both; exact derived memory database both.1 both.2) using 1
    congr 1
    funext basis
    unfold selected databaseEventProjection workspaceEventProjection
    by_cases enabled : selector basis.workspace basis.database <;>
      by_cases stored : recorded c basis.database <;> simp [enabled, stored]
  have missing := current_selected_missing_claims_mass_le c selector
  change normSquared (databaseEventProjection (fun database => ¬recorded c database)
    (selected c selector)) ≤ penalty c at missing
  exact split.symm.trans_le (add_le_add included missing)
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSelectedClaimFailureMass
