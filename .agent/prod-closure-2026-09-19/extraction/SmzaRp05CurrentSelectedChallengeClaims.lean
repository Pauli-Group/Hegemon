import SmzaRp05CurrentMixedBranchClaimReadback
import SmzaRp05CurrentMixedClaimsReadback
import SmzaRp05CurrentNonchallengeSelectorTransport
import SmzaRp05CurrentProjectedKnownClaims
import SmzaRp05CurrentKnownClaimsFailureMass
import SmzaRp05AdaptiveRetainedAdviceTransport

/-! # Actual mixed-branch challenge claims survive the nonchallenge selector

The selected challenge reads are retained by the literal mixed execution.
Because their active keys lie outside the selector's X-view, the selector
cannot alter those answers.  The known-claims mass theorem can therefore be
applied to the selected projection of that same terminal mixed state.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedChallengeClaims

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05CurrentMixedBranchClaimReadback
open SmzaRp05CurrentMixedClaimsReadback
open SmzaRp05CurrentProjectedKnownClaims
open SmzaRp05CurrentKnownClaimsFailureMass
open SmzaRp05CurrentNonchallengeSelectorTransport
open SmzaRp05AdaptiveRetainedAdviceTransport (mixedRun)
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRoleDomainConditioning
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

abbrev SelectedWork := SmzaRp05CurrentAdaptiveExecution.Work
  (Counter := Counter) (BaseWork := BaseWork)

/-- All raw key coordinates outside every recognized challenge-query frame. -/
def nonchallengeRawKeySet
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    Finset Key :=
  Finset.univ.filter (fun key => parseStageQuery (ctx.keyBytes key) = none)

theorem nonchallenge_raw_key_set_unrecognized
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (key : Key) (member : key ∈ nonchallengeRawKeySet ctx) :
    parseStageQuery (ctx.keyBytes key) = none :=
  (Finset.mem_filter.mp member).2

theorem recognized_raw_key_not_in_nonchallenge_set
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (key : Key) (recognized : parseStageQuery (ctx.keyBytes key) ≠ none) :
    key ∉ nonchallengeRawKeySet ctx := by
  intro member
  exact recognized (nonchallenge_raw_key_set_unrecognized ctx key member)

/-- Keep every actual active mixed-branch read whose bytes parse as a
recognized challenge-stage query. Do not drop recognized out-of-profile
reads: `RoleActive` deliberately leaves those in the active database too. -/
def recognizedActiveChallengeClaims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program) :
    List (ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter) :=
  (mixedBranchClaims ctx blockCap encode decode program branch).filter
    (fun claim => parseStageQuery (ctx.keyBytes claim.1.val) ≠ none)

/-- The complementary nonchallenge slice of the same mixed transcript. -/
def unrecognizedActiveBranchClaims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program) :
    List (ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter) :=
  (mixedBranchClaims ctx blockCap encode decode program branch).filter
    (fun claim => parseStageQuery (ctx.keyBytes claim.1.val) = none)

/-- Selector condition that combines the caller's X/workspace classifier
with exact nonchallenge answers from this mixed branch. -/
def branchXRoleSelector
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (xKeys : Finset Key)
    (covers : ∀ claim ∈ unrecognizedActiveBranchClaims ctx blockCap encode
      decode program branch, claim.1.val ∈ xKeys)
    (select : (XKey xKeys → Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (view : XKey xKeys → Option (VectorOutput Counter))
    (work : SelectedWork (Counter := Counter) (BaseWork := BaseWork)) : Prop :=
  select view work ∧
    ∀ claim, ∀ member : claim ∈
      unrecognizedActiveBranchClaims ctx blockCap encode decode program branch,
      view ⟨claim.1.val, covers claim member⟩ = some claim.2

/-- On a literal terminal mixed branch, the X-restricted selector preserves
the standard-decompressed answers to its selected challenge reads.  The only
set-theoretic side condition is the concrete disjointness of those challenge
keys from the X-view; no branch transcript or probability premise is added. -/
theorem actual_selected_challenge_claims_known_after_x_projection
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (initial : ActiveState ctx blockCap)
    (xKeys : Finset Key)
    (unrecognized : ∀ key ∈ xKeys,
      parseStageQuery (ctx.keyBytes key) = none)
    (covers : ∀ claim ∈ unrecognizedActiveBranchClaims ctx blockCap encode
      decode program branch, claim.1.val ∈ xKeys)
    (select : (XKey xKeys → Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (claim : ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter)
    (member : claim ∈ recognizedActiveChallengeClaims ctx blockCap encode
      decode program branch) :
    KnownAt claim.1 claim.2
      (globalDecompress
        (workspaceEventProjection
          (fun work database =>
            branchXRoleSelector ctx blockCap encode decode program branch
              xKeys covers select
              (activeXView ctx blockCap xKeys unrecognized database)
              work.original.2.2)
          (mixedRun ctx blockCap fixed encode decode program branch initial))) := by
  have claimMember : claim ∈
      mixedBranchClaims ctx blockCap encode decode program branch :=
    (List.mem_filter.mp member).1
  have claimChallenge : parseStageQuery (ctx.keyBytes claim.1.val) ≠ none :=
    of_decide_eq_true (List.mem_filter.mp member).2
  have claimOutside : claim.1.val ∉ xKeys := by
    intro inX
    exact claimChallenge (unrecognized claim.1.val inX)
  let event : ActiveMemory ctx →
      Database (ActiveKey ctx.role blockCap ctx.keyBytes)
        (VectorOutput Counter) → Prop :=
    fun memory database =>
      branchXRoleSelector ctx blockCap encode decode program branch xKeys
        covers select (activeXView ctx blockCap xKeys unrecognized database)
        memory.original.2.2
  have invariant : ∀ workspace database replacement,
      event workspace
          (setDatabaseCoordinate database claim.1 replacement) ↔
        event workspace database := by
    intro workspace database replacement
    have viewSame :
        activeXView ctx blockCap xKeys unrecognized
            (setDatabaseCoordinate database claim.1 replacement) =
          activeXView ctx blockCap xKeys unrecognized database := by
      funext x
      have different : xActiveKey ctx blockCap xKeys unrecognized x ≠ claim.1 := by
        intro same
        apply claimOutside
        have keyEq : x.val = claim.1.val := by
          simpa [xActiveKey] using congrArg Subtype.val same
        rw [← keyEq]
        exact x.property
      unfold activeXView
      rw [set_database_coordinate_other database different replacement]
    change branchXRoleSelector ctx blockCap encode decode program branch xKeys
        covers select
        (activeXView ctx blockCap xKeys unrecognized
          (setDatabaseCoordinate database claim.1 replacement))
        workspace.original.2.2 ↔
      branchXRoleSelector ctx blockCap encode decode program branch xKeys
        covers select (activeXView ctx blockCap xKeys unrecognized database)
        workspace.original.2.2
    rw [viewSame]
  have knownOriginal := mixed_branch_claim_known_at_standard
    ctx blockCap fixed encode decode program branch initial claim claimMember
  exact known_at_global_decompress_workspace_event_projection event
    claim.1 claim.2
    (mixedRun ctx blockCap fixed encode decode program branch initial)
    invariant knownOriginal

/-- The actual challenge-claim event retains all but the finite-readout loss
inside the exact X-selected mixed state. -/
theorem actual_selected_challenge_claim_event_mass_lower
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (initial : ActiveState ctx blockCap)
    (xKeys : Finset Key)
    (unrecognized : ∀ key ∈ xKeys,
      parseStageQuery (ctx.keyBytes key) = none)
    (covers : ∀ claim ∈ unrecognizedActiveBranchClaims ctx blockCap encode
      decode program branch, claim.1.val ∈ xKeys)
    (select : (XKey xKeys → Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    let claims := recognizedActiveChallengeClaims ctx blockCap encode decode
      program branch
    let selectedState := workspaceEventProjection
      (fun work database =>
        branchXRoleSelector ctx blockCap encode decode program branch xKeys
          covers select
        (activeXView ctx blockCap xKeys unrecognized database)
        work.original.2.2)
      (mixedRun ctx blockCap fixed encode decode program branch initial)
    normSquared (databaseEventProjection (ClaimsDatabaseEvent claims)
      selectedState) +
      ((2 * claims.toFinset.card : Nat) : ℝ) /
        Fintype.card (VectorOutput Counter) * normSquared selectedState ≥
      normSquared selectedState := by
  let claims := recognizedActiveChallengeClaims ctx blockCap encode decode
    program branch
  let selectedState := workspaceEventProjection
    (fun work database =>
      branchXRoleSelector ctx blockCap encode decode program branch xKeys
        covers select (activeXView ctx blockCap xKeys unrecognized database)
        work.original.2.2)
    (mixedRun ctx blockCap fixed encode decode program branch initial)
  have known : ∀ claim ∈ claims,
      KnownAt claim.1 claim.2 (globalDecompress selectedState) := by
    intro claim member
    simpa [claims, selectedState] using
      actual_selected_challenge_claims_known_after_x_projection
        ctx blockCap fixed encode decode program branch initial xKeys
        unrecognized covers select claim member
  simpa [claims, selectedState] using
    global_known_claims_event_mass_lower claims selectedState known

/-- The X-view's nonchallenge branch claims, the recognized active challenge
claims, and the same mixed branch's nonzero fixed-fiber support reconstruct
the complete verifier answer-log claim event. -/
theorem actual_x_and_challenge_claims_supply_full_branch_claims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (initial : ActiveState ctx blockCap)
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput Counter) (VectorOutput Counter) (ActiveMemory ctx))
    (xKeys : Finset Key)
    (unrecognized : ∀ key ∈ xKeys,
      parseStageQuery (ctx.keyBytes key) = none)
    (covers : ∀ claim ∈ unrecognizedActiveBranchClaims ctx blockCap encode
      decode program branch, claim.1.val ∈ xKeys)
    (select : (XKey xKeys → Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (selected : branchXRoleSelector ctx blockCap encode decode program branch
      xKeys covers select
      (activeXView ctx blockCap xKeys unrecognized basis.database)
      basis.workspace.original.2.2)
    (selectedStateNonzero :
      workspaceEventProjection
        (fun memory database =>
          branchXRoleSelector ctx blockCap encode decode program branch xKeys
            covers select
            (activeXView ctx blockCap xKeys unrecognized database)
            memory.original.2.2)
        (mixedRun ctx blockCap fixed encode decode program branch initial) basis ≠ 0)
    (challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap encode decode program branch)
      basis.database) :
    ClaimsDatabaseEvent
      (branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch))
      (mergeFixedActive ctx blockCap fixed basis.database) := by
  have mixedNonzero :
      mixedRun ctx blockCap fixed encode decode program branch initial basis ≠ 0 := by
    have selectedStateEq :
        workspaceEventProjection
          (fun memory database =>
            branchXRoleSelector ctx blockCap encode decode program branch xKeys
              covers select
              (activeXView ctx blockCap xKeys unrecognized database)
              memory.original.2.2)
          (mixedRun ctx blockCap fixed encode decode program branch initial) basis =
        mixedRun ctx blockCap fixed encode decode program branch initial basis := by
      change (if branchXRoleSelector ctx blockCap encode decode program branch
          xKeys covers select
          (activeXView ctx blockCap xKeys unrecognized basis.database)
          basis.workspace.original.2.2 then
          mixedRun ctx blockCap fixed encode decode program branch initial basis
        else 0) =
        mixedRun ctx blockCap fixed encode decode program branch initial basis
      exact if_pos selected
    rw [selectedStateEq] at selectedStateNonzero
    exact selectedStateNonzero
  have activeClaims : ClaimsDatabaseEvent
      (mixedBranchClaims ctx blockCap encode decode program branch)
      basis.database := by
    intro claim member
    by_cases nonchallenge :
        parseStageQuery (ctx.keyBytes claim.1.val) = none
    · have nonchallengeMember :
        claim ∈ unrecognizedActiveBranchClaims ctx blockCap encode decode
          program branch :=
            List.mem_filter.mpr ⟨member, decide_eq_true nonchallenge⟩
      have xValue := selected.2 claim nonchallengeMember
      have sameKey :
          xActiveKey ctx blockCap xKeys unrecognized
              ⟨claim.1.val, covers claim nonchallengeMember⟩ = claim.1 := by
        apply Subtype.ext
        rfl
      change basis.database
        (xActiveKey ctx blockCap xKeys unrecognized
          ⟨claim.1.val, covers claim nonchallengeMember⟩) = some claim.2 at xValue
      rw [sameKey] at xValue
      exact xValue
    · have challengeMember :
        claim ∈ recognizedActiveChallengeClaims ctx blockCap encode decode
          program branch := by
        have recognized : parseStageQuery (ctx.keyBytes claim.1.val) ≠ none := by
          intro parsedNone
          exact nonchallenge parsedNone
        exact List.mem_filter.mpr ⟨member, decide_eq_true recognized⟩
      exact challengeClaims claim challengeMember
  exact nonzero_mixed_branch_active_claims_supply_full_claims
    ctx blockCap fixed encode decode program branch initial basis mixedNonzero
    basis.database activeClaims

/-- Concrete specialization using the complete nonchallenge raw-key set.
Coverage and parser-none facts are derived from the literal key set, rather
than supplied by the caller. -/
theorem actual_selected_challenge_claim_event_mass_lower_on_all_x_keys
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (initial : ActiveState ctx blockCap)
    (select : (XKey (nonchallengeRawKeySet ctx) →
        Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    let xKeys := nonchallengeRawKeySet ctx
    let covers : ∀ claim ∈ unrecognizedActiveBranchClaims ctx blockCap encode
      decode program branch, claim.1.val ∈ xKeys := by
        intro claim member
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
          of_decide_eq_true (List.mem_filter.mp member).2⟩
    let claims := recognizedActiveChallengeClaims ctx blockCap encode decode
      program branch
    let selectedState := workspaceEventProjection
      (fun work database =>
        branchXRoleSelector ctx blockCap encode decode program branch xKeys
          covers select
          (activeXView ctx blockCap xKeys
            (nonchallenge_raw_key_set_unrecognized ctx) database)
          work.original.2.2)
      (mixedRun ctx blockCap fixed encode decode program branch initial)
    normSquared (databaseEventProjection (ClaimsDatabaseEvent claims)
      selectedState) +
      ((2 * claims.toFinset.card : Nat) : ℝ) /
        Fintype.card (VectorOutput Counter) * normSquared selectedState ≥
      normSquared selectedState := by
  let xKeys := nonchallengeRawKeySet ctx
  have unrecognized : ∀ key ∈ xKeys,
      parseStageQuery (ctx.keyBytes key) = none :=
    nonchallenge_raw_key_set_unrecognized ctx
  have covers : ∀ claim ∈ unrecognizedActiveBranchClaims ctx blockCap encode
      decode program branch, claim.1.val ∈ xKeys := by
    intro claim member
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
      of_decide_eq_true (List.mem_filter.mp member).2⟩
  simpa [xKeys, unrecognized, covers] using
    actual_selected_challenge_claim_event_mass_lower ctx blockCap fixed encode
      decode program branch initial xKeys unrecognized covers select

/-- The selected X-view, recognized challenge answers, and nonzero support
of the same fixed-table branch reconstruct its entire verifier answer log,
with X taken to be every raw parser-none coordinate. -/
theorem actual_all_x_and_challenge_claims_supply_full_branch_claims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (initial : ActiveState ctx blockCap)
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput Counter) (VectorOutput Counter) (ActiveMemory ctx))
    (select : (XKey (nonchallengeRawKeySet ctx) →
        Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (selected : branchXRoleSelector ctx blockCap encode decode program branch
      (nonchallengeRawKeySet ctx)
      (by
        intro claim member
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
          of_decide_eq_true (List.mem_filter.mp member).2⟩)
      select
      (activeXView ctx blockCap (nonchallengeRawKeySet ctx)
        (nonchallenge_raw_key_set_unrecognized ctx) basis.database)
      basis.workspace.original.2.2)
    (selectedStateNonzero :
      workspaceEventProjection
        (fun memory database =>
          branchXRoleSelector ctx blockCap encode decode program branch
            (nonchallengeRawKeySet ctx)
            (by
              intro claim member
              exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
                of_decide_eq_true (List.mem_filter.mp member).2⟩)
            select
            (activeXView ctx blockCap (nonchallengeRawKeySet ctx)
              (nonchallenge_raw_key_set_unrecognized ctx) database)
            memory.original.2.2)
        (mixedRun ctx blockCap fixed encode decode program branch initial) basis ≠ 0)
    (challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap encode decode program branch)
      basis.database) :
    ClaimsDatabaseEvent
      (branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch))
      (mergeFixedActive ctx blockCap fixed basis.database) := by
  apply actual_x_and_challenge_claims_supply_full_branch_claims
    ctx blockCap fixed encode decode program branch initial basis
    (nonchallengeRawKeySet ctx)
    (nonchallenge_raw_key_set_unrecognized ctx)
    (by
      intro claim member
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        of_decide_eq_true (List.mem_filter.mp member).2⟩)
    select selected selectedStateNonzero challengeClaims

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedChallengeClaims
