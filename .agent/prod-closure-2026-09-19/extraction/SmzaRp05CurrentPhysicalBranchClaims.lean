import SmzaRp05CurrentKnownClaimsAmplitude
import SmzaRp05CurrentPhysicalBranchClaimReadback
import SmzaRp05CurrentClaimDedup
import SmzaRp05AdaptivePhysicalReadBound

/-!
# Weighted CMS claim bound on an actual physical Program branch

The answer log fixes its claims in every standard basis component of the
terminal physical branch. The known-claims amplitude theorem therefore bounds
the whole unnormalised branch norm by its compressed claims mass plus the
finite CMS loss. Repeated keys are handled by exact-pair deduplication. The
only event-specific premise is a deterministic inclusion of the claims event
in the desired role event; no oracle-family simulation, normalization, or
query-independence assumption is introduced here.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalBranchClaims

open scoped BigOperators Classical
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentClaimDedup
open SmzaRp05CurrentKnownClaimsAmplitude
open SmzaRp05CurrentPhysicalBranchClaimReadback
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

variable {Input Output Phase Work Result : Type}
  [Fintype Input] [DecidableEq Input]
  [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase]
  [Fintype Work] [DecidableEq Work]

omit [DecidableEq Output] [AddCommGroup Output] [DecidableEq Phase]
  [DecidableEq Work] in
/-- Inclusion of pointwise workspace-selected events implies the associated
unnormalised event-mass inequality. -/
theorem workspace_event_mass_le_of_inclusion
    (left right : Work → Database Input Output → Prop)
    (state : State Input Output Phase Work)
    (included : ∀ work database, left work database → right work database) :
    normSquared (workspaceEventProjection left state) ≤
      normSquared (workspaceEventProjection right state) := by
  unfold normSquared workspaceEventProjection
  apply Finset.sum_le_sum
  intro basis _
  by_cases leftAt : left basis.workspace basis.database
  · have rightAt := included basis.workspace basis.database leftAt
    simp [leftAt, rightAt]
  · by_cases rightAt : right basis.workspace basis.database
    · simp [leftAt, rightAt, Complex.normSq_nonneg]
    · simp [leftAt, rightAt]

/-- Branch norm versus the current workspace role event. Every claim is the
actual answer at a raw physical read on this branch. When the claims event is
deterministically contained in the requested role event on the compressed
branch, the resulting loss is `2*C^2/|Output|` times this branch's own norm. -/
theorem physical_branch_norm_le_role_mass
    (encode : RawInput → Input)
    (decode : RawInput → Output → RawDigest)
    (program : Program Result)
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches decode program)
    (initial : State Input Output Phase Work)
    (roleEvent : Work → Database Input Output → Prop)
    (maxClaims : Nat)
    (claimBound : (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
      (SmzaRp05PhysicalAcceptedReplayLite.branchKeys encode decode program branch)
      (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers encode decode program branch)).length
        ≤ maxClaims)
    (claimsIncluded : ∀ work database,
      ClaimsDatabaseEvent
        (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
          (SmzaRp05PhysicalAcceptedReplayLite.branchKeys encode decode program branch)
          (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers encode decode program branch))
        database → roleEvent work database) :
    normSquared (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
      encode decode program branch initial) ≤
      2 * normSquared (workspaceEventProjection roleEvent
        (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          encode decode program branch initial)) +
      (2 * (maxClaims : ℝ)^2 / Fintype.card Output) *
        normSquared (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          encode decode program branch initial) := by
  classical
  let compressed := SmzaRp05PhysicalAcceptedReplayLite.physicalRun
    encode decode program branch initial
  let claims := SmzaRp05PhysicalAcceptedReplayLite.branchClaims
    (SmzaRp05PhysicalAcceptedReplayLite.branchKeys encode decode program branch)
    (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers encode decode program branch)
  have knownOriginal : ∀ claim ∈ claims,
      SmzaRp05PhysicalAcceptedReplayLite.KnownAt claim.1 claim.2
        (globalDecompress compressed) := by
    intro claim member
    simpa [claims, compressed] using
      physical_branch_claim_known_at_standard
        encode decode program branch initial claim member
  let uniqueClaims := claims.toFinset.toList
  have uniqueLength : uniqueClaims.length ≤ maxClaims :=
    (claims_dedup_length_le claims).trans (by simpa [claims] using claimBound)
  have eventEq : ClaimsDatabaseEvent uniqueClaims = ClaimsDatabaseEvent claims := by
    funext database
    exact propext (claims_event_dedup_iff claims database).symm
  have compressedNormNonnegative : 0 ≤ normSquared compressed := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  have roleMassNonnegative : 0 ≤
      normSquared (workspaceEventProjection roleEvent compressed) := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  have claimsMassLeRole :
      normSquared (databaseEventProjection (ClaimsDatabaseEvent claims) compressed) ≤
        normSquared (workspaceEventProjection roleEvent compressed) := by
    have claimsWorkspaceEq :
        workspaceEventProjection (fun _ database => ClaimsDatabaseEvent claims database)
          compressed = databaseEventProjection (ClaimsDatabaseEvent claims) compressed := by
      funext basis
      simp [workspaceEventProjection, databaseEventProjection]
    rw [← claimsWorkspaceEq]
    exact workspace_event_mass_le_of_inclusion
      (fun _ database => ClaimsDatabaseEvent claims database) roleEvent compressed
      (by intro work database records; exact claimsIncluded work database records)
  by_cases zero : normSquared compressed = 0
  · have badMassLe : normSquared compressed ≤
        2 * normSquared (workspaceEventProjection roleEvent compressed) +
          (2 * (maxClaims : ℝ)^2 / Fintype.card Output) * normSquared compressed := by
      rw [zero]
      simp only [mul_zero, add_zero]
      exact mul_nonneg (by norm_num) roleMassNonnegative
    simpa [compressed] using badMassLe
  · have standardNorm : normSquared (globalDecompress compressed) =
        normSquared compressed :=
      decompress_list_preserves_norm_squared
        (Finset.univ : Finset Input).toList compressed
    have standardNormNe : normSquared (globalDecompress compressed) ≠ 0 := by
      rw [standardNorm]
      exact zero
    have supported : ∃ basis, globalDecompress compressed basis ≠ 0 := by
      by_contra noBasis
      have standardZero : globalDecompress compressed = fun _ => (0 : ℂ) := by
        funext basis
        by_contra nonzero
        exact noBasis ⟨basis, nonzero⟩
      simp [standardZero, normSquared] at standardNormNe
    obtain ⟨basis, basisNonzero⟩ := supported
    have consistent : ∃ database : Database Input Output,
        ClaimsDatabaseEvent claims database := by
      refine ⟨basis.database, ?_⟩
      intro claim member
      have knownAt := congrFun (knownOriginal claim member) basis
      change coordinateEventProjection claim.1 claim.2
          (globalDecompress compressed) basis = globalDecompress compressed basis at knownAt
      by_contra missing
      unfold coordinateEventProjection at knownAt
      rw [if_neg missing] at knownAt
      exact basisNonzero knownAt.symm
    have uniqueInputs : (uniqueClaims.map Prod.fst).Nodup :=
      consistent_claims_dedup claims consistent
    have uniqueKnown : ∀ claim ∈ uniqueClaims,
        SmzaRp05PhysicalAcceptedReplayLite.KnownAt claim.1 claim.2
          (globalDecompress compressed) := by
      intro claim member
      apply knownOriginal claim
      exact List.mem_toFinset.mp (Finset.mem_toList.mp member)
    have amplitude := known_claims_weighted_amplitude_le
      compressed uniqueClaims uniqueInputs uniqueKnown
    have lengthBound : (uniqueClaims.length : ℝ) ≤ maxClaims := by
      exact_mod_cast uniqueLength
    have cardPositive : 0 < (Fintype.card Output : ℝ) := by
      exact_mod_cast Fintype.card_pos
    have perUnitNonnegative : 0 ≤ 1 / (Fintype.card Output : ℝ) :=
      div_nonneg (by norm_num) (le_of_lt cardPositive)
    have rootNonnegative : 0 ≤ Real.sqrt
        ((1 / (Fintype.card Output : ℝ)) * normSquared compressed) := by
      positivity
    have compressedClaimsNonnegative : 0 ≤
        normSquared (databaseEventProjection (ClaimsDatabaseEvent claims) compressed) := by
      unfold normSquared
      exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
    have amplitudeBound :
        Real.sqrt (normSquared compressed) ≤
          Real.sqrt (normSquared
            (databaseEventProjection (ClaimsDatabaseEvent claims) compressed)) +
            (maxClaims : ℝ) * Real.sqrt
              ((1 / (Fintype.card Output : ℝ)) * normSquared compressed) := by
      have amplitude' := amplitude
      rw [eventEq] at amplitude'
      calc
        Real.sqrt (normSquared compressed) ≤
          Real.sqrt (normSquared
            (databaseEventProjection (ClaimsDatabaseEvent claims) compressed)) +
            (uniqueClaims.length : ℝ) * Real.sqrt
              ((1 / (Fintype.card Output : ℝ)) * normSquared compressed) := by
          simpa using amplitude'
        _ ≤ _ := add_le_add le_rfl
          (mul_le_mul_of_nonneg_right lengthBound rootNonnegative)
    have split :
        (Real.sqrt (normSquared
          (databaseEventProjection (ClaimsDatabaseEvent claims) compressed)) +
          (maxClaims : ℝ) * Real.sqrt
            ((1 / (Fintype.card Output : ℝ)) * normSquared compressed))^2 ≤
          2 * normSquared
              (databaseEventProjection (ClaimsDatabaseEvent claims) compressed) +
          2 * (maxClaims : ℝ)^2 *
              ((1 / (Fintype.card Output : ℝ)) * normSquared compressed) := by
      have claimRoot := Real.sq_sqrt compressedClaimsNonnegative
      have penaltyRoot : (Real.sqrt
          ((1 / (Fintype.card Output : ℝ)) * normSquared compressed))^2 =
          (1 / (Fintype.card Output : ℝ)) * normSquared compressed := by
        apply Real.sq_sqrt
        exact mul_nonneg perUnitNonnegative compressedNormNonnegative
      nlinarith [sq_nonneg
        (Real.sqrt (normSquared
          (databaseEventProjection (ClaimsDatabaseEvent claims) compressed)) -
          (maxClaims : ℝ) * Real.sqrt
            ((1 / (Fintype.card Output : ℝ)) * normSquared compressed))]
    have sumNonnegative : 0 ≤
        Real.sqrt (normSquared (databaseEventProjection
          (ClaimsDatabaseEvent claims) compressed)) +
          (maxClaims : ℝ) * Real.sqrt
            ((1 / (Fintype.card Output : ℝ)) * normSquared compressed) := by
      positivity
    have branchRoot : (Real.sqrt (normSquared compressed))^2 =
        normSquared compressed := Real.sq_sqrt compressedNormNonnegative
    have squareOrder :
        (Real.sqrt (normSquared compressed))^2 ≤
          (Real.sqrt (normSquared (databaseEventProjection
            (ClaimsDatabaseEvent claims) compressed)) +
            (maxClaims : ℝ) * Real.sqrt
              ((1 / (Fintype.card Output : ℝ)) * normSquared compressed))^2 := by
      nlinarith [mul_nonneg (sub_nonneg.mpr amplitudeBound)
        (add_nonneg sumNonnegative (Real.sqrt_nonneg (normSquared compressed)))]
    have squared : normSquared compressed ≤
        2 * normSquared (databaseEventProjection
            (ClaimsDatabaseEvent claims) compressed) +
          2 * (maxClaims : ℝ)^2 *
            ((1 / (Fintype.card Output : ℝ)) * normSquared compressed) := by
      rw [branchRoot] at squareOrder
      exact squareOrder.trans split
    calc
      normSquared compressed ≤
          2 * normSquared (databaseEventProjection
            (ClaimsDatabaseEvent claims) compressed) +
          2 * (maxClaims : ℝ)^2 *
            ((1 / (Fintype.card Output : ℝ)) * normSquared compressed) := squared
      _ ≤ 2 * normSquared (workspaceEventProjection roleEvent compressed) +
          2 * (maxClaims : ℝ)^2 *
            ((1 / (Fintype.card Output : ℝ)) * normSquared compressed) := by
        exact add_le_add
          (mul_le_mul_of_nonneg_left claimsMassLeRole (by norm_num : (0 : ℝ) ≤ 2))
          le_rfl
      _ = 2 * normSquared (workspaceEventProjection roleEvent compressed) +
          (2 * (maxClaims : ℝ)^2 / Fintype.card Output) *
            normSquared compressed := by
        have cardCast : (Fintype.card Output : ℝ) ≠ 0 := ne_of_gt cardPositive
        rw [div_eq_mul_inv]
        field_simp [cardCast]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalBranchClaims
