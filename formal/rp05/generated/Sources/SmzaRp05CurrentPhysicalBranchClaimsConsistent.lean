import SmzaRp05CurrentPhysicalBranchClaimReadback

/-! # Consistency of claims on a nonzero physical branch

Recorded answers are known on the fully decompressed branch. If the branch
has nonzero mass, at least one standard basis coordinate is present, and its
database must satisfy every recorded answer simultaneously.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalBranchClaimsConsistent

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05CurrentPhysicalBranchClaimReadback
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output Phase Work Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase]
  [Fintype Work] [DecidableEq Work]

/-- A nonzero physical branch has a database satisfying its complete logged
claims. This is a same-branch consistency witness, not an independently
sampled completion. -/
theorem nonzero_physical_branch_claims_consistent
    (encode : RawInput → Key)
    (decode : RawInput → Output → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (initial : State Key Output Phase Work)
    (nonzero : normSquared (physicalRun encode decode program branch initial) ≠ 0) :
    ∃ database : Database Key Output,
      ClaimsDatabaseEvent
        (branchClaims (branchKeys encode decode program branch)
          (branchAnswers encode decode program branch)) database := by
  classical
  let compressed := physicalRun encode decode program branch initial
  let claims := branchClaims (branchKeys encode decode program branch)
    (branchAnswers encode decode program branch)
  have known : ∀ claim ∈ claims,
      KnownAt claim.1 claim.2 (globalDecompress compressed) := by
    intro claim member
    simpa [claims, compressed] using
      physical_branch_claim_known_at_standard encode decode program branch initial
        claim member
  have standardNorm : normSquared (globalDecompress compressed) =
      normSquared compressed :=
    decompress_list_preserves_norm_squared
      (Finset.univ : Finset Key).toList compressed
  have standardNormNe : normSquared (globalDecompress compressed) ≠ 0 := by
    rw [standardNorm]
    exact nonzero
  have supported : ∃ basis, globalDecompress compressed basis ≠ 0 := by
    by_contra none
    have zeroState : globalDecompress compressed = fun _ => (0 : ℂ) := by
      funext basis
      by_contra nonzeroAt
      exact none ⟨basis, nonzeroAt⟩
    simp [zeroState, normSquared] at standardNormNe
  obtain ⟨basis, basisNonzero⟩ := supported
  refine ⟨basis.database, ?_⟩
  intro claim member
  have knownAt := congrFun (known claim member) basis
  change coordinateEventProjection claim.1 claim.2
      (globalDecompress compressed) basis = globalDecompress compressed basis at knownAt
  by_contra mismatch
  unfold coordinateEventProjection at knownAt
  rw [if_neg mismatch] at knownAt
  exact basisNonzero knownAt.symm

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalBranchClaimsConsistent
