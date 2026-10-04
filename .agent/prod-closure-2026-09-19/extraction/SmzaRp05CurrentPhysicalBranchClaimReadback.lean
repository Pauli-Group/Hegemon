import SmzaRp05PhysicalAcceptedReplayLite
import HegemonCrypto.CmsOracleDatabaseBridge

/-!
# Recorded-claim readback on an actual physical Program branch

This adapter exposes the facts needed to apply a static CMS claim bridge at
one terminal branch: every concrete branch claim is known in that branch's
standard (fully decompressed) view, and the complete claims projector is the
identity there. Repeated query keys are permitted.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalBranchClaimReadback

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

variable {Key Output Phase Work Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase]
  [Fintype Work] [DecidableEq Work]

/-- Membership in the actual executed branch's transcript makes the
corresponding answer a known coordinate of its final standard view. -/
theorem physical_branch_claim_known_at_standard
    (encode : RawInput → Key)
    (decode : RawInput → Output → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (initial : State Key Output Phase Work)
    (claim : Key × Output)
    (member : claim ∈ branchClaims
      (branchKeys encode decode program branch)
      (branchAnswers encode decode program branch)) :
    KnownAt claim.1 claim.2
      (globalDecompress
        (physicalRun encode decode program branch initial)) := by
  rw [global_decompress_physical_run_eq_retainedTrace]
  exact branch_claim_known_at_repeated
    (branchKeys encode decode program branch)
    (branchAnswers encode decode program branch)
    (globalDecompress initial) claim member

omit [Fintype Key] [DecidableEq Key] [Fintype Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase] [Fintype Work] [DecidableEq Work] in
/-- If all claims have known coordinates on a state, the complete recorded
claims projector fixes that state exactly. This pointwise statement permits
arbitrary repeated keys, since conflicting claims force a zero coordinate. -/
theorem claims_projector_eq_of_known
    (claims : List (Key × Output))
    (state : State Key Output Phase Work)
    (known : ∀ claim ∈ claims, KnownAt claim.1 claim.2 state) :
    databaseEventProjection (ClaimsDatabaseEvent claims) state = state := by
  funext basis
  by_cases accepted : ClaimsDatabaseEvent claims basis.database
  · simp [databaseEventProjection, accepted]
  · have rejected : ∃ claim, claim ∈ claims ∧
        basis.database claim.1 ≠ some claim.2 := by
      by_contra noRejected
      exact accepted (by
        intro claim member
        by_contra mismatch
        exact noRejected ⟨claim, member, mismatch⟩)
    obtain ⟨claim, member, mismatch⟩ := rejected
    have coordinate := congrFun (known claim member) basis
    unfold KnownAt coordinateEventProjection at coordinate
    simp [mismatch] at coordinate
    simp [databaseEventProjection, accepted, coordinate]

/-- In particular the claims event has exactly the whole standard-view
mass on a physical answer branch. This is the readback side of the weighted
static bridge, not a claim about the verifier's accepted-event classifier. -/
theorem physical_branch_claim_event_mass_eq_norm
    (encode : RawInput → Key)
    (decode : RawInput → Output → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (initial : State Key Output Phase Work) :
    normSquared
        (databaseEventProjection
          (ClaimsDatabaseEvent
            (branchClaims (branchKeys encode decode program branch)
              (branchAnswers encode decode program branch)))
          (globalDecompress
            (physicalRun encode decode program branch initial))) =
      normSquared
        (globalDecompress
          (physicalRun encode decode program branch initial)) := by
  let claims := branchClaims (branchKeys encode decode program branch)
    (branchAnswers encode decode program branch)
  let standard := globalDecompress
    (physicalRun encode decode program branch initial)
  have knownClaims : ∀ claim ∈ claims, KnownAt claim.1 claim.2 standard := by
    intro claim member
    simpa [claims, standard] using
      physical_branch_claim_known_at_standard
        encode decode program branch initial claim member
  have projector := claims_projector_eq_of_known claims standard knownClaims
  change normSquared (databaseEventProjection (ClaimsDatabaseEvent claims) standard) =
    normSquared standard
  rw [projector]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalBranchClaimReadback
