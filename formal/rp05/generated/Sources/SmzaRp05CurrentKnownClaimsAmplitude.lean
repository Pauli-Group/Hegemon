import SmzaRp05PhysicalAcceptedReplayLite

/-! Actual recorded answers fix the standard-basis claim event. The CMS
comparison therefore bounds the entire branch norm, without an independent
oracle-family simulation premise or a normalization/postselection step. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentKnownClaimsAmplitude

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05PhysicalAcceptedReplayLite (KnownAt)

noncomputable section
set_option autoImplicit false

variable {Key Output Phase Work : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase]
  [Fintype Work] [DecidableEq Work]

theorem known_claims_weighted_amplitude_le
    (state : State Key Output Phase Work)
    (claims : List (Key × Output))
    (distinct : (claims.map Prod.fst).Nodup)
    (known : ∀ claim ∈ claims,
      KnownAt claim.1 claim.2 (globalDecompress state)) :
    Real.sqrt (normSquared state) ≤
      Real.sqrt (normSquared
        (databaseEventProjection (ClaimsDatabaseEvent claims) state)) +
      claims.length * Real.sqrt
        ((1 / (Fintype.card Output : ℝ)) * normSquared state) := by
  classical
  let standard := globalDecompress state
  have supported (basis : Basis Key Output Phase Work)
      (nonzero : standard basis ≠ 0) :
      ClaimsDatabaseEvent claims basis.database := by
    intro claim member
    have eqAt := congrFun (known claim member) basis
    change coordinateEventProjection claim.1 claim.2 standard basis = standard basis at eqAt
    by_contra missing
    unfold coordinateEventProjection at eqAt
    rw [if_neg missing] at eqAt
    exact nonzero eqAt.symm
  have standardSelected :
      databaseEventProjection (ClaimsDatabaseEvent claims) standard = standard := by
    funext basis
    by_cases zero : standard basis = 0
    · simp [databaseEventProjection, zero]
    · simp only [databaseEventProjection, if_pos (supported basis zero)]
  have total : ∀ claim ∈ claims, TotalAt claim.1 standard := by
    intro claim member basis absent
    have eqAt := congrFun (known claim member) basis
    change coordinateEventProjection claim.1 claim.2 standard basis = standard basis at eqAt
    have missing : ¬ basis.database claim.1 = some claim.2 := by simp [absent]
    unfold coordinateEventProjection at eqAt
    rw [if_neg missing] at eqAt
    exact eqAt.symm
  have normEq : normSquared standard = normSquared state :=
    decompress_list_preserves_norm_squared (Finset.univ : Finset Key).toList state
  have bridge := event_probability_decompression_amplitude_le
    (ClaimsDatabaseEvent claims) claims standard distinct
    (fun claim member database records => records claim member) total
  have selectedCompressed :
      normSquared (databaseEventProjection (ClaimsDatabaseEvent claims)
        (decompressList (claims.map Prod.fst) standard)) =
      normSquared (databaseEventProjection (ClaimsDatabaseEvent claims) state) := by
    rw [← claims_event_projection_norm_global_decompress_eq_selected
      claims standard distinct]
    simp only [standard, global_decompress_involutive]
  rw [standardSelected, selectedCompressed, normEq] at bridge
  exact bridge

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentKnownClaimsAmplitude
