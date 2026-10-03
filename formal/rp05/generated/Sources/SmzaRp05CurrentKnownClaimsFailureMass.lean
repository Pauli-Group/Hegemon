import SmzaRp05PartialReadout

set_option linter.unusedSectionVars false

/-! A concrete global-decompression instantiation of the multi-claim partial
readout bound. This is intentionally specific to claims already known on the
standard-basis image of the compressed state; it is not a replacement for
the general adaptive `C^2/M` amplitude bound. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentKnownClaimsFailureMass

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05PartialReadout

noncomputable section
set_option autoImplicit false

variable {Input Output Phase Workspace : Type}
  [Fintype Input] [DecidableEq Input]
  [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase]
  [Fintype Workspace] [DecidableEq Workspace]

/-- The actual complement failure mass after full finite-domain decompression
is bounded by the partial-readout loss, when every claimed coordinate is
known on that standard-basis state. -/
theorem global_known_claims_failure_mass_le
    (claims : List (Input × Output))
    (state : State Input Output Phase Workspace)
    (known : ∀ claim ∈ claims,
      KnownAt claim.1 claim.2 (globalDecompress state)) :
    normSquared (claimFailureProjection claims state) ≤
      ((2 * claims.toFinset.card : Nat) : ℝ) /
        Fintype.card Output * normSquared state := by
  classical
  let standardState := globalDecompress state
  have factorization : ∀ claim ∈ claims,
      ∃ otherInputs : List Input,
        claim.1 ∉ otherInputs ∧
          state = decompressList otherInputs
            (decompressAt claim.1 standardState) := by
    intro claim member
    obtain ⟨otherInputs, outside, selectedFactor⟩ :=
      nodup_decompress_list_selected_factorization claim.1
        (Finset.univ : Finset Input).toList standardState
        (by simp) (Finset.nodup_toList _)
    have recompressed :
        decompressList (Finset.univ : Finset Input).toList standardState = state := by
      change globalDecompress standardState = state
      dsimp [standardState]
      exact global_decompress_involutive state
    exact ⟨otherInputs, outside, recompressed.symm.trans selectedFactor⟩
  have rawBound := known_claims_partial_decompress_failure_le
    claims standardState state known factorization
  have normEq : normSquared standardState = normSquared state := by
    dsimp [standardState, globalDecompress]
    exact decompress_list_preserves_norm_squared
      (Finset.univ : Finset Input).toList state
  rw [normEq] at rawBound
  exact rawBound

/-- Exact squared-mass split between the claimed database event and its
complement. -/
theorem database_event_complement_mass_split
    (event : Database Input Output → Prop)
    (state : State Input Output Phase Workspace) :
    normSquared (databaseEventProjection event state) +
      normSquared (databaseEventProjection (fun database => ¬event database) state) =
        normSquared state := by
  unfold normSquared databaseEventProjection
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_congr rfl
  intro basis _
  by_cases accepted : event basis.database <;> simp [accepted]

/-- Combining the actual complement estimate with the exact event split gives
a lower bound on claimed-event mass. -/
theorem global_known_claims_event_mass_lower
    (claims : List (Input × Output))
    (state : State Input Output Phase Workspace)
    (known : ∀ claim ∈ claims,
      KnownAt claim.1 claim.2 (globalDecompress state)) :
    normSquared (databaseEventProjection (ClaimsDatabaseEvent claims) state) +
        ((2 * claims.toFinset.card : Nat) : ℝ) /
          Fintype.card Output * normSquared state ≥ normSquared state := by
  have split := database_event_complement_mass_split
    (ClaimsDatabaseEvent claims) state
  have failureBound := global_known_claims_failure_mass_le claims state known
  unfold claimFailureProjection at failureBound
  linarith

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentKnownClaimsFailureMass
