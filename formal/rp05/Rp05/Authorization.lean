import SmzaRp05AllActiveHistoricalCredentialEndpoint

namespace HegemonCrypto.SmallWood.Rp05

/-- Backward-compatible pairwise nullifier/authorization-consistency endpoint.
This is not the single-spend owner/credential endpoint below. -/
abbrev authorization_nullifier_consistency :=
  @HegemonCrypto.SmallWood.SmzaRp05CurrentJointAuthorizationMassEndpoint.actual_current_joint_authorization_failure_mass_below_129

example : @authorization_nullifier_consistency =
    @HegemonCrypto.SmallWood.SmzaRp05CurrentJointAuthorizationMassEndpoint.actual_current_joint_authorization_failure_mass_below_129 :=
  rfl

/-- Pointwise current credential/history result: five-word nullifier key,
seven-word owner bound back to the actual historical note, and unspent
position, or the retained concrete path/authorization failure. -/
abbrev single_spend_credential_binding :=
  @HegemonCrypto.SmallWood.SmzaRp05SingleSpendAuthorizationEndpoint.current_positive_spend_authorized_or_actual_history_failure

/-- Same-original-outcome initialized history mass bound. This is the inherited
measure theorem composed with pointwise positive-spend authorization failure. -/
abbrev single_spend_authorization_mass_bound :=
  @HegemonCrypto.SmallWood.SmzaRp05SingleSpendAuthorizationEndpoint.actual_current_initialized_single_spend_authorization_failure_mass_bound

/-- Actual successful-history predicate: every designated positive-native
input in the executor's exact complete trace has a five-word credential,
seven-word owner binding, historical opening match, and unspent position. -/
abbrev single_spend_authorization_success :=
  @HegemonCrypto.SmallWood.SmzaRp05SingleSpendAuthorizationEndpoint.actualCurrentSelectedHistoryPositiveSpendAuthorizationSuccess

/-- On the same original outcome, failure of the positive-native success
predicate is contained in accepted extraction failure or the actual first
charged history failure. -/
abbrev single_spend_authorization_failure_in_union :=
  @HegemonCrypto.SmallWood.SmzaRp05SingleSpendAuthorizationEndpoint.accepted_current_history_positive_spend_authorization_failure_in_union

/-- User-facing authorization failure endpoint with the literal original
Born-measure bound. -/
abbrev single_spend_authorization := @single_spend_authorization_mass_bound

/-- Every active current input has the five/seven-word credential and is
classified against its admitted history prefix as occupied, exact known-empty,
or a concrete path collision. This adds neither freshness nor spentness. -/
abbrev active_input_historical_credential_classification :=
  @HegemonCrypto.SmallWood.SmzaRp05AllActiveHistoricalCredentialEndpoint.current_run_active_input_historical_credential_classification

example : @active_input_historical_credential_classification =
    @HegemonCrypto.SmallWood.SmzaRp05AllActiveHistoricalCredentialEndpoint.current_run_active_input_historical_credential_classification :=
  rfl

/-- Public `authorization` names the quantitative outcome-wise single-spend
failure mass. The pointwise inclusion, all-active credential classification,
and earlier pairwise nullifier-consistency endpoints remain separate. -/
abbrev authorization := @single_spend_authorization

example : @authorization = @single_spend_authorization := rfl

end HegemonCrypto.SmallWood.Rp05
