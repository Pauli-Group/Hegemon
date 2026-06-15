namespace Hegemon
namespace Native
namespace StablecoinPolicyAuthorization

inductive StablecoinPolicyReject where
  | policyMissing
  | policyInactive
  | assetMismatch
  | policyHashMismatch
  | policyVersionMismatch
  | oracleCommitmentMismatch
  | attestationCommitmentMismatch
  | attestationDisputed
  | oracleStale
  | issuanceZero
  | issuanceOverLimit
deriving DecidableEq, Repr

structure StablecoinPolicyAuthorizationInput where
  stablecoinPresent : Bool
  policyKnown : Bool
  policyActive : Bool
  assetMatches : Bool
  policyHashMatches : Bool
  policyVersionMatches : Bool
  oracleCommitmentMatches : Bool
  attestationCommitmentMatches : Bool
  attestationNotDisputed : Bool
  oracleFresh : Bool
  issuanceNonzero : Bool
  issuanceWithinLimit : Bool
deriving DecidableEq, Repr

def evaluateStablecoinPolicyAuthorization
    (input : StablecoinPolicyAuthorizationInput) :
    Except StablecoinPolicyReject Unit :=
  if input.stablecoinPresent = false then
    Except.ok ()
  else if input.policyKnown = false then
    Except.error StablecoinPolicyReject.policyMissing
  else if input.policyActive = false then
    Except.error StablecoinPolicyReject.policyInactive
  else if input.assetMatches = false then
    Except.error StablecoinPolicyReject.assetMismatch
  else if input.policyHashMatches = false then
    Except.error StablecoinPolicyReject.policyHashMismatch
  else if input.policyVersionMatches = false then
    Except.error StablecoinPolicyReject.policyVersionMismatch
  else if input.oracleCommitmentMatches = false then
    Except.error StablecoinPolicyReject.oracleCommitmentMismatch
  else if input.attestationCommitmentMatches = false then
    Except.error StablecoinPolicyReject.attestationCommitmentMismatch
  else if input.attestationNotDisputed = false then
    Except.error StablecoinPolicyReject.attestationDisputed
  else if input.oracleFresh = false then
    Except.error StablecoinPolicyReject.oracleStale
  else if input.issuanceNonzero = false then
    Except.error StablecoinPolicyReject.issuanceZero
  else if input.issuanceWithinLimit = false then
    Except.error StablecoinPolicyReject.issuanceOverLimit
  else
    Except.ok ()

def stablecoinPolicyAuthorizationAccepts
    (input : StablecoinPolicyAuthorizationInput) : Bool :=
  match evaluateStablecoinPolicyAuthorization input with
  | Except.ok _ => true
  | Except.error _ => false

def stablecoinPolicyAuthorizationRejection
    (input : StablecoinPolicyAuthorizationInput) :
    Option StablecoinPolicyReject :=
  match evaluateStablecoinPolicyAuthorization input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def stablecoinPolicyAuthorizationPreconditions
    (input : StablecoinPolicyAuthorizationInput) : Bool :=
  if input.stablecoinPresent = false then
    true
  else
    input.policyKnown &&
    input.policyActive &&
    input.assetMatches &&
    input.policyHashMatches &&
    input.policyVersionMatches &&
    input.oracleCommitmentMatches &&
    input.attestationCommitmentMatches &&
    input.attestationNotDisputed &&
    input.oracleFresh &&
    input.issuanceNonzero &&
    input.issuanceWithinLimit

theorem accepts_iff_policy_preconditions
    (input : StablecoinPolicyAuthorizationInput) :
    stablecoinPolicyAuthorizationAccepts input =
      stablecoinPolicyAuthorizationPreconditions input := by
  cases input with
  | mk stablecoinPresent policyKnown policyActive assetMatches
      policyHashMatches policyVersionMatches oracleCommitmentMatches
      attestationCommitmentMatches attestationNotDisputed oracleFresh
      issuanceNonzero issuanceWithinLimit =>
      unfold stablecoinPolicyAuthorizationAccepts
      unfold stablecoinPolicyAuthorizationPreconditions
      unfold evaluateStablecoinPolicyAuthorization
      cases stablecoinPresent <;> cases policyKnown <;> cases policyActive <;>
        cases assetMatches <;> cases policyHashMatches <;>
        cases policyVersionMatches <;> cases oracleCommitmentMatches <;>
        cases attestationCommitmentMatches <;> cases attestationNotDisputed <;>
        cases oracleFresh <;> cases issuanceNonzero <;>
        cases issuanceWithinLimit <;> rfl

def authorizedPolicyInput : StablecoinPolicyAuthorizationInput :=
  {
    stablecoinPresent := true,
    policyKnown := true,
    policyActive := true,
    assetMatches := true,
    policyHashMatches := true,
    policyVersionMatches := true,
    oracleCommitmentMatches := true,
    attestationCommitmentMatches := true,
    attestationNotDisputed := true,
    oracleFresh := true,
    issuanceNonzero := true,
    issuanceWithinLimit := true
  }

theorem complete_policy_authorization_accepts :
    evaluateStablecoinPolicyAuthorization authorizedPolicyInput = Except.ok () := by
  rfl

def absentStablecoinInput : StablecoinPolicyAuthorizationInput :=
  { authorizedPolicyInput with stablecoinPresent := false }

theorem absent_stablecoin_accepts :
    evaluateStablecoinPolicyAuthorization absentStablecoinInput = Except.ok () := by
  rfl

theorem policy_missing_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (missing : input.policyKnown = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.policyMissing := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, missing]

theorem policy_inactive_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (inactive : input.policyActive = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.policyInactive := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, inactive]

theorem asset_mismatch_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (active : input.policyActive = true)
    (mismatch : input.assetMatches = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.assetMismatch := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, active, mismatch]

theorem policy_hash_mismatch_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (active : input.policyActive = true)
    (asset : input.assetMatches = true)
    (mismatch : input.policyHashMatches = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.policyHashMismatch := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, active, asset, mismatch]

theorem policy_version_mismatch_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (active : input.policyActive = true)
    (asset : input.assetMatches = true)
    (hash : input.policyHashMatches = true)
    (mismatch : input.policyVersionMatches = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.policyVersionMismatch := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, active, asset, hash, mismatch]

theorem oracle_commitment_mismatch_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (active : input.policyActive = true)
    (asset : input.assetMatches = true)
    (hash : input.policyHashMatches = true)
    (version : input.policyVersionMatches = true)
    (mismatch : input.oracleCommitmentMatches = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.oracleCommitmentMismatch := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, active, asset, hash, version, mismatch]

theorem attestation_commitment_mismatch_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (active : input.policyActive = true)
    (asset : input.assetMatches = true)
    (hash : input.policyHashMatches = true)
    (version : input.policyVersionMatches = true)
    (oracle : input.oracleCommitmentMatches = true)
    (mismatch : input.attestationCommitmentMatches = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.attestationCommitmentMismatch := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, active, asset, hash, version, oracle, mismatch]

theorem attestation_disputed_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (active : input.policyActive = true)
    (asset : input.assetMatches = true)
    (hash : input.policyHashMatches = true)
    (version : input.policyVersionMatches = true)
    (oracle : input.oracleCommitmentMatches = true)
    (attestation : input.attestationCommitmentMatches = true)
    (disputed : input.attestationNotDisputed = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.attestationDisputed := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, active, asset, hash, version, oracle, attestation, disputed]

theorem oracle_stale_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (active : input.policyActive = true)
    (asset : input.assetMatches = true)
    (hash : input.policyHashMatches = true)
    (version : input.policyVersionMatches = true)
    (oracle : input.oracleCommitmentMatches = true)
    (attestation : input.attestationCommitmentMatches = true)
    (notDisputed : input.attestationNotDisputed = true)
    (stale : input.oracleFresh = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.oracleStale := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, active, asset, hash, version, oracle, attestation, notDisputed, stale]

theorem issuance_zero_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (active : input.policyActive = true)
    (asset : input.assetMatches = true)
    (hash : input.policyHashMatches = true)
    (version : input.policyVersionMatches = true)
    (oracle : input.oracleCommitmentMatches = true)
    (attestation : input.attestationCommitmentMatches = true)
    (notDisputed : input.attestationNotDisputed = true)
    (fresh : input.oracleFresh = true)
    (zero : input.issuanceNonzero = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.issuanceZero := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, active, asset, hash, version, oracle, attestation,
    notDisputed, fresh, zero]

theorem issuance_over_limit_rejects
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (known : input.policyKnown = true)
    (active : input.policyActive = true)
    (asset : input.assetMatches = true)
    (hash : input.policyHashMatches = true)
    (version : input.policyVersionMatches = true)
    (oracle : input.oracleCommitmentMatches = true)
    (attestation : input.attestationCommitmentMatches = true)
    (notDisputed : input.attestationNotDisputed = true)
    (fresh : input.oracleFresh = true)
    (nonzero : input.issuanceNonzero = true)
    (over : input.issuanceWithinLimit = false) :
    evaluateStablecoinPolicyAuthorization input =
      Except.error StablecoinPolicyReject.issuanceOverLimit := by
  unfold evaluateStablecoinPolicyAuthorization
  simp [present, known, active, asset, hash, version, oracle, attestation,
    notDisputed, fresh, nonzero, over]

theorem accepted_present_implies_live_policy_facts
    {input : StablecoinPolicyAuthorizationInput}
    (present : input.stablecoinPresent = true)
    (accepted : stablecoinPolicyAuthorizationAccepts input = true) :
    input.policyKnown = true ∧
    input.policyActive = true ∧
    input.assetMatches = true ∧
    input.policyHashMatches = true ∧
    input.policyVersionMatches = true ∧
    input.oracleCommitmentMatches = true ∧
    input.attestationCommitmentMatches = true ∧
    input.attestationNotDisputed = true ∧
    input.oracleFresh = true ∧
    input.issuanceNonzero = true ∧
    input.issuanceWithinLimit = true := by
  cases input with
  | mk stablecoinPresent policyKnown policyActive assetMatches
      policyHashMatches policyVersionMatches oracleCommitmentMatches
      attestationCommitmentMatches attestationNotDisputed oracleFresh
      issuanceNonzero issuanceWithinLimit =>
      cases stablecoinPresent <;> cases policyKnown <;> cases policyActive <;>
        cases assetMatches <;> cases policyHashMatches <;>
        cases policyVersionMatches <;> cases oracleCommitmentMatches <;>
        cases attestationCommitmentMatches <;> cases attestationNotDisputed <;>
        cases oracleFresh <;> cases issuanceNonzero <;>
        cases issuanceWithinLimit <;>
        simp [stablecoinPolicyAuthorizationAccepts,
          evaluateStablecoinPolicyAuthorization] at present accepted ⊢

end StablecoinPolicyAuthorization
end Native
end Hegemon
