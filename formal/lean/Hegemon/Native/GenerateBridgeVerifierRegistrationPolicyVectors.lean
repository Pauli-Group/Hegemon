import Hegemon.Native.BridgeVerifierRegistrationPolicy

open Hegemon.Native.BridgeVerifierRegistrationPolicy

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson :
    Option BridgeVerifierRegistrationPolicyReject -> String
  | none => "null"
  | some BridgeVerifierRegistrationPolicyReject.notBridgeVerifierRegistration =>
      "\"not_bridge_verifier_registration\""
  | some BridgeVerifierRegistrationPolicyReject.stateDeltasPresent =>
      "\"state_deltas_present\""
  | some BridgeVerifierRegistrationPolicyReject.registrationDecodeFailed =>
      "\"registration_decode_failed\""

def effectJson
    (effect : Option BridgeVerifierRegistrationPolicyEffect) : String :=
  match effect with
  | none => "null"
  | some effect =>
      "{"
        ++ "\"registration_observed\": "
        ++ boolJson effect.registrationObserved
        ++ ", \"production_mint_verifier_enabled\": "
        ++ boolJson effect.productionMintVerifierEnabled
        ++ "}"

def caseJson
    (name : String)
    (input : BridgeVerifierRegistrationPolicyInput) : String :=
  let effect := bridgeVerifierRegistrationPolicyEffect input
  let rejection := bridgeVerifierRegistrationPolicyRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"bridge_verifier_registration\": "
      ++ boolJson input.bridgeVerifierRegistration ++ ",\n"
    ++ "      \"state_deltas_absent\": "
      ++ boolJson input.stateDeltasAbsent ++ ",\n"
    ++ "      \"registration_decoded\": "
      ++ boolJson input.registrationDecoded ++ ",\n"
    ++ "      \"descriptor_matches_release\": "
      ++ boolJson input.descriptorMatchesRelease ++ ",\n"
    ++ "      \"activation_height_reached\": "
      ++ boolJson input.activationHeightReached ++ ",\n"
    ++ "      \"pq_clean_verifier_bound\": "
      ++ boolJson input.pqCleanVerifierBound ++ ",\n"
    ++ "      \"external_verifier_soundness_accepted\": "
      ++ boolJson input.externalVerifierSoundnessAccepted ++ ",\n"
    ++ "      \"positive_minting_enabled\": "
      ++ boolJson input.positiveMintingEnabled ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson rejection ++ ",\n"
    ++ "      \"expected_effect\": " ++ effectJson effect ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_verifier_registration_policy_cases\": [\n"
    ++ caseJson "current-release-registration-is-inert"
      inertReleaseRegistration ++ ",\n"
    ++ caseJson "future-production-registration-enables-mint-verifier"
      futureProductionRegistration ++ ",\n"
    ++ caseJson "descriptor-mismatch-is-inert"
      { futureProductionRegistration with
        descriptorMatchesRelease := false } ++ ",\n"
    ++ caseJson "future-activation-height-is-inert"
      { futureProductionRegistration with
        activationHeightReached := false } ++ ",\n"
    ++ caseJson "pq-clean-verifier-missing-is-inert"
      { futureProductionRegistration with
        pqCleanVerifierBound := false } ++ ",\n"
    ++ caseJson "external-soundness-missing-is-inert"
      { futureProductionRegistration with
        externalVerifierSoundnessAccepted := false } ++ ",\n"
    ++ caseJson "positive-mint-flag-disabled-is-inert"
      { futureProductionRegistration with
        positiveMintingEnabled := false } ++ ",\n"
    ++ caseJson "not-registration-rejected"
      { inertReleaseRegistration with
        bridgeVerifierRegistration := false } ++ ",\n"
    ++ caseJson "state-delta-registration-rejected"
      { inertReleaseRegistration with
        stateDeltasAbsent := false } ++ ",\n"
    ++ caseJson "registration-decode-failure-rejected"
      { inertReleaseRegistration with
        registrationDecoded := false }
    ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
