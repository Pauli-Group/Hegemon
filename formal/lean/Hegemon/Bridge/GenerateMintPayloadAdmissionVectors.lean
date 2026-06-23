import Hegemon.Bridge.MintPayloadAdmission

open Hegemon.Bridge.MintPayloadAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option BridgeMintPayloadReject -> String
  | none => "null"
  | some BridgeMintPayloadReject.payloadDecodeFailed =>
      "\"payload_decode_failed\""
  | some BridgeMintPayloadReject.payloadHashMismatch =>
      "\"payload_hash_mismatch\""
  | some BridgeMintPayloadReject.receiptMessageHashMismatch =>
      "\"receipt_message_hash_mismatch\""
  | some BridgeMintPayloadReject.versionMismatch =>
      "\"version_mismatch\""
  | some BridgeMintPayloadReject.sourceAppFamilyMismatch =>
      "\"source_app_family_mismatch\""
  | some BridgeMintPayloadReject.destinationMismatch =>
      "\"destination_mismatch\""
  | some BridgeMintPayloadReject.mintNonceMismatch =>
      "\"mint_nonce_mismatch\""
  | some BridgeMintPayloadReject.recipientCommitmentZero =>
      "\"recipient_commitment_zero\""
  | some BridgeMintPayloadReject.amountZero =>
      "\"amount_zero\""
  | some BridgeMintPayloadReject.amountOutOfBounds =>
      "\"amount_out_of_bounds\""
  | some BridgeMintPayloadReject.nativeAssetNotAllowed =>
      "\"native_asset_not_allowed\""

def cashVmRejectionJson : Option CashVmMintBindingReject -> String
  | none => "null"
  | some CashVmMintBindingReject.versionMismatch =>
      "\"version_mismatch\""
  | some CashVmMintBindingReject.sourceAppFamilyMismatch =>
      "\"source_app_family_mismatch\""
  | some CashVmMintBindingReject.destinationMismatch =>
      "\"destination_mismatch\""
  | some CashVmMintBindingReject.mintNonceMismatch =>
      "\"mint_nonce_mismatch\""
  | some CashVmMintBindingReject.recipientCommitmentZero =>
      "\"recipient_commitment_zero\""
  | some CashVmMintBindingReject.amountZero =>
      "\"amount_zero\""
  | some CashVmMintBindingReject.amountOutOfBounds =>
      "\"amount_out_of_bounds\""
  | some CashVmMintBindingReject.nativeAssetNotAllowed =>
      "\"native_asset_not_allowed\""
  | some CashVmMintBindingReject.destinationPolicyMismatch =>
      "\"destination_policy_mismatch\""
  | some CashVmMintBindingReject.assetBindingMismatch =>
      "\"asset_binding_mismatch\""
  | some CashVmMintBindingReject.recipientBindingMismatch =>
      "\"recipient_binding_mismatch\""

def cashVmProofRejectionJson : Option CashVmProofAdmissionReject -> String
  | none => "null"
  | some CashVmProofAdmissionReject.emptyProof =>
      "\"empty_proof\""
  | some CashVmProofAdmissionReject.statementMismatch =>
      "\"proof_statement_mismatch\""
  | some CashVmProofAdmissionReject.verifierScriptMismatch =>
      "\"verifier_script_mismatch\""
  | some CashVmProofAdmissionReject.insufficientPqSoundness =>
      "\"insufficient_pq_soundness\""
  | some CashVmProofAdmissionReject.verifierUnavailable =>
      "\"proof_verification_unavailable\""
  | some CashVmProofAdmissionReject.verifierRejected =>
      "\"proof_verification_failed\""

def cashVmReplayRejectionJson : Option CashVmReplayUpdateReject -> String
  | none => "null"
  | some CashVmReplayUpdateReject.replayWitnessDepthMismatch =>
      "\"replay_witness_depth_mismatch\""
  | some CashVmReplayUpdateReject.previousReplayRootMismatch =>
      "\"previous_replay_root_mismatch\""
  | some CashVmReplayUpdateReject.replayAlreadySpent =>
      "\"replay_already_spent\""
  | some CashVmReplayUpdateReject.nextReplayRootMismatch =>
      "\"next_replay_root_mismatch\""

def caseJson (name : String) (input : BridgeMintPayloadInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"payload_decoded\": " ++ boolJson input.payloadDecoded ++ ",\n"
    ++ "      \"payload_hash_matches\": "
      ++ boolJson input.payloadHashMatches ++ ",\n"
    ++ "      \"receipt_message_hash_matches\": "
      ++ boolJson input.receiptMessageHashMatches ++ ",\n"
    ++ "      \"version_matches\": " ++ boolJson input.versionMatches ++ ",\n"
    ++ "      \"source_app_family_matches\": "
      ++ boolJson input.sourceAppFamilyMatches ++ ",\n"
    ++ "      \"destination_matches\": "
      ++ boolJson input.destinationMatches ++ ",\n"
    ++ "      \"mint_nonce_matches\": "
      ++ boolJson input.mintNonceMatches ++ ",\n"
    ++ "      \"recipient_commitment_nonzero\": "
      ++ boolJson input.recipientCommitmentNonzero ++ ",\n"
    ++ "      \"amount_nonzero\": " ++ boolJson input.amountNonzero ++ ",\n"
    ++ "      \"amount_within_bound\": "
      ++ boolJson input.amountWithinBound ++ ",\n"
    ++ "      \"asset_non_native\": " ++ boolJson input.assetNonNative ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (bridgeMintPayloadAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
    ++ rejectionJson (bridgeMintPayloadRejection input) ++ "\n"
    ++ "    }"

def cashVmCaseJson (name : String) (input : CashVmMintBindingInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"version_matches\": " ++ boolJson input.versionMatches ++ ",\n"
    ++ "      \"source_app_family_matches\": "
      ++ boolJson input.sourceAppFamilyMatches ++ ",\n"
    ++ "      \"destination_matches\": "
      ++ boolJson input.destinationMatches ++ ",\n"
    ++ "      \"mint_nonce_matches\": "
      ++ boolJson input.mintNonceMatches ++ ",\n"
    ++ "      \"recipient_commitment_nonzero\": "
      ++ boolJson input.recipientCommitmentNonzero ++ ",\n"
    ++ "      \"amount_nonzero\": " ++ boolJson input.amountNonzero ++ ",\n"
    ++ "      \"amount_within_bound\": "
      ++ boolJson input.amountWithinBound ++ ",\n"
    ++ "      \"asset_non_native\": " ++ boolJson input.assetNonNative ++ ",\n"
    ++ "      \"destination_matches_bridge_policy\": "
      ++ boolJson input.destinationMatchesBridgePolicy ++ ",\n"
    ++ "      \"bridge_instance_matches_token_category\": "
      ++ boolJson input.bridgeInstanceMatchesTokenCategory ++ ",\n"
    ++ "      \"token_category_matches_payload_asset\": "
      ++ boolJson input.tokenCategoryMatchesPayloadAsset ++ ",\n"
    ++ "      \"recipient_hash_matches_payload_recipient\": "
      ++ boolJson input.recipientHashMatchesPayloadRecipient ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (cashVmMintBindingAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ cashVmRejectionJson (cashVmMintBindingRejection input) ++ "\n"
      ++ "    }"

def cashVmProofCaseJson (name : String) (input : CashVmProofAdmissionInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"proof_nonempty\": "
      ++ boolJson input.proofNonempty ++ ",\n"
    ++ "      \"statement_digest_matches\": "
      ++ boolJson input.statementDigestMatches ++ ",\n"
    ++ "      \"verifier_script_matches\": "
      ++ boolJson input.verifierScriptMatches ++ ",\n"
    ++ "      \"pq_soundness_at_least_policy\": "
      ++ boolJson input.pqSoundnessAtLeastPolicy ++ ",\n"
    ++ "      \"verifier_available\": "
      ++ boolJson input.verifierAvailable ++ ",\n"
    ++ "      \"verifier_accepts\": "
      ++ boolJson input.verifierAccepts ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (cashVmProofAdmissionAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ cashVmProofRejectionJson (cashVmProofAdmissionRejection input) ++ "\n"
    ++ "    }"

def cashVmReplayCaseJson (name : String) (input : CashVmReplayUpdateInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"witness_depth_valid\": "
      ++ boolJson input.witnessDepthValid ++ ",\n"
    ++ "      \"previous_root_matches\": "
      ++ boolJson input.previousRootMatches ++ ",\n"
    ++ "      \"replay_leaf_absent\": "
      ++ boolJson input.replayLeafAbsent ++ ",\n"
    ++ "      \"next_root_matches\": "
      ++ boolJson input.nextRootMatches ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (cashVmReplayUpdateAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ cashVmReplayRejectionJson (cashVmReplayUpdateRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_mint_payload_admission_cases\": [\n"
    ++ caseJson "valid-bridge-mint-payload"
      validBridgeMintPayload ++ ",\n"
    ++ caseJson "payload-decode-failed-rejected"
      { validBridgeMintPayload with payloadDecoded := false } ++ ",\n"
    ++ caseJson "payload-hash-mismatch-rejected"
      { validBridgeMintPayload with payloadHashMatches := false } ++ ",\n"
    ++ caseJson "receipt-message-hash-mismatch-rejected"
      { validBridgeMintPayload with receiptMessageHashMatches := false } ++ ",\n"
    ++ caseJson "version-mismatch-rejected"
      { validBridgeMintPayload with versionMatches := false } ++ ",\n"
    ++ caseJson "source-app-family-mismatch-rejected"
      { validBridgeMintPayload with sourceAppFamilyMatches := false } ++ ",\n"
    ++ caseJson "destination-mismatch-rejected"
      { validBridgeMintPayload with destinationMatches := false } ++ ",\n"
    ++ caseJson "mint-nonce-mismatch-rejected"
      { validBridgeMintPayload with mintNonceMatches := false } ++ ",\n"
    ++ caseJson "recipient-commitment-zero-rejected"
      { validBridgeMintPayload with recipientCommitmentNonzero := false } ++ ",\n"
    ++ caseJson "amount-zero-rejected"
      { validBridgeMintPayload with amountNonzero := false } ++ ",\n"
    ++ caseJson "amount-out-of-bounds-rejected"
      { validBridgeMintPayload with amountWithinBound := false } ++ ",\n"
    ++ caseJson "native-asset-rejected"
      { validBridgeMintPayload with assetNonNative := false } ++ ",\n"
    ++ caseJson "decode-precedes-payload-hash"
      { validBridgeMintPayload with
        payloadDecoded := false,
        payloadHashMatches := false } ++ ",\n"
    ++ caseJson "payload-hash-precedes-receipt-hash"
      { validBridgeMintPayload with
        payloadHashMatches := false,
        receiptMessageHashMatches := false } ++ ",\n"
    ++ caseJson "version-precedes-source-app-family"
      { validBridgeMintPayload with
        versionMatches := false,
        sourceAppFamilyMatches := false } ++ ",\n"
    ++ caseJson "amount-zero-precedes-amount-bound"
      { validBridgeMintPayload with
        amountNonzero := false,
        amountWithinBound := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"cashvm_mint_binding_cases\": [\n"
    ++ cashVmCaseJson "valid-cashvm-mint-binding"
      validCashVmMintBinding ++ ",\n"
    ++ cashVmCaseJson "cashvm-version-mismatch-rejected"
      { validCashVmMintBinding with versionMatches := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-source-app-family-mismatch-rejected"
      { validCashVmMintBinding with sourceAppFamilyMatches := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-destination-mismatch-rejected"
      { validCashVmMintBinding with destinationMatches := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-mint-nonce-mismatch-rejected"
      { validCashVmMintBinding with mintNonceMatches := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-recipient-zero-rejected"
      { validCashVmMintBinding with recipientCommitmentNonzero := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-amount-zero-rejected"
      { validCashVmMintBinding with amountNonzero := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-amount-out-of-bounds-rejected"
      { validCashVmMintBinding with amountWithinBound := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-native-asset-rejected"
      { validCashVmMintBinding with assetNonNative := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-destination-policy-mismatch-rejected"
      { validCashVmMintBinding with
        destinationMatchesBridgePolicy := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-bridge-instance-binding-mismatch-rejected"
      { validCashVmMintBinding with
        bridgeInstanceMatchesTokenCategory := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-asset-binding-mismatch-rejected"
      { validCashVmMintBinding with
        tokenCategoryMatchesPayloadAsset := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-recipient-binding-mismatch-rejected"
      { validCashVmMintBinding with
        recipientHashMatchesPayloadRecipient := false } ++ ",\n"
    ++ cashVmCaseJson "cashvm-destination-precedes-binding"
      { validCashVmMintBinding with
          destinationMatches := false,
          sourceAppFamilyMatches := true,
          amountNonzero := false,
          destinationMatchesBridgePolicy := false,
          bridgeInstanceMatchesTokenCategory := false,
          tokenCategoryMatchesPayloadAsset := false,
          recipientHashMatchesPayloadRecipient := false } ++ "\n"
      ++ "  ],\n"
      ++ "  \"cashvm_proof_admission_cases\": [\n"
      ++ cashVmProofCaseJson "valid-cashvm-proof-admission"
        validCashVmProofAdmission ++ ",\n"
      ++ cashVmProofCaseJson "cashvm-empty-proof-rejected"
        { validCashVmProofAdmission with proofNonempty := false } ++ ",\n"
      ++ cashVmProofCaseJson "cashvm-proof-statement-mismatch-rejected"
        { validCashVmProofAdmission with statementDigestMatches := false } ++ ",\n"
      ++ cashVmProofCaseJson "cashvm-verifier-script-mismatch-rejected"
        { validCashVmProofAdmission with verifierScriptMatches := false } ++ ",\n"
      ++ cashVmProofCaseJson "cashvm-insufficient-pq-soundness-rejected"
        { validCashVmProofAdmission with pqSoundnessAtLeastPolicy := false } ++ ",\n"
      ++ cashVmProofCaseJson "cashvm-proof-verifier-unavailable-rejected"
        { validCashVmProofAdmission with verifierAvailable := false } ++ ",\n"
      ++ cashVmProofCaseJson "cashvm-proof-verifier-rejection-rejected"
        { validCashVmProofAdmission with verifierAccepts := false } ++ ",\n"
      ++ cashVmProofCaseJson "cashvm-empty-proof-precedes-statement"
        { validCashVmProofAdmission with
          proofNonempty := false,
          statementDigestMatches := false } ++ ",\n"
      ++ cashVmProofCaseJson "cashvm-unavailable-precedes-rejection"
        { validCashVmProofAdmission with
          verifierAvailable := false,
          verifierAccepts := false } ++ "\n"
      ++ "  ],\n"
      ++ "  \"cashvm_replay_update_cases\": [\n"
      ++ cashVmReplayCaseJson "valid-cashvm-replay-update"
        validCashVmReplayUpdate ++ ",\n"
      ++ cashVmReplayCaseJson "cashvm-replay-witness-depth-mismatch-rejected"
        { validCashVmReplayUpdate with
          witnessDepthValid := false } ++ ",\n"
      ++ cashVmReplayCaseJson "cashvm-replay-previous-root-mismatch-rejected"
        { validCashVmReplayUpdate with
          previousRootMatches := false } ++ ",\n"
      ++ cashVmReplayCaseJson "cashvm-replay-duplicate-leaf-rejected"
        { validCashVmReplayUpdate with
          replayLeafAbsent := false } ++ ",\n"
      ++ cashVmReplayCaseJson "cashvm-replay-next-root-mismatch-rejected"
        { validCashVmReplayUpdate with
          nextRootMatches := false } ++ ",\n"
      ++ cashVmReplayCaseJson "cashvm-replay-witness-depth-precedes-previous-root"
        { validCashVmReplayUpdate with
          witnessDepthValid := false,
          previousRootMatches := false } ++ ",\n"
      ++ cashVmReplayCaseJson "cashvm-replay-previous-root-precedes-duplicate"
        { validCashVmReplayUpdate with
          previousRootMatches := false,
          replayLeafAbsent := false } ++ "\n"
      ++ "  ]\n"
      ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
