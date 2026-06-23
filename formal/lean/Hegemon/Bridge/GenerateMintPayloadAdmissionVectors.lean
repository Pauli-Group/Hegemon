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

def caseJson (name : String) (input : BridgeMintPayloadInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"payload_decoded\": " ++ boolJson input.payloadDecoded ++ ",\n"
    ++ "      \"payload_hash_matches\": "
      ++ boolJson input.payloadHashMatches ++ ",\n"
    ++ "      \"receipt_message_hash_matches\": "
      ++ boolJson input.receiptMessageHashMatches ++ ",\n"
    ++ "      \"version_matches\": " ++ boolJson input.versionMatches ++ ",\n"
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
    ++ caseJson "amount-zero-precedes-amount-bound"
      { validBridgeMintPayload with
        amountNonzero := false,
        amountWithinBound := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
