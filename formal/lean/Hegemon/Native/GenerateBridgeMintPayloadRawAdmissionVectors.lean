import Hegemon.Bytes
import Hegemon.Native.BridgeMintPayloadRawAdmission

open Hegemon
open Hegemon.Bridge.MintPayloadAdmission
open Hegemon.Native.BridgeMintPayloadRawAdmission

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
  | some BridgeMintPayloadReject.recipientCommitmentZero =>
      "\"recipient_commitment_zero\""
  | some BridgeMintPayloadReject.amountZero =>
      "\"amount_zero\""
  | some BridgeMintPayloadReject.amountOutOfBounds =>
      "\"amount_out_of_bounds\""
  | some BridgeMintPayloadReject.nativeAssetNotAllowed =>
      "\"native_asset_not_allowed\""

def repeated (length value : Nat) : List Byte :=
  List.replicate length (byte value)

def hegemonChainIdBytes : List Byte :=
  [0xa3, 0x8e, 0xff, 0x6b, 0x93, 0xae, 0xae, 0xf8,
    0x8d, 0xe8, 0x8d, 0x5f, 0x59, 0x67, 0xcf, 0x62,
    0xe8, 0x9c, 0x20, 0x2a, 0x48, 0xf4, 0xf8, 0xf4,
    0xfd, 0xc5, 0xbe, 0xb4, 0x7f, 0x24, 0x84, 0xd7].map byte

def maxNativeBridgeMintAmount : Nat := 9223372036854775807

def bridgeMintPayloadBytes
    (version : Nat)
    (destinationChainId recipientCommitment : List Byte)
    (assetId amount mintNonce : Nat) : List Byte :=
  u16le version
    ++ destinationChainId
    ++ recipientCommitment
    ++ u64le assetId
    ++ u64le amount
    ++ u128le mintNonce

def validBridgeMintPayloadBytes : List Byte :=
  bridgeMintPayloadBytes
    1
    hegemonChainIdBytes
    (repeated 48 0x42)
    7
    42
    99

def malformedShortPayloadBytes : List Byte :=
  (List.range 31).map (fun _ => byte 0xaa)

def trailingPayloadBytes : List Byte :=
  validBridgeMintPayloadBytes ++ [0xff]

def versionMismatchPayloadBytes : List Byte :=
  bridgeMintPayloadBytes
    2
    hegemonChainIdBytes
    (repeated 48 0x42)
    7
    42
    99

def destinationMismatchPayloadBytes : List Byte :=
  bridgeMintPayloadBytes
    1
    (repeated 32 0x9a)
    (repeated 48 0x42)
    7
    42
    99

def zeroRecipientPayloadBytes : List Byte :=
  bridgeMintPayloadBytes
    1
    hegemonChainIdBytes
    (repeated 48 0)
    7
    42
    99

def zeroAmountPayloadBytes : List Byte :=
  bridgeMintPayloadBytes
    1
    hegemonChainIdBytes
    (repeated 48 0x42)
    7
    0
    99

def overBoundAmountPayloadBytes : List Byte :=
  bridgeMintPayloadBytes
    1
    hegemonChainIdBytes
    (repeated 48 0x42)
    7
    (maxNativeBridgeMintAmount + 1)
    99

def nativeAssetPayloadBytes : List Byte :=
  bridgeMintPayloadBytes
    1
    hegemonChainIdBytes
    (repeated 48 0x42)
    0
    42
    99

def caseJson
    (name fixture : String)
    (input : BridgeMintPayloadRawAdmissionInput)
    (rawBytes : List Byte) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes rawBytes ++ "\",\n"
    ++ "      \"parser_accepts\": "
    ++ boolJson input.parserAccepts ++ ",\n"
    ++ "      \"consumed_all_bytes\": "
    ++ boolJson input.consumedAllBytes ++ ",\n"
    ++ "      \"canonical_reencode_matches\": "
    ++ boolJson input.canonicalReencodeMatches ++ ",\n"
    ++ "      \"payload_hash_matches\": "
    ++ boolJson input.payloadHashMatches ++ ",\n"
    ++ "      \"receipt_message_hash_matches\": "
    ++ boolJson input.receiptMessageHashMatches ++ ",\n"
    ++ "      \"version_matches\": "
    ++ boolJson input.versionMatches ++ ",\n"
    ++ "      \"destination_matches\": "
    ++ boolJson input.destinationMatches ++ ",\n"
    ++ "      \"recipient_commitment_nonzero\": "
    ++ boolJson input.recipientCommitmentNonzero ++ ",\n"
    ++ "      \"amount_nonzero\": "
    ++ boolJson input.amountNonzero ++ ",\n"
    ++ "      \"amount_within_bound\": "
    ++ boolJson input.amountWithinBound ++ ",\n"
    ++ "      \"asset_non_native\": "
    ++ boolJson input.assetNonNative ++ ",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson (bridgeMintPayloadRawAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
    ++ rejectionJson (bridgeMintPayloadRawRejection input) ++ "\n"
    ++ "    }"

def decodedCase
    (name fixture : String)
    (rawBytes : List Byte)
    (overrides : BridgeMintPayloadRawAdmissionInput) : String :=
  caseJson name fixture overrides rawBytes

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_mint_payload_raw_admission_cases\": [\n"
    ++ caseJson "valid-raw-bridge-mint-payload"
      "valid_payload"
      validRawBridgeMintPayload
      validBridgeMintPayloadBytes ++ ",\n"
    ++ caseJson "short-raw-payload-rejected"
      "short_payload"
      { validRawBridgeMintPayload with
        parserAccepts := false,
        consumedAllBytes := false,
        canonicalReencodeMatches := false,
        versionMatches := false,
        destinationMatches := false,
        recipientCommitmentNonzero := false,
        amountNonzero := false,
        amountWithinBound := false,
        assetNonNative := false }
      malformedShortPayloadBytes ++ ",\n"
    ++ caseJson "trailing-raw-payload-rejected"
      "trailing_payload"
      { validRawBridgeMintPayload with
        consumedAllBytes := false,
        canonicalReencodeMatches := false,
        versionMatches := false,
        destinationMatches := false,
        recipientCommitmentNonzero := false,
        amountNonzero := false,
        amountWithinBound := false,
        assetNonNative := false }
      trailingPayloadBytes ++ ",\n"
    ++ caseJson "payload-hash-mismatch-raw-rejected"
      "payload_hash_mismatch"
      { validRawBridgeMintPayload with
        payloadHashMatches := false,
        receiptMessageHashMatches := false }
      validBridgeMintPayloadBytes ++ ",\n"
    ++ caseJson "receipt-message-hash-mismatch-raw-rejected"
      "receipt_message_hash_mismatch"
      { validRawBridgeMintPayload with
        receiptMessageHashMatches := false }
      validBridgeMintPayloadBytes ++ ",\n"
    ++ caseJson "version-mismatch-raw-rejected"
      "version_mismatch"
      { validRawBridgeMintPayload with
        versionMatches := false }
      versionMismatchPayloadBytes ++ ",\n"
    ++ caseJson "destination-mismatch-raw-rejected"
      "destination_mismatch"
      { validRawBridgeMintPayload with
        destinationMatches := false }
      destinationMismatchPayloadBytes ++ ",\n"
    ++ caseJson "zero-recipient-raw-rejected"
      "zero_recipient"
      { validRawBridgeMintPayload with
        recipientCommitmentNonzero := false }
      zeroRecipientPayloadBytes ++ ",\n"
    ++ caseJson "zero-amount-raw-rejected"
      "zero_amount"
      { validRawBridgeMintPayload with
        amountNonzero := false }
      zeroAmountPayloadBytes ++ ",\n"
    ++ caseJson "over-bound-amount-raw-rejected"
      "over_bound_amount"
      { validRawBridgeMintPayload with
        amountWithinBound := false }
      overBoundAmountPayloadBytes ++ ",\n"
    ++ caseJson "native-asset-raw-rejected"
      "native_asset"
      { validRawBridgeMintPayload with
        assetNonNative := false }
      nativeAssetPayloadBytes ++ ",\n"
    ++ caseJson "raw-decode-precedes-payload-hash"
      "short_payload_hash_mismatch"
      { validRawBridgeMintPayload with
        parserAccepts := false,
        consumedAllBytes := false,
        canonicalReencodeMatches := false,
        payloadHashMatches := false,
        receiptMessageHashMatches := false,
        versionMatches := false,
        destinationMatches := false,
        recipientCommitmentNonzero := false,
        amountNonzero := false,
        amountWithinBound := false,
        assetNonNative := false }
      malformedShortPayloadBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
