import Hegemon.Native.TransferActionPayloadAdmission
import Hegemon.Resource.BoundedRequestAdmission

open Hegemon.Native.TransferActionPayloadAdmission
open Hegemon.Resource.BoundedRequestAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option TransferPayloadReject -> String
  | none => "null"
  | some TransferPayloadReject.proofMissing => "\"proof_missing\""
  | some TransferPayloadReject.proofTooLarge => "\"proof_too_large\""
  | some TransferPayloadReject.anchorMismatch => "\"anchor_mismatch\""
  | some TransferPayloadReject.commitmentsMismatch => "\"commitments_mismatch\""
  | some TransferPayloadReject.inlineCiphertextTooLarge =>
      "\"inline_ciphertext_too_large\""
  | some TransferPayloadReject.ciphertextHashesMismatch =>
      "\"ciphertext_hashes_mismatch\""
  | some TransferPayloadReject.ciphertextSizesMismatch =>
      "\"ciphertext_sizes_mismatch\""
  | some TransferPayloadReject.bindingHashMismatch => "\"binding_hash_mismatch\""
  | some TransferPayloadReject.proofBindingHashMismatch =>
      "\"proof_binding_hash_mismatch\""
  | some TransferPayloadReject.feeMismatch => "\"fee_mismatch\""

def resourceRejectionJson : Option ResourceReject -> String
  | none => "null"
  | some ResourceReject.rawBytesExceeded => "\"raw_bytes_exceeded\""
  | some ResourceReject.decodedBytesExceeded => "\"decoded_bytes_exceeded\""
  | some ResourceReject.itemCountExceeded => "\"item_count_exceeded\""
  | some ResourceReject.itemBytesExceeded => "\"item_bytes_exceeded\""
  | some ResourceReject.aggregateBytesExceeded =>
      "\"aggregate_bytes_exceeded\""
  | some ResourceReject.workUnitsExceeded => "\"work_units_exceeded\""

def transferPayloadCaseJson (name : String) (input : TransferPayloadInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"proof_bytes\": " ++ toString input.proofBytes ++ ",\n"
    ++ "      \"max_proof_bytes\": " ++ toString input.maxProofBytes ++ ",\n"
    ++ "      \"anchor_matches\": " ++ boolJson input.anchorMatches ++ ",\n"
    ++ "      \"commitments_match\": " ++ boolJson input.commitmentsMatch ++ ",\n"
    ++ "      \"inline_ciphertext_bytes\": " ++ toString input.inlineCiphertextBytes ++ ",\n"
    ++ "      \"max_ciphertext_bytes\": " ++ toString input.maxCiphertextBytes ++ ",\n"
    ++ "      \"ciphertext_hashes_match\": "
      ++ boolJson input.ciphertextHashesMatch ++ ",\n"
    ++ "      \"ciphertext_sizes_match\": "
      ++ boolJson input.ciphertextSizesMatch ++ ",\n"
    ++ "      \"binding_hash_matches\": " ++ boolJson input.bindingHashMatches ++ ",\n"
    ++ "      \"proof_binding_hash_matches_key\": "
      ++ boolJson input.proofBindingHashMatchesKey ++ ",\n"
    ++ "      \"fee_matches\": " ++ boolJson input.feeMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (transferPayloadAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (transferPayloadRejection input) ++ "\n"
    ++ "    }"

def inlineCiphertextResourceCaseJson
    (name : String)
    (policy : ResourcePolicy)
    (input : InlineTransferCiphertextResourceInput) : String :=
  let request := inlineTransferCiphertextResourceRequest input
  let rejection := evaluateBoundedRequest policy request
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"route_payload_bytes\": " ++ toString input.routePayloadBytes ++ ",\n"
    ++ "      \"proof_bytes\": " ++ toString input.proofBytes ++ ",\n"
    ++ "      \"ciphertext_count\": " ++ toString input.ciphertextCount ++ ",\n"
    ++ "      \"max_ciphertext_bytes_observed\": "
      ++ toString input.maxCiphertextBytesObserved ++ ",\n"
    ++ "      \"aggregate_ciphertext_bytes\": "
      ++ toString input.aggregateCiphertextBytes ++ ",\n"
    ++ "      \"raw_byte_cap\": " ++ toString policy.rawByteCap ++ ",\n"
    ++ "      \"decoded_byte_cap\": " ++ toString policy.decodedByteCap ++ ",\n"
    ++ "      \"item_count_cap\": " ++ toString policy.itemCountCap ++ ",\n"
    ++ "      \"item_byte_cap\": " ++ toString policy.itemByteCap ++ ",\n"
    ++ "      \"aggregate_byte_cap\": " ++ toString policy.aggregateByteCap ++ ",\n"
    ++ "      \"work_unit_cap\": " ++ toString policy.workUnitCap ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ resourceRejectionJson rejection ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 2,\n"
    ++ "  \"transfer_action_payload_admission_cases\": [\n"
    ++ transferPayloadCaseJson "valid-transfer-payload"
      validTransferPayload ++ ",\n"
    ++ transferPayloadCaseJson "exact-proof-limit-accepts"
      { validTransferPayload with proofBytes := validTransferPayload.maxProofBytes } ++ ",\n"
    ++ transferPayloadCaseJson "proof-missing-rejected"
      { validTransferPayload with proofBytes := 0 } ++ ",\n"
    ++ transferPayloadCaseJson "proof-too-large-rejected"
      { validTransferPayload with
        proofBytes := validTransferPayload.maxProofBytes + 1 } ++ ",\n"
    ++ transferPayloadCaseJson "anchor-mismatch-rejected"
      { validTransferPayload with anchorMatches := false } ++ ",\n"
    ++ transferPayloadCaseJson "commitments-mismatch-rejected"
      { validTransferPayload with commitmentsMatch := false } ++ ",\n"
    ++ transferPayloadCaseJson "inline-ciphertext-too-large-rejected"
      { validTransferPayload with
        inlineCiphertextBytes := validTransferPayload.maxCiphertextBytes + 1 } ++ ",\n"
    ++ transferPayloadCaseJson "ciphertext-hashes-mismatch-rejected"
      { validTransferPayload with ciphertextHashesMatch := false } ++ ",\n"
    ++ transferPayloadCaseJson "ciphertext-sizes-mismatch-rejected"
      { validTransferPayload with ciphertextSizesMatch := false } ++ ",\n"
    ++ transferPayloadCaseJson "binding-hash-mismatch-rejected"
      { validTransferPayload with bindingHashMatches := false } ++ ",\n"
    ++ transferPayloadCaseJson "proof-binding-hash-mismatch-rejected"
      { validTransferPayload with proofBindingHashMatchesKey := false } ++ ",\n"
    ++ transferPayloadCaseJson "fee-mismatch-rejected"
      { validTransferPayload with feeMatches := false } ++ ",\n"
    ++ transferPayloadCaseJson "proof-binding-hash-mismatch-precedes-fee"
      { validTransferPayload with
        proofBindingHashMatchesKey := false,
        feeMatches := false } ++ ",\n"
    ++ transferPayloadCaseJson "proof-missing-precedes-anchor"
      { validTransferPayload with proofBytes := 0, anchorMatches := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"inline_transfer_ciphertext_resource_cases\": [\n"
    ++ inlineCiphertextResourceCaseJson
      "valid-inline-transfer-ciphertext-resource"
      productionInlineTransferCiphertextResourcePolicy
      validInlineTransferCiphertextResourceInput ++ ",\n"
    ++ inlineCiphertextResourceCaseJson
      "exact-inline-transfer-ciphertext-resource-limits"
      productionInlineTransferCiphertextResourcePolicy
      {
        routePayloadBytes :=
          productionInlineTransferCiphertextResourcePolicy.rawByteCap,
        proofBytes := 0,
        ciphertextCount :=
          productionInlineTransferCiphertextResourcePolicy.itemCountCap,
        maxCiphertextBytesObserved :=
          productionInlineTransferCiphertextResourcePolicy.itemByteCap,
        aggregateCiphertextBytes :=
          productionInlineTransferCiphertextResourcePolicy.aggregateByteCap
      } ++ ",\n"
    ++ inlineCiphertextResourceCaseJson
      "route-payload-bytes-over-cap"
      productionInlineTransferCiphertextResourcePolicy
      { validInlineTransferCiphertextResourceInput with
        routePayloadBytes :=
          productionInlineTransferCiphertextResourcePolicy.rawByteCap + 1 } ++ ",\n"
    ++ inlineCiphertextResourceCaseJson
      "decoded-proof-plus-ciphertext-bytes-over-cap"
      productionInlineTransferCiphertextResourcePolicy
      { validInlineTransferCiphertextResourceInput with
        proofBytes :=
          productionInlineTransferCiphertextResourcePolicy.decodedByteCap,
        aggregateCiphertextBytes := 1 } ++ ",\n"
    ++ inlineCiphertextResourceCaseJson
      "ciphertext-count-over-cap"
      productionInlineTransferCiphertextResourcePolicy
      { validInlineTransferCiphertextResourceInput with
        ciphertextCount :=
          productionInlineTransferCiphertextResourcePolicy.itemCountCap + 1 } ++ ",\n"
    ++ inlineCiphertextResourceCaseJson
      "ciphertext-item-bytes-over-cap"
      productionInlineTransferCiphertextResourcePolicy
      { validInlineTransferCiphertextResourceInput with
        maxCiphertextBytesObserved :=
          productionInlineTransferCiphertextResourcePolicy.itemByteCap + 1 } ++ ",\n"
    ++ inlineCiphertextResourceCaseJson
      "ciphertext-aggregate-bytes-over-cap"
      productionInlineTransferCiphertextResourcePolicy
      { validInlineTransferCiphertextResourceInput with
        aggregateCiphertextBytes :=
          productionInlineTransferCiphertextResourcePolicy.aggregateByteCap + 1 } ++ ",\n"
    ++ inlineCiphertextResourceCaseJson
      "ciphertext-count-precedes-item-bytes"
      productionInlineTransferCiphertextResourcePolicy
      { validInlineTransferCiphertextResourceInput with
        ciphertextCount :=
          productionInlineTransferCiphertextResourcePolicy.itemCountCap + 1,
        maxCiphertextBytesObserved :=
          productionInlineTransferCiphertextResourcePolicy.itemByteCap + 1 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
