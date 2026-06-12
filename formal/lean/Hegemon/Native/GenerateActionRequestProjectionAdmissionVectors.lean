import Hegemon.Native.ActionRequestProjectionAdmission

open Hegemon.Native.ActionRequestProjectionAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option ActionRequestProjectionReject -> String
  | none => "null"
  | some ActionRequestProjectionReject.jsonDecodeRejected => "\"json_decode_rejected\""
  | some ActionRequestProjectionReject.kernelEnvelopeFieldsPresent =>
      "\"kernel_envelope_fields_present\""
  | some ActionRequestProjectionReject.unsupportedRoute => "\"unsupported_route\""
  | some ActionRequestProjectionReject.nonTransferNullifiers =>
      "\"non_transfer_nullifiers\""
  | some ActionRequestProjectionReject.tooManyNullifiers => "\"too_many_nullifiers\""
  | some ActionRequestProjectionReject.invalidNullifierHex => "\"invalid_nullifier_hex\""
  | some ActionRequestProjectionReject.publicArgsTooLarge => "\"public_args_too_large\""
  | some ActionRequestProjectionReject.publicArgsBase64Rejected =>
      "\"public_args_base64_rejected\""
  | some ActionRequestProjectionReject.decodedPublicArgsTooLarge =>
      "\"decoded_public_args_too_large\""
  | some ActionRequestProjectionReject.routePayloadDecodeNotExact =>
      "\"route_payload_decode_not_exact\""

def caseJson (name fixture : String) (input : ActionRequestProjectionInput) : String :=
  let result := evaluateActionRequestProjectionRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"json_decode_accepts\": " ++ boolJson input.jsonDecodeAccepts ++ ",\n"
    ++ "      \"kernel_envelope_fields_absent\": " ++ boolJson input.kernelEnvelopeFieldsAbsent ++ ",\n"
    ++ "      \"route_supported\": " ++ boolJson input.routeSupported ++ ",\n"
    ++ "      \"nullifier_scope_valid\": " ++ boolJson input.nullifierScopeValid ++ ",\n"
    ++ "      \"nullifier_count_within_limit\": " ++ boolJson input.nullifierCountWithinLimit ++ ",\n"
    ++ "      \"nullifier_hex_valid\": " ++ boolJson input.nullifierHexValid ++ ",\n"
    ++ "      \"public_args_encoded_within_limit\": " ++ boolJson input.publicArgsEncodedWithinLimit ++ ",\n"
    ++ "      \"public_args_base64_decodes\": " ++ boolJson input.publicArgsBase64Decodes ++ ",\n"
    ++ "      \"public_args_decoded_within_limit\": " ++ boolJson input.publicArgsDecodedWithinLimit ++ ",\n"
    ++ "      \"route_payload_decodes_exactly\": " ++ boolJson input.routePayloadDecodesExactly ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"action_request_projection_admission_cases\": [\n"
    ++ caseJson "valid-empty-native-request" "valid_empty_native_request" validRequest ++ ",\n"
    ++ caseJson "valid-empty-wallet-envelope-fields" "valid_empty_wallet_envelope_fields"
      validRequest ++ ",\n"
    ++ caseJson "unknown-field-rejected" "unknown_field"
      { validRequest with jsonDecodeAccepts := false } ++ ",\n"
    ++ caseJson "object-ref-present-rejected" "object_ref_present"
      { validRequest with kernelEnvelopeFieldsAbsent := false } ++ ",\n"
    ++ caseJson "authorization-proof-present-rejected" "authorization_proof_present"
      { validRequest with kernelEnvelopeFieldsAbsent := false } ++ ",\n"
    ++ caseJson "authorization-signature-present-rejected" "authorization_signature_present"
      { validRequest with kernelEnvelopeFieldsAbsent := false } ++ ",\n"
    ++ caseJson "aux-data-present-rejected" "aux_data_present"
      { validRequest with kernelEnvelopeFieldsAbsent := false } ++ ",\n"
    ++ caseJson "unsupported-route-rejected" "unsupported_route"
      { validRequest with routeSupported := false } ++ ",\n"
    ++ caseJson "non-transfer-nullifiers-rejected" "non_transfer_nullifiers"
      { validRequest with nullifierScopeValid := false } ++ ",\n"
    ++ caseJson "too-many-nullifiers-rejected" "too_many_nullifiers"
      { validRequest with nullifierCountWithinLimit := false } ++ ",\n"
    ++ caseJson "invalid-nullifier-hex-rejected" "invalid_nullifier_hex"
      { validRequest with nullifierHexValid := false } ++ ",\n"
    ++ caseJson "encoded-public-args-too-large-rejected" "encoded_public_args_too_large"
      { validRequest with publicArgsEncodedWithinLimit := false } ++ ",\n"
    ++ caseJson "base64-public-args-rejected" "base64_public_args_rejected"
      { validRequest with publicArgsBase64Decodes := false } ++ ",\n"
    ++ caseJson "decoded-public-args-too-large-rejected" "decoded_public_args_too_large"
      { validRequest with publicArgsDecodedWithinLimit := false } ++ ",\n"
    ++ caseJson "route-payload-decode-rejected" "route_payload_decode_rejected"
      { validRequest with routePayloadDecodesExactly := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
