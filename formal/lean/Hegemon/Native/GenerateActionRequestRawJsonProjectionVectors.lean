import Hegemon.Native.ActionRequestRawJsonProjection

open Hegemon.Native.ActionRequestProjectionAdmission
open Hegemon.Native.ActionRequestRawJsonProjection

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson : List Nat -> String
  | [] => "[]"
  | head :: tail =>
      "[" ++ toString head ++ String.join (tail.map fun value => ", " ++ toString value) ++ "]"

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

def caseJson (name : String) (case : RawJsonProjectionCase) : String :=
  let input := case.projection
  let result := evaluateActionRequestProjectionRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"raw_json_bytes\": " ++ natListJson case.rawJsonBytes ++ ",\n"
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
    ++ "  \"action_request_raw_json_projection_cases\": [\n"
    ++ caseJson "valid-raw-outbound-request" validOutboundRequest ++ ",\n"
    ++ caseJson "malformed-raw-json-rejected" malformedJsonRequest ++ ",\n"
    ++ caseJson "unknown-raw-field-rejected" unknownFieldRequest ++ ",\n"
    ++ caseJson "nonempty-raw-kernel-envelope-rejected"
      nonemptyKernelEnvelopeRequest ++ ",\n"
    ++ caseJson "unsupported-raw-route-rejected" unsupportedRouteRequest ++ ",\n"
    ++ caseJson "non-transfer-raw-nullifier-rejected"
      nonTransferNullifierRequest ++ ",\n"
    ++ caseJson "invalid-transfer-raw-nullifier-rejected"
      invalidTransferNullifierRequest ++ ",\n"
    ++ caseJson "invalid-raw-base64-rejected" invalidBase64Request ++ ",\n"
    ++ caseJson "raw-route-payload-trailing-rejected" trailingPayloadRequest ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
