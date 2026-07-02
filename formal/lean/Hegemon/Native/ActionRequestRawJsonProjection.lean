import Hegemon.Bytes
import Hegemon.Native.ActionRequestProjectionAdmission

namespace Hegemon
namespace Native
namespace ActionRequestRawJsonProjection

open Hegemon
open Hegemon.Native.ActionRequestProjectionAdmission

structure RawJsonProjectionCase where
  rawJsonBytes : List Byte
  projection : ActionRequestProjectionInput
  expected : Option ActionRequestProjectionReject
deriving DecidableEq, Repr

def rawJsonProjectionCaseMatches (case : RawJsonProjectionCase) : Bool :=
  evaluateActionRequestProjectionRejection case.projection = case.expected

def validOutboundPayloadBase64 : String :=
  "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcJAFhsZWFuIGFjdGlvbiBwcm9qZWN0aW9u"

def trailingOutboundPayloadBase64 : String :=
  "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcJAFhsZWFuIGFjdGlvbiBwcm9qZWN0aW9uqg=="

def validOutboundRawJson (publicArgs : String) : String :=
  "{"
    ++ "\"binding_circuit\":2,"
    ++ "\"binding_crypto\":2,"
    ++ "\"family_id\":5,"
    ++ "\"action_id\":1,"
    ++ "\"new_nullifiers\":[],"
    ++ "\"public_args\":\"" ++ publicArgs ++ "\""
    ++ "}"

def validOutboundRequest : RawJsonProjectionCase := {
  rawJsonBytes := asciiBytes (validOutboundRawJson validOutboundPayloadBase64),
  projection := validRequest,
  expected := none
}

def malformedJsonRequest : RawJsonProjectionCase := {
  rawJsonBytes := asciiBytes "{",
  projection := { validRequest with jsonDecodeAccepts := false },
  expected := some ActionRequestProjectionReject.jsonDecodeRejected
}

def unknownFieldRequest : RawJsonProjectionCase := {
  rawJsonBytes :=
    asciiBytes
      ("{"
        ++ "\"binding_circuit\":2,"
        ++ "\"binding_crypto\":2,"
        ++ "\"family_id\":5,"
        ++ "\"action_id\":1,"
        ++ "\"new_nullifiers\":[],"
        ++ "\"public_args\":\"" ++ validOutboundPayloadBase64 ++ "\","
        ++ "\"statement_hash\":\"00\""
        ++ "}"),
  projection := { validRequest with jsonDecodeAccepts := false },
  expected := some ActionRequestProjectionReject.jsonDecodeRejected
}

def nonemptyKernelEnvelopeRequest : RawJsonProjectionCase := {
  rawJsonBytes :=
    asciiBytes
      ("{"
        ++ "\"binding_circuit\":2,"
        ++ "\"binding_crypto\":2,"
        ++ "\"family_id\":5,"
        ++ "\"action_id\":1,"
        ++ "\"object_refs\":[{\"family_id\":1,\"object_id\":\"00\",\"expected_root\":\"00\"}],"
        ++ "\"new_nullifiers\":[],"
        ++ "\"public_args\":\"" ++ validOutboundPayloadBase64 ++ "\""
        ++ "}"),
  projection := { validRequest with kernelEnvelopeFieldsAbsent := false },
  expected := some ActionRequestProjectionReject.kernelEnvelopeFieldsPresent
}

def unsupportedRouteRequest : RawJsonProjectionCase := {
  rawJsonBytes :=
    asciiBytes
      ("{"
        ++ "\"binding_circuit\":2,"
        ++ "\"binding_crypto\":2,"
        ++ "\"family_id\":5,"
        ++ "\"action_id\":65535,"
        ++ "\"new_nullifiers\":[],"
        ++ "\"public_args\":\"" ++ validOutboundPayloadBase64 ++ "\""
        ++ "}"),
  projection := { validRequest with routeSupported := false },
  expected := some ActionRequestProjectionReject.unsupportedRoute
}

def nonTransferNullifierRequest : RawJsonProjectionCase := {
  rawJsonBytes :=
    asciiBytes
      ("{"
        ++ "\"binding_circuit\":2,"
        ++ "\"binding_crypto\":2,"
        ++ "\"family_id\":5,"
        ++ "\"action_id\":1,"
        ++ "\"new_nullifiers\":[\""
        ++ "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ++ "\"],"
        ++ "\"public_args\":\"" ++ validOutboundPayloadBase64 ++ "\""
        ++ "}"),
  projection := { validRequest with nullifierScopeValid := false },
  expected := some ActionRequestProjectionReject.nonTransferNullifiers
}

def invalidTransferNullifierRequest : RawJsonProjectionCase := {
  rawJsonBytes :=
    asciiBytes
      ("{"
        ++ "\"binding_circuit\":2,"
        ++ "\"binding_crypto\":2,"
        ++ "\"family_id\":1,"
        ++ "\"action_id\":1,"
        ++ "\"new_nullifiers\":[\"not-hex\"],"
        ++ "\"public_args\":\"" ++ validOutboundPayloadBase64 ++ "\""
        ++ "}"),
  projection := { validRequest with nullifierHexValid := false },
  expected := some ActionRequestProjectionReject.invalidNullifierHex
}

def invalidBase64Request : RawJsonProjectionCase := {
  rawJsonBytes :=
    asciiBytes
      ("{"
        ++ "\"binding_circuit\":2,"
        ++ "\"binding_crypto\":2,"
        ++ "\"family_id\":5,"
        ++ "\"action_id\":1,"
        ++ "\"new_nullifiers\":[],"
        ++ "\"public_args\":\"not base64!\""
        ++ "}"),
  projection := { validRequest with publicArgsBase64Decodes := false },
  expected := some ActionRequestProjectionReject.publicArgsBase64Rejected
}

def trailingPayloadRequest : RawJsonProjectionCase := {
  rawJsonBytes := asciiBytes (validOutboundRawJson trailingOutboundPayloadBase64),
  projection := { validRequest with routePayloadDecodesExactly := false },
  expected := some ActionRequestProjectionReject.routePayloadDecodeNotExact
}

theorem raw_json_projection_case_matches_iff_expected_rejection
    {case : RawJsonProjectionCase} :
    rawJsonProjectionCaseMatches case = true ↔
      evaluateActionRequestProjectionRejection case.projection =
        case.expected := by
  cases case
  simp [rawJsonProjectionCaseMatches]

theorem valid_raw_outbound_request_accepts :
    evaluateActionRequestProjectionRejection validOutboundRequest.projection = none := by
  decide

theorem malformed_raw_json_rejects :
    evaluateActionRequestProjectionRejection malformedJsonRequest.projection =
      some ActionRequestProjectionReject.jsonDecodeRejected := by
  decide

theorem unknown_raw_field_rejects :
    evaluateActionRequestProjectionRejection unknownFieldRequest.projection =
      some ActionRequestProjectionReject.jsonDecodeRejected := by
  decide

theorem nonempty_raw_kernel_envelope_rejects :
    evaluateActionRequestProjectionRejection nonemptyKernelEnvelopeRequest.projection =
      some ActionRequestProjectionReject.kernelEnvelopeFieldsPresent := by
  decide

theorem raw_unsupported_route_rejects :
    evaluateActionRequestProjectionRejection unsupportedRouteRequest.projection =
      some ActionRequestProjectionReject.unsupportedRoute := by
  decide

theorem raw_non_transfer_nullifier_rejects :
    evaluateActionRequestProjectionRejection nonTransferNullifierRequest.projection =
      some ActionRequestProjectionReject.nonTransferNullifiers := by
  decide

theorem raw_invalid_transfer_nullifier_rejects :
    evaluateActionRequestProjectionRejection invalidTransferNullifierRequest.projection =
      some ActionRequestProjectionReject.invalidNullifierHex := by
  decide

theorem raw_base64_failure_rejects :
    evaluateActionRequestProjectionRejection invalidBase64Request.projection =
      some ActionRequestProjectionReject.publicArgsBase64Rejected := by
  decide

theorem raw_route_payload_trailing_rejects :
    evaluateActionRequestProjectionRejection trailingPayloadRequest.projection =
      some ActionRequestProjectionReject.routePayloadDecodeNotExact := by
  decide

end ActionRequestRawJsonProjection
end Native
end Hegemon
