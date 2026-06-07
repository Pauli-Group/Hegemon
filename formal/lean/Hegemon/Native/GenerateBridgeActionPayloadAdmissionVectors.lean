import Hegemon.Native.BridgeActionPayloadAdmission

open Hegemon.Native.BridgeActionPayloadAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def actionKindJson : BridgeActionKind -> String
  | BridgeActionKind.outbound => "\"outbound\""
  | BridgeActionKind.inbound => "\"inbound\""
  | BridgeActionKind.register => "\"register\""
  | BridgeActionKind.unsupported => "\"unsupported\""

def rejectionJson : Option BridgePayloadReject -> String
  | none => "null"
  | some BridgePayloadReject.notBridgeAction => "\"not_bridge_action\""
  | some BridgePayloadReject.stateDeltasPresent => "\"state_deltas_present\""
  | some BridgePayloadReject.unsupportedBridgeAction =>
      "\"unsupported_bridge_action\""
  | some BridgePayloadReject.outboundPayloadEmpty =>
      "\"outbound_payload_empty\""
  | some BridgePayloadReject.inboundProofReceiptEmpty =>
      "\"inbound_proof_receipt_empty\""
  | some BridgePayloadReject.inboundReplayKeyMismatch =>
      "\"inbound_replay_key_mismatch\""
  | some BridgePayloadReject.inboundDestinationMismatch =>
      "\"inbound_destination_mismatch\""
  | some BridgePayloadReject.inboundPayloadHashMismatch =>
      "\"inbound_payload_hash_mismatch\""

def bridgePayloadCaseJson (name : String) (input : BridgePayloadInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"bridge_route\": " ++ boolJson input.bridgeRoute ++ ",\n"
    ++ "      \"state_deltas_absent\": " ++ boolJson input.stateDeltasAbsent ++ ",\n"
    ++ "      \"action_kind\": " ++ actionKindJson input.actionKind ++ ",\n"
    ++ "      \"outbound_payload_nonempty\": "
      ++ boolJson input.outboundPayloadNonempty ++ ",\n"
    ++ "      \"inbound_proof_receipt_nonempty\": "
      ++ boolJson input.inboundProofReceiptNonempty ++ ",\n"
    ++ "      \"inbound_replay_key_matches\": "
      ++ boolJson input.inboundReplayKeyMatches ++ ",\n"
    ++ "      \"inbound_destination_matches\": "
      ++ boolJson input.inboundDestinationMatches ++ ",\n"
    ++ "      \"inbound_payload_hash_matches\": "
      ++ boolJson input.inboundPayloadHashMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (bridgePayloadAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (bridgePayloadRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_action_payload_admission_cases\": [\n"
    ++ bridgePayloadCaseJson "valid-outbound-bridge-payload"
      validOutboundBridgePayload ++ ",\n"
    ++ bridgePayloadCaseJson "valid-inbound-bridge-payload"
      validInboundBridgePayload ++ ",\n"
    ++ bridgePayloadCaseJson "valid-register-bridge-payload"
      validRegisterBridgePayload ++ ",\n"
    ++ bridgePayloadCaseJson "not-bridge-action-rejected"
      { validOutboundBridgePayload with bridgeRoute := false } ++ ",\n"
    ++ bridgePayloadCaseJson "state-deltas-present-rejected"
      { validOutboundBridgePayload with stateDeltasAbsent := false } ++ ",\n"
    ++ bridgePayloadCaseJson "unsupported-bridge-action-rejected"
      { validOutboundBridgePayload with actionKind := BridgeActionKind.unsupported } ++ ",\n"
    ++ bridgePayloadCaseJson "outbound-payload-empty-rejected"
      { validOutboundBridgePayload with outboundPayloadNonempty := false } ++ ",\n"
    ++ bridgePayloadCaseJson "inbound-proof-receipt-empty-rejected"
      { validInboundBridgePayload with inboundProofReceiptNonempty := false } ++ ",\n"
    ++ bridgePayloadCaseJson "inbound-replay-key-mismatch-rejected"
      { validInboundBridgePayload with inboundReplayKeyMatches := false } ++ ",\n"
    ++ bridgePayloadCaseJson "inbound-destination-mismatch-rejected"
      { validInboundBridgePayload with inboundDestinationMatches := false } ++ ",\n"
    ++ bridgePayloadCaseJson "inbound-payload-hash-mismatch-rejected"
      { validInboundBridgePayload with inboundPayloadHashMatches := false } ++ ",\n"
    ++ bridgePayloadCaseJson "not-bridge-precedes-state-deltas"
      { validOutboundBridgePayload with
        bridgeRoute := false,
        stateDeltasAbsent := false } ++ ",\n"
    ++ bridgePayloadCaseJson "state-deltas-precede-unsupported-action"
      { validOutboundBridgePayload with
        stateDeltasAbsent := false,
        actionKind := BridgeActionKind.unsupported } ++ ",\n"
    ++ bridgePayloadCaseJson "inbound-proof-precedes-replay-mismatch"
      { validInboundBridgePayload with
        inboundProofReceiptNonempty := false,
        inboundReplayKeyMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
