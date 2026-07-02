import Hegemon.Native.BridgeActionResourceAdmission

open Hegemon.Native.BridgeActionPayloadAdmission
open Hegemon.Native.BridgeActionResourceAdmission
open Hegemon.Resource.BoundedRequestAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def actionKindJson : BridgeActionKind -> String
  | BridgeActionKind.outbound => "\"outbound\""
  | BridgeActionKind.inbound => "\"inbound\""
  | BridgeActionKind.register => "\"register\""
  | BridgeActionKind.unsupported => "\"unsupported\""

def resourceRejectionJson : Option ResourceReject -> String
  | none => "null"
  | some ResourceReject.rawBytesExceeded => "\"raw_bytes_exceeded\""
  | some ResourceReject.decodedBytesExceeded => "\"decoded_bytes_exceeded\""
  | some ResourceReject.itemCountExceeded => "\"item_count_exceeded\""
  | some ResourceReject.itemBytesExceeded => "\"item_bytes_exceeded\""
  | some ResourceReject.aggregateBytesExceeded =>
      "\"aggregate_bytes_exceeded\""
  | some ResourceReject.workUnitsExceeded => "\"work_units_exceeded\""

def bridgeActionResourceCaseJson
    (name : String)
    (policy : ResourcePolicy)
    (input : BridgeActionResourceInput) : String :=
  let request := bridgeActionResourceRequest input
  let result := evaluateBoundedRequest policy request
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"action_kind\": " ++ actionKindJson input.actionKind ++ ",\n"
    ++ "      \"public_args_bytes\": " ++ toString input.publicArgsBytes ++ ",\n"
    ++ "      \"outbound_payload_bytes\": "
      ++ toString input.outboundPayloadBytes ++ ",\n"
    ++ "      \"inbound_proof_receipt_bytes\": "
      ++ toString input.inboundProofReceiptBytes ++ ",\n"
    ++ "      \"inbound_message_payload_bytes\": "
      ++ toString input.inboundMessagePayloadBytes ++ ",\n"
    ++ "      \"raw_byte_cap\": " ++ toString policy.rawByteCap ++ ",\n"
    ++ "      \"decoded_byte_cap\": " ++ toString policy.decodedByteCap ++ ",\n"
    ++ "      \"item_count_cap\": " ++ toString policy.itemCountCap ++ ",\n"
    ++ "      \"item_byte_cap\": " ++ toString policy.itemByteCap ++ ",\n"
    ++ "      \"aggregate_byte_cap\": "
      ++ toString policy.aggregateByteCap ++ ",\n"
    ++ "      \"work_unit_cap\": " ++ toString policy.workUnitCap ++ ",\n"
    ++ "      \"expected_raw_bytes\": " ++ toString request.rawBytes ++ ",\n"
    ++ "      \"expected_decoded_bytes\": "
      ++ toString request.decodedBytes ++ ",\n"
    ++ "      \"expected_item_count\": " ++ toString request.itemCount ++ ",\n"
    ++ "      \"expected_max_item_bytes\": "
      ++ toString request.maxItemBytes ++ ",\n"
    ++ "      \"expected_aggregate_bytes\": "
      ++ toString request.aggregateBytes ++ ",\n"
    ++ "      \"expected_work_units\": " ++ toString request.workUnits ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ resourceRejectionJson result ++ "\n"
    ++ "    }"

def exactInboundBridgeResource : BridgeActionResourceInput :=
  {
    actionKind := BridgeActionKind.inbound,
    publicArgsBytes := 4096,
    outboundPayloadBytes := 0,
    inboundProofReceiptBytes := exampleBridgeActionResourcePolicy.itemByteCap,
    inboundMessagePayloadBytes := exampleBridgeActionResourcePolicy.workUnitCap
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_action_resource_admission_cases\": [\n"
    ++ bridgeActionResourceCaseJson
      "valid-inbound-bridge-resource-accepted"
      exampleBridgeActionResourcePolicy
      validInboundBridgeResource ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "valid-outbound-bridge-resource-accepted"
      exampleBridgeActionResourcePolicy
      validOutboundBridgeResource ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "exact-inbound-receipt-and-payload-limits-accepted"
      exampleBridgeActionResourcePolicy
      exactInboundBridgeResource ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "public-args-over-raw-cap-rejected"
      exampleBridgeActionResourcePolicy
      {
        validInboundBridgeResource with
        publicArgsBytes := exampleBridgeActionResourcePolicy.rawByteCap + 1
      } ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "decoded-cap-rejected-after-raw-ok"
      { exampleBridgeActionResourcePolicy with decodedByteCap := 128 }
      validInboundBridgeResource ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "item-count-over-cap-rejected"
      { exampleBridgeActionResourcePolicy with itemCountCap := 1 }
      validInboundBridgeResource ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "inbound-proof-receipt-over-item-cap-rejected"
      exampleBridgeActionResourcePolicy
      {
        validInboundBridgeResource with
        inboundProofReceiptBytes :=
          exampleBridgeActionResourcePolicy.itemByteCap + 1
      } ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "inbound-message-payload-over-work-cap-rejected"
      exampleBridgeActionResourcePolicy
      {
        validInboundBridgeResource with
        inboundMessagePayloadBytes :=
          exampleBridgeActionResourcePolicy.workUnitCap + 1
      } ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "outbound-payload-over-work-cap-rejected"
      exampleBridgeActionResourcePolicy
      {
        validOutboundBridgeResource with
        outboundPayloadBytes :=
          exampleBridgeActionResourcePolicy.workUnitCap + 1
      } ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "dynamic-aggregate-over-cap-rejected"
      { exampleBridgeActionResourcePolicy with aggregateByteCap := 1000 }
      {
        validInboundBridgeResource with
        inboundProofReceiptBytes := 600,
        inboundMessagePayloadBytes := 600
      } ++ ",\n"
    ++ bridgeActionResourceCaseJson
      "raw-cap-precedes-later-resource-failures"
      { exampleBridgeActionResourcePolicy with itemCountCap := 1 }
      {
        validInboundBridgeResource with
        publicArgsBytes := exampleBridgeActionResourcePolicy.rawByteCap + 1,
        inboundProofReceiptBytes :=
          exampleBridgeActionResourcePolicy.itemByteCap + 1,
        inboundMessagePayloadBytes :=
          exampleBridgeActionResourcePolicy.workUnitCap + 1
      } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
