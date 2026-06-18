import Hegemon.Bytes
import Hegemon.Native.OutboundBridgeActionPayloadScaleWire

open Hegemon
open Hegemon.Native.OutboundBridgeActionPayloadScaleWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option OutboundBridgeActionPayloadScaleWireReject -> String
  | none => "null"
  | some OutboundBridgeActionPayloadScaleWireReject.parserRejected =>
      "\"parser_rejected\""
  | some OutboundBridgeActionPayloadScaleWireReject.trailingBytes =>
      "\"trailing_bytes\""
  | some OutboundBridgeActionPayloadScaleWireReject.nonCanonicalEncoding =>
      "\"non_canonical_encoding\""

def compactSmall (value : Nat) : List Byte :=
  [byte (value * 4)]

def repeated (length value : Nat) : List Byte :=
  List.replicate length (byte value)

def outboundBridgeActionPayloadBytes
    (destinationChainIdValue appFamilyId : Nat)
    (payload : List Nat) : List Byte :=
  repeated 32 destinationChainIdValue
    ++ u16le appFamilyId
    ++ compactSmall payload.length
    ++ payload.map byte

def validShortPayloadBytes : List Byte :=
  outboundBridgeActionPayloadBytes
    1 7 [0xaa, 0xbb, 0xcc]

def validEmptyPayloadBytes : List Byte :=
  outboundBridgeActionPayloadBytes
    2 9 []

def shortPayloadBytes : List Byte :=
  (List.range 16).map (fun _ => 0)

def trailingPayloadBytes : List Byte :=
  validShortPayloadBytes ++ [0xdd]

def payloadLengthOverrunBytes : List Byte :=
  repeated 32 1
    ++ u16le 7
    ++ compactSmall 4
    ++ [0xaa, 0xbb, 0xcc]

def noncanonicalEmptyPayloadPrefixBytes : List Byte :=
  repeated 32 2
    ++ u16le 9
    ++ [1, 0]

def caseJson
    (name fixture : String)
    (input : OutboundBridgeActionPayloadScaleWireInput)
    (rawBytes : List Byte) : String :=
  let result := evaluateOutboundBridgeActionPayloadScaleWireRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes rawBytes ++ "\",\n"
    ++ "      \"destination_chain_id_bytes\": "
    ++ toString input.destinationChainIdBytes ++ ",\n"
    ++ "      \"app_family_id_bytes\": "
    ++ toString input.appFamilyIdBytes ++ ",\n"
    ++ "      \"payload_compact_prefix_bytes\": "
    ++ toString input.payloadCompactPrefixBytes ++ ",\n"
    ++ "      \"payload_bytes\": " ++ toString input.payloadBytes ++ ",\n"
    ++ "      \"payload_compact_prefix_canonical\": "
    ++ boolJson input.payloadCompactPrefixCanonical ++ ",\n"
    ++ "      \"total_bytes\": " ++ toString input.totalBytes ++ ",\n"
    ++ "      \"consumed_all_bytes\": "
    ++ boolJson input.consumedAllBytes ++ ",\n"
    ++ "      \"canonical_reencode_matches\": "
    ++ boolJson input.canonicalReencodeMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"outbound_bridge_action_payload_scale_wire_cases\": [\n"
    ++ caseJson "valid-short-payload" "valid_short_payload"
      validShortPayload validShortPayloadBytes ++ ",\n"
    ++ caseJson "valid-empty-payload" "valid_empty_payload"
      validEmptyPayload validEmptyPayloadBytes ++ ",\n"
    ++ caseJson "empty-bytes-rejected" "empty_bytes"
      { validShortPayload with
        totalBytes := 0,
        canonicalReencodeMatches := false }
      [] ++ ",\n"
    ++ caseJson "short-payload-rejected" "short_payload"
      { validShortPayload with
        totalBytes := 16,
        canonicalReencodeMatches := false }
      shortPayloadBytes ++ ",\n"
    ++ caseJson "trailing-byte-rejected" "trailing_payload"
      trailingByteCase trailingPayloadBytes ++ ",\n"
    ++ caseJson "payload-length-overrun-rejected"
      "payload_length_overrun"
      payloadLengthOverrun
      payloadLengthOverrunBytes ++ ",\n"
    ++ caseJson "noncanonical-empty-payload-prefix-rejected"
      "noncanonical_empty_payload_prefix"
      noncanonicalPayloadCompactPrefix
      noncanonicalEmptyPayloadPrefixBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
