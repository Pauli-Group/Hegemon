import Hegemon.Bytes
import Hegemon.Native.InboundBridgeActionPayloadScaleWire

open Hegemon
open Hegemon.Native.InboundBridgeActionPayloadScaleWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option InboundBridgeActionPayloadScaleWireReject -> String
  | none => "null"
  | some InboundBridgeActionPayloadScaleWireReject.parserRejected =>
      "\"parser_rejected\""
  | some InboundBridgeActionPayloadScaleWireReject.trailingBytes =>
      "\"trailing_bytes\""
  | some InboundBridgeActionPayloadScaleWireReject.nonCanonicalEncoding =>
      "\"non_canonical_encoding\""

def compactSmall (value : Nat) : List Byte :=
  [byte (value * 4)]

def repeated (length value : Nat) : List Byte :=
  List.replicate length (byte value)

def bridgeMessageBytes
    (sourceChainIdValue destinationChainIdValue appFamilyId
      messageNonce sourceHeight payloadHashValue : Nat)
    (payload : List Nat) : List Byte :=
  repeated 32 sourceChainIdValue
    ++ repeated 32 destinationChainIdValue
    ++ u16le appFamilyId
    ++ u128le messageNonce
    ++ u64le sourceHeight
    ++ repeated 48 payloadHashValue
    ++ compactSmall payload.length
    ++ payload.map byte

def inboundBridgeActionPayloadBytes
    (sourceChainIdValue sourceMessageNonce verifierProgramHashValue : Nat)
    (proofReceipt : List Nat)
    (messageBytes : List Byte) : List Byte :=
  repeated 32 sourceChainIdValue
    ++ u128le sourceMessageNonce
    ++ repeated 32 verifierProgramHashValue
    ++ compactSmall proofReceipt.length
    ++ proofReceipt.map byte
    ++ messageBytes

def validShortReceiptPayloadBytes : List Byte :=
  inboundBridgeActionPayloadBytes
    1
    42
    3
    [0xaa, 0xbb]
    (bridgeMessageBytes
      1 4 7 42 99 5 [0xcc, 0xdd, 0xee])

def validEmptyReceiptPayloadBytes : List Byte :=
  inboundBridgeActionPayloadBytes
    2
    0
    6
    []
    (bridgeMessageBytes
      2 8 9 0 0 9 [])

def shortPayloadBytes : List Byte :=
  (List.range 64).map (fun _ => 0)

def trailingPayloadBytes : List Byte :=
  validShortReceiptPayloadBytes ++ [0xff]

def proofReceiptLengthOverrunBytes : List Byte :=
  repeated 32 1
    ++ u128le 42
    ++ repeated 32 3
    ++ compactSmall 3
    ++ [0xaa, 0xbb]

def messagePayloadLengthOverrunBytes : List Byte :=
  inboundBridgeActionPayloadBytes
    1
    42
    3
    [0xaa, 0xbb]
    (repeated 32 1
      ++ repeated 32 4
      ++ u16le 7
      ++ u128le 42
      ++ u64le 99
      ++ repeated 48 5
      ++ compactSmall 4
      ++ [0xcc, 0xdd, 0xee])

def noncanonicalProofReceiptPrefixBytes : List Byte :=
  repeated 32 2
    ++ u128le 0
    ++ repeated 32 6
    ++ [1, 0]
    ++ bridgeMessageBytes
      2 8 9 0 0 9 []

def noncanonicalMessagePayloadPrefixBytes : List Byte :=
  inboundBridgeActionPayloadBytes
    2
    0
    6
    []
    (repeated 32 2
      ++ repeated 32 8
      ++ u16le 9
      ++ u128le 0
      ++ u64le 0
      ++ repeated 48 9
      ++ [1, 0])

def caseJson
    (name fixture : String)
    (input : InboundBridgeActionPayloadScaleWireInput)
    (rawBytes : List Byte) : String :=
  let result := evaluateInboundBridgeActionPayloadScaleWireRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes rawBytes ++ "\",\n"
    ++ "      \"source_chain_id_bytes\": "
    ++ toString input.sourceChainIdBytes ++ ",\n"
    ++ "      \"source_message_nonce_bytes\": "
    ++ toString input.sourceMessageNonceBytes ++ ",\n"
    ++ "      \"verifier_program_hash_bytes\": "
    ++ toString input.verifierProgramHashBytes ++ ",\n"
    ++ "      \"proof_receipt_compact_prefix_bytes\": "
    ++ toString input.proofReceiptCompactPrefixBytes ++ ",\n"
    ++ "      \"proof_receipt_bytes\": "
    ++ toString input.proofReceiptBytes ++ ",\n"
    ++ "      \"proof_receipt_compact_prefix_canonical\": "
    ++ boolJson input.proofReceiptCompactPrefixCanonical ++ ",\n"
    ++ "      \"message_source_chain_id_bytes\": "
    ++ toString input.messageSourceChainIdBytes ++ ",\n"
    ++ "      \"message_destination_chain_id_bytes\": "
    ++ toString input.messageDestinationChainIdBytes ++ ",\n"
    ++ "      \"message_app_family_id_bytes\": "
    ++ toString input.messageAppFamilyIdBytes ++ ",\n"
    ++ "      \"message_nonce_bytes\": "
    ++ toString input.messageNonceBytes ++ ",\n"
    ++ "      \"message_source_height_bytes\": "
    ++ toString input.messageSourceHeightBytes ++ ",\n"
    ++ "      \"message_payload_hash_bytes\": "
    ++ toString input.messagePayloadHashBytes ++ ",\n"
    ++ "      \"message_payload_compact_prefix_bytes\": "
    ++ toString input.messagePayloadCompactPrefixBytes ++ ",\n"
    ++ "      \"message_payload_bytes\": "
    ++ toString input.messagePayloadBytes ++ ",\n"
    ++ "      \"message_payload_compact_prefix_canonical\": "
    ++ boolJson input.messagePayloadCompactPrefixCanonical ++ ",\n"
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
    ++ "  \"inbound_bridge_action_payload_scale_wire_cases\": [\n"
    ++ caseJson "valid-short-receipt-payload"
      "valid_short_receipt_payload"
      validShortReceiptPayload
      validShortReceiptPayloadBytes ++ ",\n"
    ++ caseJson "valid-empty-receipt-payload"
      "valid_empty_receipt_payload"
      validEmptyReceiptPayload
      validEmptyReceiptPayloadBytes ++ ",\n"
    ++ caseJson "empty-bytes-rejected" "empty_bytes"
      { validShortReceiptPayload with
        totalBytes := 0,
        canonicalReencodeMatches := false }
      [] ++ ",\n"
    ++ caseJson "short-payload-rejected" "short_payload"
      { validShortReceiptPayload with
        totalBytes := 64,
        canonicalReencodeMatches := false }
      shortPayloadBytes ++ ",\n"
    ++ caseJson "trailing-byte-rejected" "trailing_payload"
      trailingByteCase trailingPayloadBytes ++ ",\n"
    ++ caseJson "proof-receipt-length-overrun-rejected"
      "proof_receipt_length_overrun"
      proofReceiptLengthOverrun
      proofReceiptLengthOverrunBytes ++ ",\n"
    ++ caseJson "message-payload-length-overrun-rejected"
      "message_payload_length_overrun"
      messagePayloadLengthOverrun
      messagePayloadLengthOverrunBytes ++ ",\n"
    ++ caseJson "noncanonical-proof-receipt-prefix-rejected"
      "noncanonical_proof_receipt_prefix"
      noncanonicalProofReceiptCompactPrefix
      noncanonicalProofReceiptPrefixBytes ++ ",\n"
    ++ caseJson "noncanonical-message-payload-prefix-rejected"
      "noncanonical_message_payload_prefix"
      noncanonicalMessagePayloadCompactPrefix
      noncanonicalMessagePayloadPrefixBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
