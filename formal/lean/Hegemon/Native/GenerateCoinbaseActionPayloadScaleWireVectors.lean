import Hegemon.Bytes
import Hegemon.Native.CoinbaseActionPayloadScaleWire

open Hegemon
open Hegemon.Native.CoinbaseActionPayloadScaleWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option CoinbaseActionPayloadScaleWireReject -> String
  | none => "null"
  | some CoinbaseActionPayloadScaleWireReject.parserRejected =>
      "\"parser_rejected\""
  | some CoinbaseActionPayloadScaleWireReject.trailingBytes =>
      "\"trailing_bytes\""
  | some CoinbaseActionPayloadScaleWireReject.nonCanonicalEncoding =>
      "\"non_canonical_encoding\""

def compactSmall (value : Nat) : List Byte :=
  [byte (value * 4)]

def repeated (length value : Nat) : List Byte :=
  List.replicate length (byte value)

def coinbaseActionPayloadBytes
    (commitmentValue ciphertextValue : Nat)
    (kemCiphertext : List Nat)
    (recipientValue amount publicSeedValue : Nat) : List Byte :=
  repeated 48 commitmentValue
    ++ repeated 579 ciphertextValue
    ++ compactSmall kemCiphertext.length
    ++ kemCiphertext.map byte
    ++ repeated 69 recipientValue
    ++ u64le amount
    ++ repeated 32 publicSeedValue

def validShortKemBytes : List Byte :=
  coinbaseActionPayloadBytes
    1 2 [0xaa, 0xbb, 0xcc] 3 4 5

def validZeroKemBytes : List Byte :=
  coinbaseActionPayloadBytes
    6 7 [] 8 9 10

def shortPayloadBytes : List Byte :=
  (List.range 32).map (fun _ => 0)

def trailingPayloadBytes : List Byte :=
  validShortKemBytes ++ [0xdd]

def kemCiphertextLengthOverrunBytes : List Byte :=
  repeated 48 1
    ++ repeated 579 2
    ++ compactSmall 4
    ++ [0xaa, 0xbb, 0xcc]
    ++ repeated 69 3
    ++ u64le 4
    ++ repeated 32 5

def noncanonicalZeroKemPrefixBytes : List Byte :=
  repeated 48 6
    ++ repeated 579 7
    ++ [1, 0]
    ++ repeated 69 8
    ++ u64le 9
    ++ repeated 32 10

def caseJson
    (name fixture : String)
    (input : CoinbaseActionPayloadScaleWireInput)
    (rawBytes : List Byte) : String :=
  let result := evaluateCoinbaseActionPayloadScaleWireRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes rawBytes ++ "\",\n"
    ++ "      \"commitment_bytes\": " ++ toString input.commitmentBytes ++ ",\n"
    ++ "      \"note_ciphertext_bytes\": "
    ++ toString input.noteCiphertextBytes ++ ",\n"
    ++ "      \"kem_ciphertext_compact_prefix_bytes\": "
    ++ toString input.kemCiphertextCompactPrefixBytes ++ ",\n"
    ++ "      \"kem_ciphertext_bytes\": "
    ++ toString input.kemCiphertextBytes ++ ",\n"
    ++ "      \"kem_ciphertext_compact_prefix_canonical\": "
    ++ boolJson input.kemCiphertextCompactPrefixCanonical ++ ",\n"
    ++ "      \"recipient_address_bytes\": "
    ++ toString input.recipientAddressBytes ++ ",\n"
    ++ "      \"amount_bytes\": " ++ toString input.amountBytes ++ ",\n"
    ++ "      \"public_seed_bytes\": "
    ++ toString input.publicSeedBytes ++ ",\n"
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
    ++ "  \"coinbase_action_payload_scale_wire_cases\": [\n"
    ++ caseJson "valid-short-kem-payload" "valid_short_kem_payload"
      validShortKemPayload validShortKemBytes ++ ",\n"
    ++ caseJson "valid-zero-kem-payload" "valid_zero_kem_payload"
      validZeroKemPayload validZeroKemBytes ++ ",\n"
    ++ caseJson "empty-bytes-rejected" "empty_bytes"
      { validShortKemPayload with
        totalBytes := 0,
        canonicalReencodeMatches := false }
      [] ++ ",\n"
    ++ caseJson "short-payload-rejected" "short_payload"
      { validShortKemPayload with
        totalBytes := 32,
        canonicalReencodeMatches := false }
      shortPayloadBytes ++ ",\n"
    ++ caseJson "trailing-byte-rejected" "trailing_payload"
      trailingByteCase trailingPayloadBytes ++ ",\n"
    ++ caseJson "kem-ciphertext-length-overrun-rejected"
      "kem_ciphertext_length_overrun"
      kemCiphertextLengthOverrun
      kemCiphertextLengthOverrunBytes ++ ",\n"
    ++ caseJson "noncanonical-zero-kem-prefix-rejected"
      "noncanonical_zero_kem_prefix"
      noncanonicalKemCompactPrefix
      noncanonicalZeroKemPrefixBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
