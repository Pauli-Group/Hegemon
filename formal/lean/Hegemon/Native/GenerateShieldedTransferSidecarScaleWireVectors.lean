import Hegemon.Bytes
import Hegemon.Native.ShieldedTransferSidecarScaleWire

open Hegemon
open Hegemon.Native.ShieldedTransferSidecarScaleWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option ShieldedTransferSidecarScaleWireReject -> String
  | none => "null"
  | some ShieldedTransferSidecarScaleWireReject.parserRejected =>
      "\"parser_rejected\""
  | some ShieldedTransferSidecarScaleWireReject.trailingBytes =>
      "\"trailing_bytes\""
  | some ShieldedTransferSidecarScaleWireReject.nonCanonicalEncoding =>
      "\"non_canonical_encoding\""

def compactSmall (value : Nat) : List Byte :=
  [byte (value * 4)]

def repeated (length value : Nat) : List Byte :=
  List.replicate length (byte value)

def concatNatBytes (parts : List (List Byte)) : List Byte :=
  match parts with
  | [] => []
  | head :: tail => head ++ concatNatBytes tail

def balanceSlotsBytes (slots : List Nat) : List Byte :=
  concatNatBytes (slots.map u64le)

def u32VectorBytes (values : List Nat) : List Byte :=
  compactSmall values.length ++ concatNatBytes (values.map u32le)

def shieldedTransferSidecarBytes
    (proof : List Nat)
    (commitmentValues : List Nat)
    (ciphertextHashValues : List Nat)
    (ciphertextSizes : List Nat)
    (anchorValue : Nat)
    (balanceSlots : List Nat)
    (bindingHashValue : Nat)
    (stablecoinOptionTag : Nat)
    (stablecoinPayload : List Nat)
    (fee : Nat) : List Byte :=
  compactSmall proof.length
    ++ proof.map byte
    ++ compactSmall commitmentValues.length
    ++ concatNatBytes (commitmentValues.map (fun value => repeated 48 value))
    ++ compactSmall ciphertextHashValues.length
    ++ concatNatBytes (ciphertextHashValues.map (fun value => repeated 48 value))
    ++ u32VectorBytes ciphertextSizes
    ++ repeated 48 anchorValue
    ++ balanceSlotsBytes balanceSlots
    ++ repeated 64 bindingHashValue
    ++ [byte stablecoinOptionTag]
    ++ stablecoinPayload.map byte
    ++ u64le fee

def stablecoinBindingBytes
    (assetId policyHashValue oracleCommitmentValue
      attestationCommitmentValue issuanceDelta policyVersion : Nat) :
    List Byte :=
  u64le assetId
    ++ repeated 48 policyHashValue
    ++ repeated 48 oracleCommitmentValue
    ++ repeated 48 attestationCommitmentValue
    ++ u128le issuanceDelta
    ++ u32le policyVersion

def validOneOutputSidecarBytes : List Byte :=
  shieldedTransferSidecarBytes
    [1, 2, 3]
    [4]
    [5]
    [6]
    7
    [0, 1, 2, 3]
    8
    0
    []
    9

def validStablecoinSidecarBytes : List Byte :=
  shieldedTransferSidecarBytes
    [1, 2, 3]
    [4]
    [5]
    [6]
    7
    [0, 1, 2, 3]
    8
    1
    (stablecoinBindingBytes 11 12 13 14 15 16)
    9

def validEmptySidecarBytes : List Byte :=
  shieldedTransferSidecarBytes
    []
    []
    []
    []
    1
    [0, 0, 0, 0]
    2
    0
    []
    0

def shortSidecarBytes : List Byte :=
  (List.range 32).map (fun _ => 0)

def trailingSidecarBytes : List Byte :=
  validOneOutputSidecarBytes ++ [0xff]

def proofLengthOverrunBytes : List Byte :=
  compactSmall 4 ++ [1, 2, 3]

def ciphertextHashCountOverrunBytes : List Byte :=
  compactSmall 0
    ++ compactSmall 0
    ++ compactSmall 2
    ++ repeated 48 5

def ciphertextHashLengthOverrunBytes : List Byte :=
  compactSmall 0
    ++ compactSmall 0
    ++ compactSmall 1
    ++ repeated 47 5

def ciphertextSizeCountOverrunBytes : List Byte :=
  compactSmall 0
    ++ compactSmall 0
    ++ compactSmall 0
    ++ compactSmall 2
    ++ u32le 6

def ciphertextSizeLengthOverrunBytes : List Byte :=
  compactSmall 0
    ++ compactSmall 0
    ++ compactSmall 0
    ++ compactSmall 1
    ++ [6, 0, 0]

def noncanonicalProofPrefixBytes : List Byte :=
  [1, 0]
    ++ compactSmall 0
    ++ compactSmall 0
    ++ compactSmall 0
    ++ repeated 48 1
    ++ balanceSlotsBytes [0, 0, 0, 0]
    ++ repeated 64 2
    ++ [0]
    ++ u64le 0

def caseJson
    (name fixture : String)
    (input : ShieldedTransferSidecarScaleWireInput)
    (rawBytes : List Byte) : String :=
  let result := evaluateShieldedTransferSidecarScaleWireRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes rawBytes ++ "\",\n"
    ++ "      \"proof_compact_prefix_bytes\": "
    ++ toString input.proofCompactPrefixBytes ++ ",\n"
    ++ "      \"proof_bytes\": " ++ toString input.proofBytes ++ ",\n"
    ++ "      \"proof_compact_prefix_canonical\": "
    ++ boolJson input.proofCompactPrefixCanonical ++ ",\n"
    ++ "      \"commitment_compact_prefix_bytes\": "
    ++ toString input.commitmentCompactPrefixBytes ++ ",\n"
    ++ "      \"commitment_count\": "
    ++ toString input.commitmentCount ++ ",\n"
    ++ "      \"commitment_element_bytes\": "
    ++ toString input.commitmentElementBytes ++ ",\n"
    ++ "      \"commitment_compact_prefix_canonical\": "
    ++ boolJson input.commitmentCompactPrefixCanonical ++ ",\n"
    ++ "      \"ciphertext_hash_compact_prefix_bytes\": "
    ++ toString input.ciphertextHashCompactPrefixBytes ++ ",\n"
    ++ "      \"ciphertext_hash_count\": "
    ++ toString input.ciphertextHashCount ++ ",\n"
    ++ "      \"ciphertext_hash_element_bytes\": "
    ++ toString input.ciphertextHashElementBytes ++ ",\n"
    ++ "      \"ciphertext_hash_compact_prefix_canonical\": "
    ++ boolJson input.ciphertextHashCompactPrefixCanonical ++ ",\n"
    ++ "      \"ciphertext_size_compact_prefix_bytes\": "
    ++ toString input.ciphertextSizeCompactPrefixBytes ++ ",\n"
    ++ "      \"ciphertext_size_count\": "
    ++ toString input.ciphertextSizeCount ++ ",\n"
    ++ "      \"ciphertext_size_element_bytes\": "
    ++ toString input.ciphertextSizeElementBytes ++ ",\n"
    ++ "      \"ciphertext_size_compact_prefix_canonical\": "
    ++ boolJson input.ciphertextSizeCompactPrefixCanonical ++ ",\n"
    ++ "      \"anchor_bytes\": " ++ toString input.anchorBytes ++ ",\n"
    ++ "      \"balance_slot_count\": "
    ++ toString input.balanceSlotCount ++ ",\n"
    ++ "      \"balance_slot_bytes\": "
    ++ toString input.balanceSlotBytes ++ ",\n"
    ++ "      \"binding_hash_bytes\": "
    ++ toString input.bindingHashBytes ++ ",\n"
    ++ "      \"stablecoin_option_tag_bytes\": "
    ++ toString input.stablecoinOptionTagBytes ++ ",\n"
    ++ "      \"stablecoin_some_payload_bytes\": "
    ++ toString input.stablecoinSomePayloadBytes ++ ",\n"
    ++ "      \"fee_bytes\": " ++ toString input.feeBytes ++ ",\n"
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
    ++ "  \"shielded_transfer_sidecar_scale_wire_cases\": [\n"
    ++ caseJson "valid-one-output-sidecar"
      "valid_one_output_sidecar"
      validOneOutputSidecar
      validOneOutputSidecarBytes ++ ",\n"
    ++ caseJson "valid-empty-sidecar"
      "valid_empty_sidecar"
      validEmptySidecar
      validEmptySidecarBytes ++ ",\n"
    ++ caseJson "valid-stablecoin-sidecar"
      "valid_stablecoin_sidecar"
      validStablecoinSidecar
      validStablecoinSidecarBytes ++ ",\n"
    ++ caseJson "short-sidecar-rejected" "short_sidecar"
      { validOneOutputSidecar with
        totalBytes := 32,
        canonicalReencodeMatches := false }
      shortSidecarBytes ++ ",\n"
    ++ caseJson "trailing-byte-rejected" "trailing_sidecar"
      trailingByteCase trailingSidecarBytes ++ ",\n"
    ++ caseJson "proof-length-overrun-rejected"
      "proof_length_overrun"
      proofLengthOverrun
      proofLengthOverrunBytes ++ ",\n"
    ++ caseJson "ciphertext-hash-count-overrun-rejected"
      "ciphertext_hash_count_overrun"
      ciphertextHashCountOverrun
      ciphertextHashCountOverrunBytes ++ ",\n"
    ++ caseJson "ciphertext-hash-length-overrun-rejected"
      "ciphertext_hash_length_overrun"
      ciphertextHashLengthOverrun
      ciphertextHashLengthOverrunBytes ++ ",\n"
    ++ caseJson "ciphertext-size-count-overrun-rejected"
      "ciphertext_size_count_overrun"
      ciphertextSizeCountOverrun
      ciphertextSizeCountOverrunBytes ++ ",\n"
    ++ caseJson "ciphertext-size-length-overrun-rejected"
      "ciphertext_size_length_overrun"
      ciphertextSizeLengthOverrun
      ciphertextSizeLengthOverrunBytes ++ ",\n"
    ++ caseJson "noncanonical-proof-prefix-rejected"
      "noncanonical_proof_prefix"
      noncanonicalProofCompactPrefix
      noncanonicalProofPrefixBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
