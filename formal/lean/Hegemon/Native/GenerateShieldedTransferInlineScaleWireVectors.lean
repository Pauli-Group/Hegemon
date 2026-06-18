import Hegemon.Bytes
import Hegemon.Native.ShieldedTransferInlineScaleWire

open Hegemon
open Hegemon.Native.ShieldedTransferInlineScaleWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option ShieldedTransferInlineScaleWireReject -> String
  | none => "null"
  | some ShieldedTransferInlineScaleWireReject.parserRejected =>
      "\"parser_rejected\""
  | some ShieldedTransferInlineScaleWireReject.trailingBytes =>
      "\"trailing_bytes\""
  | some ShieldedTransferInlineScaleWireReject.nonCanonicalEncoding =>
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

def encryptedNoteBytes
    (ciphertextValue : Nat)
    (kem : List Nat) : List Byte :=
  repeated 579 ciphertextValue
    ++ compactSmall kem.length
    ++ kem.map byte

def shieldedTransferInlineBytes
    (proof : List Nat)
    (commitmentValues : List Nat)
    (notes : List (List Byte))
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
    ++ compactSmall notes.length
    ++ concatNatBytes notes
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

def validOneOutputInlineBytes : List Byte :=
  shieldedTransferInlineBytes
    [1, 2, 3]
    [4]
    [encryptedNoteBytes 5 [6, 6, 6, 6, 6, 6, 6, 6,
      6, 6, 6, 6, 6, 6, 6, 6,
      6, 6, 6, 6, 6, 6, 6, 6,
      6, 6, 6, 6, 6, 6, 6, 6]]
    7
    [0, 1, 2, 3]
    8
    0
    []
    9

def validStablecoinInlineBytes : List Byte :=
  shieldedTransferInlineBytes
    [1, 2, 3]
    [4]
    [encryptedNoteBytes 5 [6, 6, 6, 6, 6, 6, 6, 6,
      6, 6, 6, 6, 6, 6, 6, 6,
      6, 6, 6, 6, 6, 6, 6, 6,
      6, 6, 6, 6, 6, 6, 6, 6]]
    7
    [0, 1, 2, 3]
    8
    1
    (stablecoinBindingBytes 11 12 13 14 15 16)
    9

def validEmptyInlineBytes : List Byte :=
  shieldedTransferInlineBytes
    []
    []
    []
    1
    [0, 0, 0, 0]
    2
    0
    []
    0

def shortInlineBytes : List Byte :=
  (List.range 32).map (fun _ => 0)

def trailingInlineBytes : List Byte :=
  validOneOutputInlineBytes ++ [0xff]

def proofLengthOverrunBytes : List Byte :=
  compactSmall 4 ++ [1, 2, 3]

def kemLengthOverrunBytes : List Byte :=
  compactSmall 0
    ++ compactSmall 0
    ++ compactSmall 1
    ++ repeated 579 5
    ++ compactSmall 33
    ++ repeated 32 6

def noncanonicalProofPrefixBytes : List Byte :=
  [1, 0]
    ++ compactSmall 0
    ++ compactSmall 0
    ++ repeated 48 1
    ++ balanceSlotsBytes [0, 0, 0, 0]
    ++ repeated 64 2
    ++ [0]
    ++ u64le 0

def caseJson
    (name fixture : String)
    (input : ShieldedTransferInlineScaleWireInput)
    (rawBytes : List Byte) : String :=
  let result := evaluateShieldedTransferInlineScaleWireRejection input
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
    ++ "      \"ciphertext_compact_prefix_bytes\": "
    ++ toString input.ciphertextCompactPrefixBytes ++ ",\n"
    ++ "      \"ciphertext_count\": "
    ++ toString input.ciphertextCount ++ ",\n"
    ++ "      \"encrypted_note_ciphertext_bytes\": "
    ++ toString input.encryptedNoteCiphertextBytes ++ ",\n"
    ++ "      \"kem_ciphertext_compact_prefix_bytes\": "
    ++ toString input.kemCiphertextCompactPrefixBytes ++ ",\n"
    ++ "      \"kem_ciphertext_bytes\": "
    ++ toString input.kemCiphertextBytes ++ ",\n"
    ++ "      \"ciphertext_compact_prefix_canonical\": "
    ++ boolJson input.ciphertextCompactPrefixCanonical ++ ",\n"
    ++ "      \"kem_ciphertext_compact_prefix_canonical\": "
    ++ boolJson input.kemCiphertextCompactPrefixCanonical ++ ",\n"
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
    ++ "  \"shielded_transfer_inline_scale_wire_cases\": [\n"
    ++ caseJson "valid-one-output-inline"
      "valid_one_output_inline"
      validOneOutputInline
      validOneOutputInlineBytes ++ ",\n"
    ++ caseJson "valid-empty-inline"
      "valid_empty_inline"
      validEmptyInline
      validEmptyInlineBytes ++ ",\n"
    ++ caseJson "valid-stablecoin-inline"
      "valid_stablecoin_inline"
      validStablecoinInline
      validStablecoinInlineBytes ++ ",\n"
    ++ caseJson "empty-bytes-rejected" "empty_bytes"
      { validOneOutputInline with
        totalBytes := 0,
        canonicalReencodeMatches := false }
      [] ++ ",\n"
    ++ caseJson "short-inline-rejected" "short_inline"
      { validOneOutputInline with
        totalBytes := 32,
        canonicalReencodeMatches := false }
      shortInlineBytes ++ ",\n"
    ++ caseJson "trailing-byte-rejected" "trailing_inline"
      trailingByteCase trailingInlineBytes ++ ",\n"
    ++ caseJson "proof-length-overrun-rejected"
      "proof_length_overrun"
      proofLengthOverrun
      proofLengthOverrunBytes ++ ",\n"
    ++ caseJson "kem-length-overrun-rejected"
      "kem_length_overrun"
      kemLengthOverrun
      kemLengthOverrunBytes ++ ",\n"
    ++ caseJson "noncanonical-proof-prefix-rejected"
      "noncanonical_proof_prefix"
      noncanonicalProofCompactPrefix
      noncanonicalProofPrefixBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
