import Hegemon.Bytes
import Hegemon.Native.PendingActionScaleWire

open Hegemon
open Hegemon.Native.PendingActionScaleWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option PendingActionScaleWireReject -> String
  | none => "null"
  | some PendingActionScaleWireReject.parserRejected => "\"parser_rejected\""
  | some PendingActionScaleWireReject.trailingBytes => "\"trailing_bytes\""
  | some PendingActionScaleWireReject.nonCanonicalEncoding =>
      "\"non_canonical_encoding\""

def compactSmall (value : Nat) : List Byte :=
  [byte (value * 4)]

def compactLen (value : Nat) : List Byte :=
  if value < 64 then
    [byte (value * 4)]
  else
    u16le (value * 4 + 1)

def repeated (length value : Nat) : List Byte :=
  List.replicate length (byte value)

def flattenBytes : List (List Byte) -> List Byte
  | [] => []
  | row :: rest => row ++ flattenBytes rest

def noCandidatePendingActionBytes
    (txValue circuit crypto family action anchorValue : Nat)
    (nullifierValues commitmentValues ciphertextHashValues : List Nat)
    (ciphertextSizes publicArgs : List Nat)
    (fee receivedMs : Nat) : List Byte :=
  repeated 32 txValue
    ++ u16le circuit
    ++ u16le crypto
    ++ u16le family
    ++ u16le action
    ++ repeated 48 anchorValue
    ++ compactLen nullifierValues.length
    ++ flattenBytes (nullifierValues.map (repeated 48))
    ++ compactLen commitmentValues.length
    ++ flattenBytes (commitmentValues.map (repeated 48))
    ++ compactLen ciphertextHashValues.length
    ++ flattenBytes (ciphertextHashValues.map (repeated 48))
    ++ compactLen ciphertextSizes.length
    ++ flattenBytes (ciphertextSizes.map u32le)
    ++ compactLen publicArgs.length
    ++ publicArgs.map byte
    ++ u64le fee
    ++ [0]
    ++ u64le receivedMs

def candidateArtifactRecursiveBlockPayloadBytes
    (version txCount txStatementsCommitmentValue daRootValue daChunkCount
      verifierProfileValue : Nat)
    (recursiveProof : List Nat) : List Byte :=
  [byte version]
    ++ u32le txCount
    ++ repeated 48 txStatementsCommitmentValue
    ++ repeated 48 daRootValue
    ++ u32le daChunkCount
    ++ compactLen 0
    ++ [2]
    ++ [4]
    ++ repeated 48 verifierProfileValue
    ++ [0]
    ++ [1]
    ++ compactLen recursiveProof.length
    ++ recursiveProof.map byte

def someCandidatePendingActionBytes
    (txValue circuit crypto family action anchorValue : Nat)
    (nullifierValues commitmentValues ciphertextHashValues : List Nat)
    (ciphertextSizes publicArgs : List Nat)
    (fee receivedMs : Nat)
    (candidatePayload : List Byte) : List Byte :=
  repeated 32 txValue
    ++ u16le circuit
    ++ u16le crypto
    ++ u16le family
    ++ u16le action
    ++ repeated 48 anchorValue
    ++ compactLen nullifierValues.length
    ++ flattenBytes (nullifierValues.map (repeated 48))
    ++ compactLen commitmentValues.length
    ++ flattenBytes (commitmentValues.map (repeated 48))
    ++ compactLen ciphertextHashValues.length
    ++ flattenBytes (ciphertextHashValues.map (repeated 48))
    ++ compactLen ciphertextSizes.length
    ++ flattenBytes (ciphertextSizes.map u32le)
    ++ compactLen publicArgs.length
    ++ publicArgs.map byte
    ++ u64le fee
    ++ [1]
    ++ candidatePayload
    ++ u64le receivedMs

def validEmptyBytes : List Byte :=
  noCandidatePendingActionBytes
    0 0 0 0 0 0
    [] [] [] [] [] 0 0

def validOneEachBytes : List Byte :=
  noCandidatePendingActionBytes
    9 7 8 10 11 12
    [1] [2] [3] [4] [0xaa, 0xbb, 0xcc] 5 6

def validCandidatePayloadBytes : List Byte :=
  candidateArtifactRecursiveBlockPayloadBytes
    2 1 5 6 1 7 (List.replicate 32 8)

def validCandidateSomeBytes : List Byte :=
  someCandidatePendingActionBytes
    13 0 0 1 5 0
    [] [] [] [] validCandidatePayloadBytes 0 9
    validCandidatePayloadBytes

def replaceAt : Nat -> Byte -> List Byte -> List Byte
  | _idx, _value, [] => []
  | 0, value, _head :: tail => value :: tail
  | idx + 1, value, head :: tail =>
      head :: replaceAt idx value tail

def insertAt : Nat -> Byte -> List Byte -> List Byte
  | _idx, value, [] => [value]
  | 0, value, xs => value :: xs
  | idx + 1, value, head :: tail =>
      head :: insertAt idx value tail

def shortEmptyBytes : List Byte :=
  (List.range 109).map (fun _ => 0)

def trailingEmptyBytes : List Byte :=
  validEmptyBytes ++ [0xaa]

def invalidOptionTagBytes : List Byte :=
  replaceAt 101 2 validEmptyBytes

def noncanonicalNullifierZeroPrefixBytes : List Byte :=
  insertAt 89 0 (replaceAt 88 1 validEmptyBytes)

def nullifierCountOverrunBytes : List Byte :=
  replaceAt 88 8 validOneEachBytes

def publicArgsMissingBytes : List Byte :=
  replaceAt 92 4 validEmptyBytes

def candidateSomeTruncatedBytes : List Byte :=
  replaceAt 101 1 validEmptyBytes

def trailingCandidateSomeBytes : List Byte :=
  validCandidateSomeBytes ++ [0xaa]

def candidateSomeInvalidProofModeBytes : List Byte :=
  replaceAt 400 7 validCandidateSomeBytes

def candidateSomeInvalidProofKindBytes : List Byte :=
  replaceAt 401 9 validCandidateSomeBytes

def candidateSomeRecursiveProofOverrunBytes : List Byte :=
  replaceAt 452 (byte (33 * 4)) validCandidateSomeBytes

def caseJson
    (name fixture : String)
    (input : PendingActionScaleWireInput)
    (rawBytes : List Byte) : String :=
  let result := evaluatePendingActionScaleWireRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes rawBytes ++ "\",\n"
    ++ "      \"tx_hash_bytes\": " ++ toString input.txHashBytes ++ ",\n"
    ++ "      \"binding_bytes\": " ++ toString input.bindingBytes ++ ",\n"
    ++ "      \"family_id_bytes\": " ++ toString input.familyIdBytes ++ ",\n"
    ++ "      \"action_id_bytes\": " ++ toString input.actionIdBytes ++ ",\n"
    ++ "      \"anchor_bytes\": " ++ toString input.anchorBytes ++ ",\n"
    ++ "      \"nullifier_count\": " ++ toString input.nullifierCount ++ ",\n"
    ++ "      \"nullifier_element_bytes\": "
    ++ toString input.nullifierElementBytes ++ ",\n"
    ++ "      \"commitment_count\": " ++ toString input.commitmentCount ++ ",\n"
    ++ "      \"commitment_element_bytes\": "
    ++ toString input.commitmentElementBytes ++ ",\n"
    ++ "      \"ciphertext_hash_count\": "
    ++ toString input.ciphertextHashCount ++ ",\n"
    ++ "      \"ciphertext_hash_element_bytes\": "
    ++ toString input.ciphertextHashElementBytes ++ ",\n"
    ++ "      \"ciphertext_size_count\": "
    ++ toString input.ciphertextSizeCount ++ ",\n"
    ++ "      \"ciphertext_size_element_bytes\": "
    ++ toString input.ciphertextSizeElementBytes ++ ",\n"
    ++ "      \"public_args_bytes\": "
    ++ toString input.publicArgsBytes ++ ",\n"
    ++ "      \"public_args_compact_prefix_bytes\": "
    ++ toString input.publicArgsCompactPrefixBytes ++ ",\n"
    ++ "      \"compact_prefixes_canonical\": "
    ++ boolJson input.compactPrefixesCanonical ++ ",\n"
    ++ "      \"fee_bytes\": " ++ toString input.feeBytes ++ ",\n"
    ++ "      \"candidate_option_tag_bytes\": "
    ++ toString input.candidateOptionTagBytes ++ ",\n"
    ++ "      \"candidate_artifact_none\": "
    ++ boolJson input.candidateArtifactNone ++ ",\n"
    ++ "      \"candidate_artifact_payload_bytes\": "
    ++ toString input.candidateArtifactPayloadBytes ++ ",\n"
    ++ "      \"candidate_artifact_version_bytes\": "
    ++ toString input.candidateArtifactVersionBytes ++ ",\n"
    ++ "      \"candidate_artifact_tx_count_bytes\": "
    ++ toString input.candidateArtifactTxCountBytes ++ ",\n"
    ++ "      \"candidate_artifact_tx_statements_commitment_bytes\": "
    ++ toString input.candidateArtifactTxStatementsCommitmentBytes ++ ",\n"
    ++ "      \"candidate_artifact_da_root_bytes\": "
    ++ toString input.candidateArtifactDaRootBytes ++ ",\n"
    ++ "      \"candidate_artifact_da_chunk_count_bytes\": "
    ++ toString input.candidateArtifactDaChunkCountBytes ++ ",\n"
    ++ "      \"candidate_artifact_commitment_proof_bytes\": "
    ++ toString input.candidateArtifactCommitmentProofBytes ++ ",\n"
    ++ "      \"candidate_artifact_proof_mode_bytes\": "
    ++ toString input.candidateArtifactProofModeBytes ++ ",\n"
    ++ "      \"candidate_artifact_proof_kind_bytes\": "
    ++ toString input.candidateArtifactProofKindBytes ++ ",\n"
    ++ "      \"candidate_artifact_verifier_profile_bytes\": "
    ++ toString input.candidateArtifactVerifierProfileBytes ++ ",\n"
    ++ "      \"candidate_artifact_receipt_root_option_tag_bytes\": "
    ++ toString input.candidateArtifactReceiptRootOptionTagBytes ++ ",\n"
    ++ "      \"candidate_artifact_receipt_root_none\": "
    ++ boolJson input.candidateArtifactReceiptRootNone ++ ",\n"
    ++ "      \"candidate_artifact_recursive_block_option_tag_bytes\": "
    ++ toString input.candidateArtifactRecursiveBlockOptionTagBytes ++ ",\n"
    ++ "      \"candidate_artifact_recursive_block_present\": "
    ++ boolJson input.candidateArtifactRecursiveBlockPresent ++ ",\n"
    ++ "      \"candidate_artifact_recursive_proof_bytes\": "
    ++ toString input.candidateArtifactRecursiveProofBytes ++ ",\n"
    ++ "      \"received_ms_bytes\": "
    ++ toString input.receivedMsBytes ++ ",\n"
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
    ++ "  \"pending_action_scale_wire_cases\": [\n"
    ++ caseJson "valid-empty-no-candidate" "valid_empty_no_candidate"
      validEmptyNoCandidate validEmptyBytes ++ ",\n"
    ++ caseJson "valid-one-each-no-candidate" "valid_one_each_no_candidate"
      validOneEachNoCandidate validOneEachBytes ++ ",\n"
    ++ caseJson "valid-candidate-artifact-some" "valid_candidate_artifact_some"
      validCandidateArtifactSome validCandidateSomeBytes ++ ",\n"
    ++ caseJson "empty-bytes-rejected" "empty_bytes"
      { validEmptyNoCandidate with
        totalBytes := 0,
        canonicalReencodeMatches := false }
      [] ++ ",\n"
    ++ caseJson "short-empty-no-candidate-rejected" "short_empty_no_candidate"
      { validEmptyNoCandidate with
        totalBytes := 109,
        canonicalReencodeMatches := false }
      shortEmptyBytes ++ ",\n"
    ++ caseJson "trailing-empty-no-candidate-rejected"
      "trailing_empty_no_candidate"
      trailingByteCase trailingEmptyBytes ++ ",\n"
    ++ caseJson "invalid-option-tag-rejected" "invalid_option_tag"
      { validEmptyNoCandidate with
        candidateArtifactNone := false,
        canonicalReencodeMatches := false }
      invalidOptionTagBytes ++ ",\n"
    ++ caseJson "noncanonical-nullifier-zero-prefix-rejected"
      "noncanonical_nullifier_zero_prefix"
      { validEmptyNoCandidate with compactPrefixesCanonical := false }
      noncanonicalNullifierZeroPrefixBytes ++ ",\n"
    ++ caseJson "nullifier-count-overrun-rejected"
      "nullifier_count_overrun"
      malformedNullifierCountOverrun
      nullifierCountOverrunBytes ++ ",\n"
    ++ caseJson "public-args-missing-rejected" "public_args_missing"
      { validEmptyNoCandidate with
        publicArgsBytes := 1,
        totalBytes := pendingActionNoCandidateEncodedLen 0 0 0 0 0,
        canonicalReencodeMatches := false }
      publicArgsMissingBytes ++ ",\n"
    ++ caseJson "candidate-some-truncated-rejected"
      "candidate_some_truncated"
      candidateSomeMissingPayload
      candidateSomeTruncatedBytes ++ ",\n"
    ++ caseJson "trailing-candidate-some-rejected"
      "trailing_candidate_some"
      { validCandidateArtifactSome with consumedAllBytes := false }
      trailingCandidateSomeBytes ++ ",\n"
    ++ caseJson "candidate-some-invalid-proof-mode-rejected"
      "candidate_some_invalid_proof_mode"
      { validCandidateArtifactSome with
        candidateArtifactProofModeBytes := 0,
        canonicalReencodeMatches := false }
      candidateSomeInvalidProofModeBytes ++ ",\n"
    ++ caseJson "candidate-some-invalid-proof-kind-rejected"
      "candidate_some_invalid_proof_kind"
      { validCandidateArtifactSome with
        candidateArtifactProofKindBytes := 0,
        canonicalReencodeMatches := false }
      candidateSomeInvalidProofKindBytes ++ ",\n"
    ++ caseJson "candidate-some-recursive-proof-overrun-rejected"
      "candidate_some_recursive_proof_overrun"
      { validCandidateArtifactSome with
        candidateArtifactRecursiveProofBytes := 33,
        canonicalReencodeMatches := false }
      candidateSomeRecursiveProofOverrunBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
