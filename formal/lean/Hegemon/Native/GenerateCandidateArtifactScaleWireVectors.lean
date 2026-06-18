import Hegemon.Bytes
import Hegemon.Native.CandidateArtifactScaleWire

open Hegemon
open Hegemon.Native.CandidateArtifactScaleWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option CandidateArtifactScaleWireReject -> String
  | none => "null"
  | some CandidateArtifactScaleWireReject.parserRejected => "\"parser_rejected\""
  | some CandidateArtifactScaleWireReject.trailingBytes => "\"trailing_bytes\""
  | some CandidateArtifactScaleWireReject.nonCanonicalEncoding =>
      "\"non_canonical_encoding\""

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

def starkProofBytes (proof : List Nat) : List Byte :=
  compactLen proof.length ++ proof.map byte

def txValidityReceiptBytes
    (statementHashValue proofDigestValue publicInputsDigestValue
      verifierProfileValue : Nat) : List Byte :=
  repeated 48 statementHashValue
    ++ repeated 48 proofDigestValue
    ++ repeated 48 publicInputsDigestValue
    ++ repeated 48 verifierProfileValue

def receiptRootProofPayloadBytes
    (rootProof : List Nat)
    (relationIdValue shapeDigestValue leafCount foldCount : Nat)
    (receipts : List (List Byte)) : List Byte :=
  starkProofBytes rootProof
    ++ repeated 32 relationIdValue
    ++ repeated 32 shapeDigestValue
    ++ u32le leafCount
    ++ u32le foldCount
    ++ compactLen receipts.length
    ++ flattenBytes receipts

def candidateArtifactRecursiveBlockBytes
    (version txCount txStatementsCommitmentValue daRootValue daChunkCount
      verifierProfileValue : Nat)
    (proofKindBytes recursiveProof : List Nat) : List Byte :=
  [byte version]
    ++ u32le txCount
    ++ repeated 48 txStatementsCommitmentValue
    ++ repeated 48 daRootValue
    ++ u32le daChunkCount
    ++ compactLen 0
    ++ [2]
    ++ proofKindBytes.map byte
    ++ repeated 48 verifierProfileValue
    ++ [0]
    ++ [1]
    ++ starkProofBytes recursiveProof

def candidateArtifactReceiptRootBytes
    (version txCount txStatementsCommitmentValue daRootValue daChunkCount
      verifierProfileValue : Nat)
    (rootProof : List Nat)
    (relationIdValue shapeDigestValue leafCount foldCount : Nat)
    (receipts : List (List Byte)) : List Byte :=
  [byte version]
    ++ u32le txCount
    ++ repeated 48 txStatementsCommitmentValue
    ++ repeated 48 daRootValue
    ++ u32le daChunkCount
    ++ compactLen 0
    ++ [1]
    ++ [2]
    ++ repeated 48 verifierProfileValue
    ++ [1]
    ++ receiptRootProofPayloadBytes
      rootProof
      relationIdValue
      shapeDigestValue
      leafCount
      foldCount
      receipts
    ++ [0]

def validRecursiveBlockV2Bytes : List Byte :=
  candidateArtifactRecursiveBlockBytes
    2 1 5 6 1 7 [4] (List.replicate 32 8)

def validReceiptRootReceiptBytes : List Byte :=
  txValidityReceiptBytes 0x31 0x32 0x33 0x34

def validReceiptRootBytes : List Byte :=
  candidateArtifactReceiptRootBytes
    2 1 0x15 0x16 1 0x17
    [0x21, 0x22, 0x23]
    0x24 0x25 1 0
    [validReceiptRootReceiptBytes]

def validCustomProofKindBytes : List Byte :=
  candidateArtifactRecursiveBlockBytes
    2 1 5 6 1 7
    ([5] ++ List.replicate 16 0x42)
    (List.replicate 32 8)

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

def shortRecursiveBlockV2Bytes : List Byte :=
  (List.range 10).map (fun _ => 0)

def trailingRecursiveBlockV2Bytes : List Byte :=
  validRecursiveBlockV2Bytes ++ [0xaa]

def invalidProofModeBytes : List Byte :=
  replaceAt 106 7 validRecursiveBlockV2Bytes

def invalidProofKindBytes : List Byte :=
  replaceAt 107 9 validRecursiveBlockV2Bytes

def noncanonicalCommitmentProofPrefixBytes : List Byte :=
  insertAt 106 0 (replaceAt 105 1 validRecursiveBlockV2Bytes)

def recursiveProofOverrunBytes : List Byte :=
  replaceAt 158 (byte (33 * 4)) validRecursiveBlockV2Bytes

def receiptRootReceiptCountOffset (rootProofLength : Nat) : Nat :=
  1 + 4 + 48 + 48 + 4
    + 1 + 1 + 1 + 48
    + 1 + (compactLen rootProofLength).length + rootProofLength
    + 32 + 32 + 4 + 4

def receiptCountOverrunBytes : List Byte :=
  replaceAt
    (receiptRootReceiptCountOffset 3)
    (byte (2 * 4))
    validReceiptRootBytes

def caseJson
    (name fixture : String)
    (input : CandidateArtifactScaleWireInput)
    (rawBytes : List Byte) : String :=
  let result := evaluateCandidateArtifactScaleWireRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes rawBytes ++ "\",\n"
    ++ "      \"version_bytes\": " ++ toString input.versionBytes ++ ",\n"
    ++ "      \"tx_count_bytes\": " ++ toString input.txCountBytes ++ ",\n"
    ++ "      \"tx_statements_commitment_bytes\": "
    ++ toString input.txStatementsCommitmentBytes ++ ",\n"
    ++ "      \"da_root_bytes\": " ++ toString input.daRootBytes ++ ",\n"
    ++ "      \"da_chunk_count_bytes\": "
    ++ toString input.daChunkCountBytes ++ ",\n"
    ++ "      \"commitment_proof_compact_prefix_bytes\": "
    ++ toString input.commitmentProofCompactPrefixBytes ++ ",\n"
    ++ "      \"commitment_proof_bytes\": "
    ++ toString input.commitmentProofBytes ++ ",\n"
    ++ "      \"proof_mode_bytes\": " ++ toString input.proofModeBytes ++ ",\n"
    ++ "      \"proof_mode_tag_valid\": "
    ++ boolJson input.proofModeTagValid ++ ",\n"
    ++ "      \"proof_kind_bytes\": " ++ toString input.proofKindBytes ++ ",\n"
    ++ "      \"proof_kind_tag_valid\": "
    ++ boolJson input.proofKindTagValid ++ ",\n"
    ++ "      \"verifier_profile_bytes\": "
    ++ toString input.verifierProfileBytes ++ ",\n"
    ++ "      \"receipt_root_option_tag_bytes\": "
    ++ toString input.receiptRootOptionTagBytes ++ ",\n"
    ++ "      \"receipt_root_option_tag_valid\": "
    ++ boolJson input.receiptRootOptionTagValid ++ ",\n"
    ++ "      \"receipt_root_none\": "
    ++ boolJson input.receiptRootNone ++ ",\n"
    ++ "      \"receipt_root_proof_compact_prefix_bytes\": "
    ++ toString input.receiptRootProofCompactPrefixBytes ++ ",\n"
    ++ "      \"receipt_root_proof_bytes\": "
    ++ toString input.receiptRootProofBytes ++ ",\n"
    ++ "      \"receipt_root_relation_id_bytes\": "
    ++ toString input.receiptRootRelationIdBytes ++ ",\n"
    ++ "      \"receipt_root_shape_digest_bytes\": "
    ++ toString input.receiptRootShapeDigestBytes ++ ",\n"
    ++ "      \"receipt_root_leaf_count_bytes\": "
    ++ toString input.receiptRootLeafCountBytes ++ ",\n"
    ++ "      \"receipt_root_fold_count_bytes\": "
    ++ toString input.receiptRootFoldCountBytes ++ ",\n"
    ++ "      \"receipt_root_receipt_compact_prefix_bytes\": "
    ++ toString input.receiptRootReceiptCompactPrefixBytes ++ ",\n"
    ++ "      \"receipt_root_receipt_count\": "
    ++ toString input.receiptRootReceiptCount ++ ",\n"
    ++ "      \"receipt_root_receipt_element_bytes\": "
    ++ toString input.receiptRootReceiptElementBytes ++ ",\n"
    ++ "      \"recursive_block_option_tag_bytes\": "
    ++ toString input.recursiveBlockOptionTagBytes ++ ",\n"
    ++ "      \"recursive_block_option_tag_valid\": "
    ++ boolJson input.recursiveBlockOptionTagValid ++ ",\n"
    ++ "      \"recursive_block_present\": "
    ++ boolJson input.recursiveBlockPresent ++ ",\n"
    ++ "      \"recursive_proof_compact_prefix_bytes\": "
    ++ toString input.recursiveProofCompactPrefixBytes ++ ",\n"
    ++ "      \"recursive_proof_bytes\": "
    ++ toString input.recursiveProofBytes ++ ",\n"
    ++ "      \"compact_prefixes_canonical\": "
    ++ boolJson input.compactPrefixesCanonical ++ ",\n"
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
    ++ "  \"candidate_artifact_scale_wire_cases\": [\n"
    ++ caseJson "valid-recursive-block-v2"
      "valid_recursive_block_v2"
      validRecursiveBlockV2
      validRecursiveBlockV2Bytes ++ ",\n"
    ++ caseJson "valid-receipt-root"
      "valid_receipt_root"
      validReceiptRoot
      validReceiptRootBytes ++ ",\n"
    ++ caseJson "valid-custom-proof-kind"
      "valid_custom_proof_kind"
      validCustomProofKind
      validCustomProofKindBytes ++ ",\n"
    ++ caseJson "trailing-recursive-block-v2-rejected"
      "trailing_recursive_block_v2"
      trailingRecursiveBlockV2
      trailingRecursiveBlockV2Bytes ++ ",\n"
    ++ caseJson "truncated-recursive-block-v2-rejected"
      "truncated_recursive_block_v2"
      truncatedRecursiveBlockV2
      shortRecursiveBlockV2Bytes ++ ",\n"
    ++ caseJson "invalid-proof-mode-rejected"
      "invalid_proof_mode"
      invalidProofMode
      invalidProofModeBytes ++ ",\n"
    ++ caseJson "invalid-proof-kind-rejected"
      "invalid_proof_kind"
      invalidProofKind
      invalidProofKindBytes ++ ",\n"
    ++ caseJson "noncanonical-commitment-proof-prefix-rejected"
      "noncanonical_commitment_proof_prefix"
      noncanonicalCommitmentProofPrefix
      noncanonicalCommitmentProofPrefixBytes ++ ",\n"
    ++ caseJson "recursive-proof-overrun-rejected"
      "recursive_proof_overrun"
      recursiveProofOverrun
      recursiveProofOverrunBytes ++ ",\n"
    ++ caseJson "receipt-count-overrun-rejected"
      "receipt_count_overrun"
      receiptCountOverrun
      receiptCountOverrunBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
