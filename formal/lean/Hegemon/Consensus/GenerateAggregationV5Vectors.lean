import Hegemon.Consensus.AggregationV5

open Hegemon.Consensus.AggregationV5

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def nodeKindJson : NodeKind -> String
  | NodeKind.leaf => "leaf"
  | NodeKind.merge => "merge"

def headerRejectJson : Option HeaderReject -> String
  | none => "null"
  | some HeaderReject.unsupportedVersion => "\"unsupported_version\""
  | some HeaderReject.unsupportedProofFormat => "\"unsupported_proof_format\""
  | some HeaderReject.unsupportedPublicValuesEncoding =>
      "\"unsupported_public_values_encoding\""
  | some HeaderReject.statementCommitmentLength => "\"statement_commitment_length\""
  | some HeaderReject.statementCommitmentMismatch => "\"statement_commitment_mismatch\""
  | some HeaderReject.childCountOutOfRange => "\"child_count_out_of_range\""
  | some HeaderReject.subtreeTxCountMismatch => "\"subtree_tx_count_mismatch\""
  | some HeaderReject.treeLevelsMismatch => "\"tree_levels_mismatch\""
  | some HeaderReject.rootLevelOutOfRange => "\"root_level_out_of_range\""
  | some HeaderReject.fanInZero => "\"fan_in_zero\""
  | some HeaderReject.leafFanInExceedsConfigured =>
      "\"leaf_fan_in_exceeds_configured\""
  | some HeaderReject.multilevelLeafFanInMismatch =>
      "\"multilevel_leaf_fan_in_mismatch\""
  | some HeaderReject.mergeFanInMismatch => "\"merge_fan_in_mismatch\""
  | some HeaderReject.innerPublicInputsLenMismatch =>
      "\"inner_public_inputs_len_mismatch\""

def aggregationV5HeaderCaseJson (name : String) (input : HeaderInput) : String :=
  let result := evaluateHeader input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"version\": " ++ toString input.version ++ ",\n"
    ++ "      \"proof_format\": " ++ toString input.proofFormat ++ ",\n"
    ++ "      \"node_kind\": \"" ++ nodeKindJson input.nodeKind ++ "\",\n"
    ++ "      \"fan_in\": " ++ toString input.fanIn ++ ",\n"
    ++ "      \"child_count\": " ++ toString input.childCount ++ ",\n"
    ++ "      \"subtree_tx_count\": " ++ toString input.subtreeTxCount ++ ",\n"
    ++ "      \"expected_tx_count\": " ++ toString input.expectedTxCount ++ ",\n"
    ++ "      \"tree_levels\": " ++ toString input.treeLevels ++ ",\n"
    ++ "      \"root_level\": " ++ toString input.rootLevel ++ ",\n"
    ++ "      \"statement_commitment_len\": "
    ++ toString input.statementCommitmentLen ++ ",\n"
    ++ "      \"statement_commitment_matches\": "
    ++ boolJson input.statementCommitmentMatches ++ ",\n"
    ++ "      \"public_values_encoding\": "
    ++ toString input.publicValuesEncoding ++ ",\n"
    ++ "      \"inner_public_inputs_len\": "
    ++ toString input.innerPublicInputsLen ++ ",\n"
    ++ "      \"packed_public_values_len\": "
    ++ toString input.packedPublicValuesLen ++ ",\n"
    ++ "      \"configured_leaf_fan_in\": "
    ++ toString input.configuredLeafFanIn ++ ",\n"
    ++ "      \"configured_merge_fan_in\": "
    ++ toString input.configuredMergeFanIn ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ headerRejectJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"aggregation_v5_header_cases\": [\n"
    ++ aggregationV5HeaderCaseJson
      "valid-leaf-singleton-header"
      validLeafSingletonHeader ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "valid-merge-header"
      validMergeHeader ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "bad-version-rejected"
      { validLeafSingletonHeader with version := 4 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "bad-proof-format-rejected"
      { validLeafSingletonHeader with proofFormat := 4 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "bad-public-values-encoding-rejected"
      { validLeafSingletonHeader with publicValuesEncoding := 1 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "bad-commitment-length-rejected"
      { validLeafSingletonHeader with statementCommitmentLen := 47 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "commitment-mismatch-rejected"
      { validLeafSingletonHeader with statementCommitmentMatches := false } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "zero-child-count-rejected"
      { validLeafSingletonHeader with childCount := 0 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "child-count-above-fan-in-rejected"
      { validLeafSingletonHeader with childCount := 2 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "subtree-tx-count-mismatch-rejected"
      { validLeafSingletonHeader with subtreeTxCount := 2 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "tree-levels-mismatch-rejected"
      { validMergeHeader with treeLevels := 2 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "root-level-out-of-range-rejected"
      { validLeafSingletonHeader with rootLevel := 1 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "zero-fan-in-child-bounds-rejected-first"
      { validLeafSingletonHeader with fanIn := 0, childCount := 0 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "leaf-fan-in-above-configured-rejected"
      { validMergeHeader with nodeKind := NodeKind.leaf, fanIn := 2, childCount := 2 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "merge-fan-in-mismatch-rejected"
      { validMergeHeader with fanIn := 1, childCount := 1 } ++ ",\n"
    ++ aggregationV5HeaderCaseJson
      "inner-public-inputs-length-mismatch-rejected"
      { validLeafSingletonHeader with packedPublicValuesLen := 2 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
