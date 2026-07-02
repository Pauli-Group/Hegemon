import Hegemon.Consensus.RecursiveSemanticInputs

open Hegemon.Consensus.RecursiveSemanticInputs

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ toString first ++ rest.foldl (fun acc value => acc ++ ", " ++ toString value) "" ++ "]"

def semanticRejectJson : Option SemanticReject -> String
  | none => "null"
  | some SemanticReject.emptyBlock => "\"empty_block\""
  | some SemanticReject.excessiveNullifiers => "\"excessive_nullifiers\""
  | some SemanticReject.zeroNullifier => "\"zero_nullifier\""
  | some SemanticReject.missingNonzeroNullifier => "\"missing_nonzero_nullifier\""
  | some SemanticReject.duplicateNullifier => "\"duplicate_nullifier\""
  | some SemanticReject.daEncoding => "\"da_encoding\""

def semanticCaseJson (name : String) (input : SemanticDerivationInput)
    (parentLeafSeeds : List Nat)
    (source : SemanticSourceFields) : String :=
  let rejection := evaluateSemanticRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"tx_count\": " ++ toString input.txCount ++ ",\n"
    ++ "      \"nullifier_counts_within_max\": "
    ++ boolJson input.nullifierCountsWithinMax ++ ",\n"
    ++ "      \"has_zero_nullifier\": " ++ boolJson input.hasZeroNullifier ++ ",\n"
    ++ "      \"has_any_nonzero_nullifier\": "
    ++ boolJson input.hasAnyNonzeroNullifier ++ ",\n"
    ++ "      \"has_duplicate_nonzero_nullifier\": "
    ++ boolJson input.hasDuplicateNonzeroNullifier ++ ",\n"
    ++ "      \"da_encoding_valid\": " ++ boolJson input.daEncodingValid ++ ",\n"
    ++ "      \"parent_leaf_seeds\": " ++ natArrayJson parentLeafSeeds ++ ",\n"
    ++ "      \"expected_commitment_seed\": " ++ toString source.expectedCommitment ++ ",\n"
    ++ "      \"message_root_seed\": " ++ toString source.messageRoot ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ semanticRejectJson rejection ++ ",\n"
    ++ "      \"expected_tx_statements_source\": \"expected_commitment\",\n"
    ++ "      \"expected_start_shielded_source\": \"parent_tree_root\",\n"
    ++ "      \"expected_end_shielded_source\": \"applied_commitment_tree_root\",\n"
    ++ "      \"expected_start_kernel_source\": \"kernel_root(parent_tree_root)\",\n"
    ++ "      \"expected_end_kernel_source\": \"kernel_root(applied_commitment_tree_root)\",\n"
    ++ "      \"expected_nullifier_root_source\": \"nonzero_nullifier_set\",\n"
    ++ "      \"expected_da_root_source\": \"block_transactions_and_header_da_params\",\n"
    ++ "      \"expected_message_root_source\": \"header_message_root\",\n"
    ++ "      \"expected_start_tree_commitment_source\": \"parent_tree_recursive_state\",\n"
    ++ "      \"expected_end_tree_commitment_source\": \"applied_tree_recursive_state\"\n"
    ++ "    }"

def alternateSource : SemanticSourceFields :=
  { sampleSource with expectedCommitment := 18, messageRoot := 98 }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"semantic_cases\": [\n"
    ++ semanticCaseJson "valid-two-tx-default-parent" validInput [] sampleSource ++ ",\n"
    ++ semanticCaseJson "valid-one-tx-nondefault-parent" { validInput with txCount := 1 } [144]
      alternateSource ++ ",\n"
    ++ semanticCaseJson "empty-block-rejected" { validInput with txCount := 0 } [] sampleSource
      ++ ",\n"
    ++ semanticCaseJson "excessive-nullifiers-rejected"
      { validInput with nullifierCountsWithinMax := false } [] sampleSource ++ ",\n"
    ++ semanticCaseJson "zero-nullifier-rejected"
      { validInput with hasZeroNullifier := true } [] sampleSource ++ ",\n"
    ++ semanticCaseJson "missing-nonzero-nullifier-rejected"
      { validInput with hasAnyNonzeroNullifier := false } [] sampleSource ++ ",\n"
    ++ semanticCaseJson "duplicate-nullifier-rejected"
      { validInput with hasDuplicateNonzeroNullifier := true } [] sampleSource ++ ",\n"
    ++ semanticCaseJson "bad-da-params-rejected"
      { validInput with daEncodingValid := false } [] sampleSource ++ ",\n"
    ++ semanticCaseJson "duplicate-precedes-da-rejection"
      { validInput with hasDuplicateNonzeroNullifier := true, daEncodingValid := false }
      [] sampleSource ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
