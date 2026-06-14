import Hegemon.Consensus.StatementAnchorAdmission

open Hegemon.Consensus.StatementAnchorAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ toString first ++ rest.foldl (fun acc value => acc ++ ", " ++ toString value) "" ++ "]"

def boolArrayJson : List Bool -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ boolJson first ++ rest.foldl (fun acc value => acc ++ ", " ++ boolJson value) "" ++ "]"

def natArrayArrayJson : List (List Nat) -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ natArrayJson first ++ rest.foldl (fun acc value => acc ++ ", " ++ natArrayJson value) "" ++ "]"

def stringArrayJson : List String -> String
  | [] => "[]"
  | first :: rest =>
      "[\"" ++ first ++ "\"" ++ rest.foldl (fun acc value => acc ++ ", \"" ++ value ++ "\"") "" ++ "]"

def statementAnchorRejectJson : Option StatementAnchorAdmissionReject -> String
  | none => "null"
  | some StatementAnchorAdmissionReject.bindingCountMismatch => "\"binding_count_mismatch\""
  | some StatementAnchorAdmissionReject.unknownAnchor => "\"unknown_anchor\""

def statementAnchorAdmissionCaseJson
    (name : String)
    (input : StatementAnchorAdmissionInput)
    (treeDepth : Nat)
    (parentLeafSeeds : List Nat)
    (txCommitmentSeedGroups : List (List Nat))
    (anchorSources : List String)
    (anchorSourceIndexes : List Nat)
    (anchorSeedOverrides : List Nat) : String :=
  let rejection := evaluateStatementAnchorAdmission input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"tree_depth\": " ++ toString treeDepth ++ ",\n"
    ++ "      \"parent_leaf_seeds\": " ++ natArrayJson parentLeafSeeds ++ ",\n"
    ++ "      \"tx_commitment_seed_groups\": " ++ natArrayArrayJson txCommitmentSeedGroups ++ ",\n"
    ++ "      \"tx_count\": " ++ toString input.txCount ++ ",\n"
    ++ "      \"binding_count\": " ++ toString input.bindingCount ++ ",\n"
    ++ "      \"anchor_sources\": " ++ stringArrayJson anchorSources ++ ",\n"
    ++ "      \"anchor_source_indexes\": " ++ natArrayJson anchorSourceIndexes ++ ",\n"
    ++ "      \"anchor_seed_overrides\": " ++ natArrayJson anchorSeedOverrides ++ ",\n"
    ++ "      \"anchor_known_checks\": " ++ boolArrayJson input.anchorKnownChecks ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ statementAnchorRejectJson rejection ++ "\n"
    ++ "    }"

def emptyValidInput : StatementAnchorAdmissionInput :=
  {
    txCount := 0,
    bindingCount := 0,
    anchorKnownChecks := []
  }

def oneParentAnchorInput : StatementAnchorAdmissionInput :=
  {
    txCount := 1,
    bindingCount := 1,
    anchorKnownChecks := [true]
  }

def countMismatchInput : StatementAnchorAdmissionInput :=
  {
    txCount := 2,
    bindingCount := 1,
    anchorKnownChecks := [true]
  }

def unknownAnchorInput : StatementAnchorAdmissionInput :=
  {
    txCount := 1,
    bindingCount := 1,
    anchorKnownChecks := [false]
  }

def countPrecedesUnknownInput : StatementAnchorAdmissionInput :=
  {
    txCount := 2,
    bindingCount := 1,
    anchorKnownChecks := [false]
  }

def sameBlockAnchorInput : StatementAnchorAdmissionInput :=
  {
    txCount := 2,
    bindingCount := 2,
    anchorKnownChecks := [true, false]
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"statement_anchor_admission_cases\": [\n"
    ++ statementAnchorAdmissionCaseJson "valid-empty-block"
      emptyValidInput 4 [] [] [] [] [] ++ ",\n"
    ++ statementAnchorAdmissionCaseJson "valid-parent-root-anchor"
      oneParentAnchorInput 4 [] [[21]] ["parent_tree_root"] [0] [0] ++ ",\n"
    ++ statementAnchorAdmissionCaseJson "valid-retained-parent-history-anchor"
      oneParentAnchorInput 4 [31] [[32]] ["parent_history_index"] [0] [0] ++ ",\n"
    ++ statementAnchorAdmissionCaseJson "binding-count-mismatch-rejected"
      countMismatchInput 4 [] [[41], [42]] ["parent_tree_root"] [0] [0] ++ ",\n"
    ++ statementAnchorAdmissionCaseJson "unknown-anchor-rejected"
      unknownAnchorInput 4 [] [[51]] ["patterned_seed"] [0] [999] ++ ",\n"
    ++ statementAnchorAdmissionCaseJson "binding-count-precedes-unknown-anchor"
      countPrecedesUnknownInput 4 [] [[61], [62]] ["patterned_seed"] [0] [998] ++ ",\n"
    ++ statementAnchorAdmissionCaseJson "same-block-anchor-rejected"
      sameBlockAnchorInput 4 [] [[71], [72]] ["parent_tree_root", "after_tx_index"] [0, 0] [0, 0] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
