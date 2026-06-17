import Hegemon.Consensus.CommitmentTreeAppend

open Hegemon.Consensus.CommitmentTreeAppend

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ toString first ++ rest.foldl (fun acc value => acc ++ ", " ++ toString value) "" ++ "]"

def sideJson : SiblingSide -> String
  | SiblingSide.left => "\"left\""
  | SiblingSide.right => "\"right\""

def appendStepJson (step : AppendStep) : String :=
  "          {\n"
    ++ "            \"level\": " ++ toString step.level ++ ",\n"
    ++ "            \"position\": " ++ toString step.position ++ ",\n"
    ++ "            \"sibling_side\": " ++ sideJson step.siblingSide ++ ",\n"
    ++ "            \"sibling_is_default\": " ++ boolJson step.siblingIsDefault ++ "\n"
    ++ "          }"

def appendStepArrayJson : List AppendStep -> String
  | [] => "[]"
  | first :: rest =>
      "[\n" ++ appendStepJson first
        ++ rest.foldl (fun acc step => acc ++ ",\n" ++ appendStepJson step) ""
        ++ "\n        ]"

def appendSummaryJson (leafSeed : Nat) (summary : AppendSummary) : String :=
  "      {\n"
    ++ "        \"leaf_seed\": " ++ toString leafSeed ++ ",\n"
    ++ "        \"prior_leaf_count\": " ++ toString summary.priorLeafCount ++ ",\n"
    ++ "        \"leaf_index\": " ++ toString summary.leafIndex ++ ",\n"
    ++ "        \"result_leaf_count\": " ++ toString summary.resultLeafCount ++ ",\n"
    ++ "        \"prior_root_history_len\": " ++ toString summary.priorHistoryLen ++ ",\n"
    ++ "        \"root_history_len\": " ++ toString summary.resultHistoryLen ++ ",\n"
    ++ "        \"trace\": " ++ appendStepArrayJson summary.trace ++ "\n"
    ++ "      }"

def appendSummaryArrayJson
    (summariesWithSeeds : List (Nat × AppendSummary)) : String :=
  match summariesWithSeeds with
  | [] => "[]"
  | first :: rest =>
      "[\n" ++ appendSummaryJson first.fst first.snd
        ++ rest.foldl
          (fun acc item => acc ++ ",\n" ++ appendSummaryJson item.fst item.snd)
          ""
        ++ "\n    ]"

def appendCaseJson
    (name : String)
    (depth historyLimit : Nat)
    (initialLeafSeeds appendLeafSeeds : List Nat) : String :=
  let summaries := appendSummaries depth historyLimit initialLeafSeeds.length appendLeafSeeds.length
  let summariesWithSeeds := appendLeafSeeds.zip summaries
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"tree_depth\": " ++ toString depth ++ ",\n"
    ++ "      \"history_limit\": " ++ toString historyLimit ++ ",\n"
    ++ "      \"initial_leaf_seeds\": " ++ natArrayJson initialLeafSeeds ++ ",\n"
    ++ "      \"append_leaf_seeds\": " ++ natArrayJson appendLeafSeeds ++ ",\n"
    ++ "      \"expected_appends\": " ++ appendSummaryArrayJson summariesWithSeeds ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"append_cases\": [\n"
    ++ appendCaseJson "empty-tree-first-three-appends-depth4-history3" 4 3 [] [11, 12, 13] ++ ",\n"
    ++ appendCaseJson "preloaded-tree-crosses-history-window" 4 3 [21, 22, 23] [24, 25, 26, 27] ++ ",\n"
    ++ appendCaseJson "unbounded-history-zero-limit" 3 0 [] [31, 32] ++ ",\n"
    ++ appendCaseJson "depth-one-left-right-boundary" 1 2 [] [41, 42] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
