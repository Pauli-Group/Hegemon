import Hegemon.Consensus.TreeTransition

open Hegemon.Consensus.TreeTransition

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ toString first ++ rest.foldl (fun acc value => acc ++ ", " ++ toString value) "" ++ "]"

def natArrayArrayJson : List (List Nat) -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ natArrayJson first ++ rest.foldl (fun acc value => acc ++ ", " ++ natArrayJson value) "" ++ "]"

def treeTransitionRejectJson : Option TreeTransitionReject -> String
  | none => "null"
  | some TreeTransitionReject.startingRootMismatch => "\"starting_root_mismatch\""
  | some TreeTransitionReject.applyFailed => "\"apply_failed\""
  | some TreeTransitionReject.endingRootMismatch => "\"ending_root_mismatch\""

def optionalStringJson : Option String -> String
  | none => "null"
  | some value => "\"" ++ value ++ "\""

def treeTransitionCaseJson
    (name : String)
    (input : TreeTransitionInput)
    (treeDepth : Nat)
    (parentLeafSeeds : List Nat)
    (txCommitmentSeedGroups : List (List Nat))
    (proofStartingRootSource : String)
    (proofStartingRootSeed : Nat)
    (proofEndingRootSource : String)
    (proofEndingRootSeed : Nat) : String :=
  let rejection := evaluateTreeTransition input
  let resultRootSource :=
    if rejection == none then
      some "applied_commitment_tree_root"
    else
      none
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"tree_depth\": " ++ toString treeDepth ++ ",\n"
    ++ "      \"parent_leaf_seeds\": " ++ natArrayJson parentLeafSeeds ++ ",\n"
    ++ "      \"tx_commitment_seed_groups\": " ++ natArrayArrayJson txCommitmentSeedGroups ++ ",\n"
    ++ "      \"proof_starting_root_source\": \"" ++ proofStartingRootSource ++ "\",\n"
    ++ "      \"proof_starting_root_seed\": " ++ toString proofStartingRootSeed ++ ",\n"
    ++ "      \"proof_ending_root_source\": \"" ++ proofEndingRootSource ++ "\",\n"
    ++ "      \"proof_ending_root_seed\": " ++ toString proofEndingRootSeed ++ ",\n"
    ++ "      \"apply_commitments_succeeds\": " ++ boolJson input.applyCommitmentsSucceeds ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ treeTransitionRejectJson rejection ++ ",\n"
    ++ "      \"expected_result_root_source\": " ++ optionalStringJson resultRootSource ++ "\n"
    ++ "    }"

def emptyValidInput : TreeTransitionInput :=
  {
    parentRoot := 22,
    appliedRoot := 22,
    proofStartingRoot := 22,
    proofEndingRoot := 22,
    applyCommitmentsSucceeds := true
  }

def applyFailureInput : TreeTransitionInput :=
  {
    parentRoot := 31,
    appliedRoot := 32,
    proofStartingRoot := 31,
    proofEndingRoot := 32,
    applyCommitmentsSucceeds := false
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"tree_transition_cases\": [\n"
    ++ treeTransitionCaseJson "valid-empty-block" emptyValidInput 4 [] [] "parent_tree_root" 0
      "applied_commitment_tree_root" 0 ++ ",\n"
    ++ treeTransitionCaseJson "valid-one-commitment" validInput 4 [] [[21]]
      "parent_tree_root" 0 "applied_commitment_tree_root" 0 ++ ",\n"
    ++ treeTransitionCaseJson "valid-zero-commitment-ignored" validInput 4 [] [[0, 22]]
      "parent_tree_root" 0 "applied_commitment_tree_root" 0 ++ ",\n"
    ++ treeTransitionCaseJson "starting-root-mismatch-rejected"
      { validInput with proofStartingRoot := 99 } 4 [] [[23]]
      "patterned_seed" 99 "applied_commitment_tree_root" 0 ++ ",\n"
    ++ treeTransitionCaseJson "tree-append-failure-rejected" applyFailureInput 1 [31, 32] [[33]]
      "parent_tree_root" 0 "patterned_seed" 77 ++ ",\n"
    ++ treeTransitionCaseJson "ending-root-mismatch-rejected"
      { validInput with proofEndingRoot := 99 } 4 [] [[24]]
      "parent_tree_root" 0 "patterned_seed" 99 ++ ",\n"
    ++ treeTransitionCaseJson "starting-root-precedes-append-failure"
      { applyFailureInput with proofStartingRoot := 99 } 1 [41, 42] [[43]]
      "patterned_seed" 99 "patterned_seed" 77 ++ ",\n"
    ++ treeTransitionCaseJson "append-failure-precedes-ending-mismatch"
      { applyFailureInput with proofEndingRoot := 99 } 1 [51, 52] [[53]]
      "parent_tree_root" 0 "patterned_seed" 99 ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
