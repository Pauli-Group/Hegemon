import Hegemon.Consensus.RecursivePublicReplay

open Hegemon.Consensus.RecursivePublicReplay

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ toString first ++ rest.foldl (fun acc value => acc ++ ", " ++ toString value) "" ++ "]"

def replayVersionJson : ReplayVersion -> String
  | ReplayVersion.v1 => "recursive_block_v1"
  | ReplayVersion.v2 => "recursive_block_v2"

def replayRejectJson : Option ReplayReject -> String
  | none => "null"
  | some ReplayReject.txIndexGap => "\"tx_index_gap\""

def semanticJson (semantic : SemanticFields) : String :=
  "      \"tx_statements_commitment_seed\": " ++ toString semantic.txStatementsCommitment ++ ",\n"
    ++ "      \"start_shielded_root_seed\": " ++ toString semantic.startShieldedRoot ++ ",\n"
    ++ "      \"end_shielded_root_seed\": " ++ toString semantic.endShieldedRoot ++ ",\n"
    ++ "      \"start_kernel_root_seed\": " ++ toString semantic.startKernelRoot ++ ",\n"
    ++ "      \"end_kernel_root_seed\": " ++ toString semantic.endKernelRoot ++ ",\n"
    ++ "      \"nullifier_root_seed\": " ++ toString semantic.nullifierRoot ++ ",\n"
    ++ "      \"da_root_seed\": " ++ toString semantic.daRoot ++ ",\n"
    ++ "      \"message_root_seed\": " ++ toString semantic.messageRoot ++ ",\n"
    ++ "      \"start_tree_commitment_seed\": " ++ toString semantic.startTreeCommitment ++ ",\n"
    ++ "      \"end_tree_commitment_seed\": " ++ toString semantic.endTreeCommitment ++ ",\n"

def replayCaseJson (name : String) (version : ReplayVersion) (txIndices : List Nat)
    (semantic : SemanticFields) : String :=
  let rejection := evaluateReplayRejection txIndices
  let publicBytesLen := match version with
    | ReplayVersion.v1 => v1PublicBytesLen
    | ReplayVersion.v2 => v2PublicBytesLen
  let carriesMessageRoot := match version with
    | ReplayVersion.v1 => true
    | ReplayVersion.v2 => false
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"version\": \"" ++ replayVersionJson version ++ "\",\n"
    ++ "      \"tx_indices\": " ++ natArrayJson txIndices ++ ",\n"
    ++ semanticJson semantic
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ replayRejectJson rejection ++ ",\n"
    ++ "      \"expected_tx_count\": " ++ toString txIndices.length ++ ",\n"
    ++ "      \"expected_public_bytes_len\": " ++ toString publicBytesLen ++ ",\n"
    ++ "      \"expected_carries_message_root\": " ++ boolJson carriesMessageRoot ++ "\n"
    ++ "    }"

def altSemantic : SemanticFields :=
  { sampleSemantic with
    txStatementsCommitment := 18,
    messageRoot := 98,
    endTreeCommitment := 115
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"replay_cases\": [\n"
    ++ replayCaseJson "valid-v1-zero-based" ReplayVersion.v1 [0, 1, 2] sampleSemantic ++ ",\n"
    ++ replayCaseJson "valid-v2-zero-based" ReplayVersion.v2 [0, 1, 2] sampleSemantic ++ ",\n"
    ++ replayCaseJson "valid-v1-nonzero-start" ReplayVersion.v1 [5, 6, 7] altSemantic ++ ",\n"
    ++ replayCaseJson "gap-rejected-v1" ReplayVersion.v1 [0, 2, 3] sampleSemantic ++ ",\n"
    ++ replayCaseJson "duplicate-rejected-v2" ReplayVersion.v2 [0, 1, 1] sampleSemantic ++ ",\n"
    ++ replayCaseJson "decreasing-rejected-v2" ReplayVersion.v2 [2, 1, 0] sampleSemantic ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
