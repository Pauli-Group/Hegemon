import Hegemon.Native.MineableActionAdmission

open Hegemon.Native.MineableActionAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option MineableActionReject -> String
  | none => "null"
  | some MineableActionReject.unselectedCandidateArtifact =>
      "\"unselected_candidate_artifact\""
  | some MineableActionReject.sidecarCiphertextMissing =>
      "\"sidecar_ciphertext_missing\""
  | some MineableActionReject.sidecarCiphertextSizeMissing =>
      "\"sidecar_ciphertext_size_missing\""
  | some MineableActionReject.sidecarCiphertextSizeMismatch =>
      "\"sidecar_ciphertext_size_mismatch\""

def mineableActionCaseJson (name : String) (input : MineableActionInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"candidate_artifact_route\": "
      ++ boolJson input.candidateArtifactRoute ++ ",\n"
    ++ "      \"candidate_artifact_selected\": "
      ++ boolJson input.candidateArtifactSelected ++ ",\n"
    ++ "      \"sidecar_transfer_route\": "
      ++ boolJson input.sidecarTransferRoute ++ ",\n"
    ++ "      \"sidecar_ciphertexts_available\": "
      ++ boolJson input.sidecarCiphertextsAvailable ++ ",\n"
    ++ "      \"sidecar_ciphertext_sizes_present\": "
      ++ boolJson input.sidecarCiphertextSizesPresent ++ ",\n"
    ++ "      \"sidecar_ciphertext_sizes_match\": "
      ++ boolJson input.sidecarCiphertextSizesMatch ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (mineableActionAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (mineableActionRejection input) ++ "\n"
    ++ "    }"

structure MineableSelectionVectorAction where
  label : String
  fixture : String
  action : MineableSelectionAction
deriving Repr

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def selectionActionJson
    (actions : List MineableSelectionAction)
    (entry : MineableSelectionVectorAction) : String :=
  "        {\n"
    ++ "          \"label\": \"" ++ entry.label ++ "\",\n"
    ++ "          \"fixture\": \"" ++ entry.fixture ++ "\",\n"
    ++ "          \"action_id\": " ++ toString entry.action.actionId ++ ",\n"
    ++ "          \"transfer_route\": "
      ++ boolJson entry.action.transferRoute ++ ",\n"
    ++ "          \"transfer_mineable\": "
      ++ boolJson entry.action.transferMineable ++ ",\n"
    ++ "          \"candidate_artifact_route\": "
      ++ boolJson entry.action.candidateArtifactRoute ++ ",\n"
    ++ "          \"candidate_tx_count\": "
      ++ toString entry.action.candidateTxCount ++ ",\n"
    ++ "          \"expected_selected\": "
      ++ boolJson
        (selectedCandidateForOrderedActions actions =
          some entry.action.actionId) ++ ",\n"
    ++ "          \"expected_accepted\": "
      ++ boolJson (selectionActionAccepts actions entry.action) ++ "\n"
    ++ "        }"

def joinJsonObjects : List String -> String
  | [] => ""
  | [item] => item
  | item :: rest => item ++ ",\n" ++ joinJsonObjects rest

def selectionCaseJson
    (name : String)
    (entries : List MineableSelectionVectorAction) : String :=
  let actions := entries.map (fun entry => entry.action)
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"transfer_count\": "
      ++ toString (mineableTransferCount actions) ++ ",\n"
    ++ "      \"selected_candidate_action_id\": "
      ++ optionNatJson (selectedCandidateForOrderedActions actions) ++ ",\n"
    ++ "      \"actions\": [\n"
    ++ joinJsonObjects (entries.map (selectionActionJson actions)) ++ "\n"
    ++ "      ]\n"
    ++ "    }"

def pruneActionJson
    (actions : List MineableSelectionAction)
    (entry : MineableSelectionVectorAction) : String :=
  "        {\n"
    ++ "          \"label\": \"" ++ entry.label ++ "\",\n"
    ++ "          \"fixture\": \"" ++ entry.fixture ++ "\",\n"
    ++ "          \"action_id\": " ++ toString entry.action.actionId ++ ",\n"
    ++ "          \"transfer_route\": "
      ++ boolJson entry.action.transferRoute ++ ",\n"
    ++ "          \"candidate_artifact_route\": "
      ++ boolJson entry.action.candidateArtifactRoute ++ ",\n"
    ++ "          \"expected_survives_after_transfer_prune\": "
      ++ boolJson
        (survivesCandidatePruneWhenTransfersPending actions entry.action) ++ "\n"
    ++ "        }"

def pruneCaseJson
    (name : String)
    (entries : List MineableSelectionVectorAction) : String :=
  let actions := entries.map (fun entry => entry.action)
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"transfer_pending\": "
      ++ boolJson (pendingTransferPresent actions) ++ ",\n"
    ++ "      \"actions\": [\n"
    ++ joinJsonObjects (entries.map (pruneActionJson actions)) ++ "\n"
    ++ "      ]\n"
    ++ "    }"

def inlineA : MineableSelectionVectorAction :=
  {
    label := "inline-a",
    fixture := "inline-a",
    action := {
      actionId := 1,
      transferRoute := true,
      transferMineable := true,
      candidateArtifactRoute := false,
      candidateTxCount := 0
    }
  }

def sidecarA : MineableSelectionVectorAction :=
  {
    label := "sidecar-a",
    fixture := "sidecar-a",
    action := {
      actionId := 2,
      transferRoute := true,
      transferMineable := true,
      candidateArtifactRoute := false,
      candidateTxCount := 0
    }
  }

def sidecarMissing : MineableSelectionVectorAction :=
  {
    label := "sidecar-missing",
    fixture := "sidecar-missing",
    action := {
      actionId := 3,
      transferRoute := true,
      transferMineable := false,
      candidateArtifactRoute := false,
      candidateTxCount := 0
    }
  }

def candidateOneA : MineableSelectionVectorAction :=
  {
    label := "candidate-one-a",
    fixture := "candidate-one-a",
    action := {
      actionId := 101,
      transferRoute := false,
      transferMineable := false,
      candidateArtifactRoute := true,
      candidateTxCount := 1
    }
  }

def candidateOneB : MineableSelectionVectorAction :=
  {
    label := "candidate-one-b",
    fixture := "candidate-one-b",
    action := {
      actionId := 102,
      transferRoute := false,
      transferMineable := false,
      candidateArtifactRoute := true,
      candidateTxCount := 1
    }
  }

def candidateTwo : MineableSelectionVectorAction :=
  {
    label := "candidate-two",
    fixture := "candidate-two",
    action := {
      actionId := 103,
      transferRoute := false,
      transferMineable := false,
      candidateArtifactRoute := true,
      candidateTxCount := 2
    }
  }

def bridgeA : MineableSelectionVectorAction :=
  {
    label := "bridge-a",
    fixture := "bridge-a",
    action := {
      actionId := 201,
      transferRoute := false,
      transferMineable := false,
      candidateArtifactRoute := false,
      candidateTxCount := 0
    }
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 3,\n"
    ++ "  \"mineable_action_admission_cases\": [\n"
    ++ mineableActionCaseJson "plain-action-accepts" plainAction ++ ",\n"
    ++ mineableActionCaseJson "selected-candidate-accepts"
      selectedCandidate ++ ",\n"
    ++ mineableActionCaseJson "valid-sidecar-transfer-accepts"
      validSidecarTransfer ++ ",\n"
    ++ mineableActionCaseJson "unselected-candidate-rejected"
      { selectedCandidate with candidateArtifactSelected := false } ++ ",\n"
    ++ mineableActionCaseJson "sidecar-ciphertext-missing-rejected"
      { validSidecarTransfer with sidecarCiphertextsAvailable := false } ++ ",\n"
    ++ mineableActionCaseJson "sidecar-ciphertext-size-missing-rejected"
      { validSidecarTransfer with sidecarCiphertextSizesPresent := false } ++ ",\n"
    ++ mineableActionCaseJson "sidecar-ciphertext-size-mismatch-rejected"
      { validSidecarTransfer with sidecarCiphertextSizesMatch := false } ++ ",\n"
    ++ mineableActionCaseJson "candidate-precedes-sidecar-missing"
      { selectedCandidate with
        candidateArtifactSelected := false,
        sidecarTransferRoute := true,
        sidecarCiphertextsAvailable := false } ++ ",\n"
    ++ mineableActionCaseJson "sidecar-availability-precedes-size-missing"
      { validSidecarTransfer with
        sidecarCiphertextsAvailable := false,
        sidecarCiphertextSizesPresent := false } ++ ",\n"
    ++ mineableActionCaseJson "plain-action-ignores-sidecar-metadata"
      plainAction ++ "\n"
    ++ "  ],\n"
    ++ "  \"mineable_selection_cases\": [\n"
    ++ selectionCaseJson "zero-transfers-rejects-candidate"
      [candidateOneA, bridgeA] ++ ",\n"
    ++ selectionCaseJson "one-transfer-selects-matching-candidate"
      [inlineA, candidateOneA, bridgeA] ++ ",\n"
    ++ selectionCaseJson "two-transfers-selects-two-count-candidate"
      [inlineA, sidecarA, candidateOneA, candidateTwo] ++ ",\n"
    ++ selectionCaseJson "unmineable-sidecar-not-counted"
      [sidecarMissing, candidateOneA, bridgeA] ++ ",\n"
    ++ selectionCaseJson "first-matching-candidate-wins"
      [inlineA, candidateOneB, candidateOneA, bridgeA] ++ "\n"
    ++ "  ],\n"
    ++ "  \"pending_candidate_prune_cases\": [\n"
    ++ pruneCaseJson "no-transfer-keeps-candidate"
      [candidateOneA, bridgeA] ++ ",\n"
    ++ pruneCaseJson "transfer-prunes-candidate"
      [inlineA, candidateOneA, bridgeA] ++ ",\n"
    ++ pruneCaseJson "transfer-prunes-multiple-candidates"
      [inlineA, candidateOneA, candidateOneB, candidateTwo, bridgeA] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
