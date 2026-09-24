import Hegemon.Native.MineableActionAdmission
import Hegemon.Native.DaTemplateSelection
import Hegemon.Native.DaMetadataAdmission
import Hegemon.Native.ActiveV3ActionRouteAdmission

open Hegemon.Native.MineableActionAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option MineableActionReject -> String
  | none => "null"
  | some MineableActionReject.retiredCandidateArtifact =>
      "\"retired_candidate_artifact\""
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
    ++ "          \"sidecar_transfer_route\": "
      ++ boolJson entry.action.sidecarTransferRoute ++ ",\n"
    ++ "          \"transfer_mineable\": "
      ++ boolJson entry.action.transferMineable ++ ",\n"
    ++ "          \"candidate_artifact_route\": "
      ++ boolJson entry.action.candidateArtifactRoute ++ ",\n"
    ++ "          \"active_v3_route_allowed\": "
      ++ boolJson entry.action.activeV3RouteAllowed ++ ",\n"
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

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def daDecisionLabel
    (decision : Hegemon.Native.DaTemplateSelection.SingleTransferDecision) : String :=
  match decision with
  | Hegemon.Native.DaTemplateSelection.SingleTransferDecision.contributionOverflow =>
      "contribution_overflow"
  | Hegemon.Native.DaTemplateSelection.SingleTransferDecision.individuallyTooLarge _ =>
      "individually_too_large"
  | Hegemon.Native.DaTemplateSelection.SingleTransferDecision.admissible _ =>
      "admissible"

def daDecisionContributionJson
    (decision : Hegemon.Native.DaTemplateSelection.SingleTransferDecision) : String :=
  match decision with
  | Hegemon.Native.DaTemplateSelection.SingleTransferDecision.contributionOverflow => "null"
  | Hegemon.Native.DaTemplateSelection.SingleTransferDecision.individuallyTooLarge value =>
      toString value
  | Hegemon.Native.DaTemplateSelection.SingleTransferDecision.admissible value =>
      toString value

def daSingleActionCaseJson
    (name : String)
    (maxBlobBytes : Nat)
    (ciphertextSizes : List Nat) : String :=
  let decision :=
    Hegemon.Native.DaTemplateSelection.classifySingleTransfer
      maxBlobBytes ciphertextSizes
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"max_blob_bytes\": " ++ toString maxBlobBytes ++ ",\n"
    ++ "      \"ciphertext_sizes\": " ++ natListJson ciphertextSizes ++ ",\n"
    ++ "      \"expected_decision\": \"" ++ daDecisionLabel decision ++ "\",\n"
    ++ "      \"expected_contribution\": "
      ++ daDecisionContributionJson decision ++ "\n"
    ++ "    }"

def daActionJson
    (action : Hegemon.Native.DaTemplateSelection.Action) : String :=
  "        {\n"
    ++ "          \"action_id\": " ++ toString action.actionId ++ ",\n"
    ++ "          \"transfer_route\": " ++ boolJson action.transferRoute ++ ",\n"
    ++ "          \"ciphertext_sizes\": " ++ natListJson action.ciphertextSizes ++ ",\n"
    ++ "          \"encoded_bytes\": " ++ toString action.encodedBytes ++ "\n"
    ++ "        }"

def daTemplateSelectionCaseJson
    (name : String)
    (maxBlobBytes : Nat)
    (actions : List Hegemon.Native.DaTemplateSelection.Action) : String :=
  let selection := Hegemon.Native.DaTemplateSelection.select maxBlobBytes actions
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"max_blob_bytes\": " ++ toString maxBlobBytes ++ ",\n"
    ++ "      \"actions\": [\n"
    ++ joinJsonObjects (actions.map daActionJson) ++ "\n"
    ++ "      ],\n"
    ++ "      \"expected_selected_action_ids\": "
      ++ natListJson selection.selectedActionIds ++ ",\n"
    ++ "      \"expected_individually_unencodable_action_ids\": "
      ++ natListJson selection.individuallyUnencodableActionIds ++ ",\n"
    ++ "      \"expected_deferred_action_ids\": "
      ++ natListJson selection.deferredActionIds ++ ",\n"
    ++ "      \"expected_blob_bytes\": " ++ toString selection.blobBytes ++ ",\n"
    ++ "      \"expected_stopped_at_action_id\": "
      ++ optionNatJson selection.stoppedAtActionId ++ ",\n"
    ++ "      \"expected_count_stopped_at_action_id\": "
      ++ optionNatJson selection.countStoppedAtActionId ++ ",\n"
    ++ "      \"expected_selected_action_count\": "
      ++ toString selection.selectedActionCount ++ ",\n"
    ++ "      \"expected_selected_action_bytes\": "
      ++ toString selection.selectedActionBytes ++ "\n"
    ++ "    }"

def daAdaptiveTierCaseJson
    (name : String)
    (ciphertextSizes : List Nat)
    (transferCount : Nat) : String :=
  let actions :=
    (List.range transferCount).map (fun actionId =>
      ({ actionId := actionId, transferRoute := true, ciphertextSizes := ciphertextSizes } :
        Hegemon.Native.DaTemplateSelection.Action))
  let selection :=
    Hegemon.Native.DaTemplateSelection.select
      Hegemon.Native.DaTemplateSelection.maximumAdaptiveBlobBytes actions
  let tier :=
    Hegemon.Native.DaTemplateSelection.adaptiveTierForBlobBytes selection.blobBytes
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"ciphertext_sizes\": " ++ natListJson ciphertextSizes ++ ",\n"
    ++ "      \"transfer_count\": " ++ toString transferCount ++ ",\n"
    ++ "      \"expected_blob_bytes\": " ++ toString selection.blobBytes ++ ",\n"
    ++ "      \"expected_chunk_size\": "
      ++ (match tier with | none => "null" | some value => toString value.chunkBytes)
      ++ ",\n"
    ++ "      \"expected_max_blob_bytes\": "
      ++ (match tier with | none => "null" | some value => toString value.maxBlobBytes)
      ++ "\n"
    ++ "    }"

def daRawTierCaseJson (name : String) (blobBytes : Nat) : String :=
  let tier := Hegemon.Native.DaTemplateSelection.adaptiveTierForBlobBytes blobBytes
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"blob_bytes\": " ++ toString blobBytes ++ ",\n"
    ++ "      \"expected_chunk_size\": "
      ++ (match tier with | none => "null" | some value => toString value.chunkBytes)
      ++ ",\n"
    ++ "      \"expected_max_blob_bytes\": "
      ++ (match tier with | none => "null" | some value => toString value.maxBlobBytes)
      ++ "\n"
    ++ "    }"

def daMetadataRejectJson
    (result : Except Hegemon.Native.DaMetadataAdmission.Reject Unit) : String :=
  match result with
  | Except.ok _ => "null"
  | Except.error Hegemon.Native.DaMetadataAdmission.Reject.daRoot =>
      "\"da_root_mismatch\""
  | Except.error Hegemon.Native.DaMetadataAdmission.Reject.daChunkSize =>
      "\"da_chunk_size_mismatch\""
  | Except.error Hegemon.Native.DaMetadataAdmission.Reject.daSampleCount =>
      "\"da_sample_count_mismatch\""
  | Except.error Hegemon.Native.DaMetadataAdmission.Reject.daBlobLen =>
      "\"da_blob_len_mismatch\""
  | Except.error Hegemon.Native.DaMetadataAdmission.Reject.daChunkCount =>
      "\"da_chunk_count_mismatch\""

def daMetadataCaseJson
    (name : String)
    (input : Hegemon.Native.DaMetadataAdmission.Input) : String :=
  let result := Hegemon.Native.DaMetadataAdmission.evaluate input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"da_root_matches\": " ++ boolJson input.daRootMatches ++ ",\n"
    ++ "      \"da_chunk_size_matches\": " ++ boolJson input.daChunkSizeMatches ++ ",\n"
    ++ "      \"da_sample_count_matches\": " ++ boolJson input.daSampleCountMatches ++ ",\n"
    ++ "      \"da_blob_len_matches\": " ++ boolJson input.daBlobLenMatches ++ ",\n"
    ++ "      \"da_chunk_count_matches\": " ++ boolJson input.daChunkCountMatches ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (match result with | Except.ok _ => true | Except.error _ => false) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ daMetadataRejectJson result ++ "\n"
    ++ "    }"

def activeV3RouteLabel
    (route : Hegemon.Native.ActiveV3ActionRouteAdmission.Route) : String :=
  match route with
  | Hegemon.Native.ActiveV3ActionRouteAdmission.Route.inlineTransfer => "inline_transfer"
  | Hegemon.Native.ActiveV3ActionRouteAdmission.Route.sidecarTransfer => "sidecar_transfer"
  | Hegemon.Native.ActiveV3ActionRouteAdmission.Route.candidateArtifact => "candidate_artifact"
  | Hegemon.Native.ActiveV3ActionRouteAdmission.Route.coinbase => "coinbase"
  | Hegemon.Native.ActiveV3ActionRouteAdmission.Route.bridge => "bridge"
  | Hegemon.Native.ActiveV3ActionRouteAdmission.Route.unsupported => "unsupported"

def activeV3RouteRejectJson
    (result : Except Hegemon.Native.ActiveV3ActionRouteAdmission.Reject Unit) : String :=
  match result with
  | Except.ok _ => "null"
  | Except.error Hegemon.Native.ActiveV3ActionRouteAdmission.Reject.inactiveSidecar =>
      "\"inactive_sidecar\""
  | Except.error Hegemon.Native.ActiveV3ActionRouteAdmission.Reject.retiredCandidate =>
      "\"retired_candidate\""
  | Except.error Hegemon.Native.ActiveV3ActionRouteAdmission.Reject.inactiveBridge =>
      "\"inactive_bridge\""
  | Except.error Hegemon.Native.ActiveV3ActionRouteAdmission.Reject.externalCoinbase =>
      "\"external_coinbase\""
  | Except.error Hegemon.Native.ActiveV3ActionRouteAdmission.Reject.unsupportedRoute =>
      "\"unsupported_route\""

def activeV3RouteCaseJson
    (name : String)
    (input : Hegemon.Native.ActiveV3ActionRouteAdmission.Input) : String :=
  let result := Hegemon.Native.ActiveV3ActionRouteAdmission.evaluate input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"route\": \"" ++ activeV3RouteLabel input.route ++ "\",\n"
    ++ "      \"allow_internal_coinbase\": " ++ boolJson input.allowInternalCoinbase ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (match result with | Except.ok _ => true | Except.error _ => false) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ activeV3RouteRejectJson result ++ "\n"
    ++ "    }"

def jointSelectionRejectJson
    (result : Except Hegemon.Native.DaTemplateSelection.SelectionReject
      Hegemon.Native.DaTemplateSelection.Selection) : String :=
  match result with
  | Except.ok _ => "null"
  | Except.error Hegemon.Native.DaTemplateSelection.SelectionReject.reservedActionCount =>
      "\"reserved_action_count\""
  | Except.error Hegemon.Native.DaTemplateSelection.SelectionReject.reservedActionBytes =>
      "\"reserved_action_bytes\""

def jointSelectionFieldJson
    (result : Except Hegemon.Native.DaTemplateSelection.SelectionReject
      Hegemon.Native.DaTemplateSelection.Selection)
    (project : Hegemon.Native.DaTemplateSelection.Selection -> String) : String :=
  match result with
  | Except.ok selection => project selection
  | Except.error _ => "null"

def daJointSelectionCaseJson
    (name : String)
    (limits : Hegemon.Native.DaTemplateSelection.Limits)
    (actions : List Hegemon.Native.DaTemplateSelection.Action) : String :=
  let result := Hegemon.Native.DaTemplateSelection.selectWithLimits limits actions
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"max_blob_bytes\": " ++ toString limits.maxBlobBytes ++ ",\n"
    ++ "      \"max_action_count\": " ++ toString limits.maxActionCount ++ ",\n"
    ++ "      \"max_action_bytes\": " ++ toString limits.maxActionBytes ++ ",\n"
    ++ "      \"reserved_action_count\": " ++ toString limits.reservedActionCount ++ ",\n"
    ++ "      \"reserved_action_bytes\": " ++ toString limits.reservedActionBytes ++ ",\n"
    ++ "      \"actions\": [\n"
    ++ joinJsonObjects (actions.map daActionJson) ++ "\n"
    ++ "      ],\n"
    ++ "      \"expected_rejection\": " ++ jointSelectionRejectJson result ++ ",\n"
    ++ "      \"expected_selected_action_ids\": "
      ++ jointSelectionFieldJson result (fun selection => natListJson selection.selectedActionIds)
      ++ ",\n"
    ++ "      \"expected_individually_unencodable_action_ids\": "
      ++ jointSelectionFieldJson result
        (fun selection => natListJson selection.individuallyUnencodableActionIds) ++ ",\n"
    ++ "      \"expected_deferred_action_ids\": "
      ++ jointSelectionFieldJson result (fun selection => natListJson selection.deferredActionIds)
      ++ ",\n"
    ++ "      \"expected_blob_bytes\": "
      ++ jointSelectionFieldJson result (fun selection => toString selection.blobBytes) ++ ",\n"
    ++ "      \"expected_stopped_at_action_id\": "
      ++ jointSelectionFieldJson result
        (fun selection => optionNatJson selection.stoppedAtActionId) ++ ",\n"
    ++ "      \"expected_count_stopped_at_action_id\": "
      ++ jointSelectionFieldJson result
        (fun selection => optionNatJson selection.countStoppedAtActionId) ++ ",\n"
    ++ "      \"expected_selected_action_count\": "
      ++ jointSelectionFieldJson result (fun selection => toString selection.selectedActionCount)
      ++ ",\n"
    ++ "      \"expected_selected_action_bytes\": "
      ++ jointSelectionFieldJson result (fun selection => toString selection.selectedActionBytes)
      ++ "\n"
    ++ "    }"

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
      sidecarTransferRoute := false,
      transferMineable := true,
      candidateArtifactRoute := false,
      activeV3RouteAllowed := true,
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
      sidecarTransferRoute := true,
      transferMineable := true,
      candidateArtifactRoute := false,
      activeV3RouteAllowed := false,
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
      sidecarTransferRoute := true,
      transferMineable := false,
      candidateArtifactRoute := false,
      activeV3RouteAllowed := false,
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
      sidecarTransferRoute := false,
      transferMineable := false,
      candidateArtifactRoute := true,
      activeV3RouteAllowed := false,
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
      sidecarTransferRoute := false,
      transferMineable := false,
      candidateArtifactRoute := true,
      activeV3RouteAllowed := false,
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
      sidecarTransferRoute := false,
      transferMineable := false,
      candidateArtifactRoute := true,
      activeV3RouteAllowed := false,
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
      sidecarTransferRoute := false,
      transferMineable := false,
      candidateArtifactRoute := false,
      activeV3RouteAllowed := false,
      candidateTxCount := 0
    }
  }

def daOversizedAction : Hegemon.Native.DaTemplateSelection.Action :=
  {
    actionId := 1
    transferRoute := true
    ciphertextSizes := [2785269]
  }

def daContributionOverflowAction : Hegemon.Native.DaTemplateSelection.Action :=
  {
    actionId := 10
    transferRoute := true
    ciphertextSizes := [Hegemon.Native.DaTemplateSelection.usizeMax]
  }

def daOversizeSkipActions : List Hegemon.Native.DaTemplateSelection.Action :=
  [
    Hegemon.Native.DaTemplateSelection.productionTransfer 0,
    daOversizedAction,
    Hegemon.Native.DaTemplateSelection.plainAction 2,
    Hegemon.Native.DaTemplateSelection.productionTransfer 3
  ]

def daCheckedOverflowSkipActions : List Hegemon.Native.DaTemplateSelection.Action :=
  [
    daContributionOverflowAction,
    Hegemon.Native.DaTemplateSelection.plainAction 11,
    Hegemon.Native.DaTemplateSelection.productionTransfer 12
  ]

def daSizedPlain
    (actionId encodedBytes : Nat) : Hegemon.Native.DaTemplateSelection.Action :=
  {
    actionId := actionId
    transferRoute := false
    ciphertextSizes := []
    encodedBytes := encodedBytes
  }

def daSizedTransfer
    (actionId encodedBytes : Nat)
    (ciphertextSizes : List Nat) : Hegemon.Native.DaTemplateSelection.Action :=
  {
    actionId := actionId
    transferRoute := true
    ciphertextSizes := ciphertextSizes
    encodedBytes := encodedBytes
  }

def daSmallJointLimits : Hegemon.Native.DaTemplateSelection.Limits :=
  {
    maxBlobBytes := 8
    maxActionCount := 3
    maxActionBytes := 100
    reservedActionCount := 1
    reservedActionBytes := 20
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 6,\n"
    ++ "  \"mineable_action_admission_cases\": [\n"
    ++ mineableActionCaseJson "plain-action-accepts" plainAction ++ ",\n"
    ++ mineableActionCaseJson "selected-candidate-is-still-retired"
      selectedCandidate ++ ",\n"
    ++ mineableActionCaseJson "valid-sidecar-transfer-accepts"
      validSidecarTransfer ++ ",\n"
    ++ mineableActionCaseJson "unselected-candidate-is-retired"
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
    ++ selectionCaseJson "zero-transfers-retires-candidate"
      [candidateOneA, bridgeA] ++ ",\n"
    ++ selectionCaseJson "one-transfer-does-not-select-candidate"
      [inlineA, candidateOneA, bridgeA] ++ ",\n"
    ++ selectionCaseJson "two-transfers-do-not-select-candidate"
      [inlineA, candidateOneA, sidecarA, candidateTwo] ++ ",\n"
    ++ selectionCaseJson "unmineable-sidecar-and-candidate-rejected"
      [candidateOneA, sidecarMissing, bridgeA] ++ ",\n"
    ++ selectionCaseJson "multiple-candidates-all-rejected"
      [inlineA, candidateOneB, candidateOneA, bridgeA] ++ "\n"
    ++ "  ],\n"
    ++ "  \"pending_candidate_prune_cases\": [\n"
    ++ pruneCaseJson "no-transfer-keeps-candidate"
      [candidateOneA, bridgeA] ++ ",\n"
    ++ pruneCaseJson "transfer-prunes-candidate"
      [inlineA, candidateOneA, bridgeA] ++ ",\n"
    ++ pruneCaseJson "transfer-prunes-multiple-candidates"
      [inlineA, candidateOneA, candidateOneB, candidateTwo, bridgeA] ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_single_action_cases\": [\n"
    ++ daSingleActionCaseJson "checked-in-32-byte-kem-fixture-contribution"
      Hegemon.Native.DaTemplateSelection.fourKiBMaxBlobBytes
      Hegemon.Native.DaTemplateSelection.compactFixtureCiphertextSizes ++ ",\n"
    ++ daSingleActionCaseJson "full-ml-kem-production-max-contribution"
      Hegemon.Native.DaTemplateSelection.fourKiBMaxBlobBytes
      Hegemon.Native.DaTemplateSelection.productionCiphertextSizes ++ ",\n"
    ++ daSingleActionCaseJson "exact-single-action-capacity-accepted"
      Hegemon.Native.DaTemplateSelection.fourKiBMaxBlobBytes [696308] ++ ",\n"
    ++ daSingleActionCaseJson "one-byte-over-single-action-capacity-rejected"
      Hegemon.Native.DaTemplateSelection.fourKiBMaxBlobBytes [696309] ++ ",\n"
    ++ daSingleActionCaseJson "ciphertext-contribution-checked-overflow-rejected"
      Hegemon.Native.DaTemplateSelection.maximumAdaptiveBlobBytes
      [Hegemon.Native.DaTemplateSelection.usizeMax] ++ ",\n"
    ++ daSingleActionCaseJson "single-blob-prefix-checked-overflow-rejected"
      Hegemon.Native.DaTemplateSelection.maximumAdaptiveBlobBytes
      [Hegemon.Native.DaTemplateSelection.usizeMax - 8] ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_template_selection_cases\": [\n"
    ++ daTemplateSelectionCaseJson "empty-control"
      Hegemon.Native.DaTemplateSelection.maximumAdaptiveBlobBytes [] ++ ",\n"
    ++ daTemplateSelectionCaseJson "nontransfer-order-control"
      Hegemon.Native.DaTemplateSelection.maximumAdaptiveBlobBytes
      [
        Hegemon.Native.DaTemplateSelection.plainAction 20,
        Hegemon.Native.DaTemplateSelection.plainAction 21
      ] ++ ",\n"
    ++ daTemplateSelectionCaseJson "646-full-ml-kem-production-max-transfers-fit"
      Hegemon.Native.DaTemplateSelection.maximumAdaptiveBlobBytes
      (Hegemon.Native.DaTemplateSelection.productionTransfers 646) ++ ",\n"
    ++ daTemplateSelectionCaseJson "647th-full-ml-kem-transfer-deferred-later-bridge-selected"
      Hegemon.Native.DaTemplateSelection.maximumAdaptiveBlobBytes
      (Hegemon.Native.DaTemplateSelection.productionTransfers 647
        ++ [Hegemon.Native.DaTemplateSelection.bridgeAction 999]) ++ ",\n"
    ++ daTemplateSelectionCaseJson "564-checked-in-32-byte-kem-fixtures-fit-at-fixed-4k"
      Hegemon.Native.DaTemplateSelection.fourKiBMaxBlobBytes
      (Hegemon.Native.DaTemplateSelection.compactFixtureTransfers 564) ++ ",\n"
    ++ daTemplateSelectionCaseJson "565th-compact-fixture-deferred-at-fixed-4k"
      Hegemon.Native.DaTemplateSelection.fourKiBMaxBlobBytes
      (Hegemon.Native.DaTemplateSelection.compactFixtureTransfers 565) ++ ",\n"
    ++ daTemplateSelectionCaseJson "oversized-head-skipped-later-actions-retained"
      Hegemon.Native.DaTemplateSelection.maximumAdaptiveBlobBytes daOversizeSkipActions ++ ",\n"
    ++ daTemplateSelectionCaseJson "checked-overflow-head-skipped-later-actions-retained"
      Hegemon.Native.DaTemplateSelection.maximumAdaptiveBlobBytes daCheckedOverflowSkipActions ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_adaptive_tier_cases\": [\n"
    ++ daAdaptiveTierCaseJson "compact-fixture-141-selects-1k"
      Hegemon.Native.DaTemplateSelection.compactFixtureCiphertextSizes 141 ++ ",\n"
    ++ daAdaptiveTierCaseJson "compact-fixture-142-selects-4k"
      Hegemon.Native.DaTemplateSelection.compactFixtureCiphertextSizes 142 ++ ",\n"
    ++ daAdaptiveTierCaseJson "full-ml-kem-40-selects-1k"
      Hegemon.Native.DaTemplateSelection.productionCiphertextSizes 40 ++ ",\n"
    ++ daAdaptiveTierCaseJson "full-ml-kem-41-selects-4k"
      Hegemon.Native.DaTemplateSelection.productionCiphertextSizes 41 ++ ",\n"
    ++ daAdaptiveTierCaseJson "full-ml-kem-161-selects-4k"
      Hegemon.Native.DaTemplateSelection.productionCiphertextSizes 161 ++ ",\n"
    ++ daAdaptiveTierCaseJson "full-ml-kem-162-selects-16k"
      Hegemon.Native.DaTemplateSelection.productionCiphertextSizes 162 ++ ",\n"
    ++ daAdaptiveTierCaseJson "full-ml-kem-516-selects-16k"
      Hegemon.Native.DaTemplateSelection.productionCiphertextSizes 516 ++ ",\n"
    ++ daAdaptiveTierCaseJson "full-ml-kem-646-selects-16k"
      Hegemon.Native.DaTemplateSelection.productionCiphertextSizes 646 ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_raw_tier_cases\": [\n"
    ++ daRawTierCaseJson "empty-blob-selects-1k" 0 ++ ",\n"
    ++ daRawTierCaseJson "1k-capacity-exact" 174080 ++ ",\n"
    ++ daRawTierCaseJson "1k-capacity-plus-one-selects-4k" 174081 ++ ",\n"
    ++ daRawTierCaseJson "4k-capacity-exact" 696320 ++ ",\n"
    ++ daRawTierCaseJson "4k-capacity-plus-one-selects-16k" 696321 ++ ",\n"
    ++ daRawTierCaseJson "16k-capacity-exact" 2785280 ++ ",\n"
    ++ daRawTierCaseJson "16k-capacity-plus-one-rejected" 2785281 ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_metadata_admission_cases\": [\n"
    ++ daMetadataCaseJson "matching-metadata-accepted"
      Hegemon.Native.DaMetadataAdmission.valid ++ ",\n"
    ++ daMetadataCaseJson "root-mismatch-rejected"
      { Hegemon.Native.DaMetadataAdmission.valid with daRootMatches := false } ++ ",\n"
    ++ daMetadataCaseJson "chunk-size-mismatch-rejected"
      { Hegemon.Native.DaMetadataAdmission.valid with daChunkSizeMatches := false } ++ ",\n"
    ++ daMetadataCaseJson "sample-count-mismatch-rejected"
      { Hegemon.Native.DaMetadataAdmission.valid with daSampleCountMatches := false } ++ ",\n"
    ++ daMetadataCaseJson "blob-len-mismatch-rejected"
      { Hegemon.Native.DaMetadataAdmission.valid with daBlobLenMatches := false } ++ ",\n"
    ++ daMetadataCaseJson "chunk-count-mismatch-rejected"
      { Hegemon.Native.DaMetadataAdmission.valid with daChunkCountMatches := false } ++ ",\n"
    ++ daMetadataCaseJson "root-mismatch-precedes-all-metadata-mismatches"
      {
        daRootMatches := false
        daChunkSizeMatches := false
        daSampleCountMatches := false
        daBlobLenMatches := false
        daChunkCountMatches := false
      } ++ "\n"
    ++ "  ],\n"
    ++ "  \"active_v3_action_route_cases\": [\n"
    ++ activeV3RouteCaseJson "inline-transfer-mempool-accepted"
      { route := .inlineTransfer, allowInternalCoinbase := false } ++ ",\n"
    ++ activeV3RouteCaseJson "bridge-mempool-rejected-before-payload"
      { route := .bridge, allowInternalCoinbase := false } ++ ",\n"
    ++ activeV3RouteCaseJson "bridge-block-rejected-before-payload"
      { route := .bridge, allowInternalCoinbase := true } ++ ",\n"
    ++ activeV3RouteCaseJson "sidecar-mempool-rejected"
      { route := .sidecarTransfer, allowInternalCoinbase := false } ++ ",\n"
    ++ activeV3RouteCaseJson "sidecar-block-rejected"
      { route := .sidecarTransfer, allowInternalCoinbase := true } ++ ",\n"
    ++ activeV3RouteCaseJson "candidate-block-rejected"
      { route := .candidateArtifact, allowInternalCoinbase := true } ++ ",\n"
    ++ activeV3RouteCaseJson "external-coinbase-rejected"
      { route := .coinbase, allowInternalCoinbase := false } ++ ",\n"
    ++ activeV3RouteCaseJson "internal-coinbase-accepted"
      { route := .coinbase, allowInternalCoinbase := true } ++ ",\n"
    ++ activeV3RouteCaseJson "unsupported-route-rejected"
      { route := .unsupported, allowInternalCoinbase := true } ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_joint_selection_cases\": [\n"
    ++ daJointSelectionCaseJson "active-520-inline-plus-reserved-coinbase"
      Hegemon.Native.DaTemplateSelection.activeJointLimits
      (Hegemon.Native.DaTemplateSelection.productionInlineTransfers 521) ++ ",\n"
    ++ daJointSelectionCaseJson "da-overflow-defers-transfers-but-keeps-later-plain"
      {
        maxBlobBytes := 8
        maxActionCount := 10
        maxActionBytes := 1000
        reservedActionCount := 0
        reservedActionBytes := 0
      }
      [
        daSizedTransfer 0 10 [],
        daSizedTransfer 1 10 [],
        daSizedPlain 2 10,
        daSizedTransfer 3 10 [],
        daSizedTransfer 4 10 [Hegemon.Native.DaTemplateSelection.usizeMax]
      ] ++ ",\n"
    ++ daJointSelectionCaseJson "byte-head-does-not-block-later-smaller-action"
      { daSmallJointLimits with maxBlobBytes := 1000, maxActionCount := 10 }
      [daSizedPlain 0 90, daSizedPlain 1 30] ++ ",\n"
    ++ daJointSelectionCaseJson "count-full-stops-remaining-actions"
      { daSmallJointLimits with maxBlobBytes := 1000, maxActionBytes := 1000 }
      [daSizedPlain 0 10, daSizedPlain 1 10, daSizedPlain 2 10, daSizedPlain 3 10]
      ++ ",\n"
    ++ daJointSelectionCaseJson "checked-action-byte-overflow-defers-only-that-action"
      {
        maxBlobBytes := 1000
        maxActionCount := 10
        maxActionBytes := Hegemon.Native.DaTemplateSelection.usizeMax
        reservedActionCount := 0
        reservedActionBytes := 10
      }
      [
        daSizedPlain 0 Hegemon.Native.DaTemplateSelection.usizeMax,
        daSizedPlain 1 1
      ] ++ ",\n"
    ++ daJointSelectionCaseJson "exact-action-byte-cap-accepts"
      { daSmallJointLimits with maxBlobBytes := 1000, maxActionCount := 10 }
      [daSizedPlain 0 30, daSizedPlain 1 50] ++ ",\n"
    ++ daJointSelectionCaseJson "reserved-action-count-over-cap-rejected"
      { daSmallJointLimits with reservedActionCount := 4 }
      [] ++ ",\n"
    ++ daJointSelectionCaseJson "reserved-action-bytes-over-cap-rejected"
      { daSmallJointLimits with reservedActionBytes := 101 }
      [] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
