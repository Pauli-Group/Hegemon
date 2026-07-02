import Hegemon.Essence.Core

namespace Hegemon
namespace Essence
namespace GenerateCoreVectors

open Hegemon.Essence.Core

def jsonString (value : String) : String :=
  "\"" ++ value ++ "\""

def jsonArray (values : List String) : String :=
  "[" ++ String.intercalate ", " values ++ "]"

def jsonBool (value : Bool) : String :=
  if value then "true" else "false"

def optionPresent {α : Type} : Option α -> Bool
  | none => false
  | some _ => true

def sampleBefore : LedgerState :=
  { supply := 1000
    assetBalances := [
      { assetId := nativeAsset, amount := 1000 },
      { assetId := 7, amount := 0 }]
    spentNullifiers := [11, 12]
    commitments := [21, 22, 23]
    bridgeReplayKeys := [31] }

def sampleTransfer : Action :=
  { inputNullifiers := [41]
    outputCommitments := [51, 52]
    outputCiphertextTags := [61, 62]
    nativeMint := 0
    nativeBurn := 3
    assetDeltas := [{ assetId := nativeAsset, delta := -3 }]
    spendAuthorization :=
      some
        { spendKey := 101
          statementDigest := 102
          keyOwnsInputs := True
          authorizationValid := True }
    nativeMintAuthorization := none
    assetAuthorization := none
    bridgeAuthorization := none
    proofBinding :=
      some
        { statementDigest := 102
          publicInputsBound := True
          actionHashBound := True } }

def sampleBridgeReceipt : BridgeReceipt :=
  { sourceChainId := 100
    sourceMessageNonce := 5
    sourceEventId := 501
    verifierVersion := 1
    assetId := 7
    amount := 5
    destinationChainId := 200
    recipientCommitment := 71
    finalityDepth := 64
    replayKey := 91
    messageHash := 901
    payloadHash := 902 }

def sampleBridgeMint : Action :=
  { inputNullifiers := []
    outputCommitments := [71]
    outputCiphertextTags := [81]
    nativeMint := 0
    nativeBurn := 0
    assetDeltas := [{ assetId := 7, delta := 5 }]
    spendAuthorization := none
    nativeMintAuthorization := none
    assetAuthorization := none
    bridgeAuthorization :=
      some
        { receipt := sampleBridgeReceipt
          verifierAccepted := True
          finalityProved := True
          sourceEventBound := True
          messageHashBound := True
          payloadHashBound := True
          destinationChainBound := True
          amountAssetDeltaBound := True }
    proofBinding :=
      some
        { statementDigest := 202
          publicInputsBound := True
          actionHashBound := True } }

def sampleAfterTransfer : LedgerState :=
  { supply := 997
    assetBalances := [
      { assetId := nativeAsset, amount := 997 },
      { assetId := 7, amount := 0 }]
    spentNullifiers := [11, 12, 41]
    commitments := [21, 22, 23, 51, 52]
    bridgeReplayKeys := [31] }

def sampleAfterBridge : LedgerState :=
  { supply := 997
    assetBalances := [
      { assetId := nativeAsset, amount := 997 },
      { assetId := 7, amount := 5 }]
    spentNullifiers := [11, 12, 41]
    commitments := [21, 22, 23, 51, 52, 71]
    bridgeReplayKeys := [31, 91] }

def sampleObserver : ObserverView :=
  observerView sampleBefore sampleTransfer sampleAfterTransfer

def sampleBlock : Block :=
  { actions := [sampleTransfer, sampleBridgeMint] }

def coreTypesJson : String :=
  jsonArray
    (List.map jsonString
      ["LedgerState", "Action", "Block", "ObserverView", "Transition"])

def theoremJson : String :=
  jsonArray
    (List.map jsonString [
      "Hegemon.Essence.Core.transition_no_counterfeiting",
      "Hegemon.Essence.Core.transition_no_double_spend",
      "Hegemon.Essence.Core.transition_no_theft",
        "Hegemon.Essence.Core.transition_asset_isolation",
        "Hegemon.Essence.Core.transition_per_asset_conservation",
        "Hegemon.Essence.Core.transition_bridge_safety",
        "Hegemon.Essence.Core.transition_privacy_projection",
        "Hegemon.Essence.Core.transition_encoding_no_truncation",
        "Hegemon.Essence.Core.transition_nullifiers_unique_derived",
        "Hegemon.Essence.Core.transition_bridge_replay_keys_unique_derived",
        "Hegemon.Essence.Core.action_chain_supply_integrity",
        "Hegemon.Essence.Core.action_chain_nullifiers_unique",
        "Hegemon.Essence.Core.block_transition_supply_integrity",
        "Hegemon.Essence.Core.block_transition_nullifiers_unique",
        "Hegemon.Essence.Core.production_path_refines_core_transition",
        "Hegemon.Essence.Core.production_path_refines_core_security",
        "Hegemon.Essence.Core.production_path_exact_bytes",
        "Hegemon.Essence.Core.failed_production_path_publishes_no_state",
        "Hegemon.Essence.Core.external_assumption_boundary_is_named",
        "Hegemon.Essence.Core.global_privacy_requires_system_model",
        "Hegemon.Essence.Core.canonical_encoding_source_is_core",
        "Hegemon.Essence.Core.canonical_action_encoding_comes_from_core",
        "Hegemon.Essence.Core.canonical_action_term_roundtrip",
        "Hegemon.Essence.Core.canonical_action_term_injective",
        "Hegemon.Essence.Core.canonical_action_term_non_malleable"
      ])

def stageJson : String :=
  jsonArray
    (List.map jsonString
      ["parser", "admitted_action", "replay", "storage", "publication"])

def assumptionJson : String :=
  jsonArray
    (List.map jsonString [
      "ML-KEM security",
      "ML-DSA security",
      "AEAD security",
        "hash/transcript security",
        "STARK/PCS soundness",
        "DA retention",
        "storage durability",
        "local zero-knowledge",
        "timing privacy",
        "topology privacy",
        "miner-ordering privacy",
        "global traffic privacy"
      ])

def progressJson : String :=
  jsonArray
    (([
      "{\"id\": \"semantic_core_types\", \"completion_percent\": 100}",
      "{\"id\": \"core_security_theorems\", \"completion_percent\": 100}",
        "{\"id\": \"production_refinement_relation\", \"completion_percent\": 100}",
        "{\"id\": \"derived_invariants\", \"completion_percent\": 100}",
        "{\"id\": \"asset_ledger_semantics\", \"completion_percent\": 100}",
        "{\"id\": \"bridge_receipt_binding\", \"completion_percent\": 100}",
        "{\"id\": \"canonical_term_roundtrip\", \"completion_percent\": 100}",
        "{\"id\": \"named_assumption_boundary\", \"completion_percent\": 100}",
        "{\"id\": \"canonical_encoding_source\", \"completion_percent\": 100}"
      ]))

def caseJson (name : String) (action : Action) (before after : LedgerState) : String :=
  "{\n"
    ++ "      \"name\": " ++ jsonString name ++ ",\n"
    ++ "      \"before_hex\": " ++ jsonString (hexBytes (encodeLedgerState before)) ++ ",\n"
    ++ "      \"action_hex\": " ++ jsonString (hexBytes (encodeAction action)) ++ ",\n"
    ++ "      \"after_hex\": " ++ jsonString (hexBytes (encodeLedgerState after)) ++ ",\n"
    ++ "      \"observer_hex\": " ++
        jsonString (hexBytes (encodeObserverView (observerView before action after))) ++ ",\n"
    ++ "      \"native_mint\": " ++ toString action.nativeMint ++ ",\n"
    ++ "      \"native_burn\": " ++ toString action.nativeBurn ++ ",\n"
    ++ "      \"nullifier_count\": " ++ toString action.inputNullifiers.length ++ ",\n"
    ++ "      \"commitment_count\": " ++ toString action.outputCommitments.length ++ ",\n"
    ++ "      \"ciphertext_count\": " ++ toString action.outputCiphertextTags.length ++ ",\n"
      ++ "      \"bridge_replay_count\": " ++
          toString (bridgeReplayKeysFromAction action).length ++ ",\n"
      ++ "      \"spend_authorized\": " ++
          jsonBool
            (action.inputNullifiers.isEmpty ||
              optionPresent action.spendAuthorization) ++ ",\n"
      ++ "      \"proof_statement_bound\": " ++
          jsonBool (optionPresent action.proofBinding) ++ "\n"
      ++ "    }"

def casesJson : String :=
  jsonArray
    [caseJson "authorized_transfer_burn" sampleTransfer sampleBefore sampleAfterTransfer,
     caseJson "authorized_bridge_replay_mint_exception" sampleBridgeMint sampleAfterTransfer sampleAfterBridge]

def document : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"source_of_truth\": " ++ jsonString canonicalEncodingSource ++ ",\n"
    ++ "  \"single_canonical_encoding_source\": true,\n"
    ++ "  \"overall_completion_percent\": 100,\n"
    ++ "  \"core_types\": " ++ coreTypesJson ++ ",\n"
    ++ "  \"proved_theorems\": " ++ theoremJson ++ ",\n"
    ++ "  \"production_path_stages\": " ++ stageJson ++ ",\n"
    ++ "  \"named_external_assumptions\": " ++ assumptionJson ++ ",\n"
    ++ "  \"progress_items\": " ++ progressJson ++ ",\n"
    ++ "  \"cases\": " ++ casesJson ++ "\n"
    ++ "}\n"

def emit : IO Unit :=
  IO.print document

end GenerateCoreVectors
end Essence
end Hegemon

def main : IO Unit :=
  Hegemon.Essence.GenerateCoreVectors.emit
