import Hegemon.Native.BlockReplayRefinement

open Hegemon.Native.ActionStateEffect
open Hegemon.Native.BlockReplayRefinement

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def nullifierImportStateJson : NullifierImportState -> String
  | NullifierImportState.valid => "\"valid\""
  | NullifierImportState.zero => "\"zero\""
  | NullifierImportState.duplicate => "\"duplicate\""

def bridgeReplayStateJson : BridgeReplayState -> String
  | BridgeReplayState.absent => "\"absent\""
  | BridgeReplayState.valid => "\"valid\""
  | BridgeReplayState.alreadyConsumed => "\"already_consumed\""

def rejectionJson :
    Except BlockReplayReject BlockReplaySummary -> String
  | Except.ok _ => "null"
  | Except.error BlockReplayReject.ciphertextCountMismatch =>
      "\"ciphertext_count_mismatch\""
  | Except.error BlockReplayReject.commitmentIndexOverflow =>
      "\"commitment_index_overflow\""
  | Except.error BlockReplayReject.nullifierZero => "\"nullifier_zero\""
  | Except.error BlockReplayReject.duplicateNullifier =>
      "\"duplicate_nullifier\""
  | Except.error BlockReplayReject.bridgeReplayDuplicate =>
      "\"bridge_replay_duplicate\""
  | Except.error BlockReplayReject.supplyDeltaInvalid =>
      "\"supply_delta_invalid\""
  | Except.error BlockReplayReject.txCountMismatch => "\"tx_count_mismatch\""
  | Except.error BlockReplayReject.stateRootMismatch => "\"state_root_mismatch\""
  | Except.error BlockReplayReject.kernelRootMismatch =>
      "\"kernel_root_mismatch\""
  | Except.error BlockReplayReject.nullifierRootMismatch =>
      "\"nullifier_root_mismatch\""
  | Except.error BlockReplayReject.extrinsicsRootMismatch =>
      "\"extrinsics_root_mismatch\""
  | Except.error BlockReplayReject.messageRootMismatch =>
      "\"message_root_mismatch\""
  | Except.error BlockReplayReject.messageCountMismatch =>
      "\"message_count_mismatch\""
  | Except.error BlockReplayReject.headerMmrRootMismatch =>
      "\"header_mmr_root_mismatch\""
  | Except.error BlockReplayReject.headerMmrLenMismatch =>
      "\"header_mmr_len_mismatch\""
  | Except.error BlockReplayReject.supplyDigestMismatch =>
      "\"supply_digest_mismatch\""

def natOrNull :
    Except BlockReplayReject BlockReplaySummary ->
    (BlockReplaySummary -> Nat) -> String
  | Except.ok output, selector => "\"" ++ toString (selector output) ++ "\""
  | Except.error _, _ => "null"

def boolOrNull :
    Except BlockReplayReject BlockReplaySummary ->
    (BlockReplaySummary -> Bool) -> String
  | Except.ok output, selector => boolJson (selector output)
  | Except.error _, _ => "null"

def blockReplayCaseJson
    (name : String)
    (input : BlockReplayInput) : String :=
  let result := evaluateBlockReplayRefinement input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"leaf_start\": " ++ toString input.leafStart ++ ",\n"
    ++ "      \"commitment_count\": " ++ toString input.commitmentCount ++ ",\n"
    ++ "      \"ciphertext_count\": " ++ toString input.ciphertextCount ++ ",\n"
    ++ "      \"nullifier_count\": " ++ toString input.nullifierCount ++ ",\n"
    ++ "      \"nullifier_state\": "
      ++ nullifierImportStateJson input.nullifierState ++ ",\n"
    ++ "      \"bridge_replay_state\": "
      ++ bridgeReplayStateJson input.bridgeReplayState ++ ",\n"
    ++ "      \"parent_supply\": \"" ++ toString input.parentSupply ++ "\",\n"
    ++ "      \"height\": " ++ toString input.height ++ ",\n"
    ++ "      \"fee_total\": " ++ toString input.feeTotal ++ ",\n"
    ++ "      \"has_coinbase\": " ++ boolJson input.hasCoinbase ++ ",\n"
    ++ "      \"claimed_supply\": \"" ++ toString input.claimedSupply ++ "\",\n"
    ++ "      \"tx_count_matches\": " ++ boolJson input.txCountMatches ++ ",\n"
    ++ "      \"state_root_matches\": " ++ boolJson input.stateRootMatches ++ ",\n"
    ++ "      \"kernel_root_matches\": " ++ boolJson input.kernelRootMatches ++ ",\n"
    ++ "      \"nullifier_root_matches\": "
      ++ boolJson input.nullifierRootMatches ++ ",\n"
    ++ "      \"extrinsics_root_matches\": "
      ++ boolJson input.extrinsicsRootMatches ++ ",\n"
    ++ "      \"message_root_matches\": "
      ++ boolJson input.messageRootMatches ++ ",\n"
    ++ "      \"message_count_matches\": "
      ++ boolJson input.messageCountMatches ++ ",\n"
    ++ "      \"header_mmr_root_matches\": "
      ++ boolJson input.headerMmrRootMatches ++ ",\n"
    ++ "      \"header_mmr_len_matches\": "
      ++ boolJson input.headerMmrLenMatches ++ ",\n"
    ++ "      \"expected_next_leaf_count\": "
      ++ natOrNull result BlockReplaySummary.nextLeafCount ++ ",\n"
    ++ "      \"expected_imported_nullifier_count\": "
      ++ natOrNull result BlockReplaySummary.importedNullifierCount ++ ",\n"
    ++ "      \"expected_imported_bridge_replay\": "
      ++ boolOrNull result BlockReplaySummary.importedBridgeReplay ++ ",\n"
    ++ "      \"expected_supply\": "
      ++ natOrNull result BlockReplaySummary.expectedSupply ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (match result with | Except.ok _ => true | Except.error _ => false)
      ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def bridgeReplayValid : BlockReplayInput :=
  {
    validReplay with
    leafStart := 12,
    commitmentCount := 0,
    ciphertextCount := 0,
    nullifierCount := 0,
    bridgeReplayState := BridgeReplayState.valid
  }

def ciphertextCountMismatch : BlockReplayInput :=
  { validReplay with ciphertextCount := 1 }

def commitmentIndexOverflow : BlockReplayInput :=
  {
    validReplay with
    leafStart := u64Max,
    commitmentCount := 1,
    ciphertextCount := 1,
    nullifierCount := 0
  }

def bridgeReplayDuplicate : BlockReplayInput :=
  { bridgeReplayValid with bridgeReplayState := BridgeReplayState.alreadyConsumed }

def txCountMismatch : BlockReplayInput :=
  { validReplay with txCountMatches := false }

def messageCountMismatch : BlockReplayInput :=
  { validReplay with messageCountMatches := false }

def validCoinbaseReplay : BlockReplayInput :=
  {
    validReplay with
    height := 1,
    feeTotal := 1,
    hasCoinbase := true,
    claimedSupply := 499429324
  }

def coinbaseRewardOverflow : BlockReplayInput :=
  {
    validReplay with
    height := 1,
    feeTotal := Hegemon.Consensus.maxU64,
    hasCoinbase := true
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"block_replay_refinement_cases\": [\n"
    ++ blockReplayCaseJson "valid-transfer-replay" validReplay ++ ",\n"
    ++ blockReplayCaseJson "valid-bridge-replay" bridgeReplayValid ++ ",\n"
    ++ blockReplayCaseJson "valid-coinbase-replay" validCoinbaseReplay ++ ",\n"
    ++ blockReplayCaseJson "ciphertext-count-mismatch-rejected"
      ciphertextCountMismatch ++ ",\n"
    ++ blockReplayCaseJson "commitment-index-overflow-rejected"
      commitmentIndexOverflow ++ ",\n"
    ++ blockReplayCaseJson "duplicate-nullifier-replay-rejected"
      duplicateNullifierReplay ++ ",\n"
    ++ blockReplayCaseJson "bridge-replay-duplicate-rejected"
      bridgeReplayDuplicate ++ ",\n"
    ++ blockReplayCaseJson "supply-overflow-replay-rejected"
      supplyOverflowReplay ++ ",\n"
    ++ blockReplayCaseJson "coinbase-reward-overflow-rejected"
      coinbaseRewardOverflow ++ ",\n"
    ++ blockReplayCaseJson "counterfeit-supply-rejected"
      counterfeitSupplyReplay ++ ",\n"
    ++ blockReplayCaseJson "tx-count-mismatch-rejected"
      txCountMismatch ++ ",\n"
    ++ blockReplayCaseJson "message-count-mismatch-rejected"
      messageCountMismatch ++ ",\n"
    ++ blockReplayCaseJson "state-root-precedes-supply-digest"
      counterfeitStateAndSupplyReplay ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
