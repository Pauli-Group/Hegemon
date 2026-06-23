import Hegemon.Bridge.LongRange

open Hegemon.Bridge.LongRange

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ toString first ++ rest.foldl (fun acc value => acc ++ ", " ++ toString value) "" ++ "]"

def optionBoolJson : Option Bool -> String
  | none => "null"
  | some value => boolJson value

def rejectJson : Option Reject -> String
  | none => "null"
  | some Reject.verifierHashMismatch => "\"verifier_hash_mismatch\""
  | some Reject.headerMessageCountMismatch => "\"header_message_count_mismatch\""
  | some Reject.headerMmrMismatch => "\"header_mmr_mismatch\""
  | some Reject.longRangeProofMismatch => "\"long_range_proof_mismatch\""
  | some Reject.parentHashMismatch => "\"parent_hash_mismatch\""
  | some Reject.headerMmrOpeningMismatch => "\"header_mmr_opening_mismatch\""
  | some Reject.messageIndexOutOfBounds => "\"message_index_out_of_bounds\""
  | some Reject.receiptOutputMismatch => "\"receipt_output_mismatch\""
  | some Reject.flyClientSampleMismatch => "\"flyclient_sample_mismatch\""
  | some Reject.confirmationPolicyMismatch => "\"confirmation_policy_mismatch\""
  | some Reject.workPolicyMismatch => "\"work_policy_mismatch\""

def shapeCaseJson (name : String) (input : ShapeInput) : String :=
  let result := evaluateShape input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"verifier_hash_matches\": " ++ boolJson input.verifierHashMatches ++ ",\n"
    ++ "      \"message_count\": " ++ toString input.messageCount ++ ",\n"
    ++ "      \"messages_len\": " ++ toString input.messagesLen ++ ",\n"
    ++ "      \"trusted_height\": " ++ toString input.trustedHeight ++ ",\n"
    ++ "      \"tip_height\": " ++ toString input.tipHeight ++ ",\n"
    ++ "      \"tip_header_mmr_len\": " ++ toString input.tipHeaderMmrLen ++ ",\n"
    ++ "      \"tip_parent_opening_leaf_index\": "
    ++ toString input.tipParentOpeningLeafIndex ++ ",\n"
    ++ "      \"message_height\": " ++ toString input.messageHeight ++ ",\n"
    ++ "      \"message_header_mmr_len\": " ++ toString input.messageHeaderMmrLen ++ ",\n"
    ++ "      \"message_opening_leaf_index\": " ++ toString input.messageOpeningLeafIndex ++ ",\n"
    ++ "      \"message_parent_opening_leaf_index\": "
    ++ toString input.messageParentOpeningLeafIndex ++ ",\n"
    ++ "      \"message_index\": " ++ toString input.messageIndex ++ ",\n"
      ++ "      \"message_source_chain_matches\": " ++ boolJson input.messageSourceChainMatches ++ ",\n"
      ++ "      \"message_source_height\": " ++ toString input.messageSourceHeight ++ ",\n"
      ++ "      \"sample_count\": " ++ toString input.sampleCount ++ ",\n"
      ++ "      \"expected_sample_indices\": " ++ natArrayJson input.expectedSampleIndices ++ ",\n"
    ++ "      \"sample_header_heights\": " ++ natArrayJson input.sampleHeaderHeights ++ ",\n"
    ++ "      \"sample_opening_leaf_indices\": " ++ natArrayJson input.sampleOpeningLeafIndices ++ ",\n"
    ++ "      \"sample_parent_opening_leaf_indices\": "
    ++ natArrayJson input.sampleParentOpeningLeafIndices ++ ",\n"
    ++ "      \"min_confirmations\": " ++ toString input.minConfirmations ++ ",\n"
    ++ "      \"tip_work\": \"" ++ toString input.tipWork ++ "\",\n"
    ++ "      \"min_tip_work\": \"" ++ toString input.minTipWork ++ "\",\n"
    ++ "      \"expected_output_matches\": " ++ optionBoolJson input.expectedOutputMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectJson result ++ ",\n"
    ++ "      \"expected_confirmations_checked\": "
    ++ (if result == none then toString (confirmationsChecked input) else "null") ++ "\n"
    ++ "    }"

def directReceiptCaseJson (name : String) (input : DirectReceiptInput) : String :=
  let result := evaluateDirectReceipt input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"claimed_output_matches_derived\": "
      ++ boolJson input.claimedOutputMatchesDerived ++ ",\n"
    ++ "      \"min_confirmations\": " ++ toString input.minConfirmations ++ ",\n"
    ++ "      \"checkpoint_work\": \"" ++ toString input.checkpointWork ++ "\",\n"
    ++ "      \"min_work\": \"" ++ toString input.minWork ++ "\",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectJson result ++ ",\n"
    ++ "      \"expected_confirmations_checked\": "
    ++ (if result == none then toString directReceiptConfirmationsChecked else "null") ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"long_range_shape_cases\": [\n"
    ++ shapeCaseJson "valid-long-range-shape" validShape ++ ",\n"
    ++ shapeCaseJson "bad-verifier-hash-rejected"
      { validShape with verifierHashMatches := false } ++ ",\n"
    ++ shapeCaseJson "message-count-mismatch-rejected"
      { validShape with messageCount := 3 } ++ ",\n"
    ++ shapeCaseJson "tip-mmr-len-mismatch-rejected"
      { validShape with tipHeaderMmrLen := 13 } ++ ",\n"
    ++ shapeCaseJson "message-mmr-len-mismatch-rejected"
      { validShape with messageHeaderMmrLen := 11 } ++ ",\n"
    ++ shapeCaseJson "tip-not-after-message-rejected"
      { validShape with
        tipHeight := 12,
        tipHeaderMmrLen := 12,
        tipParentOpeningLeafIndex := 11 } ++ ",\n"
    ++ shapeCaseJson "message-not-after-trusted-rejected"
      { validShape with
        trustedHeight := 12,
        tipHeight := 13,
        tipHeaderMmrLen := 13,
        tipParentOpeningLeafIndex := 12 } ++ ",\n"
    ++ shapeCaseJson "trusted-height-overflow-rejected"
      { validShape with
        trustedHeight := u64Max,
        tipHeight := u64Max,
        tipHeaderMmrLen := u64Max,
        tipParentOpeningLeafIndex := u64Max,
        messageHeight := u64Max,
        messageHeaderMmrLen := u64Max,
        messageOpeningLeafIndex := u64Max,
        messageParentOpeningLeafIndex := u64Max,
        messageSourceHeight := u64Max } ++ ",\n"
    ++ shapeCaseJson "tip-parent-opening-leaf-mismatch-rejected"
      { validShape with tipParentOpeningLeafIndex := 12 } ++ ",\n"
    ++ shapeCaseJson "message-opening-leaf-mismatch-rejected"
      { validShape with messageOpeningLeafIndex := 11 } ++ ",\n"
    ++ shapeCaseJson "message-parent-opening-leaf-mismatch-rejected"
      { validShape with messageParentOpeningLeafIndex := 10 } ++ ",\n"
    ++ shapeCaseJson "message-index-oob-rejected"
      { validShape with messageIndex := 2 } ++ ",\n"
    ++ shapeCaseJson "message-source-chain-mismatch-rejected"
      { validShape with messageSourceChainMatches := false } ++ ",\n"
      ++ shapeCaseJson "message-source-height-mismatch-rejected"
        { validShape with messageSourceHeight := 13 } ++ ",\n"
      ++ shapeCaseJson "zero-sample-count-rejected"
        { validShape with sampleCount := 0 } ++ ",\n"
      ++ shapeCaseJson "sample-count-below-min-rejected"
        { validShape with sampleCount := minSampleCount - 1 } ++ ",\n"
      ++ shapeCaseJson "sample-count-above-max-rejected"
        { validShape with sampleCount := maxSampleCount + 1 } ++ ",\n"
      ++ shapeCaseJson "sample-count-mismatch-rejected"
        { validShape with sampleHeaderHeights := [11, 12] } ++ ",\n"
      ++ shapeCaseJson "sample-domain-smaller-than-count-rejected"
        { validShape with
          tipHeight := 18,
          tipHeaderMmrLen := 18,
          tipParentOpeningLeafIndex := 17 } ++ ",\n"
      ++ shapeCaseJson "duplicate-sample-indices-rejected"
        { validShape with
          expectedSampleIndices := [11, 12, 13, 14, 15, 16, 17, 17],
          sampleHeaderHeights := [11, 12, 13, 14, 15, 16, 17, 17],
          sampleOpeningLeafIndices := [11, 12, 13, 14, 15, 16, 17, 17],
          sampleParentOpeningLeafIndices := [10, 11, 12, 13, 14, 15, 16, 16] } ++ ",\n"
      ++ shapeCaseJson "sample-height-mismatch-rejected"
        { validShape with sampleHeaderHeights := [11, 12, 13, 14, 15, 16, 17, 19] } ++ ",\n"
      ++ shapeCaseJson "sample-opening-leaf-mismatch-rejected"
        { validShape with sampleOpeningLeafIndices := [11, 12, 13, 14, 15, 16, 17, 19] } ++ ",\n"
      ++ shapeCaseJson "sample-parent-opening-leaf-mismatch-rejected"
        { validShape with sampleParentOpeningLeafIndices := [10, 11, 12, 13, 14, 15, 16, 16] } ++ ",\n"
    ++ shapeCaseJson "under-confirmed-rejected"
      { validShape with minConfirmations := 12 } ++ ",\n"
    ++ shapeCaseJson "insufficient-tip-work-rejected"
      { validShape with minTipWork := 1001 } ++ ",\n"
    ++ shapeCaseJson "claimed-output-mismatch-rejected"
      { validShape with expectedOutputMatches := some false } ++ ",\n"
    ++ shapeCaseJson "claimed-output-omitted-accepted"
      { validShape with expectedOutputMatches := none } ++ "\n"
    ++ "  ],\n"
    ++ "  \"direct_receipt_cases\": [\n"
    ++ directReceiptCaseJson "valid-direct-receipt"
      validDirectReceipt ++ ",\n"
    ++ directReceiptCaseJson "direct-receipt-claimed-output-mismatch-rejected"
      { validDirectReceipt with claimedOutputMatchesDerived := false } ++ ",\n"
    ++ directReceiptCaseJson "direct-receipt-under-confirmed-rejected"
      { validDirectReceipt with minConfirmations := 2 } ++ ",\n"
    ++ directReceiptCaseJson "direct-receipt-insufficient-work-rejected"
      { validDirectReceipt with minWork := 1001 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
