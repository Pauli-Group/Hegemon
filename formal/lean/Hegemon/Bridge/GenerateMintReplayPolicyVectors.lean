import Hegemon.Bridge.MintReplayPolicy

open Hegemon
open Hegemon.Bridge
open Hegemon.Bridge.MintReplayPolicy

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option ReceiptMintReplayReject -> String
  | none => "null"
  | some ReceiptMintReplayReject.notInboundBridgeMint =>
      "\"not_inbound_bridge_mint\""
  | some ReceiptMintReplayReject.stateDeltaMintPresent =>
      "\"state_delta_mint_present\""
  | some ReceiptMintReplayReject.receiptEnvelopeMissing =>
      "\"receipt_envelope_missing\""
  | some ReceiptMintReplayReject.receiptNotVerified =>
      "\"receipt_not_verified\""
  | some ReceiptMintReplayReject.receiptPayloadMismatch =>
      "\"receipt_payload_mismatch\""
  | some ReceiptMintReplayReject.replayAlreadyConsumed =>
      "\"replay_already_consumed\""
  | some ReceiptMintReplayReject.mintNotAuthorized =>
      "\"mint_not_authorized\""
  | some ReceiptMintReplayReject.amountDoesNotMatchReceipt =>
      "\"amount_does_not_match_receipt\""
  | some ReceiptMintReplayReject.amountOutOfBounds =>
      "\"amount_out_of_bounds\""

def commaJoin : List String -> String
  | [] => ""
  | [item] => item
  | item :: rest => item ++ ", " ++ commaJoin rest

def hexArrayJson (values : List (List Byte)) : String :=
  "[" ++ commaJoin (values.map fun value => "\"" ++ hexBytes value ++ "\"") ++ "]"

def sampleReplayKey : ReplayKey :=
  patternedBytes 48 0x6d

def consumedReplayState : ReplayState :=
  { consumed := [sampleReplayKey], pending := [] }

def baseMintReplayInput : ReceiptMintReplayInput :=
  {
    inboundBridgeMint := true,
    stateDeltasAbsent := true,
    receiptEnvelopePresent := true,
    receiptVerified := true,
    receiptPayloadMatches := true,
    replayState := ReplayState.empty,
    replayKey := sampleReplayKey,
    mintAuthorized := true,
    amountMatchesReceipt := true,
    amountWithinBound := true
  }

def caseJson (name : String) (input : ReceiptMintReplayInput) : String :=
  let rejection := receiptMintReplayRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"inbound_bridge_mint\": " ++ boolJson input.inboundBridgeMint ++ ",\n"
    ++ "      \"state_deltas_absent\": " ++ boolJson input.stateDeltasAbsent ++ ",\n"
    ++ "      \"receipt_envelope_present\": " ++ boolJson input.receiptEnvelopePresent ++ ",\n"
    ++ "      \"receipt_verified\": " ++ boolJson input.receiptVerified ++ ",\n"
    ++ "      \"receipt_payload_matches\": " ++ boolJson input.receiptPayloadMatches ++ ",\n"
    ++ "      \"initial_consumed\": " ++ hexArrayJson input.replayState.consumed ++ ",\n"
    ++ "      \"initial_pending\": " ++ hexArrayJson input.replayState.pending ++ ",\n"
    ++ "      \"replay_key\": \"" ++ hexBytes input.replayKey ++ "\",\n"
    ++ "      \"mint_authorized\": " ++ boolJson input.mintAuthorized ++ ",\n"
    ++ "      \"amount_matches_receipt\": " ++ boolJson input.amountMatchesReceipt ++ ",\n"
    ++ "      \"amount_within_bound\": " ++ boolJson input.amountWithinBound ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson rejection ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_mint_replay_cases\": [\n"
    ++ caseJson "valid-inbound-mint-accepted" baseMintReplayInput ++ ",\n"
    ++ caseJson "not-inbound-bridge-mint-rejected"
      { baseMintReplayInput with inboundBridgeMint := false } ++ ",\n"
    ++ caseJson "state-delta-mint-present-rejected"
      { baseMintReplayInput with stateDeltasAbsent := false } ++ ",\n"
    ++ caseJson "receipt-missing-rejected"
      { baseMintReplayInput with receiptEnvelopePresent := false } ++ ",\n"
    ++ caseJson "receipt-not-verified-rejected"
      { baseMintReplayInput with receiptVerified := false } ++ ",\n"
    ++ caseJson "payload-mismatch-rejected"
      { baseMintReplayInput with receiptPayloadMatches := false } ++ ",\n"
    ++ caseJson "replay-already-consumed-rejected"
      { baseMintReplayInput with replayState := consumedReplayState } ++ ",\n"
    ++ caseJson "mint-not-authorized-rejected"
      { baseMintReplayInput with mintAuthorized := false } ++ ",\n"
    ++ caseJson "amount-mismatch-rejected"
      { baseMintReplayInput with amountMatchesReceipt := false } ++ ",\n"
    ++ caseJson "amount-out-of-bounds-rejected"
      { baseMintReplayInput with amountWithinBound := false } ++ ",\n"
    ++ caseJson "replay-precedes-mint-authorization"
      { baseMintReplayInput with
          replayState := consumedReplayState,
          mintAuthorized := false }
    ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
