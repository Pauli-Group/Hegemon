namespace Hegemon
namespace Bridge
namespace LongRange

def u32Max : Nat := 4294967295

inductive Reject where
  | verifierHashMismatch
  | headerMessageCountMismatch
  | headerMmrMismatch
  | longRangeProofMismatch
  | headerMmrOpeningMismatch
  | messageIndexOutOfBounds
  | receiptOutputMismatch
  | flyClientSampleMismatch
  | confirmationPolicyMismatch
  | workPolicyMismatch
deriving DecidableEq, Repr

structure ShapeInput where
  verifierHashMatches : Bool
  messageCount : Nat
  messagesLen : Nat
  trustedHeight : Nat
  tipHeight : Nat
  tipHeaderMmrLen : Nat
  messageHeight : Nat
  messageHeaderMmrLen : Nat
  messageOpeningLeafIndex : Nat
  messageIndex : Nat
  messageSourceChainMatches : Bool
  messageSourceHeight : Nat
  expectedSampleIndices : List Nat
  sampleHeaderHeights : List Nat
  sampleOpeningLeafIndices : List Nat
  minConfirmations : Nat
  tipWork : Nat
  minTipWork : Nat
  expectedOutputMatches : Option Bool
deriving DecidableEq, Repr

def confirmationsChecked (input : ShapeInput) : Nat :=
  Nat.min (input.tipHeight - input.messageHeight + 1) u32Max

def samplesMatch : List Nat -> List Nat -> List Nat -> Bool
  | [], [], [] => true
  | expected :: expectedRest, height :: heightRest, opening :: openingRest =>
      expected == height
        && expected == opening
        && samplesMatch expectedRest heightRest openingRest
  | _, _, _ => false

def outputMismatch : Option Bool -> Bool
  | some false => true
  | _ => false

def evaluateShape (input : ShapeInput) : Option Reject :=
  if input.verifierHashMatches = false then
    some Reject.verifierHashMismatch
  else if input.messagesLen > u32Max then
    some Reject.headerMessageCountMismatch
  else if input.messageCount ≠ input.messagesLen then
    some Reject.headerMessageCountMismatch
  else if input.tipHeaderMmrLen ≠ input.tipHeight then
    some Reject.headerMmrMismatch
  else if input.messageHeaderMmrLen ≠ input.messageHeight then
    some Reject.headerMmrMismatch
  else if input.tipHeight ≤ input.messageHeight then
    some Reject.longRangeProofMismatch
  else if input.messageHeight ≤ input.trustedHeight then
    some Reject.longRangeProofMismatch
  else if input.messageOpeningLeafIndex ≠ input.messageHeight then
    some Reject.headerMmrOpeningMismatch
  else if input.messageIndex ≥ input.messagesLen then
    some Reject.messageIndexOutOfBounds
  else if input.messageSourceChainMatches = false then
    some Reject.receiptOutputMismatch
  else if input.messageSourceHeight ≠ input.messageHeight then
    some Reject.receiptOutputMismatch
  else if samplesMatch
      input.expectedSampleIndices
      input.sampleHeaderHeights
      input.sampleOpeningLeafIndices = false then
    some Reject.flyClientSampleMismatch
  else if confirmationsChecked input < input.minConfirmations then
    some Reject.confirmationPolicyMismatch
  else if input.tipWork < input.minTipWork then
    some Reject.workPolicyMismatch
  else if outputMismatch input.expectedOutputMatches then
    some Reject.receiptOutputMismatch
  else
    none

def validShape : ShapeInput :=
  {
    verifierHashMatches := true,
    messageCount := 2,
    messagesLen := 2,
    trustedHeight := 10,
    tipHeight := 14,
    tipHeaderMmrLen := 14,
    messageHeight := 12,
    messageHeaderMmrLen := 12,
    messageOpeningLeafIndex := 12,
    messageIndex := 1,
    messageSourceChainMatches := true,
    messageSourceHeight := 12,
    expectedSampleIndices := [11, 12, 13],
    sampleHeaderHeights := [11, 12, 13],
    sampleOpeningLeafIndices := [11, 12, 13],
    minConfirmations := 3,
    tipWork := 1000,
    minTipWork := 900,
    expectedOutputMatches := some true
  }

theorem valid_shape_accepts :
    evaluateShape validShape = none := by
  native_decide

theorem valid_shape_confirmations :
    confirmationsChecked validShape = 3 := by
  native_decide

theorem rejects_bad_verifier_hash :
    evaluateShape { validShape with verifierHashMatches := false } =
      some Reject.verifierHashMismatch := by
  native_decide

theorem rejects_message_count_mismatch :
    evaluateShape { validShape with messageCount := 3 } =
      some Reject.headerMessageCountMismatch := by
  native_decide

theorem rejects_tip_mmr_len_mismatch :
    evaluateShape { validShape with tipHeaderMmrLen := 13 } =
      some Reject.headerMmrMismatch := by
  native_decide

theorem rejects_tip_not_after_message :
    evaluateShape { validShape with tipHeight := 12, tipHeaderMmrLen := 12 } =
      some Reject.longRangeProofMismatch := by
  native_decide

theorem rejects_message_not_after_trusted :
    evaluateShape
      { validShape with
        trustedHeight := 12,
        tipHeight := 13,
        tipHeaderMmrLen := 13 } =
      some Reject.longRangeProofMismatch := by
  native_decide

theorem rejects_message_opening_leaf_mismatch :
    evaluateShape { validShape with messageOpeningLeafIndex := 11 } =
      some Reject.headerMmrOpeningMismatch := by
  native_decide

theorem rejects_message_index_oob :
    evaluateShape { validShape with messageIndex := 2 } =
      some Reject.messageIndexOutOfBounds := by
  native_decide

theorem rejects_message_source_chain_mismatch :
    evaluateShape { validShape with messageSourceChainMatches := false } =
      some Reject.receiptOutputMismatch := by
  native_decide

theorem rejects_message_source_height_mismatch :
    evaluateShape { validShape with messageSourceHeight := 13 } =
      some Reject.receiptOutputMismatch := by
  native_decide

theorem rejects_sample_count_mismatch :
    evaluateShape { validShape with sampleHeaderHeights := [11, 12] } =
      some Reject.flyClientSampleMismatch := by
  native_decide

theorem rejects_sample_height_mismatch :
    evaluateShape { validShape with sampleHeaderHeights := [11, 13, 13] } =
      some Reject.flyClientSampleMismatch := by
  native_decide

theorem rejects_sample_opening_leaf_mismatch :
    evaluateShape { validShape with sampleOpeningLeafIndices := [11, 12, 12] } =
      some Reject.flyClientSampleMismatch := by
  native_decide

theorem rejects_under_confirmed :
    evaluateShape { validShape with minConfirmations := 4 } =
      some Reject.confirmationPolicyMismatch := by
  native_decide

theorem rejects_insufficient_tip_work :
    evaluateShape { validShape with minTipWork := 1001 } =
      some Reject.workPolicyMismatch := by
  native_decide

theorem rejects_output_mismatch :
    evaluateShape { validShape with expectedOutputMatches := some false } =
      some Reject.receiptOutputMismatch := by
  native_decide

end LongRange
end Bridge
end Hegemon
