namespace Hegemon
namespace Bridge
namespace LongRange

def u32Max : Nat := 4294967295
def u64Max : Nat := 18446744073709551615
def minSampleCount : Nat := 8
def maxSampleCount : Nat := 64

inductive Reject where
  | verifierHashMismatch
  | headerMessageCountMismatch
  | headerMmrMismatch
  | longRangeProofMismatch
  | parentHashMismatch
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
  tipParentOpeningLeafIndex : Nat
  messageHeight : Nat
  messageHeaderMmrLen : Nat
  messageOpeningLeafIndex : Nat
  messageParentOpeningLeafIndex : Nat
  messageIndex : Nat
  messageSourceChainMatches : Bool
  messageSourceHeight : Nat
  sampleCount : Nat
  expectedSampleIndices : List Nat
  sampleHeaderHeights : List Nat
  sampleOpeningLeafIndices : List Nat
  sampleParentOpeningLeafIndices : List Nat
  minConfirmations : Nat
  tipWork : Nat
  minTipWork : Nat
  expectedOutputMatches : Option Bool
deriving DecidableEq, Repr

structure DirectReceiptInput where
  claimedOutputMatchesDerived : Bool
  minConfirmations : Nat
  checkpointWork : Nat
  minWork : Nat
deriving DecidableEq, Repr

def confirmationsChecked (input : ShapeInput) : Nat :=
  Nat.min (input.tipHeight - input.messageHeight + 1) u32Max

def directReceiptConfirmationsChecked : Nat := 1

def sampleDomainLen (input : ShapeInput) : Nat :=
  input.tipHeight - (input.trustedHeight + 1)

def evaluateDirectReceipt (input : DirectReceiptInput) : Option Reject :=
  if input.claimedOutputMatchesDerived = false then
    some Reject.receiptOutputMismatch
  else if directReceiptConfirmationsChecked < input.minConfirmations then
    some Reject.confirmationPolicyMismatch
  else if input.checkpointWork < input.minWork then
    some Reject.workPolicyMismatch
  else
    none

def containsNat (needle : Nat) : List Nat -> Bool
  | [] => false
  | head :: rest =>
      head == needle || containsNat needle rest

def noDuplicatesNat : List Nat -> Bool
  | [] => true
  | head :: rest =>
      containsNat head rest == false && noDuplicatesNat rest

def samplesMatch : List Nat -> List Nat -> List Nat -> Bool
  | [], [], [] => true
  | expected :: expectedRest, height :: heightRest, opening :: openingRest =>
      expected == height
        && expected == opening
        && samplesMatch expectedRest heightRest openingRest
  | _, _, _ => false

def sampleParentsMatch : List Nat -> List Nat -> Bool
  | [], [] => true
  | height :: heightRest, parentOpening :: parentOpeningRest =>
      parentOpening + 1 == height
        && sampleParentsMatch heightRest parentOpeningRest
  | _, _ => false

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
  else if input.trustedHeight ≥ u64Max then
    some Reject.longRangeProofMismatch
  else if input.tipHeight ≤ input.messageHeight then
    some Reject.longRangeProofMismatch
  else if input.messageHeight ≤ input.trustedHeight then
    some Reject.longRangeProofMismatch
  else if input.tipParentOpeningLeafIndex + 1 ≠ input.tipHeight then
    some Reject.parentHashMismatch
  else if input.messageOpeningLeafIndex ≠ input.messageHeight then
    some Reject.headerMmrOpeningMismatch
  else if input.messageParentOpeningLeafIndex + 1 ≠ input.messageHeight then
    some Reject.parentHashMismatch
  else if input.messageIndex ≥ input.messagesLen then
    some Reject.messageIndexOutOfBounds
  else if input.messageSourceChainMatches = false then
    some Reject.receiptOutputMismatch
  else if input.messageSourceHeight ≠ input.messageHeight then
    some Reject.receiptOutputMismatch
  else if input.sampleCount < minSampleCount then
    some Reject.flyClientSampleMismatch
  else if input.sampleCount > maxSampleCount then
    some Reject.flyClientSampleMismatch
  else if sampleDomainLen input < input.sampleCount then
    some Reject.flyClientSampleMismatch
  else if input.expectedSampleIndices.length ≠ input.sampleCount then
    some Reject.flyClientSampleMismatch
  else if noDuplicatesNat input.expectedSampleIndices = false then
    some Reject.flyClientSampleMismatch
  else if samplesMatch
      input.expectedSampleIndices
      input.sampleHeaderHeights
      input.sampleOpeningLeafIndices = false then
    some Reject.flyClientSampleMismatch
  else if sampleParentsMatch
      input.sampleHeaderHeights
      input.sampleParentOpeningLeafIndices = false then
    some Reject.parentHashMismatch
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
    tipHeight := 22,
    tipHeaderMmrLen := 22,
    tipParentOpeningLeafIndex := 21,
    messageHeight := 12,
    messageHeaderMmrLen := 12,
    messageOpeningLeafIndex := 12,
    messageParentOpeningLeafIndex := 11,
    messageIndex := 1,
    messageSourceChainMatches := true,
    messageSourceHeight := 12,
    sampleCount := minSampleCount,
    expectedSampleIndices := [11, 12, 13, 14, 15, 16, 17, 18],
    sampleHeaderHeights := [11, 12, 13, 14, 15, 16, 17, 18],
    sampleOpeningLeafIndices := [11, 12, 13, 14, 15, 16, 17, 18],
    sampleParentOpeningLeafIndices := [10, 11, 12, 13, 14, 15, 16, 17],
    minConfirmations := 3,
    tipWork := 1000,
    minTipWork := 900,
    expectedOutputMatches := some true
  }

def validDirectReceipt : DirectReceiptInput :=
  {
    claimedOutputMatchesDerived := true,
    minConfirmations := 1,
    checkpointWork := 1000,
    minWork := 900
  }

theorem valid_shape_accepts :
    evaluateShape validShape = none := by
  decide

theorem valid_direct_receipt_accepts :
    evaluateDirectReceipt validDirectReceipt = none := by
  decide

theorem valid_shape_confirmations :
    confirmationsChecked validShape = 11 := by
  decide

theorem valid_direct_receipt_confirmations :
    directReceiptConfirmationsChecked = 1 := by
  decide

theorem rejects_bad_verifier_hash :
    evaluateShape { validShape with verifierHashMatches := false } =
      some Reject.verifierHashMismatch := by
  decide

theorem rejects_message_count_mismatch :
    evaluateShape { validShape with messageCount := 3 } =
      some Reject.headerMessageCountMismatch := by
  decide

theorem rejects_tip_mmr_len_mismatch :
    evaluateShape { validShape with tipHeaderMmrLen := 13 } =
      some Reject.headerMmrMismatch := by
  decide

theorem rejects_tip_not_after_message :
    evaluateShape
      { validShape with
        tipHeight := 12,
        tipHeaderMmrLen := 12,
        tipParentOpeningLeafIndex := 11 } =
      some Reject.longRangeProofMismatch := by
  decide

theorem rejects_message_not_after_trusted :
    evaluateShape
      { validShape with
        trustedHeight := 12,
        tipHeight := 13,
        tipHeaderMmrLen := 13,
        tipParentOpeningLeafIndex := 12 } =
      some Reject.longRangeProofMismatch := by
  decide

theorem rejects_trusted_height_overflow :
    evaluateShape
      { validShape with
        trustedHeight := u64Max,
        tipHeight := u64Max,
        tipHeaderMmrLen := u64Max,
        tipParentOpeningLeafIndex := u64Max,
        messageHeight := u64Max,
        messageHeaderMmrLen := u64Max,
        messageOpeningLeafIndex := u64Max,
        messageParentOpeningLeafIndex := u64Max,
        messageSourceHeight := u64Max } =
      some Reject.longRangeProofMismatch := by
  decide

theorem rejects_tip_parent_opening_leaf_mismatch :
    evaluateShape { validShape with tipParentOpeningLeafIndex := 12 } =
      some Reject.parentHashMismatch := by
  decide

theorem rejects_message_opening_leaf_mismatch :
    evaluateShape { validShape with messageOpeningLeafIndex := 11 } =
      some Reject.headerMmrOpeningMismatch := by
  decide

theorem rejects_message_parent_opening_leaf_mismatch :
    evaluateShape { validShape with messageParentOpeningLeafIndex := 10 } =
      some Reject.parentHashMismatch := by
  decide

theorem rejects_message_index_oob :
    evaluateShape { validShape with messageIndex := 2 } =
      some Reject.messageIndexOutOfBounds := by
  decide

theorem rejects_message_source_chain_mismatch :
    evaluateShape { validShape with messageSourceChainMatches := false } =
      some Reject.receiptOutputMismatch := by
  decide

theorem rejects_message_source_height_mismatch :
    evaluateShape { validShape with messageSourceHeight := 13 } =
      some Reject.receiptOutputMismatch := by
  decide

theorem rejects_zero_sample_count :
    evaluateShape { validShape with sampleCount := 0 } =
      some Reject.flyClientSampleMismatch := by
  decide

theorem rejects_sample_count_below_min :
    evaluateShape { validShape with sampleCount := minSampleCount - 1 } =
      some Reject.flyClientSampleMismatch := by
  decide

theorem rejects_sample_count_above_max :
    evaluateShape { validShape with sampleCount := maxSampleCount + 1 } =
      some Reject.flyClientSampleMismatch := by
  decide

theorem rejects_sample_count_mismatch :
    evaluateShape { validShape with sampleHeaderHeights := [11, 12] } =
      some Reject.flyClientSampleMismatch := by
  decide

theorem rejects_sample_domain_smaller_than_count :
    evaluateShape
      { validShape with
        tipHeight := 18,
        tipHeaderMmrLen := 18,
        tipParentOpeningLeafIndex := 17 } =
      some Reject.flyClientSampleMismatch := by
  decide

theorem rejects_duplicate_sample_indices :
    evaluateShape
      { validShape with
        expectedSampleIndices := [11, 12, 13, 14, 15, 16, 17, 17],
        sampleHeaderHeights := [11, 12, 13, 14, 15, 16, 17, 17],
        sampleOpeningLeafIndices := [11, 12, 13, 14, 15, 16, 17, 17],
        sampleParentOpeningLeafIndices := [10, 11, 12, 13, 14, 15, 16, 16] } =
      some Reject.flyClientSampleMismatch := by
  decide

theorem rejects_sample_height_mismatch :
    evaluateShape { validShape with sampleHeaderHeights := [11, 12, 13, 14, 15, 16, 17, 19] } =
      some Reject.flyClientSampleMismatch := by
  decide

theorem rejects_sample_opening_leaf_mismatch :
    evaluateShape { validShape with sampleOpeningLeafIndices := [11, 12, 13, 14, 15, 16, 17, 19] } =
      some Reject.flyClientSampleMismatch := by
  decide

theorem rejects_sample_parent_opening_leaf_mismatch :
    evaluateShape { validShape with sampleParentOpeningLeafIndices := [10, 11, 12, 13, 14, 15, 16, 16] } =
      some Reject.parentHashMismatch := by
  decide

theorem rejects_under_confirmed :
    evaluateShape { validShape with minConfirmations := 12 } =
      some Reject.confirmationPolicyMismatch := by
  decide

theorem rejects_insufficient_tip_work :
    evaluateShape { validShape with minTipWork := 1001 } =
      some Reject.workPolicyMismatch := by
  decide

theorem rejects_output_mismatch :
    evaluateShape { validShape with expectedOutputMatches := some false } =
      some Reject.receiptOutputMismatch := by
  decide

theorem rejects_direct_receipt_claimed_output_mismatch :
    evaluateDirectReceipt { validDirectReceipt with
      claimedOutputMatchesDerived := false } =
      some Reject.receiptOutputMismatch := by
  decide

theorem rejects_direct_receipt_under_confirmed :
    evaluateDirectReceipt { validDirectReceipt with minConfirmations := 2 } =
      some Reject.confirmationPolicyMismatch := by
  decide

theorem rejects_direct_receipt_insufficient_work :
    evaluateDirectReceipt { validDirectReceipt with
      minWork := 1001 } =
      some Reject.workPolicyMismatch := by
  decide

end LongRange
end Bridge
end Hegemon
