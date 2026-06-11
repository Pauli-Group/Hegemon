namespace Hegemon
namespace Native
namespace BridgeWitnessBackscan

inductive BridgeWitnessBackscanReject where
  | blockActionsDecodeFailed
  | noBridgeMessageInBackscan
deriving DecidableEq, Repr

structure BridgeWitnessBackscanEntry where
  height : Nat
  canonicalHashPresent : Bool
  blockKnown : Bool
  blockActionsDecoded : Bool
  messageIndexInBounds : Bool
deriving DecidableEq, Repr

def evaluateBridgeWitnessBackscan :
    List BridgeWitnessBackscanEntry ->
      Except BridgeWitnessBackscanReject Nat
  | [] => Except.error BridgeWitnessBackscanReject.noBridgeMessageInBackscan
  | entry :: rest =>
      if entry.canonicalHashPresent = false then
        evaluateBridgeWitnessBackscan rest
      else if entry.blockKnown = false then
        evaluateBridgeWitnessBackscan rest
      else if entry.blockActionsDecoded = false then
        Except.error BridgeWitnessBackscanReject.blockActionsDecodeFailed
      else if entry.messageIndexInBounds = true then
        Except.ok entry.height
      else
        evaluateBridgeWitnessBackscan rest

def bridgeWitnessBackscanAccepts
    (entries : List BridgeWitnessBackscanEntry) : Bool :=
  match evaluateBridgeWitnessBackscan entries with
  | Except.ok _ => true
  | Except.error _ => false

def bridgeWitnessBackscanRejection
    (entries : List BridgeWitnessBackscanEntry) :
      Option BridgeWitnessBackscanReject :=
  match evaluateBridgeWitnessBackscan entries with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def bridgeWitnessBackscanSelectedHeight
    (entries : List BridgeWitnessBackscanEntry) : Option Nat :=
  match evaluateBridgeWitnessBackscan entries with
  | Except.ok height => some height
  | Except.error _ => none

theorem empty_backscan_rejects :
    evaluateBridgeWitnessBackscan [] =
      Except.error BridgeWitnessBackscanReject.noBridgeMessageInBackscan := by
  rfl

theorem selectable_head_selects
    {entry : BridgeWitnessBackscanEntry}
    {rest : List BridgeWitnessBackscanEntry}
    (hHash : entry.canonicalHashPresent = true)
    (hKnown : entry.blockKnown = true)
    (hDecode : entry.blockActionsDecoded = true)
    (hIndex : entry.messageIndexInBounds = true) :
    evaluateBridgeWitnessBackscan (entry :: rest) =
      Except.ok entry.height := by
  simp [evaluateBridgeWitnessBackscan, hHash, hKnown, hDecode, hIndex]

theorem missing_hash_skips_to_tail
    {entry : BridgeWitnessBackscanEntry}
    {rest : List BridgeWitnessBackscanEntry}
    (hHash : entry.canonicalHashPresent = false) :
    evaluateBridgeWitnessBackscan (entry :: rest) =
      evaluateBridgeWitnessBackscan rest := by
  simp [evaluateBridgeWitnessBackscan, hHash]

theorem missing_block_skips_to_tail
    {entry : BridgeWitnessBackscanEntry}
    {rest : List BridgeWitnessBackscanEntry}
    (hHash : entry.canonicalHashPresent = true)
    (hKnown : entry.blockKnown = false) :
    evaluateBridgeWitnessBackscan (entry :: rest) =
      evaluateBridgeWitnessBackscan rest := by
  simp [evaluateBridgeWitnessBackscan, hHash, hKnown]

theorem decode_failure_precedes_tail
    {entry : BridgeWitnessBackscanEntry}
    {rest : List BridgeWitnessBackscanEntry}
    (hHash : entry.canonicalHashPresent = true)
    (hKnown : entry.blockKnown = true)
    (hDecode : entry.blockActionsDecoded = false) :
    evaluateBridgeWitnessBackscan (entry :: rest) =
      Except.error BridgeWitnessBackscanReject.blockActionsDecodeFailed := by
  simp [evaluateBridgeWitnessBackscan, hHash, hKnown, hDecode]

theorem message_index_miss_skips_to_tail
    {entry : BridgeWitnessBackscanEntry}
    {rest : List BridgeWitnessBackscanEntry}
    (hHash : entry.canonicalHashPresent = true)
    (hKnown : entry.blockKnown = true)
    (hDecode : entry.blockActionsDecoded = true)
    (hIndex : entry.messageIndexInBounds = false) :
    evaluateBridgeWitnessBackscan (entry :: rest) =
      evaluateBridgeWitnessBackscan rest := by
  simp [evaluateBridgeWitnessBackscan, hHash, hKnown, hDecode, hIndex]

def newestEligible : List BridgeWitnessBackscanEntry := [
  {
    height := 45,
    canonicalHashPresent := true,
    blockKnown := true,
    blockActionsDecoded := true,
    messageIndexInBounds := true
  },
  {
    height := 44,
    canonicalHashPresent := true,
    blockKnown := true,
    blockActionsDecoded := true,
    messageIndexInBounds := true
  }
]

theorem newest_eligible_candidate_wins :
    evaluateBridgeWitnessBackscan newestEligible = Except.ok 45 := by
  rfl

def skippedBeforeOlderEligible : List BridgeWitnessBackscanEntry := [
  {
    height := 45,
    canonicalHashPresent := false,
    blockKnown := false,
    blockActionsDecoded := true,
    messageIndexInBounds := false
  },
  {
    height := 44,
    canonicalHashPresent := true,
    blockKnown := false,
    blockActionsDecoded := true,
    messageIndexInBounds := false
  },
  {
    height := 43,
    canonicalHashPresent := true,
    blockKnown := true,
    blockActionsDecoded := true,
    messageIndexInBounds := false
  },
  {
    height := 42,
    canonicalHashPresent := true,
    blockKnown := true,
    blockActionsDecoded := true,
    messageIndexInBounds := true
  }
]

theorem skipped_records_and_index_misses_reach_older_match :
    evaluateBridgeWitnessBackscan skippedBeforeOlderEligible =
      Except.ok 42 := by
  rfl

def decodeFailureBeforeOlderEligible : List BridgeWitnessBackscanEntry := [
  {
    height := 45,
    canonicalHashPresent := true,
    blockKnown := true,
    blockActionsDecoded := false,
    messageIndexInBounds := false
  },
  {
    height := 44,
    canonicalHashPresent := true,
    blockKnown := true,
    blockActionsDecoded := true,
    messageIndexInBounds := true
  }
]

theorem decode_failure_precedes_older_match :
    evaluateBridgeWitnessBackscan decodeFailureBeforeOlderEligible =
      Except.error BridgeWitnessBackscanReject.blockActionsDecodeFailed := by
  rfl

def noEligibleBridgeMessage : List BridgeWitnessBackscanEntry := [
  {
    height := 45,
    canonicalHashPresent := false,
    blockKnown := false,
    blockActionsDecoded := true,
    messageIndexInBounds := false
  },
  {
    height := 44,
    canonicalHashPresent := true,
    blockKnown := true,
    blockActionsDecoded := true,
    messageIndexInBounds := false
  }
]

theorem no_eligible_bridge_message_rejects :
    evaluateBridgeWitnessBackscan noEligibleBridgeMessage =
      Except.error BridgeWitnessBackscanReject.noBridgeMessageInBackscan := by
  rfl

end BridgeWitnessBackscan
end Native
end Hegemon
