namespace Hegemon
namespace Native
namespace BridgeWitnessExportAdmission

def u32Max : Nat := 4294967295

def bridgeWitnessConfirmationsChecked
    (bestHeight messageHeight : Nat) : Option Nat :=
  if bestHeight < messageHeight then
    none
  else
    some (Nat.min (bestHeight - messageHeight + 1) u32Max)

def maxBridgeWitnessExplicitHistory : Nat := 4096

def bridgeWitnessExplicitHistoryWithinBound
    (explicitBlockHash : Bool)
    (maxExplicitHistory : Nat)
    (confirmations : Nat) : Bool :=
  if explicitBlockHash then
    !(decide (maxExplicitHistory < confirmations))
  else
    true

inductive BridgeWitnessExportReject where
  | malformedBlockHash
  | unknownBlock
  | missingCanonicalHeight
  | noncanonicalBlock
  | blockActionsDecodeFailed
  | messageIndexOutOfBounds
  | missingParent
  | tipBeforeMessage
  | explicitHistoryTooLong
deriving DecidableEq, Repr

structure BridgeWitnessExportInput where
  blockHashParameterValid : Bool
  explicitBlockHash : Bool
  blockKnown : Bool
  canonicalHeightPresent : Bool
  blockIsCanonical : Bool
  blockActionsDecoded : Bool
  messageIndexInBounds : Bool
  parentKnown : Bool
  bestHeight : Nat
  messageHeight : Nat
  maxExplicitHistory : Nat
deriving DecidableEq, Repr

def evaluateBridgeWitnessExport
    (input : BridgeWitnessExportInput) :
      Except BridgeWitnessExportReject Nat :=
  if input.blockHashParameterValid = false then
    Except.error BridgeWitnessExportReject.malformedBlockHash
  else if input.blockKnown = false then
    Except.error BridgeWitnessExportReject.unknownBlock
  else if input.canonicalHeightPresent = false then
    Except.error BridgeWitnessExportReject.missingCanonicalHeight
  else if input.blockIsCanonical = false then
    Except.error BridgeWitnessExportReject.noncanonicalBlock
  else if input.blockActionsDecoded = false then
    Except.error BridgeWitnessExportReject.blockActionsDecodeFailed
  else if input.messageIndexInBounds = false then
    Except.error BridgeWitnessExportReject.messageIndexOutOfBounds
  else if input.parentKnown = false then
    Except.error BridgeWitnessExportReject.missingParent
  else
    match bridgeWitnessConfirmationsChecked input.bestHeight input.messageHeight with
    | none => Except.error BridgeWitnessExportReject.tipBeforeMessage
    | some confirmations =>
        if input.explicitBlockHash && decide (input.maxExplicitHistory < confirmations) then
          Except.error BridgeWitnessExportReject.explicitHistoryTooLong
        else
          Except.ok confirmations

def bridgeWitnessExportAccepts
    (input : BridgeWitnessExportInput) : Bool :=
  match evaluateBridgeWitnessExport input with
  | Except.ok _ => true
  | Except.error _ => false

def bridgeWitnessExportRejection
    (input : BridgeWitnessExportInput) :
      Option BridgeWitnessExportReject :=
  match evaluateBridgeWitnessExport input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def bridgeWitnessExportConfirmations
    (input : BridgeWitnessExportInput) : Option Nat :=
  match evaluateBridgeWitnessExport input with
  | Except.ok confirmations => some confirmations
  | Except.error _ => none

def bridgeWitnessExportPreconditions
    (input : BridgeWitnessExportInput) : Bool :=
  input.blockHashParameterValid
    && input.blockKnown
    && input.canonicalHeightPresent
    && input.blockIsCanonical
    && input.blockActionsDecoded
    && input.messageIndexInBounds
    && input.parentKnown
    && match bridgeWitnessConfirmationsChecked
        input.bestHeight input.messageHeight with
      | none => false
      | some confirmations =>
          bridgeWitnessExplicitHistoryWithinBound
            input.explicitBlockHash input.maxExplicitHistory confirmations

theorem accepts_iff_bridge_witness_export_preconditions
    {input : BridgeWitnessExportInput} :
    bridgeWitnessExportAccepts input = true ↔
      bridgeWitnessExportPreconditions input = true := by
  cases input with
  | mk blockHashParameterValid explicitBlockHash blockKnown canonicalHeightPresent blockIsCanonical
      blockActionsDecoded messageIndexInBounds parentKnown bestHeight messageHeight
      maxExplicitHistory =>
      simp [
        bridgeWitnessExportAccepts,
        bridgeWitnessExportPreconditions,
        evaluateBridgeWitnessExport,
        bridgeWitnessConfirmationsChecked,
        bridgeWitnessExplicitHistoryWithinBound
      ]
      cases blockHashParameterValid <;>
        cases explicitBlockHash <;>
        cases blockKnown <;>
        cases canonicalHeightPresent <;>
        cases blockIsCanonical <;>
        cases blockActionsDecoded <;>
        cases messageIndexInBounds <;>
        cases parentKnown <;>
        simp
      all_goals
        by_cases h : bestHeight < messageHeight
        · simp [h]
        · by_cases over :
            maxExplicitHistory < Nat.min (bestHeight - messageHeight + 1) u32Max
          · simp [h, over]
          · simp [h, over]

def valid : BridgeWitnessExportInput :=
  {
    blockHashParameterValid := true,
    explicitBlockHash := false,
    blockKnown := true,
    canonicalHeightPresent := true,
    blockIsCanonical := true,
    blockActionsDecoded := true,
    messageIndexInBounds := true,
    parentKnown := true,
    bestHeight := 45,
    messageHeight := 42,
    maxExplicitHistory := maxBridgeWitnessExplicitHistory
  }

theorem valid_accepts :
    evaluateBridgeWitnessExport valid = Except.ok 4 := by
  rfl

def sameHeightValid : BridgeWitnessExportInput :=
  { valid with bestHeight := 42, messageHeight := 42 }

theorem same_height_valid_has_one_confirmation :
    evaluateBridgeWitnessExport sameHeightValid = Except.ok 1 := by
  rfl

def cappedConfirmationsValid : BridgeWitnessExportInput :=
  { valid with bestHeight := 18446744073709551615, messageHeight := 0 }

theorem large_confirmation_count_caps_to_u32_max :
    evaluateBridgeWitnessExport cappedConfirmationsValid =
      Except.ok u32Max := by
  rfl

def malformedBlockHash : BridgeWitnessExportInput :=
  { valid with blockHashParameterValid := false }

theorem malformed_block_hash_rejects :
    evaluateBridgeWitnessExport malformedBlockHash =
      Except.error BridgeWitnessExportReject.malformedBlockHash := by
  rfl

def unknownBlock : BridgeWitnessExportInput :=
  { valid with blockKnown := false }

theorem unknown_block_rejects :
    evaluateBridgeWitnessExport unknownBlock =
      Except.error BridgeWitnessExportReject.unknownBlock := by
  rfl

def missingCanonicalHeight : BridgeWitnessExportInput :=
  { valid with canonicalHeightPresent := false }

theorem missing_canonical_height_rejects :
    evaluateBridgeWitnessExport missingCanonicalHeight =
      Except.error BridgeWitnessExportReject.missingCanonicalHeight := by
  rfl

def noncanonicalBlock : BridgeWitnessExportInput :=
  { valid with blockIsCanonical := false }

theorem noncanonical_block_rejects :
    evaluateBridgeWitnessExport noncanonicalBlock =
      Except.error BridgeWitnessExportReject.noncanonicalBlock := by
  rfl

def blockActionsDecodeFailed : BridgeWitnessExportInput :=
  { valid with blockActionsDecoded := false }

theorem block_actions_decode_failed_rejects :
    evaluateBridgeWitnessExport blockActionsDecodeFailed =
      Except.error BridgeWitnessExportReject.blockActionsDecodeFailed := by
  rfl

def messageIndexOutOfBounds : BridgeWitnessExportInput :=
  { valid with messageIndexInBounds := false }

theorem message_index_out_of_bounds_rejects :
    evaluateBridgeWitnessExport messageIndexOutOfBounds =
      Except.error BridgeWitnessExportReject.messageIndexOutOfBounds := by
  rfl

def missingParent : BridgeWitnessExportInput :=
  { valid with parentKnown := false }

theorem missing_parent_rejects :
    evaluateBridgeWitnessExport missingParent =
      Except.error BridgeWitnessExportReject.missingParent := by
  rfl

def tipBeforeMessage : BridgeWitnessExportInput :=
  { valid with bestHeight := 41, messageHeight := 42 }

theorem tip_before_message_rejects :
    evaluateBridgeWitnessExport tipBeforeMessage =
      Except.error BridgeWitnessExportReject.tipBeforeMessage := by
  rfl

def explicitHistoryTooLong : BridgeWitnessExportInput :=
  { valid with
    explicitBlockHash := true,
    bestHeight := 4200,
    messageHeight := 1,
    maxExplicitHistory := maxBridgeWitnessExplicitHistory }

theorem explicit_history_too_long_rejects :
    evaluateBridgeWitnessExport explicitHistoryTooLong =
      Except.error BridgeWitnessExportReject.explicitHistoryTooLong := by
  rfl

def latestBackscanCanExceedExplicitHistoryBound : BridgeWitnessExportInput :=
  { explicitHistoryTooLong with explicitBlockHash := false }

theorem latest_backscan_not_rejected_by_explicit_history_cap :
    evaluateBridgeWitnessExport latestBackscanCanExceedExplicitHistoryBound =
      Except.ok 4200 := by
  rfl

def malformed_hash_precedes_unknown_block_input :
    BridgeWitnessExportInput :=
  { valid with blockHashParameterValid := false, blockKnown := false }

theorem malformed_hash_precedes_unknown_block :
    evaluateBridgeWitnessExport
      malformed_hash_precedes_unknown_block_input =
        Except.error BridgeWitnessExportReject.malformedBlockHash := by
  rfl

def noncanonical_precedes_decode_failure_input :
    BridgeWitnessExportInput :=
  { valid with blockIsCanonical := false, blockActionsDecoded := false }

theorem noncanonical_precedes_decode_failure :
    evaluateBridgeWitnessExport
      noncanonical_precedes_decode_failure_input =
        Except.error BridgeWitnessExportReject.noncanonicalBlock := by
  rfl

def message_index_precedes_missing_parent_input :
    BridgeWitnessExportInput :=
  { valid with messageIndexInBounds := false, parentKnown := false }

theorem message_index_precedes_missing_parent :
    evaluateBridgeWitnessExport
      message_index_precedes_missing_parent_input =
        Except.error BridgeWitnessExportReject.messageIndexOutOfBounds := by
  rfl

def missing_parent_precedes_tip_before_message_input :
    BridgeWitnessExportInput :=
  { valid with
    parentKnown := false,
    bestHeight := 41,
    messageHeight := 42 }

theorem missing_parent_precedes_tip_before_message :
    evaluateBridgeWitnessExport
      missing_parent_precedes_tip_before_message_input =
        Except.error BridgeWitnessExportReject.missingParent := by
  rfl

end BridgeWitnessExportAdmission
end Native
end Hegemon
