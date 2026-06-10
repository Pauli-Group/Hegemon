namespace Hegemon
namespace Native
namespace ActionStateEffect

def u64Max : Nat := 18446744073709551615

def checkedAddU64 (left right : Nat) : Option Nat :=
  if left + right <= u64Max then some (left + right) else none

inductive NullifierImportState where
  | valid
  | zero
  | duplicate
deriving DecidableEq, Repr

inductive BridgeReplayState where
  | absent
  | valid
  | alreadyConsumed
deriving DecidableEq, Repr

inductive ActionStateEffectReject where
  | ciphertextCountMismatch
  | commitmentIndexOverflow
  | nullifierZero
  | duplicateNullifier
  | bridgeReplayDuplicate
deriving DecidableEq, Repr

structure ActionStateEffectInput where
  leafStart : Nat
  commitmentCount : Nat
  ciphertextCount : Nat
  nullifierCount : Nat
  nullifierState : NullifierImportState
  bridgeReplayState : BridgeReplayState
deriving DecidableEq, Repr

structure ActionStateEffectOutput where
  nextLeafCount : Nat
  importedNullifierCount : Nat
  importedBridgeReplay : Bool
deriving DecidableEq, Repr

def evaluateActionStateEffect
    (input : ActionStateEffectInput) :
    Except ActionStateEffectReject ActionStateEffectOutput :=
  if input.commitmentCount = input.ciphertextCount then
    match checkedAddU64 input.leafStart input.commitmentCount with
    | none => Except.error ActionStateEffectReject.commitmentIndexOverflow
    | some nextLeaf =>
        match input.nullifierState with
        | NullifierImportState.zero =>
            Except.error ActionStateEffectReject.nullifierZero
        | NullifierImportState.duplicate =>
            Except.error ActionStateEffectReject.duplicateNullifier
        | NullifierImportState.valid =>
            match input.bridgeReplayState with
            | BridgeReplayState.alreadyConsumed =>
                Except.error ActionStateEffectReject.bridgeReplayDuplicate
            | BridgeReplayState.absent =>
                Except.ok
                  { nextLeafCount := nextLeaf,
                    importedNullifierCount := input.nullifierCount,
                    importedBridgeReplay := false }
            | BridgeReplayState.valid =>
                Except.ok
                  { nextLeafCount := nextLeaf,
                    importedNullifierCount := input.nullifierCount,
                    importedBridgeReplay := true }
  else
    Except.error ActionStateEffectReject.ciphertextCountMismatch

def actionStateEffectAccepts (input : ActionStateEffectInput) : Bool :=
  match evaluateActionStateEffect input with
  | Except.ok _ => true
  | Except.error _ => false

def actionStateEffectPreconditions (input : ActionStateEffectInput) : Bool :=
  if input.commitmentCount = input.ciphertextCount then
    match checkedAddU64 input.leafStart input.commitmentCount with
    | none => false
    | some _ =>
        match input.nullifierState with
        | NullifierImportState.valid =>
            match input.bridgeReplayState with
            | BridgeReplayState.alreadyConsumed => false
            | _ => true
        | _ => false
  else
    false

theorem accepts_iff_state_effect_preconditions
    (input : ActionStateEffectInput) :
    actionStateEffectAccepts input =
      actionStateEffectPreconditions input := by
  cases input with
  | mk leafStart commitmentCount ciphertextCount nullifierCount
      nullifierState bridgeReplayState =>
      unfold actionStateEffectAccepts actionStateEffectPreconditions
        evaluateActionStateEffect
      by_cases counts : commitmentCount = ciphertextCount
      · rw [if_pos counts, if_pos counts]
        cases addResult : checkedAddU64 leafStart commitmentCount with
        | none =>
            rfl
        | some nextLeaf =>
            cases nullifierState <;> cases bridgeReplayState <;> rfl
      · rw [if_neg counts, if_neg counts]

def validTransferEffect : ActionStateEffectInput :=
  {
    leafStart := 10,
    commitmentCount := 2,
    ciphertextCount := 2,
    nullifierCount := 1,
    nullifierState := NullifierImportState.valid,
    bridgeReplayState := BridgeReplayState.absent
  }

theorem valid_transfer_effect_accepts :
    evaluateActionStateEffect validTransferEffect =
      Except.ok
        { nextLeafCount := 12,
          importedNullifierCount := 1,
          importedBridgeReplay := false } := by
  rfl

def validBridgeReplayEffect : ActionStateEffectInput :=
  {
    leafStart := 12,
    commitmentCount := 0,
    ciphertextCount := 0,
    nullifierCount := 0,
    nullifierState := NullifierImportState.valid,
    bridgeReplayState := BridgeReplayState.valid
  }

theorem valid_bridge_replay_effect_accepts :
    evaluateActionStateEffect validBridgeReplayEffect =
      Except.ok
        { nextLeafCount := 12,
          importedNullifierCount := 0,
          importedBridgeReplay := true } := by
  rfl

def ciphertextCountMismatch : ActionStateEffectInput :=
  { validTransferEffect with ciphertextCount := 1 }

theorem ciphertext_count_mismatch_rejects :
    evaluateActionStateEffect ciphertextCountMismatch =
      Except.error ActionStateEffectReject.ciphertextCountMismatch := by
  rfl

def commitmentIndexOverflow : ActionStateEffectInput :=
  {
    leafStart := u64Max,
    commitmentCount := 1,
    ciphertextCount := 1,
    nullifierCount := 0,
    nullifierState := NullifierImportState.valid,
    bridgeReplayState := BridgeReplayState.absent
  }

theorem commitment_index_overflow_rejects :
    evaluateActionStateEffect commitmentIndexOverflow =
      Except.error ActionStateEffectReject.commitmentIndexOverflow := by
  rfl

def maxLeafEmptyAction : ActionStateEffectInput :=
  { commitmentIndexOverflow with commitmentCount := 0, ciphertextCount := 0 }

theorem max_leaf_empty_action_accepts :
    evaluateActionStateEffect maxLeafEmptyAction =
      Except.ok
        { nextLeafCount := u64Max,
          importedNullifierCount := 0,
          importedBridgeReplay := false } := by
  rfl

def zeroNullifier : ActionStateEffectInput :=
  { validTransferEffect with nullifierState := NullifierImportState.zero }

theorem zero_nullifier_rejects :
    evaluateActionStateEffect zeroNullifier =
      Except.error ActionStateEffectReject.nullifierZero := by
  rfl

def duplicateNullifier : ActionStateEffectInput :=
  { validTransferEffect with nullifierState := NullifierImportState.duplicate }

theorem duplicate_nullifier_rejects :
    evaluateActionStateEffect duplicateNullifier =
      Except.error ActionStateEffectReject.duplicateNullifier := by
  rfl

def bridgeReplayDuplicate : ActionStateEffectInput :=
  {
    leafStart := 0,
    commitmentCount := 0,
    ciphertextCount := 0,
    nullifierCount := 0,
    nullifierState := NullifierImportState.valid,
    bridgeReplayState := BridgeReplayState.alreadyConsumed
  }

theorem bridge_replay_duplicate_rejects :
    evaluateActionStateEffect bridgeReplayDuplicate =
      Except.error ActionStateEffectReject.bridgeReplayDuplicate := by
  rfl

def count_mismatch_precedes_overflow_input : ActionStateEffectInput :=
  { commitmentIndexOverflow with ciphertextCount := 0 }

theorem count_mismatch_precedes_overflow :
    evaluateActionStateEffect count_mismatch_precedes_overflow_input =
      Except.error ActionStateEffectReject.ciphertextCountMismatch := by
  rfl

def overflow_precedes_nullifier_input : ActionStateEffectInput :=
  { commitmentIndexOverflow with nullifierState := NullifierImportState.zero }

theorem overflow_precedes_nullifier :
    evaluateActionStateEffect overflow_precedes_nullifier_input =
      Except.error ActionStateEffectReject.commitmentIndexOverflow := by
  rfl

def nullifier_precedes_bridge_replay_input : ActionStateEffectInput :=
  { duplicateNullifier with bridgeReplayState := BridgeReplayState.alreadyConsumed }

theorem nullifier_precedes_bridge_replay :
    evaluateActionStateEffect nullifier_precedes_bridge_replay_input =
      Except.error ActionStateEffectReject.duplicateNullifier := by
  rfl

end ActionStateEffect
end Native
end Hegemon
