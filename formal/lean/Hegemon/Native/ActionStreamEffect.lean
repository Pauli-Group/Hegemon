import Hegemon.Native.ActionStateEffect

namespace Hegemon
namespace Native
namespace ActionStreamEffect

open Hegemon.Native.ActionStateEffect

inductive ActionStreamReject where
  | ciphertextCountMismatch
  | commitmentIndexOverflow
  | nullifierZero
  | duplicateNullifier
  | bridgeReplayDuplicate
deriving DecidableEq, Repr

structure StreamAction where
  commitmentCount : Nat
  ciphertextCount : Nat
  nullifiers : List Nat
  bridgeReplayKey : Option Nat
deriving DecidableEq, Repr

structure ActionStreamInput where
  leafStart : Nat
  spentNullifiers : List Nat
  consumedBridgeReplays : List Nat
  actions : List StreamAction
deriving DecidableEq, Repr

structure ActionStreamOutput where
  nextLeafCount : Nat
  importedNullifierCount : Nat
  importedBridgeReplayCount : Nat
  plannedStarts : List Nat
deriving DecidableEq, Repr

def containsNat (key : Nat) : List Nat -> Bool
  | [] => false
  | head :: tail =>
      if head = key then true else containsNat key tail

theorem containsNat_true_iff {key : Nat} {xs : List Nat} :
    containsNat key xs = true ↔ key ∈ xs := by
  induction xs with
  | nil => simp [containsNat]
  | cons head tail ih =>
      by_cases h : head = key
      · simp [containsNat, h]
      · constructor
        · intro ht
          simp [containsNat, h] at ht
          rw [List.mem_cons]
          exact Or.inr (ih.mp ht)
        · intro hm
          rw [List.mem_cons] at hm
          cases hm with
          | inl hk => exact False.elim (h (Eq.symm hk))
          | inr ht =>
              simp [containsNat, h]
              exact ih.mpr ht

theorem containsNat_false_not_mem {key : Nat} {xs : List Nat}
    (h : containsNat key xs = false) : key ∉ xs := by
  intro mem
  have trueH : containsNat key xs = true := containsNat_true_iff.mpr mem
  simp [trueH] at h

def importNullifiers :
    List Nat -> List Nat -> Except ActionStreamReject (List Nat × Nat)
  | known, [] => Except.ok (known, 0)
  | known, key :: rest =>
      if key = 0 then
        Except.error ActionStreamReject.nullifierZero
      else if containsNat key known then
        Except.error ActionStreamReject.duplicateNullifier
      else
        match importNullifiers (key :: known) rest with
        | Except.error rejection => Except.error rejection
        | Except.ok (nextKnown, imported) =>
            Except.ok (nextKnown, imported + 1)

theorem importNullifiers_preserves_nodup
    {known keys next : List Nat}
    {imported : Nat}
    (knownNodup : known.Nodup)
    (ok : importNullifiers known keys = Except.ok (next, imported)) :
    next.Nodup := by
  induction keys generalizing known next imported with
  | nil =>
      simp [importNullifiers] at ok
      rcases ok with ⟨hnext, _⟩
      subst next
      exact knownNodup
  | cons key rest ih =>
      unfold importNullifiers at ok
      by_cases zero : key = 0
      · simp [zero] at ok
      · simp [zero] at ok
        cases present : containsNat key known with
        | true =>
            simp [present] at ok
        | false =>
            cases rec : importNullifiers (key :: known) rest with
            | error rejection =>
                simp [present, rec] at ok
            | ok pair =>
                cases pair with
                | mk nextKnown importedRest =>
                    simp [present, rec] at ok
                    rcases ok with ⟨hnext, _⟩
                    subst next
                    have keyNotMem : key ∉ known :=
                      containsNat_false_not_mem present
                    have nextKnownNodup : (key :: known).Nodup := by
                      rw [List.nodup_cons]
                      exact ⟨keyNotMem, knownNodup⟩
                    exact ih nextKnownNodup rec

def importBridgeReplay
    (known : List Nat)
    (key : Option Nat) :
    Except ActionStreamReject (List Nat × Nat) :=
  match key with
  | none => Except.ok (known, 0)
  | some replay =>
      if containsNat replay known then
        Except.error ActionStreamReject.bridgeReplayDuplicate
      else
        Except.ok (replay :: known, 1)

def evaluateActionStreamFrom :
    Nat ->
    List Nat ->
    List Nat ->
    List StreamAction ->
    List Nat ->
    Nat ->
    Nat ->
    Except ActionStreamReject ActionStreamOutput
  | leaf, _spent, _consumed, [], plannedStarts, importedNullifiers,
      importedReplays =>
      Except.ok
        { nextLeafCount := leaf,
          importedNullifierCount := importedNullifiers,
          importedBridgeReplayCount := importedReplays,
          plannedStarts := plannedStarts }
  | leaf, spent, consumed, action :: rest, plannedStarts,
      importedNullifiers, importedReplays =>
      if action.commitmentCount = action.ciphertextCount then
        match checkedAddU64 leaf action.commitmentCount with
        | none => Except.error ActionStreamReject.commitmentIndexOverflow
        | some nextLeaf =>
            match importNullifiers spent action.nullifiers with
            | Except.error rejection => Except.error rejection
            | Except.ok (nextSpent, nullifierImports) =>
                match importBridgeReplay consumed action.bridgeReplayKey with
                | Except.error rejection => Except.error rejection
                | Except.ok (nextConsumed, replayImports) =>
                    evaluateActionStreamFrom
                      nextLeaf
                      nextSpent
                      nextConsumed
                      rest
                      (plannedStarts ++ [leaf])
                      (importedNullifiers + nullifierImports)
                      (importedReplays + replayImports)
      else
        Except.error ActionStreamReject.ciphertextCountMismatch

def importedNullifierStateFrom :
    List Nat -> List StreamAction -> List Nat
  | spent, [] => spent
  | spent, action :: rest =>
      match importNullifiers spent action.nullifiers with
      | Except.error _ => spent
      | Except.ok (nextSpent, _) =>
          importedNullifierStateFrom nextSpent rest

theorem evaluateActionStreamFrom_preserves_imported_nullifier_nodup
    {leaf : Nat}
    {spent consumed plannedStarts : List Nat}
    {actions : List StreamAction}
    {importedNullifiers importedReplays : Nat}
    {output : ActionStreamOutput}
    (spentNodup : spent.Nodup)
    (accepted :
      evaluateActionStreamFrom
        leaf
        spent
        consumed
        actions
        plannedStarts
        importedNullifiers
        importedReplays =
          Except.ok output) :
    (importedNullifierStateFrom spent actions).Nodup := by
  induction actions generalizing leaf spent consumed plannedStarts
      importedNullifiers importedReplays output with
  | nil =>
      simp [evaluateActionStreamFrom, importedNullifierStateFrom] at accepted ⊢
      exact spentNodup
  | cons action rest ih =>
      unfold evaluateActionStreamFrom at accepted
      unfold importedNullifierStateFrom
      by_cases countMatches : action.commitmentCount = action.ciphertextCount
      · simp [countMatches] at accepted
        cases nextLeafResult : checkedAddU64 leaf action.ciphertextCount with
        | none =>
            simp [nextLeafResult] at accepted
        | some nextLeaf =>
            cases importResult :
                importNullifiers spent action.nullifiers with
            | error rejection =>
                simp [nextLeafResult, importResult] at accepted
            | ok importedPair =>
                cases importedPair with
                | mk nextSpent nullifierImports =>
                    have nextSpentNodup :
                        nextSpent.Nodup :=
                      importNullifiers_preserves_nodup spentNodup
                        importResult
                    cases bridgeResult :
                        importBridgeReplay consumed action.bridgeReplayKey with
                    | error rejection =>
                        simp [
                          nextLeafResult,
                          importResult,
                          bridgeResult
                        ] at accepted
                    | ok bridgePair =>
                        cases bridgePair with
                        | mk nextConsumed replayImports =>
                            simp [
                              nextLeafResult,
                              importResult,
                              bridgeResult
                            ] at accepted
                            exact ih nextSpentNodup accepted
      · simp [countMatches] at accepted

def evaluateActionStreamEffect
    (input : ActionStreamInput) :
    Except ActionStreamReject ActionStreamOutput :=
  evaluateActionStreamFrom
    input.leafStart
    input.spentNullifiers
    input.consumedBridgeReplays
    input.actions
    []
    0
    0

theorem evaluateActionStreamEffect_preserves_imported_nullifier_nodup
    {input : ActionStreamInput}
    {output : ActionStreamOutput}
    (spentNodup : input.spentNullifiers.Nodup)
    (accepted : evaluateActionStreamEffect input = Except.ok output) :
    (importedNullifierStateFrom input.spentNullifiers input.actions).Nodup :=
  evaluateActionStreamFrom_preserves_imported_nullifier_nodup
    spentNodup accepted

def actionStreamAccepts (input : ActionStreamInput) : Bool :=
  match evaluateActionStreamEffect input with
  | Except.ok _ => true
  | Except.error _ => false

def actionStreamPreconditions (input : ActionStreamInput) : Bool :=
  actionStreamAccepts input

theorem accepts_iff_stream_preconditions
    (input : ActionStreamInput) :
    actionStreamAccepts input = actionStreamPreconditions input := by
  rfl

def validTwoActionStream : ActionStreamInput :=
  {
    leafStart := 10,
    spentNullifiers := [],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 2,
        ciphertextCount := 2,
        nullifiers := [1],
        bridgeReplayKey := none
      },
      {
        commitmentCount := 1,
        ciphertextCount := 1,
        nullifiers := [2, 3],
        bridgeReplayKey := some 7
      }
    ]
  }

theorem valid_two_action_stream_accepts :
    evaluateActionStreamEffect validTwoActionStream =
      Except.ok
        { nextLeafCount := 13,
          importedNullifierCount := 3,
          importedBridgeReplayCount := 1,
          plannedStarts := [10, 12] } := by
  rfl

def emptyStream : ActionStreamInput :=
  {
    leafStart := u64Max,
    spentNullifiers := [1, 2],
    consumedBridgeReplays := [9],
    actions := []
  }

theorem empty_stream_accepts :
    evaluateActionStreamEffect emptyStream =
      Except.ok
        { nextLeafCount := u64Max,
          importedNullifierCount := 0,
          importedBridgeReplayCount := 0,
          plannedStarts := [] } := by
  rfl

def crossActionDuplicateNullifier : ActionStreamInput :=
  {
    leafStart := 0,
    spentNullifiers := [],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 1,
        ciphertextCount := 1,
        nullifiers := [4],
        bridgeReplayKey := none
      },
      {
        commitmentCount := 1,
        ciphertextCount := 1,
        nullifiers := [4],
        bridgeReplayKey := none
      }
    ]
  }

theorem cross_action_duplicate_nullifier_rejects :
    evaluateActionStreamEffect crossActionDuplicateNullifier =
      Except.error ActionStreamReject.duplicateNullifier := by
  rfl

def withinActionDuplicateNullifier : ActionStreamInput :=
  {
    leafStart := 0,
    spentNullifiers := [],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [5, 5],
        bridgeReplayKey := none
      }
    ]
  }

theorem within_action_duplicate_nullifier_rejects :
    evaluateActionStreamEffect withinActionDuplicateNullifier =
      Except.error ActionStreamReject.duplicateNullifier := by
  rfl

def priorSpentDuplicateNullifier : ActionStreamInput :=
  {
    leafStart := 0,
    spentNullifiers := [6],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [6],
        bridgeReplayKey := none
      }
    ]
  }

theorem prior_spent_duplicate_nullifier_rejects :
    evaluateActionStreamEffect priorSpentDuplicateNullifier =
      Except.error ActionStreamReject.duplicateNullifier := by
  rfl

def zeroNullifierSecondAction : ActionStreamInput :=
  {
    leafStart := 0,
    spentNullifiers := [],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [7],
        bridgeReplayKey := none
      },
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [0],
        bridgeReplayKey := none
      }
    ]
  }

theorem zero_nullifier_second_action_rejects :
    evaluateActionStreamEffect zeroNullifierSecondAction =
      Except.error ActionStreamReject.nullifierZero := by
  rfl

def crossActionBridgeReplayDuplicate : ActionStreamInput :=
  {
    leafStart := 0,
    spentNullifiers := [],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [],
        bridgeReplayKey := some 9
      },
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [],
        bridgeReplayKey := some 9
      }
    ]
  }

theorem cross_action_bridge_replay_duplicate_rejects :
    evaluateActionStreamEffect crossActionBridgeReplayDuplicate =
      Except.error ActionStreamReject.bridgeReplayDuplicate := by
  rfl

def priorConsumedBridgeReplayDuplicate : ActionStreamInput :=
  {
    leafStart := 0,
    spentNullifiers := [],
    consumedBridgeReplays := [10],
    actions := [
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [],
        bridgeReplayKey := some 10
      }
    ]
  }

theorem prior_consumed_bridge_replay_duplicate_rejects :
    evaluateActionStreamEffect priorConsumedBridgeReplayDuplicate =
      Except.error ActionStreamReject.bridgeReplayDuplicate := by
  rfl

def secondActionCommitmentOverflow : ActionStreamInput :=
  {
    leafStart := u64Max - 1,
    spentNullifiers := [],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 1,
        ciphertextCount := 1,
        nullifiers := [],
        bridgeReplayKey := none
      },
      {
        commitmentCount := 1,
        ciphertextCount := 1,
        nullifiers := [],
        bridgeReplayKey := none
      }
    ]
  }

theorem second_action_commitment_overflow_rejects :
    evaluateActionStreamEffect secondActionCommitmentOverflow =
      Except.error ActionStreamReject.commitmentIndexOverflow := by
  rfl

def countMismatchPrecedesDuplicate : ActionStreamInput :=
  {
    leafStart := 0,
    spentNullifiers := [11],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 1,
        ciphertextCount := 0,
        nullifiers := [11],
        bridgeReplayKey := none
      }
    ]
  }

theorem count_mismatch_precedes_duplicate :
    evaluateActionStreamEffect countMismatchPrecedesDuplicate =
      Except.error ActionStreamReject.ciphertextCountMismatch := by
  rfl

def overflowPrecedesNullifier : ActionStreamInput :=
  {
    leafStart := u64Max,
    spentNullifiers := [],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 1,
        ciphertextCount := 1,
        nullifiers := [0],
        bridgeReplayKey := none
      }
    ]
  }

theorem overflow_precedes_nullifier :
    evaluateActionStreamEffect overflowPrecedesNullifier =
      Except.error ActionStreamReject.commitmentIndexOverflow := by
  rfl

def nullifierPrecedesBridgeReplay : ActionStreamInput :=
  {
    leafStart := 0,
    spentNullifiers := [12],
    consumedBridgeReplays := [12],
    actions := [
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [12],
        bridgeReplayKey := some 12
      }
    ]
  }

theorem nullifier_precedes_bridge_replay :
    evaluateActionStreamEffect nullifierPrecedesBridgeReplay =
      Except.error ActionStreamReject.duplicateNullifier := by
  rfl

end ActionStreamEffect
end Native
end Hegemon
