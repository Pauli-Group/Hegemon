namespace Hegemon
namespace Native
namespace NullifierAccumulator

inductive Reject where
  | zeroNullifier
deriving DecidableEq, Repr

/-- Symbolic MMR peak. `leaves` retains append order; production encodes each
    leaf as an exact typed 48-byte BLAKE2b-384 nullifier (`Nullifier48`) and
    replaces the symbolic list with a domain-separated RFC 7693 BLAKE2b-384
    digest. -/
structure Peak where
  height : Nat
  leaves : List Nat
deriving DecidableEq, Repr

/-- Peaks are stored right-to-left so the rightmost carry is the list head. -/
structure State where
  leafCount : Nat
  peaksRev : List Peak
deriving DecidableEq, Repr

def empty : State := { leafCount := 0, peaksRev := [] }

def mergeCarry (carry : Peak) : List Peak → List Peak
  | [] => [carry]
  | peak :: rest =>
      if peak.height = carry.height then
        mergeCarry
          { height := carry.height + 1, leaves := peak.leaves ++ carry.leaves }
          rest
      else
        carry :: peak :: rest
termination_by peaks => peaks.length

def append (state : State) (leaf : Nat) : Except Reject State :=
  if leaf = 0 then
    Except.error Reject.zeroNullifier
  else
    Except.ok {
      leafCount := state.leafCount + 1,
      peaksRev := mergeCarry { height := 0, leaves := [leaf] } state.peaksRev
    }

def appendBlock : State → List Nat → Except Reject State
  | state, [] => Except.ok state
  | state, leaf :: rest =>
      match append state leaf with
      | Except.error reject => Except.error reject
      | Except.ok next => appendBlock next rest

def appendBlocks : State → List (List Nat) → Except Reject State
  | state, [] => Except.ok state
  | state, block :: rest =>
      match appendBlock state block with
      | Except.error reject => Except.error reject
      | Except.ok next => appendBlocks next rest

def peakHeights (state : State) : List Nat :=
  state.peaksRev.reverse.map (fun peak => peak.height)

def peakLeaves (state : State) : List (List Nat) :=
  state.peaksRev.reverse.map (fun peak => peak.leaves)

def trailingOnesAux : Nat → Nat → Nat
  | _, 0 => 0
  | value, fuel + 1 =>
      if value % 2 = 1 then 1 + trailingOnesAux (value / 2) fuel else 0

def trailingOnes (value : Nat) : Nat :=
  trailingOnesAux value (value + 1)

def mergeCountsFrom : Nat → List Nat → List Nat
  | _, [] => []
  | leafCount, leaf :: rest =>
      if leaf = 0 then []
      else trailingOnes leafCount :: mergeCountsFrom (leafCount + 1) rest

def mergeCounts (blocks : List (List Nat)) : List Nat :=
  mergeCountsFrom 0 blocks.flatten

def multiBlockFixture : List (List Nat) := [[1, 2], [], [3, 4, 5]]

def stateSummary : Except Reject State → Nat × List Nat × List (List Nat)
  | Except.error _ => (0, [], [])
  | Except.ok state => (state.leafCount, peakHeights state, peakLeaves state)

def successfulPeakLeaves : Except Reject State → List (List Nat)
  | Except.error _ => []
  | Except.ok state => peakLeaves state

theorem empty_block_is_identity :
    appendBlock empty [] = Except.ok empty := by
  rfl

theorem zero_rejects_without_state :
    append empty 0 = Except.error Reject.zeroNullifier := by
  rfl

theorem five_leaf_shape_and_order :
    stateSummary (appendBlocks empty multiBlockFixture) =
      (5, [2, 0], [[1, 2, 3, 4], [5]]) := by
  native_decide

theorem eight_leaf_merge_schedule :
    mergeCounts [[1, 2, 3], [], [4, 5], [6, 7, 8]] =
      [0, 1, 0, 2, 0, 1, 0, 3] := by
  rfl

theorem rejected_leaf_stops_merge_schedule :
    mergeCounts [[1], [], [0, 2]] = [0] := by
  rfl

theorem append_order_is_observable :
    successfulPeakLeaves (appendBlocks empty [[1, 2, 3]]) ≠
      successfulPeakLeaves (appendBlocks empty [[2, 1, 3]]) := by
  native_decide

theorem fork_replay_is_deterministic :
    appendBlocks empty [[1, 2], [], [3], [8, 9]] =
      appendBlocks empty [[1], [2, 3], [], [8], [9]] := by
  rfl

end NullifierAccumulator
end Native
end Hegemon
