import SmzaRp05ReplayAnchorBridge
import SmzaRp05HistoricalTree

/-! Join the native commitment frontier replay to the existing opening-tree
model. A retained root selects an actual prefix of the same opening log;
neither root injectivity nor a unique leaf count is assumed. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoryJoin

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
open HegemonCrypto.SmallWood.SmzaRp05RetainedAnchorPrefixes
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05ReplayAnchorBridge
open HegemonCrypto.SmallWood.MerkleExtraction

set_option autoImplicit false

theorem commitment_at_opening_log (log : List V8NoteOpening) (position : Nat) :
    commitmentAt (log.map exactV8NoteCommitment) position =
      exactV8NoteCommitment (openingAt log position) := by
  unfold commitmentAt openingAt
  rw [List.length_map]
  split_ifs
  · simp only [List.getD_eq_getElem?_getD, List.getElem?_map]
    cases entry : log[position]? <;> rfl
  · rfl

theorem root_from_opening_log (log : List V8NoteOpening) (depth base : Nat) :
    rootFromLog depth base (log.map exactV8NoteCommitment) =
      (fromLog depth base log).root := by
  induction depth generalizing base with
  | zero => exact commitment_at_opening_log log base
  | succ depth ih =>
      simp only [rootFromLog, fromLog, IndexedTree.root, rp05PathHash]
      rw [ih base, ih (base + 2 ^ depth)]

/-- Concrete native replay and retained-root admission determine an opening
prefix, not just an existential list of unrelated commitment digests. -/
theorem replay_anchor_has_opening_prefix
    {native : FrontierState} (openings : List V8NoteOpening)
    (replay : NativeReplay native (openings.map exactV8NoteCommitment))
    (anchor : Digest) (admitted : anchor ∈ native.history) :
    ∃ count, count ≤ openings.length ∧
      anchor = (fromLog merkleDepth 0 (openings.take count)).root := by
  obtain ⟨ancestor, ⟨suffix, logEq⟩, rootEq⟩ :=
    replay_pre_block_anchor_has_ancestor_prefix replay anchor admitted
  have countBound : ancestor.length ≤ openings.length := by
    have lengths := congrArg List.length logEq
    simp only [List.length_map, List.length_append] at lengths
    omega
  have prefixEq : (openings.take ancestor.length).map exactV8NoteCommitment =
      ancestor := by
    rw [List.map_take, logEq]
    simp
  refine ⟨ancestor.length, countBound, ?_⟩
  calc
    anchor = rootOfLog ancestor := rootEq
    _ = rootFromLog merkleDepth 0
        ((openings.take ancestor.length).map exactV8NoteCommitment) :=
      congrArg (rootFromLog merkleDepth 0) prefixEq.symm
    _ = (fromLog merkleDepth 0 (openings.take ancestor.length)).root :=
      root_from_opening_log (openings.take ancestor.length) merkleDepth 0

/-- The reconstructed canonical path is now tied to the native retained
anchor at exactly the supplied position. This works for both occupied and
historically empty positions, including stale roots. -/
theorem replay_anchor_has_opening_path
    {native : FrontierState} (openings : List V8NoteOpening)
    (replay : NativeReplay native (openings.map exactV8NoteCommitment))
    (anchor : Digest) (admitted : anchor ∈ native.history)
    (position : Nat) (inTree : position < 2 ^ merkleDepth) :
    ∃ count, count ≤ openings.length ∧
      ∃ path, PathAt (fromLog merkleDepth 0 (openings.take count)) position
          (openingAt (openings.take count) position) path ∧
        OpensAt rp05PathHash anchor (pathSides path)
          (exactV8NoteWords (openingAt (openings.take count) position)) path := by
  obtain ⟨count, countBound, anchorEq⟩ :=
    replay_anchor_has_opening_prefix openings replay anchor admitted
  obtain ⟨path, pathAt⟩ := path_from_log merkleDepth 0 position
    (openings.take count) (Nat.zero_le _) (by simpa using inTree)
  refine ⟨count, countBound, path, pathAt, ?_⟩
  rw [anchorEq]
  exact path_at_opens pathAt

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoryJoin
