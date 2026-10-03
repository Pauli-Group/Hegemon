import SmzaRp05NativeHistoryTransitions

/-!
# Source-shaped native note frontier model

This is a direct, pure transcription of `Poseidon2V8NoteTreeState::new_empty`
and `append`: 32 default levels, `leaf_count` bits choose left/right, even
levels replace the frontier slot, and root history is deduplicated/trimmed
after the new root is computed. It is not yet a proof that Rust's Felt
implementation equals the Lean Poseidon primitive. The frontier/root
mathematical refinement is handled in `SmzaRp05FrontierCarryStep`;
record codec provenance and Rust-to-Lean primitive equivalence remain
separate obligations.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply
open HegemonCrypto.SmallWood.SmzaRp05RetainedAnchorPrefixes

set_option autoImplicit false

def defaultNode : Nat → Digest
  | 0 => knownEmptyLeaf
  | level + 1 =>
      poseidon2V8Compress14 poseidon2V8MerkleDomain
        (defaultNode level) (defaultNode level)

def defaultNodes : List Digest :=
  (List.range (merkleDepth + 1)).map defaultNode

theorem empty_log_root (depth base : Nat) :
    rootFromLog depth base [] = defaultNode depth := by
  induction depth generalizing base with
  | zero => simp [rootFromLog, commitmentAt, defaultNode]
  | succ depth ih =>
      simp only [rootFromLog, defaultNode]
      rw [ih base, ih (base + 2 ^ depth)]

theorem new_empty_root : rootOfLog [] = defaultNode merkleDepth := by
  exact empty_log_root merkleDepth 0

/-- Every subtree strictly beyond the append prefix is source-owned default,
regardless of earlier commitments. This is the even-bit branch of the carry
induction at each level. -/
theorem subtree_beyond_log_is_default
    (depth base : Nat) (log : List Digest)
    (outside : log.length ≤ base) :
    rootFromLog depth base log = defaultNode depth := by
  induction depth generalizing base with
  | zero =>
      simp [rootFromLog, commitmentAt, Nat.not_lt.mpr outside, defaultNode]
  | succ depth ih =>
      simp only [rootFromLog, defaultNode]
      have widthNonneg : 0 ≤ 2 ^ depth := Nat.zero_le _
      have rightOutside : log.length ≤ base + 2 ^ depth := by omega
      rw [ih base outside,
        ih (base + 2 ^ depth) rightOutside]

/-- Appending at the end changes exactly that leaf, not any prior occupied
position. The analogous interval lemma for `rootFromLog` is the other local
ingredient of the generic carry proof. -/
theorem commitment_before_append_unchanged
    (log : List Digest) (commitment : Digest) (position : Nat)
    (earlier : position < log.length) :
    commitmentAt (log ++ [commitment]) position =
      commitmentAt log position := by
  have appendedBound : position < (log ++ [commitment]).length := by
    simp
    omega
  unfold commitmentAt
  rw [if_pos appendedBound, if_pos earlier]
  rw [List.getD_append _ _ _ _ earlier]

theorem commitment_at_append_position
    (log : List Digest) (commitment : Digest) :
    commitmentAt (log ++ [commitment]) log.length = commitment := by
  unfold commitmentAt
  have appendedBound : log.length < (log ++ [commitment]).length := by simp
  rw [if_pos appendedBound]
  rw [List.getD_append_right _ _ _ _ (Nat.le_refl _)]
  simp

/-- A completed subtree entirely before the next append position retains
its digest. This is the odd-bit left sibling used by the carry invariant. -/
theorem subtree_before_append_unchanged
    (depth base : Nat) (log : List Digest) (commitment : Digest)
    (completed : base + 2 ^ depth ≤ log.length) :
    rootFromLog depth base (log ++ [commitment]) =
      rootFromLog depth base log := by
  induction depth generalizing base with
  | zero =>
      have earlier : base < log.length := by omega
      exact commitment_before_append_unchanged log commitment base earlier
  | succ depth ih =>
      have width : 2 ^ (depth + 1) = 2 ^ depth + 2 ^ depth := by
        simp [pow_succ, Nat.mul_two]
      have leftCompleted : base + 2 ^ depth ≤ log.length := by
        have largerPower : 2 ^ depth ≤ 2 ^ (depth + 1) := by
          rw [width]
          have powerNonneg : 0 ≤ 2 ^ depth := Nat.zero_le _
          omega
        exact le_trans (Nat.add_le_add_left largerPower base) completed
      have rightCompleted : base + 2 ^ depth + 2 ^ depth ≤ log.length := by
        rw [width] at completed
        simpa [Nat.add_assoc] using completed
      simp only [rootFromLog]
      rw [ih base leftCompleted,
        ih (base + 2 ^ depth) rightCompleted]

/-- A zero bit means the new level's containing subtree begins at the same
base as the current lower-level subtree. The proof uses quotient/remainder
decomposition, so no finite enumeration of levels is needed. -/
theorem even_bit_same_base (position level : Nat)
    (bit : (position / 2 ^ level) % 2 = 0) :
    position - position % 2 ^ (level + 1) =
      position - position % 2 ^ level := by
  let width := 2 ^ level
  have widthPos : 0 < width := by simp [width]
  have remBound : position % width < width := Nat.mod_lt _ widthPos
  change (position / width) % 2 = 0 at bit
  have quotient : position / width = 2 * (position / width / 2) := by
    have split := Nat.mod_add_div (position / width) 2
    omega
  have decomposition :
      position = position % width + (2 * width) * (position / width / 2) := by
    have split := Nat.mod_add_div position width
    rw [quotient] at split
    nlinarith
  have remainder : position % (2 * width) = position % width := by
    conv_lhs => rw [decomposition]
    rw [Nat.add_mul_mod_self_left]
    exact Nat.mod_eq_of_lt (by omega)
  have power : 2 ^ (level + 1) = 2 * width := by
    simp [width, pow_succ, Nat.mul_comm]
  rw [power, remainder]

/-- A one bit moves the containing subtree base left by exactly one
`2^level`-sized completed subtree. -/
theorem odd_bit_previous_base (position level : Nat)
    (bit : (position / 2 ^ level) % 2 = 1) :
    position - position % 2 ^ (level + 1) + 2 ^ level =
      position - position % 2 ^ level := by
  let width := 2 ^ level
  have widthPos : 0 < width := by simp [width]
  have remBound : position % width < width := Nat.mod_lt _ widthPos
  change (position / width) % 2 = 1 at bit
  have quotient : position / width =
      1 + 2 * (position / width / 2) := by
    have split := Nat.mod_add_div (position / width) 2
    omega
  have decomposition :
      position = position % width + width +
        (2 * width) * (position / width / 2) := by
    have split := Nat.mod_add_div position width
    rw [quotient] at split
    nlinarith
  have remainder : position % (2 * width) = position % width + width := by
    conv_lhs => rw [decomposition]
    rw [Nat.add_mul_mod_self_left]
    exact Nat.mod_eq_of_lt (by omega)
  have power : 2 ^ (level + 1) = 2 * width := by
    simp [width, pow_succ, Nat.mul_comm]
  have baseBound : position % width + width ≤ position := by
    calc
      position % width + width ≤
          position % width + width + (2 * width) * (position / width / 2) :=
        Nat.le_add_right _ _
      _ = position := decomposition.symm
  rw [power, remainder]
  change position - (position % width + width) + width =
    position - position % width
  omega

structure FrontierState where
  leafCount : Nat
  root : Digest
  frontier : List Digest
  defaults : List Digest
  history : List Digest

/-- Mathematical content of the frontier slots: when the next position's
bit at level `level` is one, that slot contains the completed left subtree
for the pair to which the new leaf belongs. Slots whose bit is zero can be
stale and are deliberately unconstrained. -/
def FrontierSlotsCorrect (state : FrontierState) (log : List Digest) : Prop :=
  ∀ level, level < merkleDepth →
    (log.length / 2 ^ level) % 2 = 1 →
      state.frontier.getD level knownEmptyLeaf =
        rootFromLog level
          (log.length - log.length % (2 ^ (level + 1))) log

def newEmpty : FrontierState where
  leafCount := 0
  root := defaultNode merkleDepth
  frontier := (List.range merkleDepth).map defaultNode
  defaults := defaultNodes
  history := [defaultNode merkleDepth]

theorem new_empty_slots_correct : FrontierSlotsCorrect newEmpty [] := by
  intro level bound bit
  simp at bit

structure FoldCursor where
  current : Digest
  position : Nat
  frontier : List Digest

def frontierLevel (defaults : List Digest) (level : Nat)
    (cursor : FoldCursor) : FoldCursor :=
  if cursor.position % 2 = 0 then
    { current := poseidon2V8Compress14 poseidon2V8MerkleDomain
        cursor.current (defaults.getD level knownEmptyLeaf)
      position := cursor.position / 2
      frontier := cursor.frontier.set level cursor.current }
  else
    { current := poseidon2V8Compress14 poseidon2V8MerkleDomain
        (cursor.frontier.getD level knownEmptyLeaf) cursor.current
      position := cursor.position / 2
      frontier := cursor.frontier }

def frontierAppend (state : FrontierState) (commitment : Digest) : FoldCursor :=
  (List.range merkleDepth).foldl
    (fun cursor level => frontierLevel state.defaults level cursor)
    { current := commitment
      position := state.leafCount
      frontier := state.frontier }

theorem frontier_level_preserves_length
    (defaults : List Digest) (level : Nat) (cursor : FoldCursor) :
    (frontierLevel defaults level cursor).frontier.length =
      cursor.frontier.length := by
  unfold frontierLevel
  split_ifs <;> simp

theorem frontier_level_higher_slot_unchanged
    (defaults : List Digest) (level later : Nat) (cursor : FoldCursor)
    (higher : level < later) :
    (frontierLevel defaults level cursor).frontier.getD later knownEmptyLeaf =
      cursor.frontier.getD later knownEmptyLeaf := by
  unfold frontierLevel
  split_ifs
  · by_cases bound : later < cursor.frontier.length
    · have setBound : later <
          (cursor.frontier.set level cursor.current).length := by
        simpa using bound
      have same := List.getElem_set_of_ne
        (l := cursor.frontier) (i := level) (j := later)
        (by omega) cursor.current setBound
      exact (List.getD_eq_getElem _ _ setBound).trans
        (same.trans (List.getD_eq_getElem _ _ bound).symm)
    · have setOut : cursor.frontier.length ≤ later := Nat.le_of_not_lt bound
      have setNone : (cursor.frontier.set level cursor.current)[later]? = none :=
        List.getElem?_eq_none (by simpa using setOut)
      have originalNone : cursor.frontier[later]? = none :=
        List.getElem?_eq_none setOut
      simp [List.getD_eq_getElem?_getD, setNone, originalNone]
  · rfl

theorem frontier_level_other_slot_unchanged
    (defaults : List Digest) (level other : Nat) (cursor : FoldCursor)
    (different : other ≠ level) :
    (frontierLevel defaults level cursor).frontier.getD other knownEmptyLeaf =
      cursor.frontier.getD other knownEmptyLeaf := by
  unfold frontierLevel
  split_ifs
  · by_cases bound : other < cursor.frontier.length
    · have setBound : other <
          (cursor.frontier.set level cursor.current).length := by
        simpa using bound
      have same := List.getElem_set_of_ne
        (l := cursor.frontier) (i := level) (j := other)
        (by omega) cursor.current setBound
      exact (List.getD_eq_getElem _ _ setBound).trans
        (same.trans (List.getD_eq_getElem _ _ bound).symm)
    · have setOut : cursor.frontier.length ≤ other := Nat.le_of_not_lt bound
      have setNone : (cursor.frontier.set level cursor.current)[other]? = none :=
        List.getElem?_eq_none (by simpa using setOut)
      have originalNone : cursor.frontier[other]? = none :=
        List.getElem?_eq_none setOut
      simp [List.getD_eq_getElem?_getD, setNone, originalNone]
  · rfl

theorem frontier_level_own_slot
    (defaults : List Digest) (level : Nat) (cursor : FoldCursor)
    (bound : level < cursor.frontier.length) :
    (frontierLevel defaults level cursor).frontier.getD level knownEmptyLeaf =
      if cursor.position % 2 = 0 then cursor.current
      else cursor.frontier.getD level knownEmptyLeaf := by
  unfold frontierLevel
  split_ifs
  · rw [List.getD_eq_getElem _ _ (by simpa using bound)]
    simp
  · rfl

theorem frontier_fold_preserves_length
    (defaults : List Digest) (levels : List Nat) (cursor : FoldCursor) :
    (levels.foldl (fun cursor level => frontierLevel defaults level cursor) cursor).frontier.length =
      cursor.frontier.length := by
  induction levels generalizing cursor with
  | nil => rfl
  | cons level rest ih =>
      simpa only [List.foldl_cons] using
        (ih (frontierLevel defaults level cursor)).trans
          (frontier_level_preserves_length defaults level cursor)

theorem frontier_append_preserves_length
    (state : FrontierState) (commitment : Digest) :
    (frontierAppend state commitment).frontier.length =
      state.frontier.length := by
  exact frontier_fold_preserves_length state.defaults
    (List.range merkleDepth)
    { current := commitment
      position := state.leafCount
      frontier := state.frontier }

/-- Induction invariant after `level` bits of the source carry loop.
`current` is the new subtree containing appended position `n`; the shifted
position is exactly `n / 2^level`; unvisited frontier slots are unchanged.
The latter is essential: stale visited slots may be overwritten, but a later
odd branch must read its original completed-left subtree. -/
def CarryInvariant (state : FrontierState) (log : List Digest)
    (commitment : Digest) (level : Nat) (cursor : FoldCursor) : Prop :=
  cursor.position = log.length / 2 ^ level ∧
    cursor.current =
      rootFromLog level (log.length - log.length % 2 ^ level)
        (log ++ [commitment]) ∧
    ∀ later, level ≤ later → later < merkleDepth →
      cursor.frontier.getD later knownEmptyLeaf =
        state.frontier.getD later knownEmptyLeaf

theorem carry_invariant_initial
    (state : FrontierState) (log : List Digest)
    (commitment : Digest) (count : state.leafCount = log.length) :
    CarryInvariant state log commitment 0
      { current := commitment
        position := state.leafCount
        frontier := state.frontier } := by
  constructor
  · simp [count]
  constructor
  · simp only [rootFromLog, pow_zero, Nat.mod_one, Nat.sub_zero]
    exact (commitment_at_append_position log commitment).symm
  · intro later lower upper
    rfl

/-- This is one *generic* bit step, not 32 duplicated claims. To finish it,
use `FrontierSlotsCorrect` for an odd bit, and
`subtree_beyond_log_is_default` for an even bit; show `.set` leaves higher
slots unchanged. No source or cryptographic assumption is hidden here. -/
def CarryStepCorrect : Prop :=
  ∀ state log commitment level cursor,
    state.leafCount = log.length →
    state.defaults = defaultNodes →
    FrontierSlotsCorrect state log →
    level < merkleDepth →
    CarryInvariant state log commitment level cursor →
    CarryInvariant state log commitment (level + 1)
      (frontierLevel state.defaults level cursor)

theorem carry_induction
    (step : CarryStepCorrect)
    (state : FrontierState) (log : List Digest)
    (commitment : Digest)
    (count : state.leafCount = log.length)
    (defaults : state.defaults = defaultNodes)
    (slots : FrontierSlotsCorrect state log)
    (level : Nat) (bound : level ≤ merkleDepth) :
    CarryInvariant state log commitment level
      ((List.range level).foldl
        (fun cursor currentLevel => frontierLevel state.defaults currentLevel cursor)
        { current := commitment
          position := state.leafCount
          frontier := state.frontier }) := by
  induction level with
  | zero => exact carry_invariant_initial state log commitment count
  | succ level ih =>
      rw [List.range_succ, List.foldl_append]
      simp only [List.foldl_cons, List.foldl_nil]
      exact step state log commitment level _ count defaults slots
        (by omega) (ih (by omega))

theorem frontier_root_of_carry_step
    (step : CarryStepCorrect)
    (state : FrontierState) (log : List Digest)
    (commitment : Digest)
    (count : state.leafCount = log.length)
    (defaults : state.defaults = defaultNodes)
    (slots : FrontierSlotsCorrect state log)
    (capacity : state.leafCount < 2 ^ merkleDepth) :
    (frontierAppend state commitment).current =
      rootOfLog (log ++ [commitment]) := by
  have invariant := carry_induction step state log commitment count defaults
    slots merkleDepth (by omega)
  have base : log.length - log.length % 2 ^ merkleDepth = 0 := by
    rw [Nat.mod_eq_of_lt (by omega)]
    omega
  simpa [frontierAppend, CarryInvariant, rootOfLog, base] using invariant.2.1

def append (state : FrontierState) (commitment : Digest) : Option FrontierState :=
  if state.leafCount < 2 ^ merkleDepth then
    let result := frontierAppend state commitment
    some ({
      leafCount := state.leafCount + 1
      root := result.current
      frontier := result.frontier
      defaults := state.defaults
      history := retainAfterAppend state.history result.current
    } : FrontierState)
  else none

/-- The exact extraction relation needed to transfer pure retained-history
proofs onto the source-shaped frontier state. This does not assume a unique
log length for a root digest. -/
def Refines (native : FrontierState) (ghost : NoteHistory) : Prop :=
  native.leafCount = ghost.log.length ∧
    native.root = rootOfLog ghost.log ∧
    native.history = ghost.retainedRoots ∧
    native.defaults = defaultNodes

theorem new_empty_refines : Refines newEmpty genesis := by
  simp [Refines, newEmpty, genesis, new_empty_root]

/-- Provenance rules out an arbitrary forged frontier with the same root.
The actual source state is created by `new_empty` and successful `append`;
decoded snapshots require a separate provenance argument. -/
inductive NativeReplay : FrontierState → List Digest → Prop where
  | start : NativeReplay newEmpty []
  | push {state : FrontierState} {log : List Digest}
      (prior : NativeReplay state log) (commitment : Digest)
      (capacity : state.leafCount < 2 ^ merkleDepth) :
      NativeReplay
        { leafCount := state.leafCount + 1
          root := (frontierAppend state commitment).current
          frontier := (frontierAppend state commitment).frontier
          defaults := state.defaults
          history := retainAfterAppend state.history
            (frontierAppend state commitment).current }
        (log ++ [commitment])

theorem native_replay_frontier_shape
    {state : FrontierState} {log : List Digest}
    (replay : NativeReplay state log) :
    state.frontier.length = merkleDepth := by
  induction replay with
  | start => simp [newEmpty]
  | push prior commitment capacity ih =>
      simpa [frontier_append_preserves_length] using ih

theorem native_replay_leaf_count
    {state : FrontierState} {log : List Digest}
    (replay : NativeReplay state log) :
    state.leafCount = log.length := by
  induction replay with
  | start => rfl
  | push prior commitment capacity ih =>
      simpa using congrArg Nat.succ ih

theorem native_replay_default_nodes
    {state : FrontierState} {log : List Digest}
    (replay : NativeReplay state log) :
    state.defaults = defaultNodes := by
  induction replay with
  | start => rfl
  | push prior commitment capacity ih =>
      exact ih

/-- The remaining carry-invariant preservation statement. New 1-bits either
come from a just-completed lower subtree (the source writes that slot) or
were already 1-bits (the source leaves that higher slot unchanged). This is
distinct from the root calculation proved by the generic carry fold. -/
def FrontierSlotsStepCorrect : Prop :=
  ∀ state log commitment,
    NativeReplay state log →
    state.leafCount = log.length →
    state.defaults = defaultNodes →
    FrontierSlotsCorrect state log →
    state.leafCount < 2 ^ merkleDepth →
    FrontierSlotsCorrect
      { leafCount := state.leafCount + 1
        root := (frontierAppend state commitment).current
        frontier := (frontierAppend state commitment).frontier
        defaults := state.defaults
        history := retainAfterAppend state.history
          (frontierAppend state commitment).current }
      (log ++ [commitment])

theorem replay_slots_of_generic_step
    (step : FrontierSlotsStepCorrect)
    {state : FrontierState} {log : List Digest}
    (replay : NativeReplay state log) :
    FrontierSlotsCorrect state log := by
  induction replay with
  | start => exact new_empty_slots_correct
  | push prior commitment capacity ih =>
      exact step _ _ commitment prior
        (native_replay_leaf_count prior)
        (native_replay_default_nodes prior) ih capacity

/-- The source frontier transition's mathematical core, discharged for replay
states by the generic carry induction in `SmzaRp05FrontierCarryStep`. -/
def FrontierAppendRootCorrect : Prop :=
  ∀ native ghost commitment,
    NativeReplay native ghost.log → Refines native ghost →
    FrontierSlotsCorrect native ghost.log →
    native.leafCount < 2 ^ merkleDepth →
    (frontierAppend native commitment).current =
      rootOfLog (ghost.log ++ [commitment])

theorem append_refines
    (correct : FrontierAppendRootCorrect)
    (native : FrontierState) (ghost : NoteHistory)
    (commitment : Digest) (replay : NativeReplay native ghost.log)
    (refines : Refines native ghost)
    (slots : FrontierSlotsCorrect native ghost.log)
    (capacity : native.leafCount < 2 ^ merkleDepth) :
    append native commitment = some
      ({
        leafCount := native.leafCount + 1
        root := (frontierAppend native commitment).current
        frontier := (frontierAppend native commitment).frontier
        defaults := native.defaults
        history := retainAfterAppend native.history
          (frontierAppend native commitment).current
      } : FrontierState) ∧
      Refines
        ({
          leafCount := native.leafCount + 1
          root := (frontierAppend native commitment).current
          frontier := (frontierAppend native commitment).frontier
          defaults := native.defaults
          history := retainAfterAppend native.history
            (frontierAppend native commitment).current
        } : FrontierState)
        (SmzaRp05RetainedAnchorPrefixes.append ghost commitment) := by
  constructor
  · simp [append, capacity]
  · rcases refines with ⟨count, root, history, defaults⟩
    simp [Refines, SmzaRp05RetainedAnchorPrefixes.append, count,
      correct native ghost commitment replay
        ⟨count, root, history, defaults⟩ slots capacity,
      history, defaults]

end HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
