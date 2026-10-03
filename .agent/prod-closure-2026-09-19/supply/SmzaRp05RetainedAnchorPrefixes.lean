import SmzaRp05HistoricalTree

/-!
# RP05 retained-root ancestor prefixes (source-only)

This is the node's root-history bookkeeping at append granularity: genesis
records the empty root; each append computes a new root, suppresses an equal
last root, and otherwise drops old front entries to retain at most 100 roots
before pushing the new one.  The theorem identifies *some* concrete ancestor
append prefix for each retained root.  It never recovers a unique leaf count
from a digest.  Attaching a block tests anchors against the pre-block history,
so its output appends cannot create an anchor for that same block.

The pure full-tree `rootOfLog` fixes the intended hash semantics.  A further
source refinement must prove that the native incremental frontier computes
this full-tree function and that decoded/reorganized state is a `Reachable`
state.  The theorem below does not assume those source obligations away.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05RetainedAnchorPrefixes

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply

set_option autoImplicit false

def commitmentAt (log : List Digest) (position : Nat) : Digest :=
  if position < log.length then log.getD position knownEmptyLeaf
  else knownEmptyLeaf

/-- Full depth-32 tree from the append-ordered commitment stream. -/
def rootFromLog : Nat → Nat → List Digest → Digest
  | 0, base, log => commitmentAt log base
  | depth + 1, base, log =>
      poseidon2V8Compress14 poseidon2V8MerkleDomain
        (rootFromLog depth base log)
        (rootFromLog depth (base + 2 ^ depth) log)

def rootOfLog (log : List Digest) : Digest :=
  rootFromLog merkleDepth 0 log

/-- `root_history` is a digest list, as in the source.  The append log is
ghost state reconstructed from accepted outputs and coinbases on this branch;
it adds no consensus or proof bytes. -/
structure NoteHistory where
  log : List Digest
  retainedRoots : List Digest

def genesis : NoteHistory where
  log := []
  retainedRoots := [rootOfLog []]

/-- Source `POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT`. -/
def historyLimit : Nat := 100

/-- For valid states with at most 100 roots this is the source's
pop-front-until-space, then push, with consecutive-equal-root suppression. -/
def retainAfterAppend (history : List Digest) (newRoot : Digest) : List Digest :=
  if history.getLast? = some newRoot then history
  else history.drop (history.length + 1 - historyLimit) ++ [newRoot]

def append (state : NoteHistory) (commitment : Digest) : NoteHistory :=
  let newLog := state.log ++ [commitment]
  { log := newLog
    retainedRoots := retainAfterAppend state.retainedRoots (rootOfLog newLog) }

theorem retain_after_append_bounded
    (history : List Digest) (newRoot : Digest)
    (bounded : history.length ≤ historyLimit) :
    (retainAfterAppend history newRoot).length ≤ historyLimit := by
  unfold retainAfterAppend
  split
  · exact bounded
  · simp only [List.length_append, List.length_cons, List.length_nil,
      List.length_drop]
    by_cases below : history.length < historyLimit
    · have dropEq : history.length + 1 - historyLimit = 0 := by omega
      rw [dropEq]
      omega
    · have atLimit : history.length = historyLimit := by omega
      rw [atLimit]
      have dropEq : historyLimit + 1 - historyLimit = 1 := by omega
      rw [dropEq]
      norm_num [historyLimit]

/-- Actual source admission requires the submitted anchor to belong to the
parent's retained history before outputs of the new block are appended. -/
def PreBlockAnchorAccepted (state : NoteHistory) (anchor : Digest) : Prop :=
  anchor ∈ state.retainedRoots

def IsAncestorPrefix (ancestorLog log : List Digest) : Prop :=
  ∃ suffix, log = ancestorLog ++ suffix

def RetainedRootsSound (state : NoteHistory) : Prop :=
  ∀ root ∈ state.retainedRoots,
    ∃ ancestorLog, IsAncestorPrefix ancestorLog state.log ∧
      root = rootOfLog ancestorLog

theorem genesis_retained_roots_sound : RetainedRootsSound genesis := by
  intro root member
  have equal : root = rootOfLog [] := by
    simpa [genesis] using member
  exact ⟨[], ⟨[], rfl⟩, equal⟩

/-- Dedup and front trimming can remove roots but cannot fabricate one. -/
theorem retained_member_origin
    (history : List Digest) (newRoot root : Digest)
    (member : root ∈ retainAfterAppend history newRoot) :
    root ∈ history ∨ root = newRoot := by
  unfold retainAfterAppend at member
  split at member
  · exact Or.inl member
  · rcases List.mem_append.mp member with old | new
    · exact Or.inl (List.mem_of_mem_drop old)
    · exact Or.inr (by simpa using new)

theorem append_retained_roots_sound
    (state : NoteHistory) (commitment : Digest)
    (sound : RetainedRootsSound state) :
    RetainedRootsSound (append state commitment) := by
  intro root member
  have origin := retained_member_origin state.retainedRoots
    (rootOfLog (state.log ++ [commitment])) root member
  rcases origin with old | newest
  · rcases sound root old with ⟨ancestorLog, ⟨suffix, prefixEq⟩, rootEq⟩
    refine ⟨ancestorLog, ⟨suffix ++ [commitment], ?_⟩, rootEq⟩
    simp only [append, prefixEq, List.append_assoc]
  · exact ⟨state.log ++ [commitment], ⟨[], by simp [append]⟩, newest⟩

/-- Every state reachable through the source-shaped append bookkeeping
retains only roots of concrete ancestor append prefixes. -/
inductive Reachable : NoteHistory → Prop where
  | start : Reachable genesis
  | push {state : NoteHistory} (prior : Reachable state)
      (commitment : Digest) : Reachable (append state commitment)

theorem reachable_retained_roots_sound {state : NoteHistory}
    (reachable : Reachable state) : RetainedRootsSound state := by
  induction reachable with
  | start => exact genesis_retained_roots_sound
  | push prior commitment ih =>
      exact append_retained_roots_sound _ _ ih

theorem reachable_retained_roots_bounded {state : NoteHistory}
    (reachable : Reachable state) :
    state.retainedRoots.length ≤ historyLimit := by
  induction reachable with
  | start => decide
  | push prior commitment ih =>
      exact retain_after_append_bounded _ _ ih

/-- No uniqueness of the prefix is claimed: inserting a known-default
commitment can preserve a root digest while increasing leaf count. -/
theorem accepted_anchor_has_ancestor_prefix
    {state : NoteHistory} (reachable : Reachable state)
    (anchor : Digest) (accepted : PreBlockAnchorAccepted state anchor) :
    ∃ ancestorLog, IsAncestorPrefix ancestorLog state.log ∧
      anchor = rootOfLog ancestorLog := by
  exact reachable_retained_roots_sound reachable anchor accepted

end HegemonCrypto.SmallWood.SmzaRp05RetainedAnchorPrefixes
