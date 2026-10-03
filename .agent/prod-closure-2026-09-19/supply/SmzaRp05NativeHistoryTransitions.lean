import SmzaRp05RetainedAnchorPrefixes

/-!
# Source-shaped native note history transitions

`verify_attach` copies the parent's root history before validating any exact
leaf, checks every public note anchor against that copy, then appends each
flattened output commitment in leaf order and finally the optional trailing
coinbase. A persisted block record carries its after-note-state; a detach
selects a previous canonical snapshot. This module proves the corresponding
ghost-log state-machine invariant. It does not assert that arbitrary bytes
accepted by Rust `decode_exact` came from such a snapshot, nor that the Rust
frontier recurrence computes `rootOfLog`; those are separate refinements.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05NativeHistoryTransitions

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05RetainedAnchorPrefixes

set_option autoImplicit false

/-- Source order: per-leaf `public.commitments.into_iter().flatten()` in
`exact_native_leaves` order. The inner lists have already omitted inactive
commitment slots, preserving slot order. -/
def outputStream (perLeaf : List (List Digest)) : List Digest :=
  perLeaf.flatten

def appendStream (state : NoteHistory) : List Digest → NoteHistory
  | [] => state
  | commitment :: rest => appendStream (append state commitment) rest

def attachBlock (parent : NoteHistory)
    (perLeaf : List (List Digest)) (coinbase : Option Digest) : NoteHistory :=
  let afterOutputs := appendStream parent (outputStream perLeaf)
  match coinbase with
  | none => afterOutputs
  | some commitment => append afterOutputs commitment

theorem append_stream_reachable
    {state : NoteHistory} (reachable : Reachable state)
    (stream : List Digest) : Reachable (appendStream state stream) := by
  induction stream generalizing state with
  | nil => simpa [appendStream] using reachable
  | cons commitment rest ih =>
      exact ih (.push reachable commitment)

theorem attach_block_reachable
    {parent : NoteHistory} (reachable : Reachable parent)
    (perLeaf : List (List Digest)) (coinbase : Option Digest) :
    Reachable (attachBlock parent perLeaf coinbase) := by
  unfold attachBlock
  have outputs := append_stream_reachable reachable (outputStream perLeaf)
  cases coinbase with
  | none => exact outputs
  | some commitment => exact .push outputs commitment

/-- Admission is evaluated against the parent history, not the post-output
history. One accepted public anchor therefore names some concrete ancestor
append prefix even if that digest appears at multiple leaf counts. -/
theorem pre_block_anchor_has_ancestor_prefix
    {parent : NoteHistory} (reachable : Reachable parent)
    (_perLeaf : List (List Digest)) (_coinbase : Option Digest)
    (anchor : Digest) (admitted : PreBlockAnchorAccepted parent anchor) :
    ∃ ancestorLog, IsAncestorPrefix ancestorLog parent.log ∧
      anchor = rootOfLog ancestorLog := by
  exact accepted_anchor_has_ancestor_prefix reachable anchor admitted

/-- A block record is created from a reachable parent by the source attach
ordering. The record stores both pre- and post-block ghost snapshots, so
reorg detachment returns a predecessor whose invariant was already proved. -/
structure Record where
  before : NoteHistory
  after : NoteHistory
  beforeReachable : Reachable before
  perLeaf : List (List Digest)
  coinbase : Option Digest
  afterEq : after = attachBlock before perLeaf coinbase

theorem Record.afterReachable (record : Record) : Reachable record.after := by
  rw [record.afterEq]
  exact attach_block_reachable record.beforeReachable
    record.perLeaf record.coinbase

theorem Record.beforeRootsSound (record : Record) : RetainedRootsSound record.before :=
  reachable_retained_roots_sound record.beforeReachable

theorem Record.afterRootsSound (record : Record) : RetainedRootsSound record.after :=
  reachable_retained_roots_sound record.afterReachable

/-- Source `note_state_at_checkpoint` returns `new_empty` at genesis and
`record.after_note_state` otherwise. In this model the stored record is a
record created by attach; arbitrary shape-valid decoded bytes are excluded. -/
inductive LoadedSnapshot : NoteHistory → Prop where
  | genesis : LoadedSnapshot genesis
  | attached (record : Record) : LoadedSnapshot record.after

theorem loaded_snapshot_reachable
    {state : NoteHistory} (loaded : LoadedSnapshot state) : Reachable state := by
  cases loaded with
  | genesis => exact .start
  | attached record => exact record.afterReachable

theorem loaded_anchor_has_ancestor_prefix
    {state : NoteHistory} (loaded : LoadedSnapshot state)
    (anchor : Digest) (admitted : PreBlockAnchorAccepted state anchor) :
    ∃ ancestorLog, IsAncestorPrefix ancestorLog state.log ∧
      anchor = rootOfLog ancestorLog := by
  exact accepted_anchor_has_ancestor_prefix
    (loaded_snapshot_reachable loaded) anchor admitted

/-- Source `NativeNode::open` rebuilds a scratch V8 store from genesis by
verifying every canonical exact leaf, catches a durable suffix up by the same
verifier, and calls `exact_rows_equal` before returning. The byte equality
includes `NOTE_TIP_KEY` and every block-record note snapshot. `decodeNote`
is deliberately an arbitrary deterministic decoder: byte equality alone
then forces equal decoded note states, with no cryptographic assertion about
the unkeyed record checksum. -/
structure StartupReplayGate
    (decodeNote : List Nat → Option NoteHistory) where
  scratchState : NoteHistory
  scratchReachable : Reachable scratchState
  scratchNoteBytes : List Nat
  durableNoteBytes : List Nat
  scratchDecoded : decodeNote scratchNoteBytes = some scratchState
  exactRowsEqual : durableNoteBytes = scratchNoteBytes

theorem startup_decoded_snapshot_reachable
    {decodeNote : List Nat → Option NoteHistory}
    (gate : StartupReplayGate decodeNote)
    (durable : NoteHistory)
    (decoded : decodeNote gate.durableNoteBytes = some durable) :
    Reachable durable := by
  rw [gate.exactRowsEqual, gate.scratchDecoded] at decoded
  cases Option.some.inj decoded
  exact gate.scratchReachable

theorem startup_anchor_has_ancestor_prefix
    {decodeNote : List Nat → Option NoteHistory}
    (gate : StartupReplayGate decodeNote)
    (durable : NoteHistory)
    (decoded : decodeNote gate.durableNoteBytes = some durable)
    (anchor : Digest) (admitted : PreBlockAnchorAccepted durable anchor) :
    ∃ ancestorLog, IsAncestorPrefix ancestorLog durable.log ∧
      anchor = rootOfLog ancestorLog := by
  exact accepted_anchor_has_ancestor_prefix
    (startup_decoded_snapshot_reachable gate durable decoded)
    anchor admitted

/-- Detach of a source-shaped record restores the before snapshot. This
handles arbitrary reorg depth by induction over the detached record list;
record-link equality in Rust is the external correspondence check. -/
noncomputable instance : DecidableEq NoteHistory := Classical.decEq _

noncomputable def detach : NoteHistory → List Record → Option NoteHistory
  | state, [] => some state
  | state, record :: rest =>
      if state = record.after then detach record.before rest else none

theorem detach_preserves_reachable
    {state result : NoteHistory} (reachable : Reachable state)
    (records : List Record) (detached : detach state records = some result) :
    Reachable result := by
  induction records generalizing state with
  | nil =>
      simp [detach] at detached
      subst result
      exact reachable
  | cons record rest ih =>
      simp only [detach] at detached
      split at detached
      · exact ih record.beforeReachable detached
      · simp at detached

end HegemonCrypto.SmallWood.SmzaRp05NativeHistoryTransitions
