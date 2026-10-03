import SmzaRp05HistoricalEmptyBridge
import SmzaRp05SemanticLedger

/-! Known-empty historical positions do not need to be inserted into the
live-note registry. This closes the numerical availability step from an
authenticated historical-or-empty classification and spent-note freshness.
The classification is deliberately explicit: native append/history readback
and nullifier linkage must construct it; this theorem does not assert that
Rust acceptance already supplies those premises. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureAvailability

open scoped BigOperators Classical
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05HistoricalEmptyBridge
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply
open SmzaFiniteLedgerSupply

set_option autoImplicit false

/-- A registered historical input binds to its producer's opening. An
unoccupied historical position is compared to the known-empty opening at
that anchor, even if the same position has since received a live output. -/
def HistoricalOrEmpty (registry opening : Nat → V8NoteOpening)
    (state : Ledger) (id : Nat) : Prop :=
  (id ∈ state.live ∪ state.spent ∧
    exactV8NoteCommitment (opening id) = exactV8NoteCommitment (registry id)) ∨
  Nonempty (HistoricalEmptyAt (opening id))

def EmptyPathCollision (opening : V8NoteOpening) : Prop :=
  ∃ atAnchor : HistoricalEmptyAt opening,
    Nonempty (CanonicalRp05PathCollision
      (exactV8NoteWords opening) (exactV8NoteWords knownEmptyOpening)
      atAnchor.acceptedPath atAnchor.defaultPath)

theorem historical_or_empty_native_available
    (registry opening : Nat → V8NoteOpening) (state : Ledger)
    (inputs : Finset Nat)
    (historical : ∀ id ∈ inputs, HistoricalOrEmpty registry opening state id)
    (fresh : Disjoint inputs state.spent)
    (noNoteCollision : ∀ id ∈ inputs, ¬ noteCollision (opening id) (registry id))
    (noEmptyCollision : ∀ id ∈ inputs, ¬ EmptyPathCollision (opening id)) :
    (∑ id ∈ inputs, nativeValue (opening id)) ≤ wealth registry state.live := by
  classical
  have pointwise : ∀ id ∈ inputs,
      nativeValue (opening id) ≤
        if id ∈ state.live then nativeValue (registry id) else 0 := by
    intro id member
    rcases historical id member with registered | ⟨atAnchor⟩
    · have live : id ∈ state.live := by
        rcases Finset.mem_union.mp registered.1 with live | spent
        · exact live
        · exact False.elim ((Finset.disjoint_left.mp fresh) member spent)
      have sameWords : exactV8NoteWords (opening id) =
          exactV8NoteWords (registry id) := by
        by_contra different
        exact noNoteCollision id member ⟨different, registered.2⟩
      rw [if_pos live, note_words_preserve_native sameWords]
    · let emptyAt : HistoricalEmptyAt (opening id) := Classical.choice atAnchor
      rcases historical_empty_zero_or_path_collision (opening id) emptyAt with
        zero | collision
      · have zeroNative : nativeValue (opening id) = 0 := by
          simp [nativeValue, zero.1]
        rw [zeroNative]
        exact Nat.zero_le _
      · exact False.elim (noEmptyCollision id member ⟨emptyAt, collision⟩)
  calc
    (∑ id ∈ inputs, nativeValue (opening id)) ≤
        ∑ id ∈ inputs, if id ∈ state.live then nativeValue (registry id) else 0 :=
      Finset.sum_le_sum pointwise
    _ = wealth registry (inputs.filter fun id => id ∈ state.live) := by
      simp only [wealth, Finset.sum_filter]
    _ ≤ wealth registry state.live :=
      wealth_mono registry (by
        intro id member
        exact (Finset.mem_filter.mp member).2)

/-- This is the formerly explicit `available` field of the arithmetic
AcceptedStep, now derived from the registry and historical-empty cases. -/
theorem accepted_transfer_native_available
    (registry : Nat → V8NoteOpening) (state : Ledger) (tx : Transfer)
    (historical : ∀ id ∈ tx.inputs,
      HistoricalOrEmpty registry tx.inputOpening state id)
    (fresh : Disjoint tx.inputs state.spent)
    (noNoteCollision : ∀ id ∈ tx.inputs,
      ¬ noteCollision (tx.inputOpening id) (registry id))
    (noEmptyCollision : ∀ id ∈ tx.inputs,
      ¬ EmptyPathCollision (tx.inputOpening id))
    (inputRealization : (∑ id ∈ tx.inputs, nativeValue (tx.inputOpening id)) =
      SmzaRp05FinalSupplySoundness.inputNative tx.statement tx.packed) :
    SmzaRp05FinalSupplySoundness.inputNative tx.statement tx.packed ≤
      wealth registry state.live := by
  rw [← inputRealization]
  exact historical_or_empty_native_available registry tx.inputOpening state
    tx.inputs historical fresh noNoteCollision noEmptyCollision

/-- Build the existing arithmetic transfer constructor from accepted relation
bytes and historical inputs; the caller supplies neither availability nor a
conservation equation. The scalar pre-state is the live registry's wealth. -/
theorem accepted_historical_transfer_step
    {program : Hegemon.Transaction.Poseidon2V8RelationProgram.RelationProgramComponents}
    (registry : Nat → V8NoteOpening) (state : Ledger) (tx : Transfer)
    {primitives : V8SemanticPrimitives}
    (canonical : CanonicalPublicStatement primitives tx.statement)
    (accepted : program.AcceptsPacked (encodePublicStatement tx.statement) tx.packed)
    (historical : ∀ id ∈ tx.inputs,
      HistoricalOrEmpty registry tx.inputOpening state id)
    (fresh : Disjoint tx.inputs state.spent)
    (noNoteCollision : ∀ id ∈ tx.inputs,
      ¬ noteCollision (tx.inputOpening id) (registry id))
    (noEmptyCollision : ∀ id ∈ tx.inputs,
      ¬ EmptyPathCollision (tx.inputOpening id))
    (inputRealization : (∑ id ∈ tx.inputs, nativeValue (tx.inputOpening id)) =
      SmzaRp05FinalSupplySoundness.inputNative tx.statement tx.packed) :
    SmzaRp05FinalSupplySoundness.AcceptedStep program
      { circulating := wealth registry state.live
        feeEscrow := state.feeEscrow
        issuedHeights := state.issuedHeights }
      (.transfer tx.statement tx.packed)
      { circulating := wealth registry state.live -
          SmzaRp05FinalSupplySoundness.inputNative tx.statement tx.packed +
          SmzaRp05FinalSupplySoundness.outputNative tx.statement tx.packed
        feeEscrow := state.feeEscrow + tx.statement.fee
        issuedHeights := state.issuedHeights } := by
  exact .transfer _ tx.statement tx.packed ⟨primitives, canonical⟩ accepted
    (accepted_transfer_native_available registry state tx historical fresh
      noNoteCollision noEmptyCollision inputRealization)

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureAvailability
