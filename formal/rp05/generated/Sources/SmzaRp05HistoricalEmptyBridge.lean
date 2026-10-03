import SmzaRp05KnownEmptySupply
import SmzaRp05LedgerMerkleBinding

/-!
# Historical-anchor empty-leaf bridge (source-only)

Compare an extracted accepted note path with the canonical default path at
the *same historical anchor and position*.  The existing path comparator
constructs the first actual note-hash or ordered Merkle-compression collision
when the effective inputs diverge.  If they do not diverge, the accepted
note's first two canonical words are zero.  The path and root premises below
must be supplied by the concrete append-only historical tree and accepted
proof readback; they are not new cryptographic assumptions.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05HistoricalEmptyBridge

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply

set_option autoImplicit false

/-- Actual accepted and canonical default paths at the same historical
anchor.  Equality of `root` and `sides` forces equal anchor/position; a later
append at the same numerical position does not alter this record. -/
structure HistoricalEmptyAt (opening : V8NoteOpening) where
  root : Digest
  sides : List ChildSide
  acceptedPath : AuthenticationPath Digest
  defaultPath : AuthenticationPath Digest
  accepted : OpensAt rp05PathHash root sides
    (exactV8NoteWords opening) acceptedPath
  canonicalDefault : OpensAt rp05PathHash root sides
    (exactV8NoteWords knownEmptyOpening) defaultPath
  acceptedEffective : CanonicalEffectivePath
    (exactV8NoteWords opening) acceptedPath
  defaultEffective : CanonicalEffectivePath
    (exactV8NoteWords knownEmptyOpening) defaultPath

/-- Equal canonical note words force the native value and asset to equal the
known default's first two words. -/
theorem equal_empty_note_words_zero_native
    (opening : V8NoteOpening)
    (equal : exactV8NoteWords opening =
      exactV8NoteWords knownEmptyOpening) :
    opening.value = 0 ∧ opening.assetId = 0 := by
  have value := congrArg (fun words : List Nat => words.getD 0 0) equal
  have asset := congrArg (fun words : List Nat => words.getD 1 0) equal
  constructor
  · simpa [exactV8NoteWords, knownEmptyOpening,
      SmzaRp05ThresholdRegistry.currentKnownEmptyOpening] using value
  · simpa [exactV8NoteWords, knownEmptyOpening,
      SmzaRp05ThresholdRegistry.currentKnownEmptyOpening] using asset

/-- Historical unused-position classification without a fixed-target
preimage game.  The right branch contains actual effective inputs, their
membership in the supplied paths and equal outputs of the same RP05 hash
family. -/
theorem historical_empty_zero_or_path_collision
    (opening : V8NoteOpening) (atAnchor : HistoricalEmptyAt opening) :
    (opening.value = 0 ∧ opening.assetId = 0) ∨
      Nonempty (CanonicalRp05PathCollision
        (exactV8NoteWords opening) (exactV8NoteWords knownEmptyOpening)
        atAnchor.acceptedPath atAnchor.defaultPath) := by
  rcases accepted_rp05_canonical_notes_or_collision
      atAnchor.root atAnchor.sides opening knownEmptyOpening
      atAnchor.acceptedPath atAnchor.defaultPath
      atAnchor.accepted atAnchor.canonicalDefault
      atAnchor.acceptedEffective atAnchor.defaultEffective with
    equal | collision
  · exact Or.inl (equal_empty_note_words_zero_native opening equal)
  · exact Or.inr ⟨collision⟩

/-- Two empty positions are zero-valued on the no-collision branch, including
the case where an older anchor predates an output later appended at one of
those numerical positions. -/
theorem two_historical_empty_inputs
    (first second : V8NoteOpening)
    (firstAt : HistoricalEmptyAt first)
    (secondAt : HistoricalEmptyAt second) :
    Nonempty (CanonicalRp05PathCollision
        (exactV8NoteWords first) (exactV8NoteWords knownEmptyOpening)
        firstAt.acceptedPath firstAt.defaultPath) ∨
      Nonempty (CanonicalRp05PathCollision
        (exactV8NoteWords second) (exactV8NoteWords knownEmptyOpening)
        secondAt.acceptedPath secondAt.defaultPath) ∨
      (first.value + second.value = 0 ∧
        first.assetId = 0 ∧ second.assetId = 0) := by
  rcases historical_empty_zero_or_path_collision first firstAt with
    firstZero | firstCollision
  · rcases historical_empty_zero_or_path_collision second secondAt with
      secondZero | secondCollision
    · exact Or.inr (Or.inr ⟨by simp [firstZero.1, secondZero.1],
        firstZero.2, secondZero.2⟩)
    · exact Or.inr (Or.inl secondCollision)
  · exact Or.inl firstCollision

end HegemonCrypto.SmallWood.SmzaRp05HistoricalEmptyBridge
