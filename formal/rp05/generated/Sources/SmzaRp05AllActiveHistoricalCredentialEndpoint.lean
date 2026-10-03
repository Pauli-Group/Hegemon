import SmzaRp05SingleSpendAuthorizationEndpoint
import SmzaRp05SupplyClosureHistoricalInputs
import SmzaRp05SupplyClosureHistoryJoin
import SmzaRp05SupplyClosureLedgerJoin

/-! # All-active current credential and historical-opening classification

Every active input of the designated accepted source retains its current
five-word credential and seven-word owner binding. Its admitted anchor selects
an actual prefix of the replayed opening log. The input then matches an occupied
opening, matches the exact known-empty opening at that historical prefix, or
exhibits the existing concrete canonical path collision.

This is a pointwise result for all assets, including zero-value inputs. It
does not assert that every active position was created or is unspent. In
particular, a known-empty historical position may be occupied by a later
append. The positive-native chronological consumer and its quantitative
failure event remain separate. Validation is recorded with the public wrapper's receipts.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AllActiveHistoricalCredentialEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
  (CurrentInputPathCollision)
open HegemonCrypto.SmallWood.SmzaRp05SingleSpendAuthorizationEndpoint
  (CurrentSingleSpendCredentialFacts current_run_active_input_has_credential_facts)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs
  (publicAnchor accepted_at_history_words_or_collision)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoryJoin
  (replay_anchor_has_opening_prefix)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureLedgerJoin
  (opening_at_prefix)
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
  (openingAt fromLog opening_at_unoccupied)
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply (knownEmptyOpening)
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureIdentity (selectedMessage)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative (noteOwnerWord)
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
  (projectNote projectPosition spongeSourceWord)
open scoped Classical

set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

local notation "Statement" => SmzaRp05StatementNamespace.Statement

/-- The occupied case retains the exact admitted ancestor, not merely a
position that happens to be occupied in the current snapshot. Its seven owner
coordinates are those selected by this same accepted source input. -/
def CurrentActiveOccupiedHistoricalFacts
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2) : Prop :=
  ∃ count, count ≤ ledgerPrefix.snapshot.openings.length ∧
    publicAnchor (encodePublicStatement typed) =
      (fromLog merkleDepth 0 (ledgerPrefix.snapshot.openings.take count)).root ∧
    projectPosition (sourcePacked run) input.val <
      (ledgerPrefix.snapshot.openings.take count).length ∧
    exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)) =
      exactV8NoteWords (openingAt (ledgerPrefix.snapshot.openings.take count)
        (projectPosition (sourcePacked run) input.val)) ∧
    exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)) =
      exactV8NoteWords (openingAt ledgerPrefix.snapshot.openings
        (projectPosition (sourcePacked run) input.val)) ∧
    ∀ limb : Fin 7,
      (exactV8NoteWords (openingAt ledgerPrefix.snapshot.openings
        (projectPosition (sourcePacked run) input.val))).getD
          (noteOwnerWord limb) 0 =
        (selectedMessage (sourcePacked run) input).digest.getD limb.val 0

/-- An exact known-empty opening is an allowed historical classification,
not a collision. The unoccupied test refers to the admitted ancestor. -/
def CurrentActiveKnownEmptyHistoricalFacts
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2) : Prop :=
  ∃ count, count ≤ ledgerPrefix.snapshot.openings.length ∧
    publicAnchor (encodePublicStatement typed) =
      (fromLog merkleDepth 0 (ledgerPrefix.snapshot.openings.take count)).root ∧
    (ledgerPrefix.snapshot.openings.take count).length ≤
      projectPosition (sourcePacked run) input.val ∧
    exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)) =
      exactV8NoteWords knownEmptyOpening

private theorem projected_note_owner_coordinate_from_words
    (word : Nat → Nat) (limb : Fin 7) :
    ([word 0, word 1] ++
      (List.range 4).map (fun i => word (2 + i)) ++
      (List.range 4).map (fun i => word (6 + i)) ++
      (List.range 4).map (fun i => word (10 + i)) ++
      (List.range 4).map (fun i => word (14 + i))).getD
        (noteOwnerWord limb) 0 = word (noteOwnerWord limb) := by
  fin_cases limb <;> rfl

private theorem projected_note_owner_coordinate (packed : List Nat)
    (input : Fin 2) (limb : Fin 7) :
    (exactV8NoteWords (projectNote packed (noteCall input))).getD
        (noteOwnerWord limb) 0 =
      spongeSourceWord packed (noteCall input) (noteOwnerWord limb) := by
  let word := fun coordinate => spongeSourceWord packed (noteCall input) coordinate
  change ([word 0, word 1] ++
      (List.range 4).map (fun i => word (2 + i)) ++
      (List.range 4).map (fun i => word (6 + i)) ++
      (List.range 4).map (fun i => word (10 + i)) ++
      (List.range 4).map (fun i => word (14 + i))).getD
        (noteOwnerWord limb) 0 = word (noteOwnerWord limb)
  exact projected_note_owner_coordinate_from_words word limb

/-- Exact note-word equality transports the current selected owner vector
to any matching historical opening, independently of its asset or value. -/
theorem occupied_opening_owner_coordinates
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2)
    (credential : CurrentSingleSpendCredentialFacts run input)
    (opening : V8NoteOpening)
    (sameWords : exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)) =
      exactV8NoteWords opening) :
    ∀ limb : Fin 7,
      (exactV8NoteWords opening).getD (noteOwnerWord limb) 0 =
        (selectedMessage (sourcePacked run) input).digest.getD limb.val 0 := by
  intro limb
  have coordinate := congrArg
    (fun words : List Nat => words.getD (noteOwnerWord limb) 0) sameWords
  calc
    _ = (exactV8NoteWords (projectNote (sourcePacked run) (noteCall input))).getD
        (noteOwnerWord limb) 0 := coordinate.symm
    _ = spongeSourceWord (sourcePacked run) (noteCall input)
        (noteOwnerWord limb) := projected_note_owner_coordinate _ _ _
    _ = (sourcePacked run).getD ((95 + input.val) * 64 + limb.val) 0 :=
      credential.noteFrameOwner limb
    _ = (selectedMessage (sourcePacked run) input).digest.getD limb.val 0 :=
      credential.sevenWordRecordedOwner limb

/-- Every active designated source input has its current credential binding
and either an occupied historical opening, the exact historical known-empty
opening, or the existing actual canonical path-collision witness. No native
value, separate packed witness, or historical success premise is supplied. -/
theorem current_run_active_input_historical_credential_classification
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2)
    (active : (encodePublicStatement typed).getD input.val 0 = 1)
    (admitted : publicAnchor (encodePublicStatement typed) ∈
      ledgerPrefix.snapshot.parent.history) :
    CurrentSingleSpendCredentialFacts run input ∧
      (CurrentActiveOccupiedHistoricalFacts ledgerPrefix run input ∨
        CurrentActiveKnownEmptyHistoricalFacts ledgerPrefix run input ∨
        CurrentInputPathCollision run ledgerPrefix.snapshot input) := by
  have credential := current_run_active_input_has_credential_facts run input active
  refine ⟨credential, ?_⟩
  obtain ⟨count, countBound, anchor⟩ := replay_anchor_has_opening_prefix
    ledgerPrefix.snapshot.openings ledgerPrefix.snapshot.replay
    (publicAnchor (encodePublicStatement typed)) admitted
  rcases accepted_at_history_words_or_collision credential.accepted typed input active
      (ledgerPrefix.snapshot.openings.take count)
      (fun opening member => ledgerPrefix.snapshot.canonical opening
        (List.mem_of_mem_take member)) anchor with equal | collision
  · by_cases occupied : projectPosition (sourcePacked run) input.val <
        (ledgerPrefix.snapshot.openings.take count).length
    · have fullEqual :
          exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)) =
            exactV8NoteWords (openingAt ledgerPrefix.snapshot.openings
              (projectPosition (sourcePacked run) input.val)) := by
        exact equal.trans (congrArg exactV8NoteWords
          (opening_at_prefix ledgerPrefix.snapshot.openings count
            (projectPosition (sourcePacked run) input.val) occupied))
      exact Or.inl ⟨count, countBound, anchor, occupied, equal, fullEqual,
        occupied_opening_owner_coordinates run input credential _ fullEqual⟩
    · have unoccupied := Nat.le_of_not_lt occupied
      have emptyEqual :
          exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)) =
            exactV8NoteWords knownEmptyOpening := by
        exact equal.trans (congrArg exactV8NoteWords
          (opening_at_unoccupied (ledgerPrefix.snapshot.openings.take count)
            (projectPosition (sourcePacked run) input.val) unoccupied))
      exact Or.inr (Or.inl ⟨count, countBound, anchor, unoccupied, emptyEqual⟩)
  · exact Or.inr (Or.inr ⟨count, countBound, collision⟩)

end HegemonCrypto.SmallWood.SmzaRp05AllActiveHistoricalCredentialEndpoint
