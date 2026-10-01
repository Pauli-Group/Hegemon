import SmzaRp05FinalSupplySoundness
import SmzaRp05ThresholdRegistry

/-!
# RP05 known-empty native supply bridge (source-only)

The repaired note tree uses the commitment of a publicly known zero-value
opening at every unoccupied leaf.  This file fixes that opening in the exact
semantic note type and proves the deterministic empty-leaf dichotomy: an
authenticated different opening is an ordinary same-function note collision;
an equal opening has zero native value.  The existing accepted-execution
theorem then bounds the branch's native potential and lifetime issuance.

`authenticated` below is the equal-leaf outcome of historical-anchor path
comparison.  A differing leaf/root must separately return a Merkle
compression collision.  This module does not derive that path comparison,
accepted-registry membership, replay protection, or a concrete Rust/Lean
source conformance receipt.  It introduces no fixed-target preimage premise
and changes neither the relation nor proof serialization.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction
open HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness
open HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry

set_option autoImplicit false

/-- Full seven-word identity for the fixed nonzero key `[1,0,0,0,0]`,
shared with the corrected current registry instance. -/
def knownEmptyIdentity : Hegemon.Transaction.Poseidon2V8SemanticSpecification.Digest :=
  currentKnownEmptyIdentity

/-- The eighteen canonical note words from the repaired source helper.
The first four identity words are the authorization key and the remaining
three are the first three randomness words. -/
def knownEmptyOpening : V8NoteOpening := currentKnownEmptyOpening

def knownEmptyLeaf : Hegemon.Transaction.Poseidon2V8SemanticSpecification.Digest :=
  exactV8NoteCommitment knownEmptyOpening

/-- Concrete note-family input for the current RP05 registry evaluator.
The source's seven-word SingleKey identity is retained alongside the exact
eighteen-word note opening; it is not included twice in the note hash. -/
def sourceKnownEmptyPreimage : CurrentBindingPreimage :=
  .note currentKnownEmptyNotePreimage

theorem source_empty_registry_digest :
    currentBindingModel.digest sourceKnownEmptyPreimage = knownEmptyLeaf := rfl

theorem source_empty_registry_zero_native :
    currentOriginCodec.noteValue sourceKnownEmptyPreimage = 0 ∧
      currentOriginCodec.noteAsset sourceKnownEmptyPreimage = 0 := by
  exact ⟨rfl, rfl⟩

/-- The current registry's canonical empty note now selects the exact
source-shaped opening.  This fixes the note-family side only; the separate
SingleKey authorization evaluator still requires source binding. -/
theorem current_registry_selects_source_known_empty :
    currentOriginCodec.canonicalEmptyOpening =
      sourceKnownEmptyPreimage := rfl

theorem known_empty_is_zero_native :
    knownEmptyOpening.value = 0 ∧ knownEmptyOpening.assetId = 0 := by
  exact ⟨rfl, rfl⟩

/-- Ordinary note-binding game output: two different canonical note
openings evaluated by the same exact note commitment function. -/
structure NoteCollision (opening : V8NoteOpening) : Prop where
  different : opening ≠ knownEmptyOpening
  sameCommitment : exactV8NoteCommitment opening = knownEmptyLeaf

/-- The known default opening makes an unused-position accepted note either
zero-valued or a concrete ordinary note collision.  No preimage-security
condition is supplied by the caller. -/
theorem authenticated_empty_zero_or_collision
    (opening : V8NoteOpening)
    (authenticated : exactV8NoteCommitment opening = knownEmptyLeaf) :
    opening.value = 0 ∧ opening.assetId = 0 ∨ NoteCollision opening := by
  by_cases equal : opening = knownEmptyOpening
  · left
    subst opening
    exact known_empty_is_zero_native
  · right
    exact ⟨equal, authenticated⟩

/-- Stale-anchor empty positions are classified against the leaf at that
anchor.  On the no-collision branch, both inputs have zero value even if a
later branch append occupies one of their positions.  The position/anchor
comparison supplies the equal-commitment hypotheses here. -/
theorem two_authenticated_empty_inputs
    (first second : V8NoteOpening)
    (firstAuthenticated : exactV8NoteCommitment first = knownEmptyLeaf)
    (secondAuthenticated : exactV8NoteCommitment second = knownEmptyLeaf) :
    NoteCollision first ∨ NoteCollision second ∨
      (first.value + second.value = 0 ∧
        first.assetId = 0 ∧ second.assetId = 0) := by
  rcases authenticated_empty_zero_or_collision first firstAuthenticated with
    firstZero | firstCollision
  · rcases authenticated_empty_zero_or_collision second secondAuthenticated with
      secondZero | secondCollision
    · exact Or.inr (Or.inr ⟨by simp [firstZero.1, secondZero.1],
        firstZero.2, secondZero.2⟩)
    · exact Or.inr (Or.inl secondCollision)
  · exact Or.inl firstCollision

/-- Compose the repaired empty-leaf case with the already proved accepted
transfer/coinbase/no-coinbase branch invariant and checked integer-floor
halving cap.  The `run` premise is the accepted relation execution; the two
authenticated hypotheses are the equal-leaf results of separate historical
path checks.  Full SUPPLY still needs the concrete path/registry refinement. -/
theorem accepted_branch_empty_inputs_or_collision
    {program : Hegemon.Transaction.Poseidon2V8RelationProgram.RelationProgramComponents}
    [SmzaRp05BalanceCore.BalanceCertificate program]
    {before after : SupplyState}
    {actions : List AcceptedAction} {initial : Nat}
    (run : AcceptedExecution program before actions after)
    (genesis : potential before ≤ initial + issuanceAllowance before)
    (first second : V8NoteOpening)
    (firstAuthenticated : exactV8NoteCommitment first = knownEmptyLeaf)
    (secondAuthenticated : exactV8NoteCommitment second = knownEmptyLeaf) :
    NoteCollision first ∨ NoteCollision second ∨
      (first.value + second.value = 0 ∧
        first.assetId = 0 ∧ second.assetId = 0 ∧
        potential after ≤ initial + issuanceAllowance after ∧
        issuanceAllowance after ≤ Hegemon.Consensus.maxMonetarySupply ∧
        after.circulating ≤ initial + Hegemon.Consensus.maxMonetarySupply) := by
  rcases two_authenticated_empty_inputs first second firstAuthenticated
      secondAuthenticated with firstCollision | secondCollision | zero
  · exact Or.inl firstCollision
  · exact Or.inr (Or.inl secondCollision)
  · rcases accepted_rp05_lifetime_issuance_and_conservation run genesis with
      ⟨conserved, issued, capped⟩
    exact Or.inr (Or.inr ⟨zero.1, zero.2.1, zero.2.2,
      conserved, issued, capped⟩)

end HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply
