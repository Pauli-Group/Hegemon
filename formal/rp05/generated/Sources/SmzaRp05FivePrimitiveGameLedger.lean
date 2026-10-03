import SmzaRp05ThresholdRegistry
import Hegemon.Transaction.Poseidon2V8SemanticSpecification

/-!
# Conditional five-game RP05 primitive ledger

This file composes five *separate* collision/claw-game advantages.  The game
evaluators are the source-live SingleKey sponge, accumulator Compress14,
cross-domain SingleKey/accumulator claw, note-leaf sponge, and ordered Merkle
Compress14.  The theorem is conditional on an explicit coverage premise and
five game bounds.  It does not assert that Poseidon2 is collision resistant,
instantiate any advantage, or claim a numerical security level.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05FivePrimitiveGameLedger

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false

/-- Canonical seven-lane compression operand. -/
abbrev CanonicalDigest := Fin 7 → Fin fieldModulus

def canonicalDigestWords (digest : CanonicalDigest) : Digest :=
  List.ofFn fun lane => (digest lane).val

abbrev CanonicalSingleKey := Fin 5 → Fin fieldModulus

def canonicalSingleKeyWords (key : CanonicalSingleKey) : List Nat :=
  List.ofFn (fun lane => (key lane).val) ++ [0, 0]

def singleKeyEvaluator (key : CanonicalSingleKey) : Digest :=
  poseidon2V8Sponge currentSourceSingleKeyDomain (canonicalSingleKeyWords key)

abbrev CompressionInput := CanonicalDigest × CanonicalDigest

def accumulatorCompress14Evaluator (input : CompressionInput) : Digest :=
  poseidon2V8Compress14 currentAuthorizationBindingDomain
    (canonicalDigestWords input.1) (canonicalDigestWords input.2)

def merkleCompress14Evaluator (input : CompressionInput) : Digest :=
  poseidon2V8Compress14 poseidon2V8MerkleDomain
    (canonicalDigestWords input.1) (canonicalDigestWords input.2)

/-- A tagged domain pair for the genuine cross-mode claw.  The tag is part of
the game input, while equality is tested on the actual seven output words. -/
abbrev MixedDomainInput := Sum CanonicalSingleKey CompressionInput

def mixedDomainEvaluator : MixedDomainInput → Digest
  | .inl key => singleKeyEvaluator key
  | .inr input => accumulatorCompress14Evaluator input

def CanonicalNoteOpening (note : V8NoteOpening) : Prop :=
  note.recipientKey.length = 4 ∧ note.authorizationKey.length = 4 ∧
  note.rho.length = 4 ∧ note.randomness.length = 4 ∧
  ∀ word ∈ exactV8NoteWords note, word < fieldModulus

def noteLeafEvaluator (note : V8NoteOpening) : Digest :=
  exactV8NoteCommitment note

/-- Exact winning predicates for the five idealized primitive games.  Note
the effective-input check on leaf notes and the cross-domain requirement on
the claw game; metadata-only differences do not count as a collision. -/
def singleKeyCollision (pair : CanonicalSingleKey × CanonicalSingleKey) : Prop :=
  pair.1 ≠ pair.2 ∧ singleKeyEvaluator pair.1 = singleKeyEvaluator pair.2

def accumulatorCompress14Collision
    (pair : CompressionInput × CompressionInput) : Prop :=
  pair.1 ≠ pair.2 ∧ accumulatorCompress14Evaluator pair.1 =
    accumulatorCompress14Evaluator pair.2

def mixedDomainClaw (pair : MixedDomainInput × MixedDomainInput) : Prop :=
  ((∃ left right, pair.1 = .inl left ∧ pair.2 = .inr right) ∨
    (∃ left right, pair.1 = .inr left ∧ pair.2 = .inl right)) ∧
  mixedDomainEvaluator pair.1 = mixedDomainEvaluator pair.2

def noteLeafCollision (pair : V8NoteOpening × V8NoteOpening) : Prop :=
  CanonicalNoteOpening pair.1 ∧ CanonicalNoteOpening pair.2 ∧
  exactV8NoteWords pair.1 ≠ exactV8NoteWords pair.2 ∧
  noteLeafEvaluator pair.1 = noteLeafEvaluator pair.2

def merkleCompress14Collision
    (pair : CompressionInput × CompressionInput) : Prop :=
  pair.1 ≠ pair.2 ∧ merkleCompress14Evaluator pair.1 =
    merkleCompress14Evaluator pair.2

def eventMassTerm {Coin : Type} (mass : Coin → ℚ)
    (event : Coin → Prop) (coin : Coin) : ℚ :=
  if event coin then mass coin else 0

noncomputable def eventProbability {Coin : Type} [Fintype Coin]
    (mass : Coin → ℚ) (event : Coin → Prop) : ℚ :=
  ∑ coin, eventMassTerm mass event coin

structure FivePrimitiveExperiment (Coin : Type) [Fintype Coin] where
  mass : Coin → ℚ
  mass_nonnegative : ∀ coin, 0 ≤ mass coin
  mass_normalized : ∑ coin, mass coin = 1
  singleKeyOutput : Coin → CanonicalSingleKey × CanonicalSingleKey
  accumulatorOutput : Coin → CompressionInput × CompressionInput
  mixedDomainOutput : Coin → MixedDomainInput × MixedDomainInput
  noteLeafOutput : Coin → V8NoteOpening × V8NoteOpening
  noteLeaf_left_canonical : ∀ coin,
    CanonicalNoteOpening (noteLeafOutput coin).1
  noteLeaf_right_canonical : ∀ coin,
    CanonicalNoteOpening (noteLeafOutput coin).2
  merkleOutput : Coin → CompressionInput × CompressionInput
  acceptedFailure : Coin → Prop
  /-- This is the exact reduction-coverage obligation from an application
  failure to one of the named games.  It is not a cryptographic bound. -/
  failure_covered : ∀ coin, acceptedFailure coin →
    singleKeyCollision (singleKeyOutput coin) ∨
    accumulatorCompress14Collision (accumulatorOutput coin) ∨
    mixedDomainClaw (mixedDomainOutput coin) ∨
    noteLeafCollision (noteLeafOutput coin) ∨
    merkleCompress14Collision (merkleOutput coin)

def singleKeyWinProbability {Coin : Type} [Fintype Coin]
    (experiment : FivePrimitiveExperiment Coin) : ℚ :=
  eventProbability experiment.mass
    (fun coin => singleKeyCollision (experiment.singleKeyOutput coin))

def accumulatorWinProbability {Coin : Type} [Fintype Coin]
    (experiment : FivePrimitiveExperiment Coin) : ℚ :=
  eventProbability experiment.mass
    (fun coin => accumulatorCompress14Collision (experiment.accumulatorOutput coin))

def mixedDomainWinProbability {Coin : Type} [Fintype Coin]
    (experiment : FivePrimitiveExperiment Coin) : ℚ :=
  eventProbability experiment.mass
    (fun coin => mixedDomainClaw (experiment.mixedDomainOutput coin))

def noteLeafWinProbability {Coin : Type} [Fintype Coin]
    (experiment : FivePrimitiveExperiment Coin) : ℚ :=
  eventProbability experiment.mass
    (fun coin => noteLeafCollision (experiment.noteLeafOutput coin))

def merkleWinProbability {Coin : Type} [Fintype Coin]
    (experiment : FivePrimitiveExperiment Coin) : ℚ :=
  eventProbability experiment.mass
    (fun coin => merkleCompress14Collision (experiment.merkleOutput coin))

def acceptedFailureProbability {Coin : Type} [Fintype Coin]
    (experiment : FivePrimitiveExperiment Coin) : ℚ :=
  eventProbability experiment.mass experiment.acceptedFailure

private theorem event_mass_term_nonnegative {Coin : Type}
    (mass : Coin → ℚ) (event : Coin → Prop)
    (nonnegative : ∀ coin, 0 ≤ mass coin) (coin : Coin) :
    0 ≤ eventMassTerm mass event coin := by
  by_cases h : event coin
  · simp [eventMassTerm, h, nonnegative coin]
  · simp [eventMassTerm, h]

private theorem selected_term_le_five_sum
    (x a b c d e : ℚ) (ha : 0 ≤ a) (hb : 0 ≤ b) (hc : 0 ≤ c)
    (hd : 0 ≤ d) (he : 0 ≤ e)
    (hit : x = a ∨ x = b ∨ x = c ∨ x = d ∨ x = e) :
    x ≤ a + b + c + d + e := by
  rcases hit with h | h | h | h | h
  · subst x
    exact (le_add_of_nonneg_right
      (add_nonneg hb (add_nonneg hc (add_nonneg hd he)))).trans_eq (by ac_rfl)
  · subst x
    exact (le_add_of_nonneg_right
      (add_nonneg ha (add_nonneg hc (add_nonneg hd he)))).trans_eq (by ac_rfl)
  · subst x
    exact (le_add_of_nonneg_right
      (add_nonneg ha (add_nonneg hb (add_nonneg hd he)))).trans_eq (by ac_rfl)
  · subst x
    exact (le_add_of_nonneg_right
      (add_nonneg ha (add_nonneg hb (add_nonneg hc he)))).trans_eq (by ac_rfl)
  · subst x
    exact (le_add_of_nonneg_right
      (add_nonneg ha (add_nonneg hb (add_nonneg hc hd)))).trans_eq (by ac_rfl)

/-- Five-event union bound for a normalized finite experiment. It is the
quantitative composition step, proved from pointwise coverage and
nonnegative mass rather than assumed as a probability axiom. -/
theorem acceptedFailureProbability_le_five_game_sum
    {Coin : Type} [Fintype Coin]
    (experiment : FivePrimitiveExperiment Coin) :
    acceptedFailureProbability experiment ≤
      singleKeyWinProbability experiment +
      accumulatorWinProbability experiment +
      mixedDomainWinProbability experiment +
      noteLeafWinProbability experiment +
      merkleWinProbability experiment := by
  let e₁ := fun coin => singleKeyCollision (experiment.singleKeyOutput coin)
  let e₂ := fun coin => accumulatorCompress14Collision
    (experiment.accumulatorOutput coin)
  let e₃ := fun coin => mixedDomainClaw (experiment.mixedDomainOutput coin)
  let e₄ := fun coin => noteLeafCollision (experiment.noteLeafOutput coin)
  let e₅ := fun coin => merkleCompress14Collision (experiment.merkleOutput coin)
  have pointwise (coin : Coin) :
      eventMassTerm experiment.mass experiment.acceptedFailure coin ≤
        eventMassTerm experiment.mass e₁ coin +
        eventMassTerm experiment.mass e₂ coin +
        eventMassTerm experiment.mass e₃ coin +
        eventMassTerm experiment.mass e₄ coin +
        eventMassTerm experiment.mass e₅ coin := by
    have n₁ := event_mass_term_nonnegative experiment.mass e₁
      experiment.mass_nonnegative coin
    have n₂ := event_mass_term_nonnegative experiment.mass e₂
      experiment.mass_nonnegative coin
    have n₃ := event_mass_term_nonnegative experiment.mass e₃
      experiment.mass_nonnegative coin
    have n₄ := event_mass_term_nonnegative experiment.mass e₄
      experiment.mass_nonnegative coin
    have n₅ := event_mass_term_nonnegative experiment.mass e₅
      experiment.mass_nonnegative coin
    by_cases bad : experiment.acceptedFailure coin
    · have hit : eventMassTerm experiment.mass experiment.acceptedFailure coin =
          eventMassTerm experiment.mass e₁ coin ∨
        eventMassTerm experiment.mass experiment.acceptedFailure coin =
          eventMassTerm experiment.mass e₂ coin ∨
        eventMassTerm experiment.mass experiment.acceptedFailure coin =
          eventMassTerm experiment.mass e₃ coin ∨
        eventMassTerm experiment.mass experiment.acceptedFailure coin =
          eventMassTerm experiment.mass e₄ coin ∨
        eventMassTerm experiment.mass experiment.acceptedFailure coin =
          eventMassTerm experiment.mass e₅ coin := by
        rcases experiment.failure_covered coin bad with h₁ | h₂ | h₃ | h₄ | h₅
        · left
          simp [eventMassTerm, bad, e₁, h₁]
        · right; left
          simp [eventMassTerm, bad, e₂, h₂]
        · right; right; left
          simp [eventMassTerm, bad, e₃, h₃]
        · right; right; right; left
          simp [eventMassTerm, bad, e₄, h₄]
        · right; right; right; right
          simp [eventMassTerm, bad, e₅, h₅]
      exact selected_term_le_five_sum
        (eventMassTerm experiment.mass experiment.acceptedFailure coin)
        (eventMassTerm experiment.mass e₁ coin)
        (eventMassTerm experiment.mass e₂ coin)
        (eventMassTerm experiment.mass e₃ coin)
        (eventMassTerm experiment.mass e₄ coin)
        (eventMassTerm experiment.mass e₅ coin) n₁ n₂ n₃ n₄ n₅ hit
    · have nonnegativeSum :
          0 ≤ eventMassTerm experiment.mass e₁ coin +
            (eventMassTerm experiment.mass e₂ coin +
              (eventMassTerm experiment.mass e₃ coin +
                (eventMassTerm experiment.mass e₄ coin +
                  eventMassTerm experiment.mass e₅ coin))) :=
        add_nonneg n₁ (add_nonneg n₂ (add_nonneg n₃ (add_nonneg n₄ n₅)))
      simp only [eventMassTerm, bad, if_false]
      simpa only [eventMassTerm, add_assoc] using nonnegativeSum
  calc
    acceptedFailureProbability experiment ≤
        eventProbability experiment.mass e₁ + eventProbability experiment.mass e₂ +
          eventProbability experiment.mass e₃ + eventProbability experiment.mass e₄ +
          eventProbability experiment.mass e₅ := by
      unfold acceptedFailureProbability eventProbability
      calc
        _ ≤ ∑ coin, (eventMassTerm experiment.mass e₁ coin +
            eventMassTerm experiment.mass e₂ coin +
            eventMassTerm experiment.mass e₃ coin +
            eventMassTerm experiment.mass e₄ coin +
            eventMassTerm experiment.mass e₅ coin) :=
          Finset.sum_le_sum (fun coin _ => pointwise coin)
        _ = _ := by simp only [Finset.sum_add_distrib]
    _ = singleKeyWinProbability experiment +
          accumulatorWinProbability experiment + mixedDomainWinProbability experiment +
          noteLeafWinProbability experiment + merkleWinProbability experiment := rfl

/-- Conditional quantitative closure. Each premise is an explicit bound on
the corresponding idealized primitive game; no premise identifies these
advantages with `1/2^n` or claims any unconditional Poseidon2 property. -/
theorem acceptedFailureProbability_le_assumed_game_bounds
    {Coin : Type} [Fintype Coin]
    (experiment : FivePrimitiveExperiment Coin)
    (singleKeyBound accumulatorBound mixedDomainBound noteLeafBound
      merkleBound : ℚ)
    (singleKeyGame : singleKeyWinProbability experiment ≤ singleKeyBound)
    (accumulatorGame : accumulatorWinProbability experiment ≤ accumulatorBound)
    (mixedDomainGame : mixedDomainWinProbability experiment ≤ mixedDomainBound)
    (noteLeafGame : noteLeafWinProbability experiment ≤ noteLeafBound)
    (merkleGame : merkleWinProbability experiment ≤ merkleBound) :
    acceptedFailureProbability experiment ≤
      singleKeyBound + accumulatorBound + mixedDomainBound + noteLeafBound +
        merkleBound := by
  calc
    acceptedFailureProbability experiment ≤
        singleKeyWinProbability experiment + accumulatorWinProbability experiment +
          mixedDomainWinProbability experiment + noteLeafWinProbability experiment +
          merkleWinProbability experiment :=
      acceptedFailureProbability_le_five_game_sum experiment
    _ ≤ singleKeyBound + accumulatorBound + mixedDomainBound + noteLeafBound +
          merkleBound := by
      have h12 := add_le_add singleKeyGame accumulatorGame
      have h123 := add_le_add h12 mixedDomainGame
      have h1234 := add_le_add h123 noteLeafGame
      exact add_le_add h1234 merkleGame

end
end HegemonCrypto.SmallWood.SmzaRp05FivePrimitiveGameLedger
