import Hegemon.Transaction.Poseidon2V8SemanticSpecification
import Mathlib.Data.Rat.Defs
import Mathlib.Algebra.Order.BigOperators.Group.Finset

/-!
# RP05 primitive nullifier collision game

This module is independent of the generated RP05 source-certificate chain.
It formalizes the exact primitive game and the generic bridge contract needed
to apply it to accepted spends. The source-binding proof is a field of the
spend certificate, so this theorem does not claim that the current generated
certificate has discharged that field. No output-width estimate is used as a
security bound.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PrimitiveCollisionGameLuna

open Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option autoImplicit false

def rp05NullifierDomain : Nat := 0x484e_554c_5632_0001

/-- A canonical primitive input is represented by twelve field elements.
Using `Fin fieldModulus` makes both length and canonicality part of its type. -/
structure CanonicalPreimage where
  word : Fin 12 → Fin fieldModulus

def CanonicalPreimage.toWords (input : CanonicalPreimage) : List Nat :=
  List.ofFn (fun index : Fin 12 => (input.word index).val)

@[simp] theorem CanonicalPreimage.toWords_length (input : CanonicalPreimage) :
    input.toWords.length = 12 := by
  simp [CanonicalPreimage.toWords]

private theorem foldPreservesLength {α β : Type}
    (items : List α) (step : List β → α → List β) {width : Nat}
    (stepLength : ∀ state item, (step state item).length = width)
    (state : List β) (stateLength : state.length = width) :
    (items.foldl step state).length = width := by
  induction items generalizing state with
  | nil => simpa using stateLength
  | cons head tail ih =>
      simp only [List.foldl_cons]
      exact ih (step state head) (stepLength state head)

private theorem poseidonPermutationLength (state : List Nat) :
    (_root_.Hegemon.Transaction.Poseidon2Width16Kernel.permutation state).length =
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.width := by
  unfold _root_.Hegemon.Transaction.Poseidon2Width16Kernel.permutation
  apply foldPreservesLength
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.externalRoundConstantsTerminal
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.externalRound
    (by intro state constants; exact
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.external_round_length state constants)
  apply foldPreservesLength
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.internalRoundConstants
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.internalRound
    (by intro state constant; exact
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.internal_round_length state constant)
  apply foldPreservesLength
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.externalRoundConstantsInitial
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.externalRound
    (by intro state constants; exact
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.external_round_length state constants)
  exact _root_.Hegemon.Transaction.Poseidon2Width16Kernel.external_linear_layer_length state

private theorem absorbBlockLength (domain : Nat) (inputs : List Nat)
    (blockCount : Nat) (state : List Nat) (block : Nat) :
    (poseidon2V8AbsorbBlock domain inputs blockCount state block).length =
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.width := by
  simp [poseidon2V8AbsorbBlock, poseidonPermutationLength]

/-- The sponge really returns seven words for every canonical twelve-word
input; the game does not treat out-of-range `getD` defaults as digest limbs. -/
theorem rp05Sponge_length (input : CanonicalPreimage) :
    (poseidon2V8Sponge rp05NullifierDomain input.toWords).length = 7 := by
  unfold poseidon2V8Sponge
  simp only [List.length_take]
  have startLength : poseidon2V8InitialState.length =
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.width := by
    simp [poseidon2V8InitialState]
  have foldedLength := foldPreservesLength
    (List.range (Nat.max 1
      ((input.toWords.length + _root_.Hegemon.Transaction.Poseidon2Width16Kernel.rate - 1) /
        _root_.Hegemon.Transaction.Poseidon2Width16Kernel.rate)))
    (poseidon2V8AbsorbBlock rp05NullifierDomain input.toWords
      (Nat.max 1
        ((input.toWords.length + _root_.Hegemon.Transaction.Poseidon2Width16Kernel.rate - 1) /
          _root_.Hegemon.Transaction.Poseidon2Width16Kernel.rate)))
    (by
      intro state block
      exact absorbBlockLength rp05NullifierDomain input.toWords _ state block)
    poseidon2V8InitialState startLength
  rw [Nat.min_eq_left]
  · rfl
  · rw [foldedLength]
    decide

/-- The seven indexed words returned by the exact V8 sponge at the current
RP05 nullifier domain. The `Fin 7` index covers the complete public digest. -/
def nullifierOutput (input : CanonicalPreimage) : Fin 7 → Nat :=
  fun limb => (poseidon2V8Sponge rp05NullifierDomain input.toWords).getD limb.val 0

abbrev CollisionGameOutput := CanonicalPreimage × CanonicalPreimage

/-- The adversary wins exactly when it gives distinct canonical twelve-word
inputs whose seven RP05 nullifier output words all agree. -/
def wins (output : CollisionGameOutput) : Prop :=
  output.1 ≠ output.2 ∧
    ∀ limb : Fin 7, nullifierOutput output.1 limb = nullifierOutput output.2 limb

/-- An accepted-spend adapter supplies the acceptance evidence at type
`Acceptance`, a canonical nullifier preimage, its seven public words, and the
source-certificate binding from those words to this exact primitive. -/
structure SourceCertifiedActiveSpend (Acceptance : Type) where
  acceptance : Acceptance
  preimage : CanonicalPreimage
  publicNullifier : Fin 7 → Nat
  sourceCertificate : ∀ limb : Fin 7,
    publicNullifier limb = nullifierOutput preimage limb

abbrev ReplayPair (Acceptance : Type) :=
  SourceCertifiedActiveSpend Acceptance × SourceCertifiedActiveSpend Acceptance

/-- The source event: same seven public nullifier words but different
position word (word seven) in the canonical preimages. -/
def sourceReplayWins {Acceptance : Type} (pair : ReplayPair Acceptance) : Prop :=
  pair.1.publicNullifier = pair.2.publicNullifier ∧
    pair.1.preimage.word ⟨7, by decide⟩ ≠ pair.2.preimage.word ⟨7, by decide⟩

def toCollisionGameOutput {Acceptance : Type} (pair : ReplayPair Acceptance) :
    CollisionGameOutput := (pair.1.preimage, pair.2.preimage)

/-- Pointwise accepted-spend reduction. Equal public outputs transfer through
the source certificate to equal primitive outputs. Distinct source positions
make the canonical inputs distinct by their seventh word. -/
theorem sourceReplayWins_maps_to_primitiveWin {Acceptance : Type}
    (pair : ReplayPair Acceptance) (sourceWin : sourceReplayWins pair) :
    wins (toCollisionGameOutput pair) := by
  constructor
  · intro sameInput
    have samePosition := congrArg (fun input : CanonicalPreimage =>
      input.word ⟨7, by decide⟩) sameInput
    exact sourceWin.2 samePosition
  · intro limb
    change nullifierOutput pair.1.preimage limb = nullifierOutput pair.2.preimage limb
    rw [← pair.1.sourceCertificate limb, ← pair.2.sourceCertificate limb]
    exact congrArg (fun output : Fin 7 → Nat => output limb) sourceWin.1

/-- Finite randomized adversary. The externally chosen mass function is a
normalized nonnegative rational distribution over its finite coin space. -/
structure FiniteReplayAdversary (Acceptance : Type) where
  coins : Type
  [finiteCoins : Fintype coins]
  output : coins → ReplayPair Acceptance
  mass : coins → ℚ
  mass_nonnegative : ∀ coin, 0 ≤ mass coin
  mass_normalized : ∑ coin, mass coin = 1

noncomputable def eventProbability {Acceptance : Type}
    (adversary : FiniteReplayAdversary Acceptance)
    (event : ReplayPair Acceptance → Prop) : ℚ := by
  classical
  letI := adversary.finiteCoins
  exact ∑ coin, if event (adversary.output coin) then adversary.mass coin else 0

noncomputable def sourceReplayProbability {Acceptance : Type}
    (adversary : FiniteReplayAdversary Acceptance) : ℚ :=
  eventProbability adversary sourceReplayWins

noncomputable def primitiveCollisionProbability {Acceptance : Type}
    (adversary : FiniteReplayAdversary Acceptance) : ℚ :=
  eventProbability adversary (fun pair => wins (toCollisionGameOutput pair))

/-- Event inclusion lifts the pointwise reduction to finite randomized
adversaries: replay probability is at most the induced primitive-game win
probability. -/
theorem sourceReplayProbability_le_primitiveCollisionProbability
    {Acceptance : Type} (adversary : FiniteReplayAdversary Acceptance) :
    sourceReplayProbability adversary ≤ primitiveCollisionProbability adversary := by
  classical
  letI := adversary.finiteCoins
  have hsum :
      (∑ coin : adversary.coins,
        if sourceReplayWins (adversary.output coin) then adversary.mass coin else 0) ≤
      (∑ coin : adversary.coins,
        if wins (toCollisionGameOutput (adversary.output coin))
        then adversary.mass coin else 0) := by
    have termLE : ∀ coin : adversary.coins,
        (if sourceReplayWins (adversary.output coin) then adversary.mass coin else 0) ≤
          (if wins (toCollisionGameOutput (adversary.output coin))
          then adversary.mass coin else 0) := by
      intro coin
      by_cases sourceWin : sourceReplayWins (adversary.output coin)
      · have primitiveWin := sourceReplayWins_maps_to_primitiveWin
          (adversary.output coin) sourceWin
        simp [sourceWin, primitiveWin]
      · by_cases primitiveWin : wins (toCollisionGameOutput (adversary.output coin))
        · simp [sourceWin, primitiveWin]
          exact adversary.mass_nonnegative coin
        · simp [sourceWin, primitiveWin]
    change (Finset.univ : Finset adversary.coins).sum (fun coin =>
        if sourceReplayWins (adversary.output coin) then adversary.mass coin else 0) ≤
      (Finset.univ : Finset adversary.coins).sum (fun coin =>
        if wins (toCollisionGameOutput (adversary.output coin))
        then adversary.mass coin else 0)
    have sumLE (s : Finset adversary.coins) :
        s.sum (fun coin => if sourceReplayWins (adversary.output coin)
          then adversary.mass coin else 0) ≤
        s.sum (fun coin => if wins (toCollisionGameOutput (adversary.output coin))
          then adversary.mass coin else 0) := by
      induction s using Finset.induction_on with
      | empty => simp
      | @insert coin s absent ih =>
          simp only [Finset.sum_insert absent]
          calc
            _ ≤ (if wins (toCollisionGameOutput (adversary.output coin))
                then adversary.mass coin else 0) +
                s.sum (fun coin => if sourceReplayWins (adversary.output coin)
                  then adversary.mass coin else 0) :=
              Rat.add_le_add_right.mpr (termLE coin)
            _ ≤ _ := Rat.add_le_add_left.mpr ih
    exact sumLE Finset.univ
  exact hsum

/-- Explicit primitive-advantage assumption for the adversary induced by the
source reduction. The resulting replay bound is conditional on this
assumption; this module does not instantiate it or prove a construction-
specific classical or quantum bound. -/
def PrimitiveAdvantageAtMost {Acceptance : Type}
    (adversary : FiniteReplayAdversary Acceptance) (epsilon : ℚ) : Prop :=
  primitiveCollisionProbability adversary ≤ epsilon

theorem sourceReplayProbability_le_assumedPrimitiveAdvantage
    {Acceptance : Type} (adversary : FiniteReplayAdversary Acceptance)
    (epsilon : ℚ)
    (primitiveAssumption : PrimitiveAdvantageAtMost adversary epsilon) :
    sourceReplayProbability adversary ≤ epsilon := by
  calc
    sourceReplayProbability adversary ≤ primitiveCollisionProbability adversary :=
      sourceReplayProbability_le_primitiveCollisionProbability adversary
    _ ≤ epsilon := primitiveAssumption

end HegemonCrypto.SmallWood.SmzaRp05PrimitiveCollisionGameLuna
