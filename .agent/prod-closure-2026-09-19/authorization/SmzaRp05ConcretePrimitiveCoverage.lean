import SmzaRp05AuthorizationClosureCrossTransaction
import SmzaRp05FivePrimitiveGameLedger

/-! Exact reduction of the framed authorization collision witness to the
three authorization games in the five-primitive ledger.  This module does
not cover the other supply/history alternatives. -/

namespace HegemonCrypto.SmallWood.SmzaRp05ConcretePrimitiveCoverage

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureIdentity
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureCrossTransaction
open HegemonCrypto.SmallWood.SmzaRp05LiveAuthorizationIdentity
open HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry
open HegemonCrypto.SmallWood.SmzaRp05FivePrimitiveGameLedger

set_option autoImplicit false

private theorem modulus_pos : 0 < fieldModulus := by decide

private def keyFin (key : Fin 5 → Nat)
    (canonical : ∀ limb, key limb < fieldModulus) : CanonicalSingleKey :=
  fun limb => ⟨key limb, canonical limb⟩

private def rightFin (right : List Nat)
    (canonical : right.length = 7 ∧ ∀ word ∈ right, word < fieldModulus) :
    CanonicalDigest := fun limb =>
  ⟨right.getD limb.val 0, by
    have hlen : limb.val < right.length := by rw [canonical.1]; exact limb.isLt
    have hword : right[limb.val] ∈ right := List.getElem_mem hlen
    rw [List.getD_eq_getElem _ _ hlen]
    exact canonical.2 _ hword⟩

private def paddedKeyFin (key : Fin 5 → Nat)
    (canonical : ∀ limb, key limb < fieldModulus) : CanonicalDigest :=
  fun limb => if h : limb.val < 5 then
      ⟨key ⟨limb.val, h⟩, canonical ⟨limb.val, h⟩⟩
    else ⟨0, modulus_pos⟩

private theorem keyFin_words (key : Fin 5 → Nat)
    (canonical : ∀ limb, key limb < fieldModulus) :
    canonicalSingleKeyWords (keyFin key canonical) =
      currentSingleKeyWords key := by
  simp [canonicalSingleKeyWords,
    SmzaRp05ThresholdRegistry.currentSingleKeyWords, keyFin]

private theorem paddedKey_words (key : Fin 5 → Nat)
    (canonical : ∀ limb, key limb < fieldModulus) :
    canonicalDigestWords (paddedKeyFin key canonical) =
      SmzaRp05ThresholdRegistry.currentSingleKeyWords key := by
  unfold canonicalDigestWords paddedKeyFin
    SmzaRp05ThresholdRegistry.currentSingleKeyWords
  apply List.ext_getElem
  · simp
  · intro i h₁ h₂
    have hi : i < 7 := by simpa using h₁
    simp only [List.getElem_ofFn]
    interval_cases i <;> simp

private theorem right_words (right : List Nat)
    (canonical : right.length = 7 ∧ ∀ word ∈ right, word < fieldModulus) :
    canonicalDigestWords (rightFin right canonical) = right := by
  unfold canonicalDigestWords rightFin
  apply List.ext_getElem
  · simp [canonical.1]
  · intro i h₁ h₂
    simp only [List.getElem_ofFn]
    rw [List.getD_eq_getElem _ _ (by simpa [canonical.1] using h₁)]

private def framedGameInput (message : FramedAuthorizationInput)
    (canonical : message.Canonical) : MixedDomainInput :=
  match message with
  | .single key => .inl (keyFin key canonical.1)
  | .bound key right => .inr
      (paddedKeyFin key canonical.1, rightFin right canonical.2)

private theorem framedGameInput_evaluator (message : FramedAuthorizationInput)
    (canonical : message.Canonical) :
    mixedDomainEvaluator (framedGameInput message canonical) = message.digest := by
  cases message with
  | single key =>
      change poseidon2V8Sponge
          SmzaRp05ThresholdRegistry.currentSourceSingleKeyDomain
          (canonicalSingleKeyWords (keyFin key canonical.1)) =
        poseidon2V8Sponge SmzaRp05ThresholdRegistry.currentSingleKeyDomain
          (currentSingleKeyWords key)
      rw [keyFin_words]
      rfl
  | bound key right =>
      rcases canonical with ⟨keyCanonical, rightCanonical⟩
      change poseidon2V8Compress14 currentAuthorizationBindingDomain
          (canonicalDigestWords (paddedKeyFin key keyCanonical))
          (canonicalDigestWords (rightFin right rightCanonical)) =
        poseidon2V8Compress14 currentAuthorizationBindingDomain
          (currentSingleKeyWords key) right
      rw [paddedKey_words, right_words]

private theorem keyFin_injective {left right : Fin 5 → Nat}
    (leftCanonical : ∀ limb, left limb < fieldModulus)
    (rightCanonical : ∀ limb, right limb < fieldModulus)
    (equal : keyFin left leftCanonical = keyFin right rightCanonical) :
    left = right := by
  funext limb
  have h := congrFun equal limb
  exact congrArg Fin.val h

private theorem paddedKeyFin_injective {left right : Fin 5 → Nat}
    (leftCanonical : ∀ limb, left limb < fieldModulus)
    (rightCanonical : ∀ limb, right limb < fieldModulus)
    (equal : paddedKeyFin left leftCanonical = paddedKeyFin right rightCanonical) :
    left = right := by
  funext limb
  have h := congrFun equal ⟨limb.val, by omega⟩
  have hval := congrArg Fin.val h
  simpa [paddedKeyFin] using hval

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
    (Hegemon.Transaction.Poseidon2Width16Kernel.permutation state).length =
      Hegemon.Transaction.Poseidon2Width16Kernel.width := by
  unfold Hegemon.Transaction.Poseidon2Width16Kernel.permutation
  apply foldPreservesLength
    Hegemon.Transaction.Poseidon2Width16Kernel.externalRoundConstantsTerminal
    Hegemon.Transaction.Poseidon2Width16Kernel.externalRound
    (by intro state constants; exact
      Hegemon.Transaction.Poseidon2Width16Kernel.external_round_length state constants)
  apply foldPreservesLength
    Hegemon.Transaction.Poseidon2Width16Kernel.internalRoundConstants
    Hegemon.Transaction.Poseidon2Width16Kernel.internalRound
    (by intro state constant; exact
      Hegemon.Transaction.Poseidon2Width16Kernel.internal_round_length state constant)
  apply foldPreservesLength
    Hegemon.Transaction.Poseidon2Width16Kernel.externalRoundConstantsInitial
    Hegemon.Transaction.Poseidon2Width16Kernel.externalRound
    (by intro state constants; exact
      Hegemon.Transaction.Poseidon2Width16Kernel.external_round_length state constants)
  exact Hegemon.Transaction.Poseidon2Width16Kernel.external_linear_layer_length state

private theorem spongeLength (domain : Nat) (inputs : List Nat) :
    (poseidon2V8Sponge domain inputs).length = digestWords := by
  unfold poseidon2V8Sponge
  simp only [List.length_take]
  have startLength : poseidon2V8InitialState.length =
      Hegemon.Transaction.Poseidon2Width16Kernel.width := by
    simp [poseidon2V8InitialState]
  have foldedLength := foldPreservesLength
    (List.range (Nat.max 1
      ((inputs.length + Hegemon.Transaction.Poseidon2Width16Kernel.rate - 1) /
        Hegemon.Transaction.Poseidon2Width16Kernel.rate)))
    (poseidon2V8AbsorbBlock domain inputs
      (Nat.max 1
        ((inputs.length + Hegemon.Transaction.Poseidon2Width16Kernel.rate - 1) /
          Hegemon.Transaction.Poseidon2Width16Kernel.rate)))
    (by intro state block; simp [poseidon2V8AbsorbBlock, poseidonPermutationLength])
    poseidon2V8InitialState startLength
  simp [digestWords, foldedLength,
    Hegemon.Transaction.Poseidon2Width16Kernel.width]

private theorem compressLength (domain : Nat) (left right : Digest) :
    (poseidon2V8Compress14 domain left right).length = digestWords := by
  unfold poseidon2V8Compress14
  simp only [List.length_take]
  rw [poseidonPermutationLength]
  decide

private theorem framedDigestLength (message : FramedAuthorizationInput) :
    message.digest.length = 7 := by
  cases message with
  | single key =>
      simp [FramedAuthorizationInput.digest, LiveAuthorizationInput.digest,
        spongeLength, digestWords]
  | bound key right =>
      simp [FramedAuthorizationInput.digest, LiveAuthorizationInput.digest,
        compressLength, digestWords]

private theorem framed_digest_equal
    {left right : FramedAuthorizationInput}
    (collision : FramedAuthorizationCollision left right) :
    left.digest = right.digest := by
  have leftLength : left.digest.length = 7 := framedDigestLength left
  apply List.ext_getElem
  · cases left <;> cases right <;>
      simp [FramedAuthorizationInput.digest, LiveAuthorizationInput.digest,
        spongeLength, compressLength, digestWords]
  · intro i hi₁ hi₂
    have indexBound : i < 7 := by simpa [leftLength] using hi₁
    calc
      left.digest[i] = left.digest.getD i 0 :=
        (List.getD_eq_getElem _ _ hi₁).symm
      _ = right.digest.getD i 0 := collision.2.2.2 ⟨i, indexBound⟩
      _ = right.digest[i] := List.getD_eq_getElem _ _ hi₂

private def FramedAuthorizationGameWins
    (left right : FramedAuthorizationInput)
    (leftCanonical : left.Canonical) (rightCanonical : right.Canonical) : Prop :=
  match left, right with
  | .single leftKey, .single rightKey =>
      singleKeyCollision
        (keyFin leftKey leftCanonical.1, keyFin rightKey rightCanonical.1)
  | .bound leftKey leftRight, .bound rightKey rightRight =>
      accumulatorCompress14Collision
        ((paddedKeyFin leftKey leftCanonical.1, rightFin leftRight leftCanonical.2),
         (paddedKeyFin rightKey rightCanonical.1, rightFin rightRight rightCanonical.2))
  | .single leftKey, .bound rightKey rightRight => mixedDomainClaw
      (framedGameInput (.single leftKey) leftCanonical,
        framedGameInput (.bound rightKey rightRight) rightCanonical)
  | .bound leftKey leftRight, .single rightKey => mixedDomainClaw
      (framedGameInput (.bound leftKey leftRight) leftCanonical,
        framedGameInput (.single rightKey) rightCanonical)

/-- Exact tagged game output selected deterministically by the two current
framed source messages. The payload is the canonical input pair of the named
primitive game; no unrelated existential pair is used. -/
inductive FramedAuthorizationGameOutput where
  | singleKey (pair : CanonicalSingleKey × CanonicalSingleKey)
  | accumulator (pair : CompressionInput × CompressionInput)
  | mixed (pair : MixedDomainInput × MixedDomainInput)

def FramedAuthorizationGameOutput.wins : FramedAuthorizationGameOutput → Prop
  | .singleKey pair => singleKeyCollision pair
  | .accumulator pair => accumulatorCompress14Collision pair
  | .mixed pair => mixedDomainClaw pair

def framedAuthorizationGameOutput (left right : FramedAuthorizationInput)
    (leftCanonical : left.Canonical) (rightCanonical : right.Canonical) :
    FramedAuthorizationGameOutput :=
  match left, right with
  | .single leftKey, .single rightKey =>
      .singleKey (keyFin leftKey leftCanonical.1, keyFin rightKey rightCanonical.1)
  | .bound leftKey leftRight, .bound rightKey rightRight =>
      .accumulator
        ((paddedKeyFin leftKey leftCanonical.1, rightFin leftRight leftCanonical.2),
         (paddedKeyFin rightKey rightCanonical.1, rightFin rightRight rightCanonical.2))
  | .single leftKey, .bound rightKey rightRight =>
      .mixed (framedGameInput (.single leftKey) leftCanonical,
        framedGameInput (.bound rightKey rightRight) rightCanonical)
  | .bound leftKey leftRight, .single rightKey =>
      .mixed (framedGameInput (.bound leftKey leftRight) leftCanonical,
        framedGameInput (.single rightKey) rightCanonical)

/-- The source-canonical framed collision deterministically wins either the
single-key collision game, the accumulator Compress14 collision game, or
the cross-domain claw game.  The outputs are exact ledger game inputs, not
assumed collision witnesses. -/
theorem framedAuthorizationCollision_to_three_games
    {left right : FramedAuthorizationInput}
    (collision : FramedAuthorizationCollision left right) :
    FramedAuthorizationGameWins left right collision.1 collision.2.1 := by
  cases left with
  | single lk =>
    cases right with
    | single rk =>
      have keyDifferent : keyFin lk collision.1.1 ≠ keyFin rk collision.2.1.1 := by
        intro equal
        apply collision.2.2.1
        exact keyFin_injective collision.1.1 collision.2.1.1 equal
      have digestEqual :
          singleKeyEvaluator (keyFin lk collision.1.1) =
            singleKeyEvaluator (keyFin rk collision.2.1.1) := by
        calc
          singleKeyEvaluator (keyFin lk collision.1.1) =
              (FramedAuthorizationInput.single lk).digest := by
            simp [singleKeyEvaluator, FramedAuthorizationInput.digest,
              LiveAuthorizationInput.digest, keyFin_words,
              SmzaRp05ThresholdRegistry.currentSingleKeyDomain,
              SmzaRp05ThresholdRegistry.currentSourceSingleKeyDomain]
          _ = (FramedAuthorizationInput.single rk).digest := framed_digest_equal collision
          _ = singleKeyEvaluator (keyFin rk collision.2.1.1) := by
            simp [singleKeyEvaluator, FramedAuthorizationInput.digest,
              LiveAuthorizationInput.digest, keyFin_words,
              SmzaRp05ThresholdRegistry.currentSingleKeyDomain,
              SmzaRp05ThresholdRegistry.currentSourceSingleKeyDomain]
      exact ⟨keyDifferent, digestEqual⟩
    | bound rk rr =>
      simpa [FramedAuthorizationGameWins, framedGameInput] using
        (show mixedDomainClaw
          (framedGameInput (.single lk) collision.1,
            framedGameInput (.bound rk rr) collision.2.1) from by
              refine ⟨Or.inl ⟨keyFin lk collision.1.1,
                (paddedKeyFin rk collision.2.1.1,
                  rightFin rr collision.2.1.2), rfl, rfl⟩, ?_⟩
              simpa [framedGameInput_evaluator] using framed_digest_equal collision)
  | bound lk lr =>
    cases right with
    | single rk =>
      simpa [FramedAuthorizationGameWins, framedGameInput] using
        (show mixedDomainClaw
          (framedGameInput (.bound lk lr) collision.1,
            framedGameInput (.single rk) collision.2.1) from by
              refine ⟨Or.inr ⟨(paddedKeyFin lk collision.1.1,
                rightFin lr collision.1.2), keyFin rk collision.2.1.1,
                rfl, rfl⟩, ?_⟩
              simpa [framedGameInput_evaluator] using framed_digest_equal collision)
    | bound rk rr =>
      have accDifferent :
          (paddedKeyFin lk collision.1.1, rightFin lr collision.1.2) ≠
            (paddedKeyFin rk collision.2.1.1, rightFin rr collision.2.1.2) := by
        intro equal
        apply collision.2.2.1
        exact paddedKeyFin_injective collision.1.1 collision.2.1.1
          (congrArg Prod.fst equal)
      have digestEqual :
          accumulatorCompress14Evaluator
              (paddedKeyFin lk collision.1.1, rightFin lr collision.1.2) =
            accumulatorCompress14Evaluator
              (paddedKeyFin rk collision.2.1.1, rightFin rr collision.2.1.2) := by
        calc
          accumulatorCompress14Evaluator
              (paddedKeyFin lk collision.1.1, rightFin lr collision.1.2) =
              (FramedAuthorizationInput.bound lk lr).digest := by
            simp [accumulatorCompress14Evaluator,
              FramedAuthorizationInput.digest, LiveAuthorizationInput.digest,
              SmzaRp05ThresholdRegistry.currentSingleKeyWords,
              paddedKey_words, right_words]
          _ = (FramedAuthorizationInput.bound rk rr).digest := framed_digest_equal collision
          _ = accumulatorCompress14Evaluator
              (paddedKeyFin rk collision.2.1.1, rightFin rr collision.2.1.2) := by
            simp [accumulatorCompress14Evaluator,
              FramedAuthorizationInput.digest, LiveAuthorizationInput.digest,
              SmzaRp05ThresholdRegistry.currentSingleKeyWords,
              paddedKey_words, right_words]
      simpa [FramedAuthorizationGameWins] using ⟨accDifferent, digestEqual⟩

/-- The source collision wins the exact deterministic game output selected
from these same messages. -/
theorem framedAuthorizationCollision_wins_selected_game
    {left right : FramedAuthorizationInput}
    (collision : FramedAuthorizationCollision left right) :
    (framedAuthorizationGameOutput left right collision.1 collision.2.1).wins := by
  cases left with
  | single leftKey =>
    cases right with
    | single rightKey => exact framedAuthorizationCollision_to_three_games collision
    | bound rightKey rightWords => exact framedAuthorizationCollision_to_three_games collision
  | bound leftKey leftWords =>
    cases right with
    | single rightKey => exact framedAuthorizationCollision_to_three_games collision
    | bound rightKey rightWords => exact framedAuthorizationCollision_to_three_games collision

/-- Public event interface for downstream original-weight composition. This
exposes the three named win predicates while leaving the constructor-selected
canonical inputs implicit in the existential witnesses. -/
theorem framedAuthorizationCollision_explicit_game_wins
    {left right : FramedAuthorizationInput}
    (collision : FramedAuthorizationCollision left right) :
    (∃ pair : CanonicalSingleKey × CanonicalSingleKey,
      singleKeyCollision pair) ∨
    (∃ pair : CompressionInput × CompressionInput,
      accumulatorCompress14Collision pair) ∨
    (∃ pair : MixedDomainInput × MixedDomainInput,
      mixedDomainClaw pair) := by
  cases left with
  | single leftKey =>
    cases right with
    | single rightKey =>
        exact Or.inl ⟨_, framedAuthorizationCollision_to_three_games collision⟩
    | bound rightKey rightWords =>
        exact Or.inr (Or.inr ⟨_, framedAuthorizationCollision_to_three_games collision⟩)
  | bound leftKey leftWords =>
    cases right with
    | single rightKey =>
        exact Or.inr (Or.inr ⟨_, framedAuthorizationCollision_to_three_games collision⟩)
    | bound rightKey rightWords =>
        exact Or.inr (Or.inl ⟨_, framedAuthorizationCollision_to_three_games collision⟩)

end HegemonCrypto.SmallWood.SmzaRp05ConcretePrimitiveCoverage
