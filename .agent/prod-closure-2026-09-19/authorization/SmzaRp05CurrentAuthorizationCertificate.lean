import SmzaRp05AuthorizationClosureNullifier
import SmzaRp05ConcretePrimitiveCoverage

/-! A same-original-outcome composition for the two current authorization
certificate failures supported by the source: distinct accepted nullifier
preimages with a common public output, and a same-owner/same-position/same-rho
comparison with different public nullifiers. The latter is reduced through
the actual framed source theorem. The three authorization domains remain
separate from the 12-word nullifier sponge. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAuthorizationCertificate

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureIdentity
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureCrossTransaction
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureNullifier
open HegemonCrypto.SmallWood.SmzaRp05PrimitiveCollisionGameLuna
open HegemonCrypto.SmallWood.SmzaRp05FivePrimitiveGameLedger
open HegemonCrypto.SmallWood.SmzaRp05CurrentNullifierCertificates
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05ConcretePrimitiveCoverage
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open scoped Classical

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

/-- The source-side comparison data consumed by the accepted cross-transaction
authorization theorem. Both executions are actual accepted active inputs;
owner, projected position, and rho equality are explicit source facts. -/
structure SameSourceNoteEvidence (left right : AcceptedActiveSpend) : Type where
  sameOwner : ∀ limb : Fin 7,
    left.packed.getD ((95 + left.input.val) * 64 + limb.val) 0 =
      right.packed.getD ((95 + right.input.val) * 64 + limb.val) 0
  samePosition : projectPosition left.packed left.input.val =
    projectPosition right.packed right.input.val
  sameRho : ∀ limb : Fin 4,
    spongeSourceWord left.packed (inputNoteFirstCall left.input) (6 + limb.val) =
      spongeSourceWord right.packed (inputNoteFirstCall right.input) (6 + limb.val)

structure CurrentAuthorizationPairCertificate where
  left : AcceptedActiveSpend
  right : AcceptedActiveSpend
  sameSourceNote : Option (SameSourceNoteEvidence left right)

def CurrentAuthorizationPairCertificate.spends
    (certificate : CurrentAuthorizationPairCertificate) : AcceptedSpendPair :=
  (certificate.left, certificate.right)

def activePublicNullifier (spend : AcceptedActiveSpend) : Fin 7 → Nat :=
  fun limb => spend.publicWords.getD (4 + spend.input.val * 7 + limb.val) 0

def selectedAuthorizationMessage (spend : AcceptedActiveSpend) :
    FramedAuthorizationInput :=
  selectedMessage spend.packed spend.input

theorem selectedAuthorizationCanonical (spend : AcceptedActiveSpend) :
    (selectedAuthorizationMessage spend).Canonical :=
  accepted_message_canonical spend.accepted spend.input

def selectedAuthorizationGameOutput
    (certificate : CurrentAuthorizationPairCertificate) :
    FramedAuthorizationGameOutput :=
  framedAuthorizationGameOutput
    (selectedAuthorizationMessage certificate.left)
    (selectedAuthorizationMessage certificate.right)
    (selectedAuthorizationCanonical certificate.left)
    (selectedAuthorizationCanonical certificate.right)

/-- The two source-supported failure predicates for this certificate path.
The second is not a supplied framed hash collision: it is the actual source
comparison context together with differing public nullifiers. -/
def nullifierPreimageAliasFailure
    (certificate : CurrentAuthorizationPairCertificate) : Prop :=
  acceptedPreimageAlias certificate.spends

def authorizationOutputMismatchFailure
    (certificate : CurrentAuthorizationPairCertificate) : Prop :=
  ∃ sourceNote, certificate.sameSourceNote = some sourceNote ∧
    activePublicNullifier certificate.left ≠ activePublicNullifier certificate.right

def currentAuthorizationCertificateFailure
    (certificate : CurrentAuthorizationPairCertificate) : Prop :=
  nullifierPreimageAliasFailure certificate ∨
    authorizationOutputMismatchFailure certificate

private theorem mismatch_yields_framed_collision
    (certificate : CurrentAuthorizationPairCertificate)
    (sourceNote : SameSourceNoteEvidence certificate.left certificate.right)
    (mismatch : activePublicNullifier certificate.left ≠
      activePublicNullifier certificate.right) :
    FramedAuthorizationCollision
      (selectedMessage certificate.left.packed certificate.left.input)
      (selectedMessage certificate.right.packed certificate.right.input) := by
  rcases accepted_same_note_position_preimage_or_authorization_collision
      certificate.left.accepted certificate.right.accepted
      certificate.left.input certificate.right.input
      certificate.left.active certificate.right.active
      sourceNote.sameOwner sourceNote.samePosition sourceNote.sameRho with
    equalPreimages | framed
  · have sameOutputs :
        activePublicNullifier certificate.left =
          activePublicNullifier certificate.right := by
      funext limb
      unfold activePublicNullifier
      rw [accepted_current_active_public_nullifier
          certificate.left.accepted certificate.left.input certificate.left.active limb,
        accepted_current_active_public_nullifier
          certificate.right.accepted certificate.right.input certificate.right.active limb,
        equalPreimages]
    exact False.elim (mismatch sameOutputs)
  · exact framed

/-- Actual accepted current source comparisons map to one of the three exact
authorization games. No primitive hardness is asserted here. -/
theorem authorizationOutputMismatch_has_one_of_three_game_wins
    (certificate : CurrentAuthorizationPairCertificate)
    (sourceNote : SameSourceNoteEvidence certificate.left certificate.right)
    (mismatch : activePublicNullifier certificate.left ≠
      activePublicNullifier certificate.right) :
    (∃ pair : CanonicalSingleKey × CanonicalSingleKey,
      singleKeyCollision pair) ∨
    (∃ pair : CompressionInput × CompressionInput,
      accumulatorCompress14Collision pair) ∨
    (∃ pair : MixedDomainInput × MixedDomainInput,
      mixedDomainClaw pair) := by
  exact framedAuthorizationCollision_explicit_game_wins
    (mismatch_yields_framed_collision certificate sourceNote mismatch)

theorem authorizationOutputMismatch_wins_selected_game
    (certificate : CurrentAuthorizationPairCertificate)
    (sourceNote : SameSourceNoteEvidence certificate.left certificate.right)
    (mismatch : activePublicNullifier certificate.left ≠
      activePublicNullifier certificate.right) :
    (selectedAuthorizationGameOutput certificate).wins := by
  exact framedAuthorizationCollision_wins_selected_game
    (mismatch_yields_framed_collision certificate sourceNote mismatch)

/-- The two certificate failures reduce pointwise to the distinct-domain
primitive games: the 12-word nullifier game, SingleKey, accumulator
Compress14, or the mixed-domain claw. -/
theorem currentAuthorizationCertificateFailure_has_primitive_win
    (certificate : CurrentAuthorizationPairCertificate)
    (failure : currentAuthorizationCertificateFailure certificate) :
    wins (toCollisionGameOutput (sourcePair certificate.spends)) ∨
      (selectedAuthorizationGameOutput certificate).wins := by
  rcases failure with aliasing | mismatch
  · exact Or.inl (acceptedPreimageAlias_wins_primitive_game
      certificate.spends aliasing)
  · obtain ⟨sourceNote, _evidence, publicMismatch⟩ := mismatch
    exact Or.inr (authorizationOutputMismatch_wins_selected_game
      certificate sourceNote publicMismatch)

noncomputable def outcomeEventMass {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (event : Outcome → Prop) : ℝ :=
  ∑ outcome, if event outcome then mass outcome else 0

def currentAuthorizationFailureEvent {Outcome : Type}
    (output : Outcome → Option CurrentAuthorizationPairCertificate)
    (outcome : Outcome) : Prop :=
  ∃ certificate, output outcome = some certificate ∧
    currentAuthorizationCertificateFailure certificate

def nullifierPrimitiveEvent {Outcome : Type}
    (output : Outcome → Option CurrentAuthorizationPairCertificate)
    (outcome : Outcome) : Prop :=
  ∃ certificate, output outcome = some certificate ∧
    wins (toCollisionGameOutput (sourcePair certificate.spends))

def singleKeyPrimitiveEvent {Outcome : Type}
    (output : Outcome → Option CurrentAuthorizationPairCertificate)
    (outcome : Outcome) : Prop :=
  ∃ certificate pair, output outcome = some certificate ∧
    selectedAuthorizationGameOutput certificate = .singleKey pair ∧
    singleKeyCollision pair

def accumulatorPrimitiveEvent {Outcome : Type}
    (output : Outcome → Option CurrentAuthorizationPairCertificate)
    (outcome : Outcome) : Prop :=
  ∃ certificate pair, output outcome = some certificate ∧
    selectedAuthorizationGameOutput certificate = .accumulator pair ∧
    accumulatorCompress14Collision pair

def mixedClawPrimitiveEvent {Outcome : Type}
    (output : Outcome → Option CurrentAuthorizationPairCertificate)
    (outcome : Outcome) : Prop :=
  ∃ certificate pair, output outcome = some certificate ∧
    selectedAuthorizationGameOutput certificate = .mixed pair ∧
    mixedDomainClaw pair

private theorem eventMassTerm_nonnegative {Outcome : Type}
    (mass : Outcome → ℝ) (event : Outcome → Prop)
    (nonnegative : ∀ outcome, 0 ≤ mass outcome) (outcome : Outcome) :
    0 ≤ (if event outcome then mass outcome else 0) := by
  by_cases selected : event outcome <;> simp [selected, nonnegative outcome]

private theorem four_term_cover {x a b c d : ℝ}
    (na : 0 ≤ a) (nb : 0 ≤ b) (nc : 0 ≤ c) (nd : 0 ≤ d)
    (hit : x = a ∨ x = b ∨ x = c ∨ x = d) : x ≤ a + b + c + d := by
  rcases hit with h | h | h | h
  · subst x
    exact (le_add_of_nonneg_right (add_nonneg nb (add_nonneg nc nd))).trans_eq
      (by ac_rfl)
  · subst x; exact (le_add_of_nonneg_right (add_nonneg na (add_nonneg nc nd))).trans_eq
      (by ac_rfl)
  · subst x; exact (le_add_of_nonneg_right (add_nonneg na (add_nonneg nb nd))).trans_eq
      (by ac_rfl)
  · subst x; exact (le_add_of_nonneg_right (add_nonneg na (add_nonneg nb nc))).trans_eq
      (by ac_rfl)

/-- Same-original-outcome weighted reduction. Aborted/absent outcomes remain
in the original measure and contribute zero; no acceptance conditioning,
uniformity, or independence is assumed. -/
theorem currentAuthorizationFailureMass_le_four_game_masses
    {Outcome : Type} [Fintype Outcome]
    (output : Outcome → Option CurrentAuthorizationPairCertificate)
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome) :
    outcomeEventMass mass (currentAuthorizationFailureEvent output) ≤
      outcomeEventMass mass (nullifierPrimitiveEvent output) +
      outcomeEventMass mass (singleKeyPrimitiveEvent output) +
      outcomeEventMass mass (accumulatorPrimitiveEvent output) +
      outcomeEventMass mass (mixedClawPrimitiveEvent output) := by
  classical
  let nEvent := nullifierPrimitiveEvent output
  let sEvent := singleKeyPrimitiveEvent output
  let aEvent := accumulatorPrimitiveEvent output
  let mEvent := mixedClawPrimitiveEvent output
  have pointwise (outcome : Outcome) :
      (if currentAuthorizationFailureEvent output outcome then mass outcome else 0) ≤
        (if nEvent outcome then mass outcome else 0) +
        (if sEvent outcome then mass outcome else 0) +
        (if aEvent outcome then mass outcome else 0) +
        (if mEvent outcome then mass outcome else 0) := by
    by_cases failure : currentAuthorizationFailureEvent output outcome
    · have failureHit : currentAuthorizationFailureEvent output outcome := failure
      obtain ⟨certificate, outputEq, certFailure⟩ := failure
      have covered := currentAuthorizationCertificateFailure_has_primitive_win
        certificate certFailure
      have hit :
          (if currentAuthorizationFailureEvent output outcome then mass outcome else 0) =
            (if nEvent outcome then mass outcome else 0) ∨
          (if currentAuthorizationFailureEvent output outcome then mass outcome else 0) =
            (if sEvent outcome then mass outcome else 0) ∨
          (if currentAuthorizationFailureEvent output outcome then mass outcome else 0) =
            (if aEvent outcome then mass outcome else 0) ∨
          (if currentAuthorizationFailureEvent output outcome then mass outcome else 0) =
            (if mEvent outcome then mass outcome else 0) := by
        rcases covered with nullifier | authorizationWin
        · left
          have nullifierHit : nEvent outcome := by
            exact ⟨certificate, outputEq, nullifier⟩
          simp only [if_pos failureHit, if_pos nullifierHit]
        · cases gameOutput : selectedAuthorizationGameOutput certificate with
          | singleKey pair =>
              right; left
              have pairWin : singleKeyCollision pair := by
                rw [gameOutput, FramedAuthorizationGameOutput.wins] at authorizationWin
                exact authorizationWin
              have frameHit : sEvent outcome := by
                exact ⟨certificate, pair, outputEq, gameOutput, pairWin⟩
              simp only [if_pos failureHit, if_pos frameHit]
          | accumulator pair =>
              right; right; left
              have pairWin : accumulatorCompress14Collision pair := by
                rw [gameOutput, FramedAuthorizationGameOutput.wins] at authorizationWin
                exact authorizationWin
              have frameHit : aEvent outcome := by
                exact ⟨certificate, pair, outputEq, gameOutput, pairWin⟩
              simp only [if_pos failureHit, if_pos frameHit]
          | mixed pair =>
              right; right; right
              have pairWin : mixedDomainClaw pair := by
                rw [gameOutput, FramedAuthorizationGameOutput.wins] at authorizationWin
                exact authorizationWin
              have frameHit : mEvent outcome := by
                exact ⟨certificate, pair, outputEq, gameOutput, pairWin⟩
              simp only [if_pos failureHit, if_pos frameHit]
      exact four_term_cover
        (eventMassTerm_nonnegative mass nEvent nonnegative outcome)
        (eventMassTerm_nonnegative mass sEvent nonnegative outcome)
        (eventMassTerm_nonnegative mass aEvent nonnegative outcome)
        (eventMassTerm_nonnegative mass mEvent nonnegative outcome) hit
    · simp only [if_neg failure]
      have n := eventMassTerm_nonnegative mass nEvent nonnegative outcome
      have s := eventMassTerm_nonnegative mass sEvent nonnegative outcome
      have a := eventMassTerm_nonnegative mass aEvent nonnegative outcome
      have m := eventMassTerm_nonnegative mass mEvent nonnegative outcome
      exact add_nonneg (add_nonneg (add_nonneg n s) a) m
  unfold outcomeEventMass
  calc
    _ ≤ ∑ outcome,
          ((if nEvent outcome then mass outcome else 0) +
            (if sEvent outcome then mass outcome else 0) +
            (if aEvent outcome then mass outcome else 0) +
            (if mEvent outcome then mass outcome else 0)) :=
      Finset.sum_le_sum (fun outcome _ => pointwise outcome)
    _ = _ := by
      simp only [Finset.sum_add_distrib]
      change
        (∑ x, if nEvent x then mass x else 0) +
          (∑ x, if sEvent x then mass x else 0) +
          (∑ x, if aEvent x then mass x else 0) +
          (∑ x, if mEvent x then mass x else 0) =
        (∑ x, if nEvent x then mass x else 0) +
          (∑ x, if sEvent x then mass x else 0) +
          (∑ x, if aEvent x then mass x else 0) +
          (∑ x, if mEvent x then mass x else 0)
      rfl

/-- Conditional endpoint for the exact four source-derived games. The
assumptions are advantage bounds on these same-output, same-weight event
masses; no output-width estimate or claim of unconditional Poseidon security
is inserted. -/
theorem currentAuthorizationFailureMass_le_assumed_advantages
    {Outcome : Type} [Fintype Outcome]
    (output : Outcome → Option CurrentAuthorizationPairCertificate)
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed : ℝ)
    (nullifierBound : outcomeEventMass mass (nullifierPrimitiveEvent output) ≤ epsilonNullifier)
    (singleBound : outcomeEventMass mass (singleKeyPrimitiveEvent output) ≤ epsilonSingle)
    (accumulatorBound : outcomeEventMass mass (accumulatorPrimitiveEvent output) ≤ epsilonAccumulator)
    (mixedBound : outcomeEventMass mass (mixedClawPrimitiveEvent output) ≤ epsilonMixed) :
    outcomeEventMass mass (currentAuthorizationFailureEvent output) ≤
      epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
  calc
    outcomeEventMass mass (currentAuthorizationFailureEvent output) ≤
        outcomeEventMass mass (nullifierPrimitiveEvent output) +
          outcomeEventMass mass (singleKeyPrimitiveEvent output) +
          outcomeEventMass mass (accumulatorPrimitiveEvent output) +
          outcomeEventMass mass (mixedClawPrimitiveEvent output) :=
      currentAuthorizationFailureMass_le_four_game_masses output mass nonnegative
    _ ≤ epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
      calc
        _ ≤ epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed :=
          add_le_add (add_le_add (add_le_add nullifierBound singleBound)
            accumulatorBound) mixedBound

end HegemonCrypto.SmallWood.SmzaRp05CurrentAuthorizationCertificate
