import HegemonCrypto.SmallWoodV8Smz9RobustQueryMismatch

/-!
# Joint fresh-subset sampling for matrix-dependent SMZ9 agreement

The prefix may be an entire matrix and an adversarial response fixed before the final query.
Its agreement set can depend arbitrarily on that prefix. We count the actual independent product
of a uniform finite prefix and the existing uniform twenty-subset challenge. The small-agreement
event is bounded by `choose(bound,20) / choose(2^23,20)`, without assuming prefix/response
independence. This is ideal finite sampling only; no Fiat--Shamir/QROM law is inferred.
-/

namespace HegemonCrypto.SmallWood.V8Smz9JointQuerySampling

open V8Smz9RobustQueryMismatch
open scoped BigOperators

noncomputable section

set_option maxHeartbeats 100000
set_option maxRecDepth 5000

section Swap

variable {Prefix Outcome : Type*} [Fintype Prefix] [Fintype Outcome]
  [DecidableEq Prefix] [DecidableEq Outcome]

def transposeEvents (events : Prefix → Finset Outcome) (outcome : Outcome) : Finset Prefix :=
  Finset.univ.filter fun context => outcome ∈ events context

/-- Swapping the independent coordinates preserves each accepted pair exactly. -/
def acceptedSwapEquiv (events : Prefix → Finset Outcome) :
    FiniteEvents.Accepted events ≃ FiniteEvents.Accepted (transposeEvents events) where
  toFun accepted := ⟨accepted.2.val, ⟨accepted.1, by
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, accepted.2.property⟩⟩⟩
  invFun accepted := ⟨accepted.2.val, ⟨accepted.1,
    (Finset.mem_filter.mp accepted.2.property).2⟩⟩
  left_inv _ := rfl
  right_inv _ := rfl

omit [DecidableEq Prefix] in
theorem joint_probability_swap (events : Prefix → Finset Outcome) :
    FiniteEvents.jointProbability events =
      FiniteEvents.jointProbability (transposeEvents events) := by
  unfold FiniteEvents.jointProbability
  rw [Fintype.card_congr (acceptedSwapEquiv events), mul_comm]

end Swap

/-- Every accepting actual challenge is a twenty-subset of the fixed agreement set. -/
def withinEvent (agreement : Finset Position) : Finset Challenge :=
  Finset.univ.filter fun challenge => challenge.val ⊆ agreement

abbrev WithinChallenge (agreement : Finset Position) :=
  { challenge : Challenge // challenge.val ⊆ agreement }

noncomputable instance (agreement : Finset Position) : Fintype (WithinChallenge agreement) :=
  Fintype.ofFinite _

def withinChallengeEquiv (agreement : Finset Position) :
    WithinChallenge agreement ≃ { sample // sample ∈ agreement.powersetCard 20 } where
  toFun challenge := ⟨challenge.val.val,
    Finset.mem_powersetCard.mpr ⟨challenge.property, challenge.val.property⟩⟩
  invFun sample := ⟨⟨sample.val, (Finset.mem_powersetCard.mp sample.property).2⟩,
    (Finset.mem_powersetCard.mp sample.property).1⟩
  left_inv _ := by apply Subtype.ext; apply Subtype.ext; rfl
  right_inv _ := by apply Subtype.ext; rfl

theorem within_event_card (agreement : Finset Position) :
    (withinEvent agreement).card = Nat.choose agreement.card 20 := by
  have subtypeCard : Fintype.card (WithinChallenge agreement) =
      Nat.choose agreement.card 20 := by
    rw [Fintype.card_congr (withinChallengeEquiv agreement)]
    simp only [Fintype.card_coe, Finset.card_powersetCard]
  calc
    (withinEvent agreement).card = Fintype.card (WithinChallenge agreement) :=
      (Fintype.card_subtype _).symm
    _ = Nat.choose agreement.card 20 := subtypeCard

def subsetBound (bound : Nat) : Rat :=
  (Nat.choose bound 20 : Rat) / Nat.choose V8Smz9LogicalOracle.decsDomainSize 20

/-- Exact conditional acceptance probability, counted on the actual challenge type. -/
theorem within_probability_exact (agreement : Finset Position) :
    FiniteEvents.probability (withinEvent agreement) =
      (Nat.choose agreement.card 20 : Rat) /
        Nat.choose V8Smz9LogicalOracle.decsDomainSize 20 := by
  unfold FiniteEvents.probability
  rw [within_event_card, V8Smz9LogicalOracle.decs_opening_challenge_card]
  rfl

theorem within_probability_le (agreement : Finset Position) (bound : Nat)
    (bounded : agreement.card ≤ bound) :
    FiniteEvents.probability (withinEvent agreement) ≤ subsetBound bound := by
  rw [within_probability_exact]
  apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
  exact_mod_cast Nat.choose_le_choose 20 bounded

/-- Only outcomes whose already-fixed agreement set is small are counted. -/
def smallAgreementEvent (agreement : Finset Position) (bound : Nat) : Finset Challenge :=
  if agreement.card ≤ bound then withinEvent agreement else ∅

theorem mem_small_agreement_event (agreement : Finset Position) (bound : Nat)
    (challenge : Challenge) :
    challenge ∈ smallAgreementEvent agreement bound ↔
      agreement.card ≤ bound ∧ challenge.val ⊆ agreement := by
  by_cases bounded : agreement.card ≤ bound
  · rw [smallAgreementEvent, if_pos bounded]
    simp only [withinEvent, Finset.mem_filter, Finset.mem_univ, true_and, bounded]
  · rw [smallAgreementEvent, if_neg bounded]
    simp only [Finset.notMem_empty, bounded, false_and]

theorem small_agreement_probability_le (agreement : Finset Position) (bound : Nat) :
    FiniteEvents.probability (smallAgreementEvent agreement bound) ≤ subsetBound bound := by
  by_cases bounded : agreement.card ≤ bound
  · rw [smallAgreementEvent, if_pos bounded]
    exact within_probability_le agreement bound bounded
  · rw [smallAgreementEvent, if_neg bounded, FiniteEvents.probability_empty]
    unfold subsetBound
    positivity

section PrefixDependent

variable {Prefix : Type*} [Fintype Prefix] [Nonempty Prefix]

/-- Actual accepted-pair fraction: the agreement may depend arbitrarily on the complete prefix. -/
def jointSmallAgreementProbability (agreement : Prefix → Finset Position) (bound : Nat) : Rat :=
  FiniteEvents.jointProbability fun context => smallAgreementEvent (agreement context) bound

theorem joint_small_agreement_probability_le (agreement : Prefix → Finset Position) (bound : Nat) :
    jointSmallAgreementProbability agreement bound ≤
      (Nat.choose bound 20 : Rat) / Nat.choose V8Smz9LogicalOracle.decsDomainSize 20 := by
  exact FiniteEvents.joint_probability_le _ _
    (fun context => small_agreement_probability_le (agreement context) bound)

/-- If every prefix has small agreement, the untruncated all-queries acceptance obeys the bound. -/
theorem joint_within_probability_le (agreement : Prefix → Finset Position) (bound : Nat)
    (bounded : ∀ context, (agreement context).card ≤ bound) :
    FiniteEvents.jointProbability (fun context => withinEvent (agreement context)) ≤
      (Nat.choose bound 20 : Rat) / Nat.choose V8Smz9LogicalOracle.decsDomainSize 20 := by
  exact FiniteEvents.joint_probability_le _ _
    (fun context => within_probability_le (agreement context) bound (bounded context))

variable [DecidableEq Prefix]

/-- Query-outer orientation, convenient for composition with fixed-candidate mismatch events. -/
def smallAgreementPrefixEvent (agreement : Prefix → Finset Position) (bound : Nat)
    (challenge : Challenge) : Finset Prefix :=
  transposeEvents (fun context => smallAgreementEvent (agreement context) bound) challenge

omit [Nonempty Prefix] [DecidableEq Prefix] in
theorem mem_small_agreement_prefix_event (agreement : Prefix → Finset Position) (bound : Nat)
    (challenge : Challenge) (context : Prefix) :
    context ∈ smallAgreementPrefixEvent agreement bound challenge ↔
      (agreement context).card ≤ bound ∧ challenge.val ⊆ agreement context := by
  simp only [smallAgreementPrefixEvent, transposeEvents, Finset.mem_filter, Finset.mem_univ,
    true_and, mem_small_agreement_event]

omit [DecidableEq Prefix] in
theorem query_outer_small_agreement_probability_le (agreement : Prefix → Finset Position)
    (bound : Nat) :
    FiniteEvents.jointProbability (smallAgreementPrefixEvent agreement bound) ≤
      (Nat.choose bound 20 : Rat) / Nat.choose V8Smz9LogicalOracle.decsDomainSize 20 := by
  rw [show smallAgreementPrefixEvent agreement bound =
    transposeEvents (fun context => smallAgreementEvent (agreement context) bound) by rfl]
  rw [← joint_probability_swap]
  exact joint_small_agreement_probability_le agreement bound

end PrefixDependent

end

end HegemonCrypto.SmallWood.V8Smz9JointQuerySampling
