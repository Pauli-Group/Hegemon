import SmzaRp05CurrentAuthorizationCertificate

/-! Turn an actual pair of accepted active spends into the optional-evidence
certificate used by the checked four-game reduction. The source-note option is
constructed from the pair itself; callers do not classify whether it exists. -/

namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedPairAuthorization

open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureNullifier
open HegemonCrypto.SmallWood.SmzaRp05CurrentAuthorizationCertificate
open HegemonCrypto.SmallWood.SmzaRp05PrimitiveCollisionGameLuna
open HegemonCrypto.SmallWood.SmzaRp05FivePrimitiveGameLedger
open scoped Classical

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

noncomputable def certificateOfAcceptedPair (pair : AcceptedSpendPair) :
    CurrentAuthorizationPairCertificate :=
  { left := pair.1
    right := pair.2
    sameSourceNote :=
      if evidence : Nonempty (SameSourceNoteEvidence pair.1 pair.2) then
        some (Classical.choice evidence) else none }

/-- Actual accepted-pair failure: a nullifier-preimage alias, or the precise
same-owner/position/rho source condition with different current public
nullifiers. -/
def acceptedPairAuthorizationFailure (pair : AcceptedSpendPair) : Prop :=
  acceptedPreimageAlias pair ∨
    (Nonempty (SameSourceNoteEvidence pair.1 pair.2) ∧
      activePublicNullifier pair.1 ≠ activePublicNullifier pair.2)

theorem acceptedPairAuthorizationFailure_iff_certificate
    (pair : AcceptedSpendPair) :
    acceptedPairAuthorizationFailure pair ↔
      currentAuthorizationCertificateFailure (certificateOfAcceptedPair pair) := by
  constructor
  · intro failure
    rcases failure with aliasing | ⟨evidence, mismatch⟩
    · exact Or.inl aliasing
    · right
      refine ⟨Classical.choice evidence, ?_, mismatch⟩
      simp [certificateOfAcceptedPair, evidence]
  · intro failure
    rcases failure with aliasing | mismatch
    · exact Or.inl aliasing
    · obtain ⟨evidence, optionEq, publicMismatch⟩ := mismatch
      have sourceNote : Nonempty (SameSourceNoteEvidence pair.1 pair.2) := by
        by_cases existsEvidence : Nonempty (SameSourceNoteEvidence pair.1 pair.2)
        · exact existsEvidence
        · simp [certificateOfAcceptedPair, existsEvidence] at optionEq
      exact Or.inr ⟨sourceNote, publicMismatch⟩

noncomputable def certificateOutput {Outcome : Type}
    (output : Outcome → Option AcceptedSpendPair) :
    Outcome → Option CurrentAuthorizationPairCertificate :=
  fun outcome => (output outcome).map certificateOfAcceptedPair

def acceptedPairAuthorizationFailureEvent {Outcome : Type}
    (output : Outcome → Option AcceptedSpendPair) (outcome : Outcome) : Prop :=
  ∃ pair, output outcome = some pair ∧ acceptedPairAuthorizationFailure pair

theorem acceptedPairFailureEvent_iff_certificateEvent {Outcome : Type}
    (output : Outcome → Option AcceptedSpendPair) (outcome : Outcome) :
    acceptedPairAuthorizationFailureEvent output outcome ↔
      currentAuthorizationFailureEvent (certificateOutput output) outcome := by
  constructor
  · rintro ⟨pair, outputEq, failure⟩
    refine ⟨certificateOfAcceptedPair pair, ?_, ?_⟩
    · simp [certificateOutput, outputEq]
    · exact (acceptedPairAuthorizationFailure_iff_certificate pair).mp failure
  · rintro ⟨certificate, certificateEq, failure⟩
    cases outputEq : output outcome with
    | none => simp [certificateOutput, outputEq] at certificateEq
    | some pair =>
        have certEq : certificateOfAcceptedPair pair = certificate := by
          simpa [certificateOutput, outputEq] using certificateEq
        subst certificate
        exact ⟨pair, outputEq,
          (acceptedPairAuthorizationFailure_iff_certificate pair).mpr failure⟩

def acceptedPairNullifierPrimitiveEvent {Outcome : Type}
    (output : Outcome → Option AcceptedSpendPair) (outcome : Outcome) : Prop :=
  nullifierPrimitiveEvent (certificateOutput output) outcome

def acceptedPairSingleKeyPrimitiveEvent {Outcome : Type}
    (output : Outcome → Option AcceptedSpendPair) (outcome : Outcome) : Prop :=
  singleKeyPrimitiveEvent (certificateOutput output) outcome

def acceptedPairAccumulatorPrimitiveEvent {Outcome : Type}
    (output : Outcome → Option AcceptedSpendPair) (outcome : Outcome) : Prop :=
  accumulatorPrimitiveEvent (certificateOutput output) outcome

def acceptedPairMixedClawPrimitiveEvent {Outcome : Type}
    (output : Outcome → Option AcceptedSpendPair) (outcome : Outcome) : Prop :=
  mixedClawPrimitiveEvent (certificateOutput output) outcome

private theorem outcomeEventMass_congr {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (left right : Outcome → Prop)
    (sameEvent : ∀ outcome, left outcome ↔ right outcome) :
    outcomeEventMass mass left = outcomeEventMass mass right := by
  classical
  unfold outcomeEventMass
  apply Finset.sum_congr rfl
  intro outcome _
  by_cases hleft : left outcome
  · have hright := (sameEvent outcome).mp hleft
    simp [hleft, hright]
  · have hright : ¬ right outcome := fun hright => hleft ((sameEvent outcome).mpr hright)
    simp [hleft, hright]

/-- The concrete accepted-pair event receives the checked same-original-mass
four-game bound. `none` outcomes remain absent on both sides, and all primitive
events use the deterministic selected outputs of the mapped certificates. -/
theorem acceptedPairFailureMass_le_four_game_masses
    {Outcome : Type} [Fintype Outcome]
    (output : Outcome → Option AcceptedSpendPair)
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome) :
    outcomeEventMass mass (acceptedPairAuthorizationFailureEvent output) ≤
      outcomeEventMass mass (acceptedPairNullifierPrimitiveEvent output) +
      outcomeEventMass mass (acceptedPairSingleKeyPrimitiveEvent output) +
      outcomeEventMass mass (acceptedPairAccumulatorPrimitiveEvent output) +
      outcomeEventMass mass (acceptedPairMixedClawPrimitiveEvent output) := by
  rw [outcomeEventMass_congr mass
      (acceptedPairAuthorizationFailureEvent output)
      (currentAuthorizationFailureEvent (certificateOutput output))
      (acceptedPairFailureEvent_iff_certificateEvent output)]
  exact currentAuthorizationFailureMass_le_four_game_masses
    (certificateOutput output) mass nonnegative

end HegemonCrypto.SmallWood.SmzaRp05AcceptedPairAuthorization
