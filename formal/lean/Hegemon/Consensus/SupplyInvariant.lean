import Hegemon.Consensus.Supply

namespace Hegemon
namespace Consensus
namespace SupplyInvariant

structure SupplyDelta where
  minted : Nat
  fees : Int
  burns : Nat
deriving Repr

structure ClaimedSupplyStep where
  minted : Nat
  fees : Int
  burns : Nat
  claimedSupply : Nat
deriving Repr

def ClaimedSupplyStep.delta (step : ClaimedSupplyStep) : SupplyDelta :=
  { minted := step.minted, fees := step.fees, burns := step.burns }

def applySupplyDelta (parent : Nat) (delta : SupplyDelta) : Option Nat :=
  expectedConsensusSupply parent delta.minted delta.fees delta.burns

def validateClaimedSupplyStep
    (parent : Nat)
    (step : ClaimedSupplyStep) : Option Nat :=
  match applySupplyDelta parent step.delta with
  | none => none
  | some next =>
      if next = step.claimedSupply then some next else none

def expectedSupplyAfter
    (parent : Nat)
    (steps : List SupplyDelta) : Option Nat :=
  match steps with
  | [] => some parent
  | step :: rest =>
      match applySupplyDelta parent step with
      | none => none
      | some next => expectedSupplyAfter next rest

def validateClaimedSupplyChain
    (parent : Nat)
    (steps : List ClaimedSupplyStep) : Option Nat :=
  match steps with
  | [] => some parent
  | step :: rest =>
      match validateClaimedSupplyStep parent step with
      | none => none
      | some next => validateClaimedSupplyChain next rest

theorem valid_step_claims_expected_supply
    {parent next : Nat}
    {step : ClaimedSupplyStep}
    (accepted : validateClaimedSupplyStep parent step = some next) :
    applySupplyDelta parent step.delta = some step.claimedSupply
      ∧ next = step.claimedSupply := by
  unfold validateClaimedSupplyStep at accepted
  cases deltaEq : applySupplyDelta parent step.delta with
  | none =>
      simp [deltaEq] at accepted
  | some computed =>
      by_cases claimEq : computed = step.claimedSupply
      · simp [deltaEq, claimEq] at accepted
        exact ⟨by simp [claimEq], accepted.symm⟩
      · simp [deltaEq, claimEq] at accepted

theorem claimed_supply_mismatch_rejects
    {parent expected claimed : Nat}
    {step : ClaimedSupplyStep}
    (deltaEq : applySupplyDelta parent step.delta = some expected)
    (claimEq : step.claimedSupply = claimed)
    (mismatch : expected ≠ claimed) :
    validateClaimedSupplyStep parent step = none := by
  unfold validateClaimedSupplyStep
  rw [deltaEq, claimEq]
  simp [mismatch]

theorem supply_delta_failure_rejects_step
    {parent : Nat}
    {step : ClaimedSupplyStep}
    (deltaEq : applySupplyDelta parent step.delta = none) :
    validateClaimedSupplyStep parent step = none := by
  unfold validateClaimedSupplyStep
  rw [deltaEq]

theorem validated_chain_matches_expected_deltas
    {genesis final : Nat}
    {steps : List ClaimedSupplyStep}
    (accepted : validateClaimedSupplyChain genesis steps = some final) :
    expectedSupplyAfter genesis (steps.map ClaimedSupplyStep.delta) = some final := by
  induction steps generalizing genesis with
  | nil =>
      simp [validateClaimedSupplyChain, expectedSupplyAfter] at accepted ⊢
      exact accepted
  | cons step rest ih =>
      unfold validateClaimedSupplyChain at accepted
      unfold expectedSupplyAfter
      cases stepEq : validateClaimedSupplyStep genesis step with
      | none =>
          simp [stepEq] at accepted
      | some next =>
          have stepFacts := valid_step_claims_expected_supply stepEq
          have deltaEq : applySupplyDelta genesis step.delta = some next := by
            rw [stepFacts.left, stepFacts.right]
          simp [deltaEq]
          simp [stepEq] at accepted
          exact ih accepted

def validTwoStepChain : List ClaimedSupplyStep :=
  [
    { minted := 25, fees := 5, burns := 0, claimedSupply := 130 },
    { minted := 0, fees := 0, burns := 40, claimedSupply := 90 }
  ]

theorem valid_two_step_chain_accepts :
    validateClaimedSupplyChain 100 validTwoStepChain = some 90 := by
  rfl

theorem valid_two_step_chain_matches_expected :
    expectedSupplyAfter 100 (validTwoStepChain.map ClaimedSupplyStep.delta) = some 90 := by
  exact validated_chain_matches_expected_deltas valid_two_step_chain_accepts

def counterfeitSecondStep : List ClaimedSupplyStep :=
  [
    { minted := 25, fees := 5, burns := 0, claimedSupply := 130 },
    { minted := 0, fees := 0, burns := 40, claimedSupply := 91 }
  ]

theorem counterfeit_second_step_rejects :
    validateClaimedSupplyChain 100 counterfeitSecondStep = none := by
  rfl

def overflowStep : ClaimedSupplyStep :=
  {
    minted := 10,
    fees := 0,
    burns := 0,
    claimedSupply := maxSupplyDigest
  }

theorem overflow_step_rejects :
    validateClaimedSupplyStep (maxSupplyDigest - 5) overflowStep = none := by
  rfl

end SupplyInvariant
end Consensus
end Hegemon
