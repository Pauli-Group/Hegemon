import Hegemon.Consensus.Supply
import Hegemon.Transaction.ProofSystemBoundary

namespace Hegemon
namespace Consensus
namespace SupplyInvariant

open Hegemon.Transaction
open Hegemon.Transaction.AssetIsolation
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofSystemBoundary

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

def supplyDeltaWithFees (step : ClaimedSupplyStep) (fees : Int) :
    SupplyDelta :=
  { minted := step.minted, fees := fees, burns := step.burns }

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

theorem valid_step_claims_expected_supply_with_bound_fees
    {parent next : Nat}
    {boundFees : Int}
    {step : ClaimedSupplyStep}
    (feeBinding : step.fees = boundFees)
    (accepted : validateClaimedSupplyStep parent step = some next) :
    applySupplyDelta parent (supplyDeltaWithFees step boundFees) =
        some step.claimedSupply
      ∧ next = step.claimedSupply := by
  rw [← feeBinding]
  simpa [supplyDeltaWithFees, ClaimedSupplyStep.delta] using
    valid_step_claims_expected_supply accepted

theorem accepted_transaction_chain_native_delta_feeds_valid_claimed_supply_step
    {parent next : Nat}
    {step : ClaimedSupplyStep}
    {transitions : List AcceptedAssetTransition}
    (feeBinding :
      step.fees = acceptedChainAssetDelta nativeAsset transitions)
    (accepted : validateClaimedSupplyStep parent step = some next) :
    acceptedChainAssetDelta nativeAsset transitions =
        acceptedChainAuthorizedAssetDelta nativeAsset transitions
      ∧ applySupplyDelta parent
          (supplyDeltaWithFees
            step
            (acceptedChainAuthorizedAssetDelta nativeAsset transitions)) =
          some step.claimedSupply
      ∧ next = step.claimedSupply := by
  have authorized :
      acceptedChainAssetDelta nativeAsset transitions =
        acceptedChainAuthorizedAssetDelta nativeAsset transitions :=
    accepted_chain_asset_delta_authorized
  have feeBindingAuthorized :
      step.fees =
        acceptedChainAuthorizedAssetDelta nativeAsset transitions := by
    rw [feeBinding, authorized]
  have supplyFacts :=
    valid_step_claims_expected_supply_with_bound_fees
      feeBindingAuthorized
      accepted
  exact ⟨authorized, supplyFacts.left, supplyFacts.right⟩

structure AcceptedChainSupplyConservationCertificate
    (parent next : Nat)
    (step : ClaimedSupplyStep)
    (transitions : List AcceptedAssetTransition) : Prop where
  nativeDeltaAuthorized :
    acceptedChainAssetDelta nativeAsset transitions =
      acceptedChainAuthorizedAssetDelta nativeAsset transitions
  feeBoundToNativeDelta :
    step.fees = acceptedChainAssetDelta nativeAsset transitions
  claimedSupplyDelta :
    applySupplyDelta parent
        (supplyDeltaWithFees
          step
          (acceptedChainAuthorizedAssetDelta nativeAsset transitions)) =
      some step.claimedSupply
  acceptedNext : next = step.claimedSupply
  perAssetAuthorizedDelta :
    ∀ {assetId : Nat},
      acceptedChainAssetDelta assetId transitions =
        acceptedChainAuthorizedAssetDelta assetId transitions
  nonNativeNoExceptionDeltaZero :
    ∀ {assetId : Nat},
      assetId ≠ nativeAsset ->
      (∀ transition,
        transition ∈ transitions ->
          ¬ transitionHasStablecoinException assetId transition) ->
      acceptedChainAssetDelta assetId transitions = 0
  nonNativeNonzeroRequiresStablecoinException :
    ∀ {assetId : Nat},
      assetId ≠ nativeAsset ->
      acceptedChainAssetDelta assetId transitions ≠ 0 ->
      ∃ transition,
        transition ∈ transitions
          ∧ transitionHasStablecoinException assetId transition

theorem accepted_transaction_chain_yields_supply_conservation_certificate
    {parent next : Nat}
    {step : ClaimedSupplyStep}
    {transitions : List AcceptedAssetTransition}
    (feeBinding :
      step.fees = acceptedChainAssetDelta nativeAsset transitions)
    (accepted : validateClaimedSupplyStep parent step = some next) :
    AcceptedChainSupplyConservationCertificate
      parent
      next
      step
      transitions := by
  have supplyFacts :=
    accepted_transaction_chain_native_delta_feeds_valid_claimed_supply_step
      feeBinding
      accepted
  exact
    { nativeDeltaAuthorized := supplyFacts.left
      feeBoundToNativeDelta := feeBinding
      claimedSupplyDelta := supplyFacts.right.left
      acceptedNext := supplyFacts.right.right
      perAssetAuthorizedDelta := by
        intro assetId
        exact accepted_chain_asset_delta_authorized
      nonNativeNoExceptionDeltaZero := by
        intro assetId nonNative noException
        exact accepted_chain_non_native_no_exception_delta_zero
          nonNative
          noException
      nonNativeNonzeroRequiresStablecoinException := by
        intro assetId nonNative nonzero
        exact accepted_chain_non_native_nonzero_requires_exception
          nonNative
          nonzero }

theorem canonical_no_theft_boundary_native_delta_feeds_valid_claimed_supply_step
    {parent next : Nat}
    {step : ClaimedSupplyStep}
    {wrapper : ProofWrapperAdmission.ProofWrapperInput}
    {shape : PublicInputs.PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List SpendAuthorization.InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (boundary :
      CanonicalProofSystemNoTheftBoundaryFacts
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (feeBinding :
      step.fees = publicAuthorizedAssetDeltaValue publicFields nativeAsset)
    (accepted : validateClaimedSupplyStep parent step = some next) :
    slotDelta nativeAsset slots =
        publicAuthorizedAssetDeltaValue publicFields nativeAsset
      ∧ authorizedAssetDeltaValue balanceWitness nativeAsset =
        publicAuthorizedAssetDeltaValue publicFields nativeAsset
      ∧ applySupplyDelta parent
          (supplyDeltaWithFees step (slotDelta nativeAsset slots)) =
        some step.claimedSupply
      ∧ next = step.claimedSupply := by
  have publicDelta :
      slotDelta nativeAsset slots =
        publicAuthorizedAssetDeltaValue publicFields nativeAsset :=
    boundary.publicAuthorizedDelta
  have witnessDelta :
      slotDelta nativeAsset slots =
        authorizedAssetDeltaValue balanceWitness nativeAsset :=
    boundary.witnessAuthorizedDelta
  have witnessPublic :
      authorizedAssetDeltaValue balanceWitness nativeAsset =
        publicAuthorizedAssetDeltaValue publicFields nativeAsset := by
    calc
      authorizedAssetDeltaValue balanceWitness nativeAsset =
          slotDelta nativeAsset slots := witnessDelta.symm
      _ = publicAuthorizedAssetDeltaValue publicFields nativeAsset :=
          publicDelta
  have feeBindingSlot :
      step.fees = slotDelta nativeAsset slots := by
    rw [feeBinding, ← publicDelta]
  have supplyFacts :=
    valid_step_claims_expected_supply_with_bound_fees
      feeBindingSlot
      accepted
  exact
    ⟨publicDelta,
      witnessPublic,
      supplyFacts.left,
      supplyFacts.right⟩

structure CanonicalProductionSupplyConservationCertificate
    (parent next : Nat)
    (step : ClaimedSupplyStep)
    (wrapper : ProofWrapperAdmission.ProofWrapperInput)
    (shape : PublicInputs.PublicInputShape)
    (publicFields : PublicInputBinding.PublicFields)
    (serializedFields : PublicInputBinding.SerializedFields)
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields : ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses : List SpendAuthorization.InputSpendWitness)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop where
  proofBoundary :
    CanonicalProofSystemNoTheftBoundaryFacts
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot
      spendWitnesses
      balanceWitness
      slots
  feeBoundToPublicNativeDelta :
    step.fees = publicAuthorizedAssetDeltaValue publicFields nativeAsset
  nativePublicDelta :
    slotDelta nativeAsset slots =
      publicAuthorizedAssetDeltaValue publicFields nativeAsset
  nativeWitnessDelta :
    authorizedAssetDeltaValue balanceWitness nativeAsset =
      publicAuthorizedAssetDeltaValue publicFields nativeAsset
  claimedSupplyDelta :
    applySupplyDelta parent
        (supplyDeltaWithFees step (slotDelta nativeAsset slots)) =
      some step.claimedSupply
  acceptedNext : next = step.claimedSupply
  perAssetWitnessConservation :
    ∀ {assetId : Nat},
      slotDelta assetId slots =
        authorizedAssetDeltaValue balanceWitness assetId
  perAssetPublicConservation :
    ∀ {assetId : Nat},
      slotDelta assetId slots =
        publicAuthorizedAssetDeltaValue publicFields assetId
  nonNativeStablecoinExceptionSurface :
    ∀ {assetId : Nat},
      assetId ≠ nativeAsset ->
      slotDelta assetId slots ≠ 0 ->
      StablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        (slotDelta assetId slots)
  authorizedNonNativeStablecoinMintException :
    ∀ {assetId : Nat}
      {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes},
      assetId ≠ nativeAsset ->
      slotDelta assetId slots ≠ 0 ->
      livePolicyAuthorizes
        (stablecoinMintExceptionPayload
          publicFields
          assetId
          (slotDelta assetId slots)) ->
      AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        (slotDelta assetId slots)
        livePolicyAuthorizes

theorem canonical_no_theft_boundary_yields_production_supply_conservation_certificate
    {parent next : Nat}
    {step : ClaimedSupplyStep}
    {wrapper : ProofWrapperAdmission.ProofWrapperInput}
    {shape : PublicInputs.PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List SpendAuthorization.InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (boundary :
      CanonicalProofSystemNoTheftBoundaryFacts
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (feeBinding :
      step.fees = publicAuthorizedAssetDeltaValue publicFields nativeAsset)
    (accepted : validateClaimedSupplyStep parent step = some next) :
    CanonicalProductionSupplyConservationCertificate
      parent
      next
      step
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot
      spendWitnesses
      balanceWitness
      slots := by
  have supplyFacts :=
    canonical_no_theft_boundary_native_delta_feeds_valid_claimed_supply_step
      boundary
      feeBinding
      accepted
  exact
    { proofBoundary := boundary
      feeBoundToPublicNativeDelta := feeBinding
      nativePublicDelta := supplyFacts.left
      nativeWitnessDelta := supplyFacts.right.left
      claimedSupplyDelta := supplyFacts.right.right.left
      acceptedNext := supplyFacts.right.right.right
      perAssetWitnessConservation := by
        intro assetId
        exact boundary.witnessAuthorizedDelta (assetId := assetId)
      perAssetPublicConservation := by
        intro assetId
        exact boundary.publicAuthorizedDelta (assetId := assetId)
      nonNativeStablecoinExceptionSurface := by
        intro assetId nonNative nonzero
        exact boundary.nonNativeNonzeroExceptionSurface
          (assetId := assetId)
          nonNative
          nonzero
      authorizedNonNativeStablecoinMintException := by
        intro assetId livePolicyAuthorizes nonNative nonzero authorized
        exact stablecoin_mint_exception_authorized_payload_bound_to_statement
          (boundary.nonNativeNonzeroExceptionSurface
            (assetId := assetId)
            nonNative
            nonzero)
          authorized }

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
