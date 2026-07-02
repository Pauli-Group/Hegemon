import Hegemon.Native.StablecoinPolicyAuthorization
import Hegemon.Transaction.CanonicalVerifierBoundary

namespace Hegemon
namespace Native
namespace StablecoinPolicyLiveAuthorization

open Hegemon.Native.StablecoinPolicyAuthorization
open Hegemon.Transaction.CanonicalVerifierBoundary

def nativeStablecoinLivePolicyAuthorizes
    (input : StablecoinPolicyAuthorizationInput)
    (productionPayload : StablecoinMintExceptionPayload) :
    LiveStablecoinPolicyAuthorizes :=
  fun candidate =>
    candidate = productionPayload
      ∧ input.stablecoinPresent = true
      ∧ input.policyKnown = true
      ∧ input.policyActive = true
      ∧ input.policyLifecycleOpen = true
      ∧ input.assetMatches = true
      ∧ input.policyHashMatches = true
      ∧ input.policyVersionMatches = true
      ∧ input.oracleCommitmentMatches = true
      ∧ input.attestationCommitmentMatches = true
      ∧ input.attestationNotDisputed = true
      ∧ input.oracleFresh = true
      ∧ input.issuanceNonzero = true
      ∧ input.issuanceWithinLimit = true

structure NativeStablecoinLiveAuthorizationFacts
    (input : StablecoinPolicyAuthorizationInput)
    (productionPayload : StablecoinMintExceptionPayload) : Prop where
  authorizesPayload :
    nativeStablecoinLivePolicyAuthorizes
      input
      productionPayload
      productionPayload
  authorizesOnlyExactPayload :
    ∀ candidate,
      nativeStablecoinLivePolicyAuthorizes
        input
        productionPayload
        candidate ->
        candidate = productionPayload
  policyKnown : input.policyKnown = true
  policyActive : input.policyActive = true
  policyLifecycleOpen : input.policyLifecycleOpen = true
  assetMatches : input.assetMatches = true
  policyHashMatches : input.policyHashMatches = true
  policyVersionMatches : input.policyVersionMatches = true
  oracleCommitmentMatches : input.oracleCommitmentMatches = true
  attestationCommitmentMatches :
    input.attestationCommitmentMatches = true
  attestationNotDisputed : input.attestationNotDisputed = true
  oracleFresh : input.oracleFresh = true
  issuanceNonzero : input.issuanceNonzero = true
  issuanceWithinLimit : input.issuanceWithinLimit = true

theorem native_policy_authorization_accepts_authorizes_exact_payload
    {input : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    (present : input.stablecoinPresent = true)
    (accepted : stablecoinPolicyAuthorizationAccepts input = true) :
    nativeStablecoinLivePolicyAuthorizes
      input
      productionPayload
      productionPayload := by
  rcases accepted_present_implies_live_policy_facts present accepted with
    ⟨policyKnown, policyActive, policyLifecycleOpen, assetMatches,
      policyHashMatches, policyVersionMatches, oracleCommitmentMatches,
      attestationCommitmentMatches, attestationNotDisputed, oracleFresh,
      issuanceNonzero, issuanceWithinLimit⟩
  exact
    ⟨rfl, present, policyKnown, policyActive, policyLifecycleOpen,
      assetMatches, policyHashMatches, policyVersionMatches,
      oracleCommitmentMatches, attestationCommitmentMatches,
      attestationNotDisputed, oracleFresh, issuanceNonzero,
      issuanceWithinLimit⟩

theorem native_policy_authorization_accepts_authorizes_matching_payload
    {input : StablecoinPolicyAuthorizationInput}
    {productionPayload candidate : StablecoinMintExceptionPayload}
    (present : input.stablecoinPresent = true)
    (accepted : stablecoinPolicyAuthorizationAccepts input = true)
    (exactPayload : productionPayload = candidate) :
    nativeStablecoinLivePolicyAuthorizes
      input
      productionPayload
      candidate := by
  rcases accepted_present_implies_live_policy_facts present accepted with
    ⟨policyKnown, policyActive, policyLifecycleOpen, assetMatches,
      policyHashMatches, policyVersionMatches, oracleCommitmentMatches,
      attestationCommitmentMatches, attestationNotDisputed, oracleFresh,
      issuanceNonzero, issuanceWithinLimit⟩
  exact
    ⟨exactPayload.symm, present, policyKnown, policyActive,
      policyLifecycleOpen, assetMatches, policyHashMatches,
      policyVersionMatches, oracleCommitmentMatches,
      attestationCommitmentMatches, attestationNotDisputed, oracleFresh,
      issuanceNonzero, issuanceWithinLimit⟩

theorem native_policy_authorization_accepts_authorizes_only_exact_payload
    {input : StablecoinPolicyAuthorizationInput}
    {payload candidate : StablecoinMintExceptionPayload}
    (authorized :
      nativeStablecoinLivePolicyAuthorizes input payload candidate) :
    candidate = payload :=
  authorized.1

theorem native_policy_authorization_accepts_live_authorization_facts
    {input : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    (present : input.stablecoinPresent = true)
    (accepted : stablecoinPolicyAuthorizationAccepts input = true) :
    NativeStablecoinLiveAuthorizationFacts input productionPayload := by
  rcases accepted_present_implies_live_policy_facts present accepted with
    ⟨policyKnown, policyActive, policyLifecycleOpen, assetMatches,
      policyHashMatches, policyVersionMatches, oracleCommitmentMatches,
      attestationCommitmentMatches, attestationNotDisputed, oracleFresh,
      issuanceNonzero, issuanceWithinLimit⟩
  exact
    { authorizesPayload :=
        native_policy_authorization_accepts_authorizes_exact_payload
          present
          accepted
      authorizesOnlyExactPayload := by
        intro candidate authorized
        exact
          native_policy_authorization_accepts_authorizes_only_exact_payload
            authorized
      policyKnown := policyKnown
      policyActive := policyActive
      policyLifecycleOpen := policyLifecycleOpen
      assetMatches := assetMatches
      policyHashMatches := policyHashMatches
      policyVersionMatches := policyVersionMatches
      oracleCommitmentMatches := oracleCommitmentMatches
      attestationCommitmentMatches := attestationCommitmentMatches
      attestationNotDisputed := attestationNotDisputed
      oracleFresh := oracleFresh
      issuanceNonzero := issuanceNonzero
      issuanceWithinLimit := issuanceWithinLimit }

theorem native_policy_not_live_denies_exact_payload_authorization
    {input : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    (_present : input.stablecoinPresent = true)
    (_known : input.policyKnown = true)
    (_active : input.policyActive = true)
    (notLive : input.policyLifecycleOpen = false) :
    ¬ nativeStablecoinLivePolicyAuthorizes
        input
        productionPayload
        productionPayload := by
  intro authorized
  rcases authorized with
    ⟨_, _, _, _, lifecycleOpen, _, _, _, _, _, _, _, _, _⟩
  rw [notLive] at lifecycleOpen
  contradiction

theorem stablecoin_mint_exception_surface_authorized_by_native_policy
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {input : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    (exceptionSurface :
      StablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        delta)
    (present : input.stablecoinPresent = true)
    (accepted : stablecoinPolicyAuthorizationAccepts input = true)
    (exactPayload :
      productionPayload =
        stablecoinMintExceptionPayload publicFields assetId delta) :
    AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      delta
      (nativeStablecoinLivePolicyAuthorizes
        input
        productionPayload) := by
  exact
    stablecoin_mint_exception_authorized_payload_bound_to_statement
      exceptionSurface
      (native_policy_authorization_accepts_authorizes_matching_payload
        present
        accepted
        exactPayload)

theorem publication_stablecoin_exception_surface_authorized_by_native_policy
    {publicationFacts : Prop}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {input : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    (publicationAndSurface :
      publicationFacts
        ∧ StablecoinMintExceptionSurface
          publicFields
          bound
          statementFields
          bindingFields
          assetId
          delta)
    (present : input.stablecoinPresent = true)
    (accepted : stablecoinPolicyAuthorizationAccepts input = true)
    (exactPayload :
      productionPayload =
        stablecoinMintExceptionPayload publicFields assetId delta) :
    publicationFacts
      ∧ AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        delta
        (nativeStablecoinLivePolicyAuthorizes
          input
          productionPayload) := by
  rcases publicationAndSurface with ⟨publicationFacts, exceptionSurface⟩
  exact
    ⟨publicationFacts,
      stablecoin_mint_exception_surface_authorized_by_native_policy
        exceptionSurface
        present
        accepted
        exactPayload⟩

end StablecoinPolicyLiveAuthorization
end Native
end Hegemon
