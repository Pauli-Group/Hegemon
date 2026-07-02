namespace Hegemon
namespace Native
namespace BridgeVerifierRegistrationPolicy

inductive BridgeVerifierRegistrationPolicyReject where
  | notBridgeVerifierRegistration
  | stateDeltasPresent
  | registrationDecodeFailed
deriving DecidableEq, Repr

structure BridgeVerifierRegistrationPolicyInput where
  bridgeVerifierRegistration : Bool
  stateDeltasAbsent : Bool
  registrationDecoded : Bool
  descriptorMatchesRelease : Bool
  activationHeightReached : Bool
  pqCleanVerifierBound : Bool
  externalVerifierSoundnessAccepted : Bool
  positiveMintingEnabled : Bool
deriving DecidableEq, Repr

structure BridgeVerifierRegistrationPolicyEffect where
  registrationObserved : Bool
  productionMintVerifierEnabled : Bool
deriving DecidableEq, Repr

def productionMintVerifierEnabled
    (input : BridgeVerifierRegistrationPolicyInput) : Bool :=
  input.descriptorMatchesRelease
    && input.activationHeightReached
    && input.pqCleanVerifierBound
    && input.externalVerifierSoundnessAccepted
    && input.positiveMintingEnabled

def evaluateBridgeVerifierRegistrationPolicy
    (input : BridgeVerifierRegistrationPolicyInput) :
      Except
        BridgeVerifierRegistrationPolicyReject
        BridgeVerifierRegistrationPolicyEffect :=
  if input.bridgeVerifierRegistration = false then
    Except.error BridgeVerifierRegistrationPolicyReject.notBridgeVerifierRegistration
  else if input.stateDeltasAbsent = false then
    Except.error BridgeVerifierRegistrationPolicyReject.stateDeltasPresent
  else if input.registrationDecoded = false then
    Except.error BridgeVerifierRegistrationPolicyReject.registrationDecodeFailed
  else
    Except.ok {
      registrationObserved := true,
      productionMintVerifierEnabled :=
        productionMintVerifierEnabled input
    }

def bridgeVerifierRegistrationPolicyAccepts
    (input : BridgeVerifierRegistrationPolicyInput) : Bool :=
  match evaluateBridgeVerifierRegistrationPolicy input with
  | Except.ok _ => true
  | Except.error _ => false

def bridgeVerifierRegistrationPolicyRejection
    (input : BridgeVerifierRegistrationPolicyInput) :
      Option BridgeVerifierRegistrationPolicyReject :=
  match evaluateBridgeVerifierRegistrationPolicy input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def bridgeVerifierRegistrationPolicyEffect
    (input : BridgeVerifierRegistrationPolicyInput) :
      Option BridgeVerifierRegistrationPolicyEffect :=
  match evaluateBridgeVerifierRegistrationPolicy input with
  | Except.ok effect => some effect
  | Except.error _ => none

def bridgeVerifierRegistrationPolicyPreconditions
    (input : BridgeVerifierRegistrationPolicyInput) : Bool :=
  input.bridgeVerifierRegistration
    && input.stateDeltasAbsent
    && input.registrationDecoded

def BridgeVerifierRegistrationPolicyFacts
    (input : BridgeVerifierRegistrationPolicyInput)
    (effect : BridgeVerifierRegistrationPolicyEffect) : Prop :=
  input.bridgeVerifierRegistration = true
    ∧ input.stateDeltasAbsent = true
    ∧ input.registrationDecoded = true
    ∧ effect.registrationObserved = true
    ∧ effect.productionMintVerifierEnabled =
        productionMintVerifierEnabled input

theorem accepts_iff_registration_policy_preconditions
    (input : BridgeVerifierRegistrationPolicyInput) :
    bridgeVerifierRegistrationPolicyAccepts input = true ↔
      bridgeVerifierRegistrationPolicyPreconditions input = true := by
  cases input with
  | mk bridgeVerifierRegistration stateDeltasAbsent registrationDecoded
      descriptorMatchesRelease activationHeightReached pqCleanVerifierBound
      externalVerifierSoundnessAccepted positiveMintingEnabled =>
      cases bridgeVerifierRegistration <;>
        cases stateDeltasAbsent <;>
        cases registrationDecoded <;>
        cases descriptorMatchesRelease <;>
        cases activationHeightReached <;>
        cases pqCleanVerifierBound <;>
        cases externalVerifierSoundnessAccepted <;>
        cases positiveMintingEnabled <;>
        simp [
          bridgeVerifierRegistrationPolicyAccepts,
          bridgeVerifierRegistrationPolicyPreconditions,
          evaluateBridgeVerifierRegistrationPolicy,
          productionMintVerifierEnabled
        ]

theorem not_registration_rejects
    {input : BridgeVerifierRegistrationPolicyInput}
    (notRegistration : input.bridgeVerifierRegistration = false) :
    evaluateBridgeVerifierRegistrationPolicy input =
      Except.error
        BridgeVerifierRegistrationPolicyReject.notBridgeVerifierRegistration := by
  unfold evaluateBridgeVerifierRegistrationPolicy
  simp [notRegistration]

theorem state_delta_registration_rejects_before_decode
    {input : BridgeVerifierRegistrationPolicyInput}
    (registration : input.bridgeVerifierRegistration = true)
    (stateDelta : input.stateDeltasAbsent = false) :
    evaluateBridgeVerifierRegistrationPolicy input =
      Except.error
        BridgeVerifierRegistrationPolicyReject.stateDeltasPresent := by
  unfold evaluateBridgeVerifierRegistrationPolicy
  simp [registration, stateDelta]

theorem registration_decode_failure_rejects_before_activation
    {input : BridgeVerifierRegistrationPolicyInput}
    (registration : input.bridgeVerifierRegistration = true)
    (noDelta : input.stateDeltasAbsent = true)
    (decodeFailed : input.registrationDecoded = false) :
    evaluateBridgeVerifierRegistrationPolicy input =
      Except.error
        BridgeVerifierRegistrationPolicyReject.registrationDecodeFailed := by
  unfold evaluateBridgeVerifierRegistrationPolicy
  simp [registration, noDelta, decodeFailed]

theorem accepted_registration_policy_facts
    {input : BridgeVerifierRegistrationPolicyInput}
    {effect : BridgeVerifierRegistrationPolicyEffect}
    (ok :
      evaluateBridgeVerifierRegistrationPolicy input =
        Except.ok effect) :
    BridgeVerifierRegistrationPolicyFacts input effect := by
  cases input with
  | mk bridgeVerifierRegistration stateDeltasAbsent registrationDecoded
      descriptorMatchesRelease activationHeightReached pqCleanVerifierBound
      externalVerifierSoundnessAccepted positiveMintingEnabled =>
      unfold evaluateBridgeVerifierRegistrationPolicy at ok
      cases bridgeVerifierRegistration <;>
        cases stateDeltasAbsent <;>
        cases registrationDecoded <;>
        cases descriptorMatchesRelease <;>
        cases activationHeightReached <;>
        cases pqCleanVerifierBound <;>
        cases externalVerifierSoundnessAccepted <;>
        cases positiveMintingEnabled <;>
        simp [
          productionMintVerifierEnabled,
          BridgeVerifierRegistrationPolicyFacts
        ] at ok ⊢
      all_goals
        subst effect
        simp

theorem positive_minting_disabled_registration_is_inert
    {input : BridgeVerifierRegistrationPolicyInput}
    {effect : BridgeVerifierRegistrationPolicyEffect}
    (disabled : input.positiveMintingEnabled = false)
    (ok :
      evaluateBridgeVerifierRegistrationPolicy input =
        Except.ok effect) :
    effect.productionMintVerifierEnabled = false := by
  have facts := accepted_registration_policy_facts ok
  rw [facts.right.right.right.right, productionMintVerifierEnabled]
  simp [disabled]

theorem missing_pq_clean_verifier_registration_is_inert
    {input : BridgeVerifierRegistrationPolicyInput}
    {effect : BridgeVerifierRegistrationPolicyEffect}
    (missing : input.pqCleanVerifierBound = false)
    (ok :
      evaluateBridgeVerifierRegistrationPolicy input =
        Except.ok effect) :
    effect.productionMintVerifierEnabled = false := by
  have facts := accepted_registration_policy_facts ok
  rw [facts.right.right.right.right, productionMintVerifierEnabled]
  simp [missing]

theorem missing_external_soundness_registration_is_inert
    {input : BridgeVerifierRegistrationPolicyInput}
    {effect : BridgeVerifierRegistrationPolicyEffect}
    (missing : input.externalVerifierSoundnessAccepted = false)
    (ok :
      evaluateBridgeVerifierRegistrationPolicy input =
        Except.ok effect) :
    effect.productionMintVerifierEnabled = false := by
  have facts := accepted_registration_policy_facts ok
  rw [facts.right.right.right.right, productionMintVerifierEnabled]
  simp [missing]

theorem descriptor_mismatch_registration_is_inert
    {input : BridgeVerifierRegistrationPolicyInput}
    {effect : BridgeVerifierRegistrationPolicyEffect}
    (mismatch : input.descriptorMatchesRelease = false)
    (ok :
      evaluateBridgeVerifierRegistrationPolicy input =
        Except.ok effect) :
    effect.productionMintVerifierEnabled = false := by
  have facts := accepted_registration_policy_facts ok
  rw [facts.right.right.right.right, productionMintVerifierEnabled]
  simp [mismatch]

theorem accepted_all_gates_enable_production_mint_verifier
    {input : BridgeVerifierRegistrationPolicyInput}
    {effect : BridgeVerifierRegistrationPolicyEffect}
    (descriptor : input.descriptorMatchesRelease = true)
    (height : input.activationHeightReached = true)
    (pqClean : input.pqCleanVerifierBound = true)
    (externalSoundness :
      input.externalVerifierSoundnessAccepted = true)
    (positiveMint : input.positiveMintingEnabled = true)
    (ok :
      evaluateBridgeVerifierRegistrationPolicy input =
        Except.ok effect) :
    effect.productionMintVerifierEnabled = true := by
  have facts := accepted_registration_policy_facts ok
  rw [facts.right.right.right.right, productionMintVerifierEnabled]
  simp [
    descriptor,
    height,
    pqClean,
    externalSoundness,
    positiveMint
  ]

def inertReleaseRegistration : BridgeVerifierRegistrationPolicyInput :=
  {
    bridgeVerifierRegistration := true,
    stateDeltasAbsent := true,
    registrationDecoded := true,
    descriptorMatchesRelease := true,
    activationHeightReached := true,
    pqCleanVerifierBound := false,
    externalVerifierSoundnessAccepted := false,
    positiveMintingEnabled := false
  }

def futureProductionRegistration : BridgeVerifierRegistrationPolicyInput :=
  {
    bridgeVerifierRegistration := true,
    stateDeltasAbsent := true,
    registrationDecoded := true,
    descriptorMatchesRelease := true,
    activationHeightReached := true,
    pqCleanVerifierBound := true,
    externalVerifierSoundnessAccepted := true,
    positiveMintingEnabled := true
  }

theorem inert_release_registration_accepts_without_enabling_mint :
    bridgeVerifierRegistrationPolicyEffect inertReleaseRegistration =
      some {
        registrationObserved := true,
        productionMintVerifierEnabled := false
      } := by
  decide

theorem future_production_registration_enables_mint_verifier :
    bridgeVerifierRegistrationPolicyEffect futureProductionRegistration =
      some {
        registrationObserved := true,
        productionMintVerifierEnabled := true
      } := by
  decide

end BridgeVerifierRegistrationPolicy
end Native
end Hegemon
