import HegemonCrypto.KnowledgeSoundnessTarget

/-!
# Fail-closed research assurance boundary

This inventory names the cryptographic obligations that remain open. It is not evidence for any
obligation and contains no mechanism for replacing proofs with boolean attestations.
-/

namespace HegemonCrypto.AssuranceBoundary

inductive Obligation where
  | exactProductionToCCS
  | exactProtocolTranscript
  | honestProverCompleteness
  | interactiveKnowledgeSoundness
  | commitmentBindingReduction
  | fiatShamirRomAdaptiveKnowledgeSoundness
  | fiatShamirQromAdaptiveKnowledgeSoundness
  | primitiveHashSecurity
  | concreteParameterSoundness
  | canonicalSerializationRefinement
  | rustVerifierRefinement
  | proverRandomnessAndSecretHandling
deriving DecidableEq, Repr, Fintype

def openObligations : Finset Obligation := Finset.univ

theorem every_cryptographic_obligation_remains_open
    (obligation : Obligation) :
    obligation ∈ openObligations := by
  simp [openObligations]

def productionSecurityClaimAuthorized : Bool := decide (openObligations = ∅)

theorem open_research_posture_cannot_authorize_production_security_claim :
    productionSecurityClaimAuthorized = false := by
  decide

end HegemonCrypto.AssuranceBoundary
