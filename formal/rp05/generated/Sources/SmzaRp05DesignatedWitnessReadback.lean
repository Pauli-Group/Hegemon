import SmzaRp05ActualAcceptedAuthorizationEndpoint

/-! Small readback projections for the selector-derived actual authorization
carrier. These lemmas intentionally stop reduction before unfolding the
accepted relation witness. -/

namespace HegemonCrypto.SmallWood.SmzaRp05DesignatedWitnessReadback

open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
open SmzaQ38Recovery (packedFromRows)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (encodePublicStatement)

set_option autoImplicit false

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl
  HegemonCrypto.SmallWood.SmzaRp05RelationRefinement.candidate
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
  SmzaQ38Recovery.packedFromRows

@[simp] theorem comparison_pair_left_packed
    (comparison : DesignatedAuthorizationComparison) :
    comparison.pair.1.packed =
      packedFromRows comparison.leftWitness.source.data := by
  rfl

@[simp] theorem comparison_pair_right_packed
    (comparison : DesignatedAuthorizationComparison) :
    comparison.pair.2.packed =
      packedFromRows comparison.rightWitness.source.data := by
  rfl

@[simp] theorem comparison_pair_left_input
    (comparison : DesignatedAuthorizationComparison) :
    comparison.pair.1.input = comparison.leftInput := by
  rfl

@[simp] theorem comparison_pair_right_input
    (comparison : DesignatedAuthorizationComparison) :
    comparison.pair.2.input = comparison.rightInput := by
  rfl

@[simp] theorem comparison_pair_left_public_words
    (comparison : DesignatedAuthorizationComparison) :
    comparison.pair.1.publicWords = encodePublicStatement comparison.leftTyped := by
  rfl

@[simp] theorem comparison_pair_right_public_words
    (comparison : DesignatedAuthorizationComparison) :
    comparison.pair.2.publicWords = encodePublicStatement comparison.rightTyped := by
  rfl

end HegemonCrypto.SmallWood.SmzaRp05DesignatedWitnessReadback
