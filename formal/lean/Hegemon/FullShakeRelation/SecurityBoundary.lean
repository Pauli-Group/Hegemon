import Hegemon.FullShakeRelation.Grammar
import Hegemon.FullShakeRelation.StateMachine

namespace Hegemon
namespace FullShakeRelation

/-!
These certificate fields are intentionally propositions supplied by future
independent work.  Merely constructing the executable semantic model above
does not inhabit them and therefore cannot be used to claim SHAKE security,
M4 constraint refinement, Rust parser refinement, zero knowledge, or strict
PQ128/QROM soundness.
-/

structure CryptographicAssumptions where
  shake256FrameBinding : Prop
  shake256DigestCollisionResistance : Prop
  shake512TranscriptQromAnalysis : Prop
  e384FieldAndPcsSoundness : Prop

structure ImplementationRefinementCertificates where
  rustParserAcceptsIffLeanGrammar : Prop
  rustScalarAcceptsIffLeanSemantics : Prop
  m4CircuitAcceptsIffRustScalar : Prop
  nativeActionAdmissionUsesExactActivation : Prop

structure PrivacyCertificates where
  completeZeroKnowledgeSimulator : Prop
  transcriptDistributionIndistinguishable : Prop
  noWitnessDependentParserShape : Prop

structure StrictReleaseCertificate where
  cryptography : CryptographicAssumptions
  implementation : ImplementationRefinementCertificates
  privacy : PrivacyCertificates
  exactGrammar : canonicalWidths.total = canonicalStatementBytes
  exactAcceptedMasks : acceptedMaskCodes.length = 9
  exactRejectedMasks : rejectedMaskCodes.length = 7

def semanticObligationsMechanized : Bool :=
  canonicalWidths.total == canonicalStatementBytes
    && acceptedMaskCodes.length == 9
    && rejectedMaskCodes.length == 7
    && signedCanonical zeroSignedAmount

theorem current_semantic_obligations_are_mechanized :
    semanticObligationsMechanized = true := by
  decide

/- No theorem in this namespace manufactures a StrictReleaseCertificate. -/

end FullShakeRelation
end Hegemon
