import Hegemon.Native.MaterializedConsensusDaBlobRefinement
import Hegemon.Release.ReleasePostureCertificate

namespace Hegemon
namespace Release
namespace HighestStandardCompletionCertificate

open Hegemon.Native.MaterializedConsensusDaBlobRefinement
open Hegemon.Release.ReleasePostureCertificate

structure ExternalSecurityAssumptionBundle
    (materializedResiduals : MaterializedTransferCoreResidualAssumptions)
    (primitiveCryptoAssumptions
      zeroKnowledgeSimulatorAssumptions
      ciphertextConfidentialityAssumptions
      externalBridgeProofSoundness
      releaseInfrastructureAssumptions
      performanceBudgetPreserved : Prop) : Prop where
  parserEquivalence :
    materializedResiduals.arbitraryParserEquivalence
  hashSecurityEquivalence :
    materializedResiduals.hashSecurityEquivalence
  proofSystemSoundness :
    materializedResiduals.proofSystemSoundness
  storageDurabilityBelowSled :
    materializedResiduals.storageDurabilityBelowSled
  daAvailabilityRetention :
    materializedResiduals.daAvailabilityRetention
  completeNativeNodeEquivalence :
    materializedResiduals.completeNativeNodeEquivalence
  primitiveCryptoAssumptions :
    primitiveCryptoAssumptions
  zeroKnowledgeSimulatorAssumptions :
    zeroKnowledgeSimulatorAssumptions
  ciphertextConfidentialityAssumptions :
    ciphertextConfidentialityAssumptions
  externalBridgeProofSoundness :
    externalBridgeProofSoundness
  releaseInfrastructureAssumptions :
    releaseInfrastructureAssumptions
  performanceBudgetPreserved :
    performanceBudgetPreserved

structure HighestStandardInternalTheoremBundle
    (noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
      proofStatementBinding
      proofSystemResidualBoundary
      canonicalEncodingNonMalleability
      replayReorgStartupRefinement
      daSidecarBinding
      bridgeMintReplaySafety
      pqNetworkChannelSafety
      resourceDoSBounds : Prop)
    (materializedResiduals : MaterializedTransferCoreResidualAssumptions) :
    Prop where
  materializedCoreReview :
    MaterializedTransferHighestStandardResidualReviewFacts
      noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
      materializedResiduals
  proofStatementBinding :
    proofStatementBinding
  proofSystemResidualBoundary :
    proofSystemResidualBoundary
  canonicalEncodingNonMalleability :
    canonicalEncodingNonMalleability
  replayReorgStartupRefinement :
    replayReorgStartupRefinement
  daSidecarBinding :
    daSidecarBinding
  bridgeMintReplaySafety :
    bridgeMintReplaySafety
  pqNetworkChannelSafety :
    pqNetworkChannelSafety
  resourceDoSBounds :
    resourceDoSBounds

structure HighestStandardFormalVerificationCompletionCertificate
    (releaseSurface : ReleasePostureSurface)
    (noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
      proofStatementBinding
      proofSystemResidualBoundary
      canonicalEncodingNonMalleability
      replayReorgStartupRefinement
      daSidecarBinding
      bridgeMintReplaySafety
      pqNetworkChannelSafety
      resourceDoSBounds
      primitiveCryptoAssumptions
      zeroKnowledgeSimulatorAssumptions
      ciphertextConfidentialityAssumptions
      externalBridgeProofSoundness
      releaseInfrastructureAssumptions
      performanceBudgetPreserved : Prop)
    (materializedResiduals : MaterializedTransferCoreResidualAssumptions) :
    Prop where
  internalTheorems :
    HighestStandardInternalTheoremBundle
      noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
      proofStatementBinding
      proofSystemResidualBoundary
      canonicalEncodingNonMalleability
      replayReorgStartupRefinement
      daSidecarBinding
      bridgeMintReplaySafety
      pqNetworkChannelSafety
      resourceDoSBounds
      materializedResiduals
  externalResiduals :
    ExternalSecurityAssumptionBundle
      materializedResiduals
      primitiveCryptoAssumptions
      zeroKnowledgeSimulatorAssumptions
      ciphertextConfidentialityAssumptions
      externalBridgeProofSoundness
      releaseInfrastructureAssumptions
      performanceBudgetPreserved
  releaseGate :
    ProductionReleaseGateCertificate releaseSurface

theorem accepted_internal_bundle_and_release_gate_yield_highest_standard_completion_certificate
    {releaseSurface : ReleasePostureSurface}
    {noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
      proofStatementBinding
      proofSystemResidualBoundary
      canonicalEncodingNonMalleability
      replayReorgStartupRefinement
      daSidecarBinding
      bridgeMintReplaySafety
      pqNetworkChannelSafety
      resourceDoSBounds
      primitiveCryptoAssumptions
      zeroKnowledgeSimulatorAssumptions
      ciphertextConfidentialityAssumptions
      externalBridgeProofSoundness
      releaseInfrastructureAssumptions
      performanceBudgetPreserved : Prop}
    {materializedResiduals : MaterializedTransferCoreResidualAssumptions}
    (internal :
      HighestStandardInternalTheoremBundle
        noCounterfeiting
        acceptedLedgerReplay
        commitmentRootPublication
        noDoubleSpend
        bridgeReplayUnique
        activeInputNoTheft
        totalInputAuthorization
        smallwoodVerifierExport
        authorizedPerAssetDelta
        authorizedStablecoinException
        nativeStablecoinPolicyLive
        consensusDaBlobRefinement
        txLeafStatementArtifact
        txLeafNativeStatementArtifact
        txLeafCiphertextPublication
        statementCiphertextVectorPublication
        sidecarMaterialization
        privacyBoundary
        admissionSafety
        proofStatementBinding
        proofSystemResidualBoundary
        canonicalEncodingNonMalleability
        replayReorgStartupRefinement
        daSidecarBinding
        bridgeMintReplaySafety
        pqNetworkChannelSafety
        resourceDoSBounds
        materializedResiduals)
    (external :
      ExternalSecurityAssumptionBundle
        materializedResiduals
        primitiveCryptoAssumptions
        zeroKnowledgeSimulatorAssumptions
        ciphertextConfidentialityAssumptions
        externalBridgeProofSoundness
        releaseInfrastructureAssumptions
        performanceBudgetPreserved)
    (releaseGate :
      ProductionReleaseGateCertificate releaseSurface) :
    HighestStandardFormalVerificationCompletionCertificate
      releaseSurface
      noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
      proofStatementBinding
      proofSystemResidualBoundary
      canonicalEncodingNonMalleability
      replayReorgStartupRefinement
      daSidecarBinding
      bridgeMintReplaySafety
      pqNetworkChannelSafety
      resourceDoSBounds
      primitiveCryptoAssumptions
      zeroKnowledgeSimulatorAssumptions
      ciphertextConfidentialityAssumptions
      externalBridgeProofSoundness
      releaseInfrastructureAssumptions
      performanceBudgetPreserved
      materializedResiduals := by
  exact {
    internalTheorems := internal,
    externalResiduals := external,
    releaseGate := releaseGate
  }

theorem completion_certificate_exposes_critical_chain_security_and_residuals
    {releaseSurface : ReleasePostureSurface}
    {noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
      proofStatementBinding
      proofSystemResidualBoundary
      canonicalEncodingNonMalleability
      replayReorgStartupRefinement
      daSidecarBinding
      bridgeMintReplaySafety
      pqNetworkChannelSafety
      resourceDoSBounds
      primitiveCryptoAssumptions
      zeroKnowledgeSimulatorAssumptions
      ciphertextConfidentialityAssumptions
      externalBridgeProofSoundness
      releaseInfrastructureAssumptions
      performanceBudgetPreserved : Prop}
    {materializedResiduals : MaterializedTransferCoreResidualAssumptions}
    (certificate :
      HighestStandardFormalVerificationCompletionCertificate
        releaseSurface
        noCounterfeiting
        acceptedLedgerReplay
        commitmentRootPublication
        noDoubleSpend
        bridgeReplayUnique
        activeInputNoTheft
        totalInputAuthorization
        smallwoodVerifierExport
        authorizedPerAssetDelta
        authorizedStablecoinException
        nativeStablecoinPolicyLive
        consensusDaBlobRefinement
        txLeafStatementArtifact
        txLeafNativeStatementArtifact
        txLeafCiphertextPublication
        statementCiphertextVectorPublication
        sidecarMaterialization
        privacyBoundary
        admissionSafety
        proofStatementBinding
        proofSystemResidualBoundary
        canonicalEncodingNonMalleability
        replayReorgStartupRefinement
        daSidecarBinding
        bridgeMintReplaySafety
        pqNetworkChannelSafety
        resourceDoSBounds
        primitiveCryptoAssumptions
        zeroKnowledgeSimulatorAssumptions
        ciphertextConfidentialityAssumptions
        externalBridgeProofSoundness
        releaseInfrastructureAssumptions
        performanceBudgetPreserved
        materializedResiduals) :
    noCounterfeiting
      ∧ noDoubleSpend
      ∧ activeInputNoTheft
      ∧ totalInputAuthorization
      ∧ authorizedPerAssetDelta
      ∧ authorizedStablecoinException
      ∧ consensusDaBlobRefinement
      ∧ proofStatementBinding
      ∧ proofSystemResidualBoundary
      ∧ canonicalEncodingNonMalleability
      ∧ replayReorgStartupRefinement
      ∧ daSidecarBinding
      ∧ bridgeMintReplaySafety
      ∧ pqNetworkChannelSafety
      ∧ resourceDoSBounds
      ∧ primitiveCryptoAssumptions
      ∧ zeroKnowledgeSimulatorAssumptions
      ∧ ciphertextConfidentialityAssumptions
      ∧ externalBridgeProofSoundness
      ∧ releaseInfrastructureAssumptions
      ∧ performanceBudgetPreserved := by
  let core := certificate.internalTheorems.materializedCoreReview.coreReview
  exact
    ⟨certificate.internalTheorems.materializedCoreReview.noCounterfeiting,
      certificate.internalTheorems.materializedCoreReview.noDoubleSpend,
      core.activeInputNoTheft,
      core.totalInputAuthorization,
      core.authorizedPerAssetDelta,
      core.authorizedStablecoinException,
      core.consensusDaBlobRefinement,
      certificate.internalTheorems.proofStatementBinding,
      certificate.internalTheorems.proofSystemResidualBoundary,
      certificate.internalTheorems.canonicalEncodingNonMalleability,
      certificate.internalTheorems.replayReorgStartupRefinement,
      certificate.internalTheorems.daSidecarBinding,
      certificate.internalTheorems.bridgeMintReplaySafety,
      certificate.internalTheorems.pqNetworkChannelSafety,
      certificate.internalTheorems.resourceDoSBounds,
      certificate.externalResiduals.primitiveCryptoAssumptions,
      certificate.externalResiduals.zeroKnowledgeSimulatorAssumptions,
      certificate.externalResiduals.ciphertextConfidentialityAssumptions,
      certificate.externalResiduals.externalBridgeProofSoundness,
      certificate.externalResiduals.releaseInfrastructureAssumptions,
      certificate.externalResiduals.performanceBudgetPreserved⟩

theorem completion_certificate_binds_release_gate_and_native_backend_posture
    {releaseSurface : ReleasePostureSurface}
    {noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
      proofStatementBinding
      proofSystemResidualBoundary
      canonicalEncodingNonMalleability
      replayReorgStartupRefinement
      daSidecarBinding
      bridgeMintReplaySafety
      pqNetworkChannelSafety
      resourceDoSBounds
      primitiveCryptoAssumptions
      zeroKnowledgeSimulatorAssumptions
      ciphertextConfidentialityAssumptions
      externalBridgeProofSoundness
      releaseInfrastructureAssumptions
      performanceBudgetPreserved : Prop}
    {materializedResiduals : MaterializedTransferCoreResidualAssumptions}
    (certificate :
      HighestStandardFormalVerificationCompletionCertificate
        releaseSurface
        noCounterfeiting
        acceptedLedgerReplay
        commitmentRootPublication
        noDoubleSpend
        bridgeReplayUnique
        activeInputNoTheft
        totalInputAuthorization
        smallwoodVerifierExport
        authorizedPerAssetDelta
        authorizedStablecoinException
        nativeStablecoinPolicyLive
        consensusDaBlobRefinement
        txLeafStatementArtifact
        txLeafNativeStatementArtifact
        txLeafCiphertextPublication
        statementCiphertextVectorPublication
        sidecarMaterialization
        privacyBoundary
        admissionSafety
        proofStatementBinding
        proofSystemResidualBoundary
        canonicalEncodingNonMalleability
        replayReorgStartupRefinement
        daSidecarBinding
        bridgeMintReplaySafety
        pqNetworkChannelSafety
        resourceDoSBounds
        primitiveCryptoAssumptions
        zeroKnowledgeSimulatorAssumptions
        ciphertextConfidentialityAssumptions
        externalBridgeProofSoundness
        releaseInfrastructureAssumptions
        performanceBudgetPreserved
        materializedResiduals) :
    releaseSurface.nativeBackendPosture.requireAccepted = true
      ∧ Hegemon.Native.NativeBackendReleasePosture.acceptedPreconditions
          releaseSurface.nativeBackendPosture = true
      ∧ Hegemon.Native.NativeBackendReleasePosture.releasePosturePreconditions
          releaseSurface.nativeBackendPosture = true := by
  exact production_release_gate_certificate_requires_native_backend_accepted_mode
    certificate.releaseGate

end HighestStandardCompletionCertificate
end Release
end Hegemon
