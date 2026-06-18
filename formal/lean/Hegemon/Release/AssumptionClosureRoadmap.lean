import Hegemon.Release.HighestStandardCompletionCertificate

namespace Hegemon
namespace Release
namespace AssumptionClosureRoadmap

structure MechanizedRefinementTracks
    (parserRawByteRefinement
      nativeNodeRefinement
      deployedProofAirRefinement
      bridgeMintVerifierRefinement : Prop) : Prop where
  parserRawByteRefinement :
    parserRawByteRefinement
  nativeNodeRefinement :
    nativeNodeRefinement
  deployedProofAirRefinement :
    deployedProofAirRefinement
  bridgeMintVerifierRefinement :
    bridgeMintVerifierRefinement

structure NamedPrimitiveCryptoAssumptions
    (mlKemMlDsaSecurity
      symmetricHashTranscriptSecurity
      starkFriPcsSoundness
      ciphertextIndistinguishability
      nativeLatticeBackendExternalReview
      osRngQuality : Prop) : Prop where
  mlKemMlDsaSecurity :
    mlKemMlDsaSecurity
  symmetricHashTranscriptSecurity :
    symmetricHashTranscriptSecurity
  starkFriPcsSoundness :
    starkFriPcsSoundness
  ciphertextIndistinguishability :
    ciphertextIndistinguishability
  nativeLatticeBackendExternalReview :
    nativeLatticeBackendExternalReview
  osRngQuality :
    osRngQuality

structure FailClosedSystemModelAssumptions
    (daAvailabilityRetention
      storageFsyncDurability
      globalPrivacyTrafficModel
      releaseInfrastructureEnforcement
      dependencyScannerCompleteness
      performanceBudgetMonitoring : Prop) : Prop where
  daAvailabilityRetention :
    daAvailabilityRetention
  storageFsyncDurability :
    storageFsyncDurability
  globalPrivacyTrafficModel :
    globalPrivacyTrafficModel
  releaseInfrastructureEnforcement :
    releaseInfrastructureEnforcement
  dependencyScannerCompleteness :
    dependencyScannerCompleteness
  performanceBudgetMonitoring :
    performanceBudgetMonitoring

structure ResidualAssumptionClosureRoadmap
    (parserRawByteRefinement
      nativeNodeRefinement
      deployedProofAirRefinement
      bridgeMintVerifierRefinement
      mlKemMlDsaSecurity
      symmetricHashTranscriptSecurity
      starkFriPcsSoundness
      ciphertextIndistinguishability
      nativeLatticeBackendExternalReview
      osRngQuality
      daAvailabilityRetention
      storageFsyncDurability
      globalPrivacyTrafficModel
      releaseInfrastructureEnforcement
      dependencyScannerCompleteness
      performanceBudgetMonitoring : Prop) : Prop where
  mechanizedRefinement :
    MechanizedRefinementTracks
      parserRawByteRefinement
      nativeNodeRefinement
      deployedProofAirRefinement
      bridgeMintVerifierRefinement
  primitiveCrypto :
    NamedPrimitiveCryptoAssumptions
      mlKemMlDsaSecurity
      symmetricHashTranscriptSecurity
      starkFriPcsSoundness
      ciphertextIndistinguishability
      nativeLatticeBackendExternalReview
      osRngQuality
  systemModel :
    FailClosedSystemModelAssumptions
      daAvailabilityRetention
      storageFsyncDurability
      globalPrivacyTrafficModel
      releaseInfrastructureEnforcement
      dependencyScannerCompleteness
      performanceBudgetMonitoring

theorem residual_closure_roadmap_exposes_mechanized_refinement_tracks
    {parserRawByteRefinement
      nativeNodeRefinement
      deployedProofAirRefinement
      bridgeMintVerifierRefinement
      mlKemMlDsaSecurity
      symmetricHashTranscriptSecurity
      starkFriPcsSoundness
      ciphertextIndistinguishability
      nativeLatticeBackendExternalReview
      osRngQuality
      daAvailabilityRetention
      storageFsyncDurability
      globalPrivacyTrafficModel
      releaseInfrastructureEnforcement
      dependencyScannerCompleteness
      performanceBudgetMonitoring : Prop}
    (roadmap :
      ResidualAssumptionClosureRoadmap
        parserRawByteRefinement
        nativeNodeRefinement
        deployedProofAirRefinement
        bridgeMintVerifierRefinement
        mlKemMlDsaSecurity
        symmetricHashTranscriptSecurity
        starkFriPcsSoundness
        ciphertextIndistinguishability
        nativeLatticeBackendExternalReview
        osRngQuality
        daAvailabilityRetention
        storageFsyncDurability
        globalPrivacyTrafficModel
        releaseInfrastructureEnforcement
        dependencyScannerCompleteness
        performanceBudgetMonitoring) :
    parserRawByteRefinement
      ∧ nativeNodeRefinement
      ∧ deployedProofAirRefinement
      ∧ bridgeMintVerifierRefinement := by
  exact
    ⟨roadmap.mechanizedRefinement.parserRawByteRefinement,
      roadmap.mechanizedRefinement.nativeNodeRefinement,
      roadmap.mechanizedRefinement.deployedProofAirRefinement,
      roadmap.mechanizedRefinement.bridgeMintVerifierRefinement⟩

theorem residual_closure_roadmap_exposes_named_primitive_crypto_assumptions
    {parserRawByteRefinement
      nativeNodeRefinement
      deployedProofAirRefinement
      bridgeMintVerifierRefinement
      mlKemMlDsaSecurity
      symmetricHashTranscriptSecurity
      starkFriPcsSoundness
      ciphertextIndistinguishability
      nativeLatticeBackendExternalReview
      osRngQuality
      daAvailabilityRetention
      storageFsyncDurability
      globalPrivacyTrafficModel
      releaseInfrastructureEnforcement
      dependencyScannerCompleteness
      performanceBudgetMonitoring : Prop}
    (roadmap :
      ResidualAssumptionClosureRoadmap
        parserRawByteRefinement
        nativeNodeRefinement
        deployedProofAirRefinement
        bridgeMintVerifierRefinement
        mlKemMlDsaSecurity
        symmetricHashTranscriptSecurity
        starkFriPcsSoundness
        ciphertextIndistinguishability
        nativeLatticeBackendExternalReview
        osRngQuality
        daAvailabilityRetention
        storageFsyncDurability
        globalPrivacyTrafficModel
        releaseInfrastructureEnforcement
        dependencyScannerCompleteness
        performanceBudgetMonitoring) :
    mlKemMlDsaSecurity
      ∧ symmetricHashTranscriptSecurity
      ∧ starkFriPcsSoundness
      ∧ ciphertextIndistinguishability
      ∧ nativeLatticeBackendExternalReview
      ∧ osRngQuality := by
  exact
    ⟨roadmap.primitiveCrypto.mlKemMlDsaSecurity,
      roadmap.primitiveCrypto.symmetricHashTranscriptSecurity,
      roadmap.primitiveCrypto.starkFriPcsSoundness,
      roadmap.primitiveCrypto.ciphertextIndistinguishability,
      roadmap.primitiveCrypto.nativeLatticeBackendExternalReview,
      roadmap.primitiveCrypto.osRngQuality⟩

theorem residual_closure_roadmap_exposes_fail_closed_system_model_assumptions
    {parserRawByteRefinement
      nativeNodeRefinement
      deployedProofAirRefinement
      bridgeMintVerifierRefinement
      mlKemMlDsaSecurity
      symmetricHashTranscriptSecurity
      starkFriPcsSoundness
      ciphertextIndistinguishability
      nativeLatticeBackendExternalReview
      osRngQuality
      daAvailabilityRetention
      storageFsyncDurability
      globalPrivacyTrafficModel
      releaseInfrastructureEnforcement
      dependencyScannerCompleteness
      performanceBudgetMonitoring : Prop}
    (roadmap :
      ResidualAssumptionClosureRoadmap
        parserRawByteRefinement
        nativeNodeRefinement
        deployedProofAirRefinement
        bridgeMintVerifierRefinement
        mlKemMlDsaSecurity
        symmetricHashTranscriptSecurity
        starkFriPcsSoundness
        ciphertextIndistinguishability
        nativeLatticeBackendExternalReview
        osRngQuality
        daAvailabilityRetention
        storageFsyncDurability
        globalPrivacyTrafficModel
        releaseInfrastructureEnforcement
        dependencyScannerCompleteness
        performanceBudgetMonitoring) :
    daAvailabilityRetention
      ∧ storageFsyncDurability
      ∧ globalPrivacyTrafficModel
      ∧ releaseInfrastructureEnforcement
      ∧ dependencyScannerCompleteness
      ∧ performanceBudgetMonitoring := by
  exact
    ⟨roadmap.systemModel.daAvailabilityRetention,
      roadmap.systemModel.storageFsyncDurability,
      roadmap.systemModel.globalPrivacyTrafficModel,
      roadmap.systemModel.releaseInfrastructureEnforcement,
      roadmap.systemModel.dependencyScannerCompleteness,
      roadmap.systemModel.performanceBudgetMonitoring⟩

theorem residual_closure_roadmap_splits_all_open_assumptions
    {parserRawByteRefinement
      nativeNodeRefinement
      deployedProofAirRefinement
      bridgeMintVerifierRefinement
      mlKemMlDsaSecurity
      symmetricHashTranscriptSecurity
      starkFriPcsSoundness
      ciphertextIndistinguishability
      nativeLatticeBackendExternalReview
      osRngQuality
      daAvailabilityRetention
      storageFsyncDurability
      globalPrivacyTrafficModel
      releaseInfrastructureEnforcement
      dependencyScannerCompleteness
      performanceBudgetMonitoring : Prop}
    (roadmap :
      ResidualAssumptionClosureRoadmap
        parserRawByteRefinement
        nativeNodeRefinement
        deployedProofAirRefinement
        bridgeMintVerifierRefinement
        mlKemMlDsaSecurity
        symmetricHashTranscriptSecurity
        starkFriPcsSoundness
        ciphertextIndistinguishability
        nativeLatticeBackendExternalReview
        osRngQuality
        daAvailabilityRetention
        storageFsyncDurability
        globalPrivacyTrafficModel
        releaseInfrastructureEnforcement
        dependencyScannerCompleteness
        performanceBudgetMonitoring) :
    (parserRawByteRefinement
      ∧ nativeNodeRefinement
      ∧ deployedProofAirRefinement
      ∧ bridgeMintVerifierRefinement)
      ∧ (mlKemMlDsaSecurity
        ∧ symmetricHashTranscriptSecurity
        ∧ starkFriPcsSoundness
        ∧ ciphertextIndistinguishability
        ∧ nativeLatticeBackendExternalReview
        ∧ osRngQuality)
      ∧ (daAvailabilityRetention
        ∧ storageFsyncDurability
        ∧ globalPrivacyTrafficModel
        ∧ releaseInfrastructureEnforcement
        ∧ dependencyScannerCompleteness
        ∧ performanceBudgetMonitoring) := by
  exact
    ⟨residual_closure_roadmap_exposes_mechanized_refinement_tracks roadmap,
      residual_closure_roadmap_exposes_named_primitive_crypto_assumptions roadmap,
      residual_closure_roadmap_exposes_fail_closed_system_model_assumptions roadmap⟩

end AssumptionClosureRoadmap
end Release
end Hegemon
