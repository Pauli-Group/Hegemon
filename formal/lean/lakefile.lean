import Lake
open Lake DSL

package hegemon_formal where
  version := v!"0.1.0"

lean_lib Hegemon where
  roots := #[`Hegemon]

lean_exe gen_bridge_vectors where
  root := `Hegemon.Bridge.GenerateVectors

lean_exe gen_bridge_checkpoint_output_vectors where
  root := `Hegemon.Bridge.GenerateCheckpointOutputVectors

lean_exe gen_bridge_long_range_vectors where
  root := `Hegemon.Bridge.GenerateLongRangeVectors

lean_exe gen_bridge_header_mmr_vectors where
  root := `Hegemon.Bridge.GenerateHeaderMmrVectors

lean_exe gen_bridge_header_mmr_transcript_vectors where
  root := `Hegemon.Bridge.GenerateHeaderMmrTranscriptVectors

lean_exe gen_bridge_flyclient_vectors where
  root := `Hegemon.Bridge.GenerateFlyClientVectors

lean_exe gen_bridge_mint_replay_policy_vectors where
  root := `Hegemon.Bridge.GenerateMintReplayPolicyVectors

lean_exe gen_bridge_mint_payload_admission_vectors where
  root := `Hegemon.Bridge.GenerateMintPayloadAdmissionVectors

lean_exe gen_aggregation_v5_vectors where
  root := `Hegemon.Consensus.GenerateAggregationV5Vectors

lean_exe gen_commitment_tree_append_vectors where
  root := `Hegemon.Consensus.GenerateCommitmentTreeAppendVectors

lean_exe gen_da_root_vectors where
  root := `Hegemon.Consensus.GenerateDaRootVectors

lean_exe gen_shielded_vectors where
  root := `Hegemon.Shielded.GenerateVectors

lean_exe gen_consensus_vectors where
  root := `Hegemon.Consensus.GenerateVectors

lean_exe gen_header_vectors where
  root := `Hegemon.Consensus.GenerateHeaderVectors

lean_exe gen_miner_identity_vectors where
  root := `Hegemon.Consensus.GenerateMinerIdentityVectors

lean_exe gen_native_tx_leaf_admission_vectors where
  root := `Hegemon.Consensus.GenerateNativeTxLeafAdmissionVectors

lean_exe gen_pow_vectors where
  root := `Hegemon.Consensus.GeneratePowVectors

lean_exe gen_proof_policy_vectors where
  root := `Hegemon.Consensus.GenerateProofPolicyVectors

lean_exe gen_proven_batch_binding_vectors where
  root := `Hegemon.Consensus.GenerateProvenBatchBindingVectors

lean_exe gen_receipt_root_admission_vectors where
  root := `Hegemon.Consensus.GenerateReceiptRootAdmissionVectors

lean_exe gen_recursive_block_admission_vectors where
  root := `Hegemon.Consensus.GenerateRecursiveBlockAdmissionVectors

lean_exe gen_recursive_block_v2_verifier_surface_vectors where
  root := `Hegemon.Consensus.GenerateRecursiveBlockV2VerifierSurfaceVectors

lean_exe gen_recursive_public_replay_vectors where
  root := `Hegemon.Consensus.GenerateRecursivePublicReplayVectors

lean_exe gen_recursive_semantic_input_vectors where
  root := `Hegemon.Consensus.GenerateRecursiveSemanticInputVectors

lean_exe gen_supply_vectors where
  root := `Hegemon.Consensus.GenerateSupplyVectors

lean_exe gen_supply_invariant_vectors where
  root := `Hegemon.Consensus.GenerateSupplyInvariantVectors

lean_exe gen_statement_anchor_admission_vectors where
  root := `Hegemon.Consensus.GenerateStatementAnchorAdmissionVectors

lean_exe gen_tree_transition_vectors where
  root := `Hegemon.Consensus.GenerateTreeTransitionVectors

lean_exe gen_version_policy_vectors where
  root := `Hegemon.Consensus.GenerateVersionPolicyVectors

lean_exe gen_action_order_vectors where
  root := `Hegemon.Native.GenerateActionOrderVectors

lean_exe gen_action_request_projection_admission_vectors where
  root := `Hegemon.Native.GenerateActionRequestProjectionAdmissionVectors

lean_exe gen_atomic_commit_manifest_admission_vectors where
  root := `Hegemon.Native.GenerateAtomicCommitManifestAdmissionVectors

lean_exe gen_action_hash_admission_vectors where
  root := `Hegemon.Native.GenerateActionHashAdmissionVectors

lean_exe gen_action_root_transcript_vectors where
  root := `Hegemon.Native.GenerateActionRootTranscriptVectors

lean_exe gen_action_state_effect_vectors where
  root := `Hegemon.Native.GenerateActionStateEffectVectors

lean_exe gen_action_stream_effect_vectors where
  root := `Hegemon.Native.GenerateActionStreamEffectVectors

lean_exe gen_action_plan_application_admission_vectors where
  root := `Hegemon.Native.GenerateActionPlanApplicationAdmissionVectors

lean_exe gen_action_wire_replay_projection_admission_vectors where
  root := `Hegemon.Native.GenerateActionWireReplayProjectionAdmissionVectors

lean_exe gen_announced_block_admission_vectors where
  root := `Hegemon.Native.GenerateAnnouncedBlockAdmissionVectors

lean_exe gen_block_index_reload_vectors where
  root := `Hegemon.Native.GenerateBlockIndexReloadVectors

lean_exe gen_canonical_state_reload_vectors where
  root := `Hegemon.Native.GenerateCanonicalStateReloadVectors

lean_exe gen_bridge_replay_reload_vectors where
  root := `Hegemon.Native.GenerateBridgeReplayReloadVectors

lean_exe gen_pending_action_reload_vectors where
  root := `Hegemon.Native.GeneratePendingActionReloadVectors

lean_exe gen_action_scope_admission_vectors where
  root := `Hegemon.Native.GenerateActionScopeAdmissionVectors

lean_exe gen_block_action_validation_vectors where
  root := `Hegemon.Native.GenerateBlockActionValidationVectors

lean_exe gen_bridge_action_payload_admission_vectors where
  root := `Hegemon.Native.GenerateBridgeActionPayloadAdmissionVectors

lean_exe gen_bridge_action_resource_admission_vectors where
  root := `Hegemon.Native.GenerateBridgeActionResourceAdmissionVectors

lean_exe gen_bridge_witness_backscan_vectors where
  root := `Hegemon.Native.GenerateBridgeWitnessBackscanVectors

lean_exe gen_bridge_witness_export_admission_vectors where
  root := `Hegemon.Native.GenerateBridgeWitnessExportAdmissionVectors

lean_exe gen_inbound_bridge_receipt_admission_vectors where
  root := `Hegemon.Native.GenerateInboundBridgeReceiptAdmissionVectors

lean_exe gen_risc0_release_verifier_vectors where
  root := `Hegemon.Native.GenerateRisc0ReleaseVerifierVectors

lean_exe gen_native_backend_review_policy_vectors where
  root := `Hegemon.Native.GenerateNativeBackendReviewPolicyVectors

lean_exe gen_native_backend_release_posture_vectors where
  root := `Hegemon.Native.GenerateNativeBackendReleasePostureVectors

lean_exe gen_release_pq_binary_policy_vectors where
  root := `Hegemon.Release.GeneratePqBinaryPolicyVectors

lean_exe gen_ci_release_gate_vectors where
  root := `Hegemon.Release.GenerateCiReleaseGateVectors

lean_exe gen_dependency_audit_policy_vectors where
  root := `Hegemon.Release.GenerateDependencyAuditPolicyVectors

lean_exe gen_transfer_action_payload_admission_vectors where
  root := `Hegemon.Native.GenerateTransferActionPayloadAdmissionVectors

lean_exe gen_transfer_state_admission_vectors where
  root := `Hegemon.Native.GenerateTransferStateAdmissionVectors

lean_exe gen_block_artifact_binding_admission_vectors where
  root := `Hegemon.Native.GenerateBlockArtifactBindingAdmissionVectors

lean_exe gen_block_commitment_admission_vectors where
  root := `Hegemon.Native.GenerateBlockCommitmentAdmissionVectors

lean_exe gen_block_replay_refinement_vectors where
  root := `Hegemon.Native.GenerateBlockReplayRefinementVectors

lean_exe gen_candidate_artifact_admission_vectors where
  root := `Hegemon.Native.GenerateCandidateArtifactAdmissionVectors

lean_exe gen_candidate_artifact_scale_wire_vectors where
  root := `Hegemon.Native.GenerateCandidateArtifactScaleWireVectors

lean_exe gen_candidate_artifact_coupling_admission_vectors where
  root := `Hegemon.Native.GenerateCandidateArtifactCouplingAdmissionVectors

lean_exe gen_canonical_reorg_chain_admission_vectors where
  root := `Hegemon.Native.GenerateCanonicalReorgChainAdmissionVectors

lean_exe gen_codec_admission_vectors where
  root := `Hegemon.Native.GenerateCodecAdmissionVectors

lean_exe gen_pending_action_scale_wire_vectors where
  root := `Hegemon.Native.GeneratePendingActionScaleWireVectors

lean_exe gen_coinbase_accounting_admission_vectors where
  root := `Hegemon.Native.GenerateCoinbaseAccountingAdmissionVectors

lean_exe gen_coinbase_action_payload_admission_vectors where
  root := `Hegemon.Native.GenerateCoinbaseActionPayloadAdmissionVectors

lean_exe gen_coinbase_action_payload_scale_wire_vectors where
  root := `Hegemon.Native.GenerateCoinbaseActionPayloadScaleWireVectors

lean_exe gen_outbound_bridge_action_payload_scale_wire_vectors where
  root := `Hegemon.Native.GenerateOutboundBridgeActionPayloadScaleWireVectors

lean_exe gen_inbound_bridge_action_payload_scale_wire_vectors where
  root := `Hegemon.Native.GenerateInboundBridgeActionPayloadScaleWireVectors

lean_exe gen_bridge_verifier_registration_scale_wire_vectors where
  root := `Hegemon.Native.GenerateBridgeVerifierRegistrationScaleWireVectors

lean_exe gen_shielded_transfer_inline_scale_wire_vectors where
  root := `Hegemon.Native.GenerateShieldedTransferInlineScaleWireVectors

lean_exe gen_shielded_transfer_sidecar_scale_wire_vectors where
  root := `Hegemon.Native.GenerateShieldedTransferSidecarScaleWireVectors

lean_exe gen_mineable_action_admission_vectors where
  root := `Hegemon.Native.GenerateMineableActionAdmissionVectors

lean_exe gen_native_miner_identity_vectors where
  root := `Hegemon.Native.GenerateMinerIdentityVectors

lean_exe gen_mined_work_admission_vectors where
  root := `Hegemon.Native.GenerateMinedWorkAdmissionVectors

lean_exe gen_mined_block_commit_publication_vectors where
  root := `Hegemon.Native.GenerateMinedBlockCommitPublicationVectors

lean_exe gen_block_action_replay_publication_vectors where
  root := `Hegemon.Native.GenerateBlockActionReplayPublicationVectors

lean_exe gen_pending_action_field_projection_vectors where
  root := `Hegemon.Native.GeneratePendingActionFieldProjectionVectors

lean_exe gen_work_template_admission_vectors where
  root := `Hegemon.Native.GenerateWorkTemplateAdmissionVectors

lean_exe gen_recursive_artifact_context_admission_vectors where
  root := `Hegemon.Native.GenerateRecursiveArtifactContextAdmissionVectors

lean_exe gen_resource_budget_admission_vectors where
  root := `Hegemon.Native.GenerateResourceBudgetAdmissionVectors

lean_exe gen_bounded_request_admission_vectors where
  root := `Hegemon.Resource.GenerateBoundedRequestAdmissionVectors

lean_exe gen_preheavy_resource_bound_surface_vectors where
  root := `Hegemon.Native.GeneratePreHeavyWorkResourceBoundSurfaceVectors

lean_exe gen_rpc_admission_vectors where
  root := `Hegemon.Native.GenerateRpcAdmissionVectors

lean_exe gen_sidecar_upload_admission_vectors where
  root := `Hegemon.Native.GenerateSidecarUploadAdmissionVectors

lean_exe gen_staged_ciphertext_reload_vectors where
  root := `Hegemon.Native.GenerateStagedCiphertextReloadVectors

lean_exe gen_staged_proof_reload_vectors where
  root := `Hegemon.Native.GenerateStagedProofReloadVectors

lean_exe gen_stablecoin_policy_authorization_vectors where
  root := `Hegemon.Native.GenerateStablecoinPolicyAuthorizationVectors

lean_exe gen_storage_durability_admission_vectors where
  root := `Hegemon.Native.GenerateStorageDurabilityAdmissionVectors

lean_exe gen_sync_admission_vectors where
  root := `Hegemon.Native.GenerateSyncAdmissionVectors

lean_exe gen_sync_response_import_vectors where
  root := `Hegemon.Native.GenerateSyncResponseImportVectors

lean_exe gen_network_secure_channel_vectors where
  root := `Hegemon.Network.GenerateSecureChannelVectors

lean_exe gen_pq_noise_vectors where
  root := `Hegemon.Network.GeneratePqNoiseVectors

lean_exe gen_frame_resource_admission_vectors where
  root := `Hegemon.Network.GenerateFrameResourceAdmissionVectors

lean_exe gen_peer_store_capacity_admission_vectors where
  root := `Hegemon.Network.GeneratePeerStoreCapacityAdmissionVectors

lean_exe gen_queue_resource_admission_vectors where
  root := `Hegemon.Network.GenerateQueueResourceAdmissionVectors

lean_exe gen_note_ciphertext_wire_vectors where
  root := `Hegemon.Wallet.GenerateNoteCiphertextWireVectors

lean_exe gen_wallet_output_batch_vectors where
  root := `Hegemon.Privacy.GenerateWalletOutputBatchVectors

lean_exe gen_ciphertext_archive_boundary_vectors where
  root := `Hegemon.Privacy.GenerateCiphertextArchiveBoundaryVectors

lean_exe gen_native_tx_leaf_artifact_vectors where
  root := `Hegemon.Native.GenerateTxLeafArtifactVectors

lean_exe gen_native_receipt_root_vectors where
  root := `Hegemon.Native.GenerateReceiptRootVectors

lean_exe gen_transaction_vectors where
  root := `Hegemon.Transaction.GenerateVectors

lean_exe gen_note_commitment_input_vectors where
  root := `Hegemon.Transaction.GenerateNoteCommitmentInputVectors

lean_exe gen_nullifier_input_vectors where
  root := `Hegemon.Transaction.GenerateNullifierInputVectors

lean_exe gen_smallwood_spend_authorization_vectors where
  root := `Hegemon.Transaction.GenerateSmallWoodSpendAuthorizationVectors

lean_exe gen_smallwood_candidate_wrapper_admission_vectors where
  root := `Hegemon.Transaction.GenerateSmallWoodCandidateWrapperAdmissionVectors

lean_exe gen_smallwood_transcript_binding_vectors where
  root := `Hegemon.Transaction.GenerateSmallWoodTranscriptBindingVectors

lean_exe gen_smallwood_public_statement_binding_vectors where
  root := `Hegemon.Transaction.GenerateSmallWoodPublicStatementBindingVectors

lean_exe gen_smallwood_verifier_statement_projection_vectors where
  root := `Hegemon.Transaction.GenerateSmallWoodVerifierStatementProjectionVectors

lean_exe gen_smallwood_recursive_envelope_wire_vectors where
  root := `Hegemon.Transaction.GenerateSmallWoodRecursiveEnvelopeWireVectors

lean_exe gen_merkle_vectors where
  root := `Hegemon.Transaction.GenerateMerkleVectors

lean_exe gen_public_input_vectors where
  root := `Hegemon.Transaction.GeneratePublicInputVectors

lean_exe gen_public_input_binding_vectors where
  root := `Hegemon.Transaction.GeneratePublicInputBindingVectors

lean_exe gen_proof_statement_binding_vectors where
  root := `Hegemon.Transaction.GenerateProofStatementBindingVectors

lean_exe gen_proof_wrapper_admission_vectors where
  root := `Hegemon.Transaction.GenerateProofWrapperAdmissionVectors

lean_exe gen_proof_wrapper_wire_vectors where
  root := `Hegemon.Transaction.GenerateProofWrapperWireVectors

lean_exe gen_statement_hash_vectors where
  root := `Hegemon.Transaction.GenerateStatementHashVectors

lean_exe gen_tx_validity_claim_matching_vectors where
  root := `Hegemon.Transaction.GenerateTxValidityClaimMatchingVectors
