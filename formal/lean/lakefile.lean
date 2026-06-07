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

lean_exe gen_aggregation_v5_vectors where
  root := `Hegemon.Consensus.GenerateAggregationV5Vectors

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

lean_exe gen_recursive_public_replay_vectors where
  root := `Hegemon.Consensus.GenerateRecursivePublicReplayVectors

lean_exe gen_recursive_semantic_input_vectors where
  root := `Hegemon.Consensus.GenerateRecursiveSemanticInputVectors

lean_exe gen_supply_vectors where
  root := `Hegemon.Consensus.GenerateSupplyVectors

lean_exe gen_tree_transition_vectors where
  root := `Hegemon.Consensus.GenerateTreeTransitionVectors

lean_exe gen_version_policy_vectors where
  root := `Hegemon.Consensus.GenerateVersionPolicyVectors

lean_exe gen_action_order_vectors where
  root := `Hegemon.Native.GenerateActionOrderVectors

lean_exe gen_action_hash_admission_vectors where
  root := `Hegemon.Native.GenerateActionHashAdmissionVectors

lean_exe gen_action_scope_admission_vectors where
  root := `Hegemon.Native.GenerateActionScopeAdmissionVectors

lean_exe gen_bridge_action_payload_admission_vectors where
  root := `Hegemon.Native.GenerateBridgeActionPayloadAdmissionVectors

lean_exe gen_transfer_action_payload_admission_vectors where
  root := `Hegemon.Native.GenerateTransferActionPayloadAdmissionVectors

lean_exe gen_block_commitment_admission_vectors where
  root := `Hegemon.Native.GenerateBlockCommitmentAdmissionVectors

lean_exe gen_candidate_artifact_admission_vectors where
  root := `Hegemon.Native.GenerateCandidateArtifactAdmissionVectors

lean_exe gen_candidate_artifact_coupling_admission_vectors where
  root := `Hegemon.Native.GenerateCandidateArtifactCouplingAdmissionVectors

lean_exe gen_coinbase_accounting_admission_vectors where
  root := `Hegemon.Native.GenerateCoinbaseAccountingAdmissionVectors

lean_exe gen_native_tx_leaf_artifact_vectors where
  root := `Hegemon.Native.GenerateTxLeafArtifactVectors

lean_exe gen_native_receipt_root_vectors where
  root := `Hegemon.Native.GenerateReceiptRootVectors

lean_exe gen_transaction_vectors where
  root := `Hegemon.Transaction.GenerateVectors

lean_exe gen_merkle_vectors where
  root := `Hegemon.Transaction.GenerateMerkleVectors

lean_exe gen_public_input_vectors where
  root := `Hegemon.Transaction.GeneratePublicInputVectors

lean_exe gen_public_input_binding_vectors where
  root := `Hegemon.Transaction.GeneratePublicInputBindingVectors

lean_exe gen_statement_hash_vectors where
  root := `Hegemon.Transaction.GenerateStatementHashVectors
