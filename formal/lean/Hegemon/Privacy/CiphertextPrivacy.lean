import Hegemon.Privacy.Observer

namespace Hegemon
namespace Privacy
namespace CiphertextPrivacy

open Hegemon.Privacy.Observer

structure CiphertextPrivacyGame (left right : ShieldedTransactionWorld) where
  leftValid : validObserverChainSurface left
  rightValid : validObserverChainSurface right
  publicInputs : samePublicInputs left right
  summaries : left.ciphertextSummaries = right.ciphertextSummaries
  placement : samePlacement left right
  wireIndistinguishable : Prop
  wireIndistinguishableProof : wireIndistinguishable

structure PrivacyBoundaryAssumptions where
  proofSystemZeroKnowledge : Prop
  walletMetadataHygiene : Prop
  timingAndBatchingPolicy : Prop
  networkMetadataPolicy : Prop

structure PrivacyBoundaryAssumptionProofs
    (assumptions : PrivacyBoundaryAssumptions) : Prop where
  proofSystemZeroKnowledge : assumptions.proofSystemZeroKnowledge
  walletMetadataHygiene : assumptions.walletMetadataHygiene
  timingAndBatchingPolicy : assumptions.timingAndBatchingPolicy
  networkMetadataPolicy : assumptions.networkMetadataPolicy

def samePublicCiphertextShape
    (left right : ShieldedTransactionWorld) : Prop :=
  samePublicInputs left right
    ∧ left.ciphertextSummaries = right.ciphertextSummaries
    ∧ samePlacement left right

structure CiphertextPrivacyBoundaryFacts
    (left right : ShieldedTransactionWorld)
    (wireIndistinguishable : Prop)
    (assumptions : PrivacyBoundaryAssumptions) : Prop where
  publicCiphertextShape : samePublicCiphertextShape left right
  activeOutputCountEq :
    activeOutputCount left.publicInputs =
      activeOutputCount right.publicInputs
  ciphertextSummaryCountEq :
    left.ciphertextSummaries.length =
      right.ciphertextSummaries.length
  summariesHaveChainFormat :
    summariesHaveChainCiphertextFormat left.ciphertextSummaries
      ∧ summariesHaveChainCiphertextFormat right.ciphertextSummaries
  publicMetadataLeakage : samePublicMetadataLeakage left right
  batchTimingLeakage : sameBatchTimingLeakage left right
  rawWireIndistinguishable : wireIndistinguishable
  proofSystemZeroKnowledge : assumptions.proofSystemZeroKnowledge
  walletMetadataHygiene : assumptions.walletMetadataHygiene
  timingAndBatchingPolicy : assumptions.timingAndBatchingPolicy
  networkMetadataPolicy : assumptions.networkMetadataPolicy
  leftObserverIgnoresSecrets :
    ∀ privateWitness proverRandomnessSeed,
      observerView
          { left with
            privateWitness := privateWitness
            proverRandomnessSeed := proverRandomnessSeed } =
        observerView left
  rightObserverIgnoresSecrets :
    ∀ privateWitness proverRandomnessSeed,
      observerView
          { right with
            privateWitness := privateWitness
            proverRandomnessSeed := proverRandomnessSeed } =
        observerView right
  leftPublicMetadataIgnoresSecrets :
    ∀ privateWitness proverRandomnessSeed,
      publicMetadataView
          { left with
            privateWitness := privateWitness
            proverRandomnessSeed := proverRandomnessSeed } =
        publicMetadataView left
  rightPublicMetadataIgnoresSecrets :
    ∀ privateWitness proverRandomnessSeed,
      publicMetadataView
          { right with
            privateWitness := privateWitness
            proverRandomnessSeed := proverRandomnessSeed } =
        publicMetadataView right
  leftBatchTimingIgnoresSecrets :
    ∀ privateWitness proverRandomnessSeed,
      batchTimingView
          { left with
            privateWitness := privateWitness
            proverRandomnessSeed := proverRandomnessSeed } =
        batchTimingView left
  rightBatchTimingIgnoresSecrets :
    ∀ privateWitness proverRandomnessSeed,
      batchTimingView
          { right with
            privateWitness := privateWitness
            proverRandomnessSeed := proverRandomnessSeed } =
        batchTimingView right
  leftObserverIgnoresLocalActionMetadata :
    ∀ localActionMetadata,
      observerView
          { left with
            localActionMetadata := localActionMetadata } =
        observerView left
  rightObserverIgnoresLocalActionMetadata :
    ∀ localActionMetadata,
      observerView
          { right with
            localActionMetadata := localActionMetadata } =
        observerView right
  leftPublicMetadataIgnoresLocalActionMetadata :
    ∀ localActionMetadata,
      publicMetadataView
          { left with
            localActionMetadata := localActionMetadata } =
        publicMetadataView left
  rightPublicMetadataIgnoresLocalActionMetadata :
    ∀ localActionMetadata,
      publicMetadataView
          { right with
            localActionMetadata := localActionMetadata } =
        publicMetadataView right
  leftBatchTimingIgnoresLocalActionMetadata :
    ∀ localActionMetadata,
      batchTimingView
          { left with
            localActionMetadata := localActionMetadata } =
        batchTimingView left
  rightBatchTimingIgnoresLocalActionMetadata :
    ∀ localActionMetadata,
      batchTimingView
          { right with
            localActionMetadata := localActionMetadata } =
        batchTimingView right
  leftObserverIgnoresLocalNetworkMetadata :
    ∀ localNetworkMetadata,
      observerView
          { left with
            localNetworkMetadata := localNetworkMetadata } =
        observerView left
  rightObserverIgnoresLocalNetworkMetadata :
    ∀ localNetworkMetadata,
      observerView
          { right with
            localNetworkMetadata := localNetworkMetadata } =
        observerView right
  leftPublicMetadataIgnoresLocalNetworkMetadata :
    ∀ localNetworkMetadata,
      publicMetadataView
          { left with
            localNetworkMetadata := localNetworkMetadata } =
        publicMetadataView left
  rightPublicMetadataIgnoresLocalNetworkMetadata :
    ∀ localNetworkMetadata,
      publicMetadataView
          { right with
            localNetworkMetadata := localNetworkMetadata } =
        publicMetadataView right
  leftBatchTimingIgnoresLocalNetworkMetadata :
    ∀ localNetworkMetadata,
      batchTimingView
          { left with
            localNetworkMetadata := localNetworkMetadata } =
        batchTimingView left
  rightBatchTimingIgnoresLocalNetworkMetadata :
    ∀ localNetworkMetadata,
      batchTimingView
          { right with
            localNetworkMetadata := localNetworkMetadata } =
        batchTimingView right

structure SecretResamplingPrivacyFacts
    (left right : ShieldedTransactionWorld)
    (wireIndistinguishable : Prop)
    (assumptions : PrivacyBoundaryAssumptions) : Prop where
  publicCiphertextShape : samePublicCiphertextShape left right
  publicMetadataLeakage : samePublicMetadataLeakage left right
  batchTimingLeakage : sameBatchTimingLeakage left right
  rawWireIndistinguishable : wireIndistinguishable
  proofSystemZeroKnowledge : assumptions.proofSystemZeroKnowledge
  walletMetadataHygiene : assumptions.walletMetadataHygiene
  timingAndBatchingPolicy : assumptions.timingAndBatchingPolicy
  networkMetadataPolicy : assumptions.networkMetadataPolicy
  publicMetadataStableUnderIndependentSecretResampling :
    ∀ leftPrivateWitness rightPrivateWitness
      leftProverRandomnessSeed rightProverRandomnessSeed,
      samePublicMetadataLeakage
        { left with
          privateWitness := leftPrivateWitness
          proverRandomnessSeed := leftProverRandomnessSeed }
        { right with
          privateWitness := rightPrivateWitness
          proverRandomnessSeed := rightProverRandomnessSeed }
  batchTimingStableUnderIndependentSecretResampling :
    ∀ leftPrivateWitness rightPrivateWitness
      leftProverRandomnessSeed rightProverRandomnessSeed,
      sameBatchTimingLeakage
        { left with
          privateWitness := leftPrivateWitness
          proverRandomnessSeed := leftProverRandomnessSeed }
        { right with
          privateWitness := rightPrivateWitness
          proverRandomnessSeed := rightProverRandomnessSeed }
  publicMetadataStableUnderIndependentSecretAndLocalResampling :
    ∀ leftPrivateWitness rightPrivateWitness
      leftProverRandomnessSeed rightProverRandomnessSeed
      leftLocal rightLocal,
      samePublicMetadataLeakage
        { left with
          privateWitness := leftPrivateWitness
          proverRandomnessSeed := leftProverRandomnessSeed
          localActionMetadata := leftLocal }
        { right with
          privateWitness := rightPrivateWitness
          proverRandomnessSeed := rightProverRandomnessSeed
          localActionMetadata := rightLocal }
  batchTimingStableUnderIndependentSecretAndLocalResampling :
    ∀ leftPrivateWitness rightPrivateWitness
      leftProverRandomnessSeed rightProverRandomnessSeed
      leftLocal rightLocal,
      sameBatchTimingLeakage
        { left with
          privateWitness := leftPrivateWitness
          proverRandomnessSeed := leftProverRandomnessSeed
          localActionMetadata := leftLocal }
        { right with
          privateWitness := rightPrivateWitness
          proverRandomnessSeed := rightProverRandomnessSeed
          localActionMetadata := rightLocal }
  publicMetadataStableUnderIndependentSecretAndLocalNetworkResampling :
    ∀ leftPrivateWitness rightPrivateWitness
      leftProverRandomnessSeed rightProverRandomnessSeed
      leftNetwork rightNetwork,
      samePublicMetadataLeakage
        { left with
          privateWitness := leftPrivateWitness
          proverRandomnessSeed := leftProverRandomnessSeed
          localNetworkMetadata := leftNetwork }
        { right with
          privateWitness := rightPrivateWitness
          proverRandomnessSeed := rightProverRandomnessSeed
          localNetworkMetadata := rightNetwork }
  batchTimingStableUnderIndependentSecretAndLocalNetworkResampling :
    ∀ leftPrivateWitness rightPrivateWitness
      leftProverRandomnessSeed rightProverRandomnessSeed
      leftNetwork rightNetwork,
      sameBatchTimingLeakage
        { left with
          privateWitness := leftPrivateWitness
          proverRandomnessSeed := leftProverRandomnessSeed
          localNetworkMetadata := leftNetwork }
        { right with
          privateWitness := rightPrivateWitness
          proverRandomnessSeed := rightProverRandomnessSeed
          localNetworkMetadata := rightNetwork }

structure RawWireExcludedPublicLeakageFacts
    (left right : ShieldedTransactionWorld)
    (wireIndistinguishable : Prop) : Prop where
  publicMetadataLeakage : samePublicMetadataLeakage left right
  batchTimingLeakage : sameBatchTimingLeakage left right
  rawWireIndistinguishable : wireIndistinguishable
  sameWireDischargesFullObserverLeakage :
    left.ciphertextBytes = right.ciphertextBytes -> sameAllowedLeakage left right

structure CiphertextPrivacyOpenAssumptionBoundaryFacts
    (left right : ShieldedTransactionWorld)
    (wireIndistinguishable : Prop)
    (assumptions : PrivacyBoundaryAssumptions) : Prop where
  deterministicPublicBoundary :
    CiphertextPrivacyBoundaryFacts left right wireIndistinguishable assumptions
  secretResamplingBoundary :
    SecretResamplingPrivacyFacts left right wireIndistinguishable assumptions
  rawWireExcludedPublicLeakageBoundary :
    RawWireExcludedPublicLeakageFacts left right wireIndistinguishable
  sameWireDischargesRawWirePrivacy :
    left.ciphertextBytes = right.ciphertextBytes -> sameAllowedLeakage left right
  rawWireIndistinguishable : wireIndistinguishable
  proofSystemZeroKnowledge : assumptions.proofSystemZeroKnowledge
  walletMetadataHygiene : assumptions.walletMetadataHygiene
  timingAndBatchingPolicy : assumptions.timingAndBatchingPolicy
  networkMetadataPolicy : assumptions.networkMetadataPolicy

theorem ciphertext_privacy_game_preserves_public_ciphertext_shape
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    samePublicCiphertextShape left right := by
  exact ⟨game.publicInputs, game.summaries, game.placement⟩

theorem ciphertext_privacy_game_preserves_active_output_count
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    activeOutputCount left.publicInputs =
      activeOutputCount right.publicInputs :=
  same_public_inputs_active_output_count game.publicInputs

theorem ciphertext_privacy_game_preserves_ciphertext_summary_count
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    left.ciphertextSummaries.length =
      right.ciphertextSummaries.length := by
  rw [game.summaries]

theorem ciphertext_privacy_game_summaries_have_chain_format
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    summariesHaveChainCiphertextFormat left.ciphertextSummaries
      ∧ summariesHaveChainCiphertextFormat right.ciphertextSummaries := by
  exact
    ⟨valid_observer_chain_surface_summaries_have_chain_format game.leftValid,
      valid_observer_chain_surface_summaries_have_chain_format game.rightValid⟩

theorem ciphertext_privacy_game_preserves_public_metadata_leakage
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    samePublicMetadataLeakage left right := by
  exact
    same_public_metadata_leakage_of_public_summaries_and_placement
      game.publicInputs
      game.summaries
      game.placement

theorem ciphertext_privacy_game_preserves_batch_timing_leakage
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    sameBatchTimingLeakage left right := by
  exact
    same_batch_timing_leakage_of_valid_public_inputs_and_placement
      game.leftValid
      game.rightValid
      game.publicInputs
      game.placement

theorem ciphertext_privacy_game_only_open_crypto_obligation
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    game.wireIndistinguishable := by
  exact game.wireIndistinguishableProof

theorem ciphertext_privacy_game_unlinkability_reduces_to_raw_wire_indistinguishability
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    samePublicCiphertextShape left right
      ∧ samePublicMetadataLeakage left right
      ∧ sameBatchTimingLeakage left right
      ∧ game.wireIndistinguishable := by
  exact
    ⟨ciphertext_privacy_game_preserves_public_ciphertext_shape game,
      ciphertext_privacy_game_preserves_public_metadata_leakage game,
      ciphertext_privacy_game_preserves_batch_timing_leakage game,
      ciphertext_privacy_game_only_open_crypto_obligation game⟩

theorem ciphertext_privacy_game_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions) :
    CiphertextPrivacyBoundaryFacts
      left
      right
      game.wireIndistinguishable
      assumptions := by
  exact {
    publicCiphertextShape :=
      ciphertext_privacy_game_preserves_public_ciphertext_shape game
    activeOutputCountEq :=
      ciphertext_privacy_game_preserves_active_output_count game
    ciphertextSummaryCountEq :=
      ciphertext_privacy_game_preserves_ciphertext_summary_count game
    summariesHaveChainFormat :=
      ciphertext_privacy_game_summaries_have_chain_format game
    publicMetadataLeakage :=
      ciphertext_privacy_game_preserves_public_metadata_leakage game
    batchTimingLeakage :=
      ciphertext_privacy_game_preserves_batch_timing_leakage game
    rawWireIndistinguishable :=
      ciphertext_privacy_game_only_open_crypto_obligation game
    proofSystemZeroKnowledge :=
      assumptionProofs.proofSystemZeroKnowledge
    walletMetadataHygiene :=
      assumptionProofs.walletMetadataHygiene
    timingAndBatchingPolicy :=
      assumptionProofs.timingAndBatchingPolicy
    networkMetadataPolicy :=
      assumptionProofs.networkMetadataPolicy
    leftObserverIgnoresSecrets :=
      fun privateWitness proverRandomnessSeed =>
        observer_view_ignores_private_witness_and_randomness
          left
          privateWitness
          proverRandomnessSeed
    rightObserverIgnoresSecrets :=
      fun privateWitness proverRandomnessSeed =>
        observer_view_ignores_private_witness_and_randomness
          right
          privateWitness
          proverRandomnessSeed
    leftPublicMetadataIgnoresSecrets :=
      fun privateWitness proverRandomnessSeed =>
        public_metadata_view_ignores_private_witness_and_randomness
          left
          privateWitness
          proverRandomnessSeed
    rightPublicMetadataIgnoresSecrets :=
      fun privateWitness proverRandomnessSeed =>
        public_metadata_view_ignores_private_witness_and_randomness
          right
          privateWitness
          proverRandomnessSeed
    leftBatchTimingIgnoresSecrets :=
      fun privateWitness proverRandomnessSeed =>
        batch_timing_view_ignores_private_witness_and_randomness
          left
          privateWitness
          proverRandomnessSeed
    rightBatchTimingIgnoresSecrets :=
      fun privateWitness proverRandomnessSeed =>
        batch_timing_view_ignores_private_witness_and_randomness
          right
          privateWitness
          proverRandomnessSeed
    leftObserverIgnoresLocalActionMetadata :=
      fun localActionMetadata =>
        observer_view_ignores_local_action_metadata
          left
          localActionMetadata
    rightObserverIgnoresLocalActionMetadata :=
      fun localActionMetadata =>
        observer_view_ignores_local_action_metadata
          right
          localActionMetadata
    leftPublicMetadataIgnoresLocalActionMetadata :=
      fun localActionMetadata =>
        public_metadata_view_ignores_local_action_metadata
          left
          localActionMetadata
    rightPublicMetadataIgnoresLocalActionMetadata :=
      fun localActionMetadata =>
        public_metadata_view_ignores_local_action_metadata
          right
          localActionMetadata
    leftBatchTimingIgnoresLocalActionMetadata :=
      fun localActionMetadata =>
        batch_timing_view_ignores_local_action_metadata
          left
          localActionMetadata
    rightBatchTimingIgnoresLocalActionMetadata :=
      fun localActionMetadata =>
        batch_timing_view_ignores_local_action_metadata
          right
          localActionMetadata
    leftObserverIgnoresLocalNetworkMetadata :=
      fun localNetworkMetadata =>
        observer_view_ignores_local_network_metadata
          left
          localNetworkMetadata
    rightObserverIgnoresLocalNetworkMetadata :=
      fun localNetworkMetadata =>
        observer_view_ignores_local_network_metadata
          right
          localNetworkMetadata
    leftPublicMetadataIgnoresLocalNetworkMetadata :=
      fun localNetworkMetadata =>
        public_metadata_view_ignores_local_network_metadata
          left
          localNetworkMetadata
    rightPublicMetadataIgnoresLocalNetworkMetadata :=
      fun localNetworkMetadata =>
        public_metadata_view_ignores_local_network_metadata
          right
          localNetworkMetadata
    leftBatchTimingIgnoresLocalNetworkMetadata :=
      fun localNetworkMetadata =>
        batch_timing_view_ignores_local_network_metadata
          left
          localNetworkMetadata
    rightBatchTimingIgnoresLocalNetworkMetadata :=
      fun localNetworkMetadata =>
        batch_timing_view_ignores_local_network_metadata
          right
          localNetworkMetadata
  }

theorem ciphertext_privacy_game_secret_resampling_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions) :
    SecretResamplingPrivacyFacts
      left
      right
      game.wireIndistinguishable
      assumptions := by
  have boundary :=
    ciphertext_privacy_game_boundary_facts
      game
      assumptionProofs
  exact {
    publicCiphertextShape := boundary.publicCiphertextShape
    publicMetadataLeakage := boundary.publicMetadataLeakage
    batchTimingLeakage := boundary.batchTimingLeakage
    rawWireIndistinguishable := boundary.rawWireIndistinguishable
    proofSystemZeroKnowledge := boundary.proofSystemZeroKnowledge
    walletMetadataHygiene := boundary.walletMetadataHygiene
    timingAndBatchingPolicy := boundary.timingAndBatchingPolicy
    networkMetadataPolicy := boundary.networkMetadataPolicy
    publicMetadataStableUnderIndependentSecretResampling :=
      fun leftPrivateWitness rightPrivateWitness
        leftProverRandomnessSeed rightProverRandomnessSeed => by
        unfold samePublicMetadataLeakage
        calc
          publicMetadataView
              { left with
                privateWitness := leftPrivateWitness
                proverRandomnessSeed := leftProverRandomnessSeed } =
            publicMetadataView left :=
              boundary.leftPublicMetadataIgnoresSecrets
                leftPrivateWitness
                leftProverRandomnessSeed
          _ = publicMetadataView right :=
              boundary.publicMetadataLeakage
          _ =
            publicMetadataView
              { right with
                privateWitness := rightPrivateWitness
                proverRandomnessSeed := rightProverRandomnessSeed } :=
              (boundary.rightPublicMetadataIgnoresSecrets
                rightPrivateWitness
                rightProverRandomnessSeed).symm
    batchTimingStableUnderIndependentSecretResampling :=
      fun leftPrivateWitness rightPrivateWitness
        leftProverRandomnessSeed rightProverRandomnessSeed => by
        unfold sameBatchTimingLeakage
        calc
          batchTimingView
              { left with
                privateWitness := leftPrivateWitness
                proverRandomnessSeed := leftProverRandomnessSeed } =
            batchTimingView left :=
              boundary.leftBatchTimingIgnoresSecrets
                leftPrivateWitness
                leftProverRandomnessSeed
          _ = batchTimingView right :=
              boundary.batchTimingLeakage
          _ =
            batchTimingView
              { right with
                privateWitness := rightPrivateWitness
                proverRandomnessSeed := rightProverRandomnessSeed } :=
              (boundary.rightBatchTimingIgnoresSecrets
                rightPrivateWitness
                rightProverRandomnessSeed).symm
    publicMetadataStableUnderIndependentSecretAndLocalResampling :=
      fun leftPrivateWitness rightPrivateWitness
        leftProverRandomnessSeed rightProverRandomnessSeed
        leftLocal rightLocal => by
        unfold samePublicMetadataLeakage
        calc
          publicMetadataView
              { left with
                privateWitness := leftPrivateWitness
                proverRandomnessSeed := leftProverRandomnessSeed
                localActionMetadata := leftLocal } =
            publicMetadataView left :=
              public_metadata_view_ignores_private_witness_randomness_and_local_metadata
                left
                leftPrivateWitness
                leftProverRandomnessSeed
                leftLocal
          _ = publicMetadataView right :=
              boundary.publicMetadataLeakage
          _ =
            publicMetadataView
              { right with
                privateWitness := rightPrivateWitness
                proverRandomnessSeed := rightProverRandomnessSeed
                localActionMetadata := rightLocal } :=
              (public_metadata_view_ignores_private_witness_randomness_and_local_metadata
                right
                rightPrivateWitness
                rightProverRandomnessSeed
                rightLocal).symm
    batchTimingStableUnderIndependentSecretAndLocalResampling :=
      fun leftPrivateWitness rightPrivateWitness
        leftProverRandomnessSeed rightProverRandomnessSeed
        leftLocal rightLocal => by
        unfold sameBatchTimingLeakage
        calc
          batchTimingView
              { left with
                privateWitness := leftPrivateWitness
                proverRandomnessSeed := leftProverRandomnessSeed
                localActionMetadata := leftLocal } =
            batchTimingView left :=
              batch_timing_view_ignores_private_witness_randomness_and_local_metadata
                left
                leftPrivateWitness
                leftProverRandomnessSeed
                leftLocal
          _ = batchTimingView right :=
              boundary.batchTimingLeakage
          _ =
            batchTimingView
              { right with
                privateWitness := rightPrivateWitness
                proverRandomnessSeed := rightProverRandomnessSeed
                localActionMetadata := rightLocal } :=
              (batch_timing_view_ignores_private_witness_randomness_and_local_metadata
                right
                rightPrivateWitness
                rightProverRandomnessSeed
                rightLocal).symm
    publicMetadataStableUnderIndependentSecretAndLocalNetworkResampling :=
      fun leftPrivateWitness rightPrivateWitness
        leftProverRandomnessSeed rightProverRandomnessSeed
        leftNetwork rightNetwork => by
        unfold samePublicMetadataLeakage
        calc
          publicMetadataView
              { left with
                privateWitness := leftPrivateWitness
                proverRandomnessSeed := leftProverRandomnessSeed
                localNetworkMetadata := leftNetwork } =
            publicMetadataView left :=
              public_metadata_view_ignores_private_witness_randomness_and_local_network_metadata
                left
                leftPrivateWitness
                leftProverRandomnessSeed
                leftNetwork
          _ = publicMetadataView right :=
              boundary.publicMetadataLeakage
          _ =
            publicMetadataView
              { right with
                privateWitness := rightPrivateWitness
                proverRandomnessSeed := rightProverRandomnessSeed
                localNetworkMetadata := rightNetwork } :=
              (public_metadata_view_ignores_private_witness_randomness_and_local_network_metadata
                right
                rightPrivateWitness
                rightProverRandomnessSeed
                rightNetwork).symm
    batchTimingStableUnderIndependentSecretAndLocalNetworkResampling :=
      fun leftPrivateWitness rightPrivateWitness
        leftProverRandomnessSeed rightProverRandomnessSeed
        leftNetwork rightNetwork => by
        unfold sameBatchTimingLeakage
        calc
          batchTimingView
              { left with
                privateWitness := leftPrivateWitness
                proverRandomnessSeed := leftProverRandomnessSeed
                localNetworkMetadata := leftNetwork } =
            batchTimingView left :=
              batch_timing_view_ignores_private_witness_randomness_and_local_network_metadata
                left
                leftPrivateWitness
                leftProverRandomnessSeed
                leftNetwork
          _ = batchTimingView right :=
              boundary.batchTimingLeakage
          _ =
            batchTimingView
              { right with
                privateWitness := rightPrivateWitness
                proverRandomnessSeed := rightProverRandomnessSeed
                localNetworkMetadata := rightNetwork } :=
              (batch_timing_view_ignores_private_witness_randomness_and_local_network_metadata
                right
                rightPrivateWitness
                rightProverRandomnessSeed
                rightNetwork).symm
  }

def buildCiphertextPrivacyGame
    {left right : ShieldedTransactionWorld}
    (leftValid : validObserverChainSurface left)
    (rightValid : validObserverChainSurface right)
    (publicInputs : samePublicInputs left right)
    (summaries : left.ciphertextSummaries = right.ciphertextSummaries)
    (placement : samePlacement left right)
    (wireIndistinguishable : Prop)
    (wireIndistinguishableProof : wireIndistinguishable) :
    CiphertextPrivacyGame left right := by
  exact
    { leftValid := leftValid
      rightValid := rightValid
      publicInputs := publicInputs
      summaries := summaries
      placement := placement
      wireIndistinguishable := wireIndistinguishable
      wireIndistinguishableProof := wireIndistinguishableProof }

def ciphertext_privacy_game_resample_local_action_metadata
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    (leftLocal rightLocal : LocalActionMetadata) :
    CiphertextPrivacyGame
      { left with localActionMetadata := leftLocal }
      { right with localActionMetadata := rightLocal } := by
  exact
    { leftValid :=
        valid_observer_chain_surface_stable_under_local_action_metadata
          game.leftValid
          leftLocal
      rightValid :=
        valid_observer_chain_surface_stable_under_local_action_metadata
          game.rightValid
          rightLocal
      publicInputs := by
        simpa [samePublicInputs] using game.publicInputs
      summaries := by
        simpa using game.summaries
      placement := by
        simpa [samePlacement] using game.placement
      wireIndistinguishable := game.wireIndistinguishable
      wireIndistinguishableProof := game.wireIndistinguishableProof }

theorem ciphertext_privacy_game_local_action_metadata_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions)
    (leftLocal rightLocal : LocalActionMetadata) :
    samePublicMetadataLeakage
        { left with localActionMetadata := leftLocal }
        { right with localActionMetadata := rightLocal }
      ∧ sameBatchTimingLeakage
        { left with localActionMetadata := leftLocal }
        { right with localActionMetadata := rightLocal }
      ∧ game.wireIndistinguishable
      ∧ assumptions.proofSystemZeroKnowledge
      ∧ assumptions.walletMetadataHygiene
      ∧ assumptions.timingAndBatchingPolicy
      ∧ assumptions.networkMetadataPolicy := by
  exact
    ⟨same_public_metadata_leakage_stable_under_local_action_metadata
        (ciphertext_privacy_game_preserves_public_metadata_leakage game)
        leftLocal
        rightLocal,
      same_batch_timing_leakage_stable_under_local_action_metadata
        (ciphertext_privacy_game_preserves_batch_timing_leakage game)
        leftLocal
        rightLocal,
      ciphertext_privacy_game_only_open_crypto_obligation game,
      assumptionProofs.proofSystemZeroKnowledge,
      assumptionProofs.walletMetadataHygiene,
      assumptionProofs.timingAndBatchingPolicy,
      assumptionProofs.networkMetadataPolicy⟩

def ciphertext_privacy_game_resample_local_address_metadata
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    (leftAddress rightAddress : LocalAddressMetadata) :
    CiphertextPrivacyGame
      { left with localAddressMetadata := leftAddress }
      { right with localAddressMetadata := rightAddress } := by
  exact
    { leftValid :=
        valid_observer_chain_surface_stable_under_local_address_metadata
          game.leftValid
          leftAddress
      rightValid :=
        valid_observer_chain_surface_stable_under_local_address_metadata
          game.rightValid
          rightAddress
      publicInputs := by
        simpa [samePublicInputs] using game.publicInputs
      summaries := by
        simpa using game.summaries
      placement := by
        simpa [samePlacement] using game.placement
      wireIndistinguishable := game.wireIndistinguishable
      wireIndistinguishableProof := game.wireIndistinguishableProof }

theorem ciphertext_privacy_game_local_address_metadata_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions)
    (leftAddress rightAddress : LocalAddressMetadata) :
    samePublicMetadataLeakage
        { left with localAddressMetadata := leftAddress }
        { right with localAddressMetadata := rightAddress }
      ∧ sameBatchTimingLeakage
        { left with localAddressMetadata := leftAddress }
        { right with localAddressMetadata := rightAddress }
      ∧ game.wireIndistinguishable
      ∧ assumptions.proofSystemZeroKnowledge
      ∧ assumptions.walletMetadataHygiene
      ∧ assumptions.timingAndBatchingPolicy
      ∧ assumptions.networkMetadataPolicy := by
  exact
    ⟨same_public_metadata_leakage_stable_under_local_address_metadata
        (ciphertext_privacy_game_preserves_public_metadata_leakage game)
        leftAddress
        rightAddress,
      same_batch_timing_leakage_stable_under_local_address_metadata
        (ciphertext_privacy_game_preserves_batch_timing_leakage game)
        leftAddress
        rightAddress,
      ciphertext_privacy_game_only_open_crypto_obligation game,
      assumptionProofs.proofSystemZeroKnowledge,
      assumptionProofs.walletMetadataHygiene,
      assumptionProofs.timingAndBatchingPolicy,
      assumptionProofs.networkMetadataPolicy⟩

def ciphertext_privacy_game_resample_local_network_metadata
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    CiphertextPrivacyGame
      { left with localNetworkMetadata := leftNetwork }
      { right with localNetworkMetadata := rightNetwork } := by
  exact
    { leftValid :=
        valid_observer_chain_surface_stable_under_local_network_metadata
          game.leftValid
          leftNetwork
      rightValid :=
        valid_observer_chain_surface_stable_under_local_network_metadata
          game.rightValid
          rightNetwork
      publicInputs := by
        simpa [samePublicInputs] using game.publicInputs
      summaries := by
        simpa using game.summaries
      placement := by
        simpa [samePlacement] using game.placement
      wireIndistinguishable := game.wireIndistinguishable
      wireIndistinguishableProof := game.wireIndistinguishableProof }

def ciphertext_privacy_game_resample_all_local_metadata
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    (leftLocal rightLocal : LocalActionMetadata)
    (leftAddress rightAddress : LocalAddressMetadata)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    CiphertextPrivacyGame
      { left with
        localActionMetadata := leftLocal
        localAddressMetadata := leftAddress
        localNetworkMetadata := leftNetwork }
      { right with
        localActionMetadata := rightLocal
        localAddressMetadata := rightAddress
        localNetworkMetadata := rightNetwork } := by
  exact
    { leftValid :=
        valid_observer_chain_surface_stable_under_all_local_metadata
          game.leftValid
          leftLocal
          leftAddress
          leftNetwork
      rightValid :=
        valid_observer_chain_surface_stable_under_all_local_metadata
          game.rightValid
          rightLocal
          rightAddress
          rightNetwork
      publicInputs := by
        simpa [samePublicInputs] using game.publicInputs
      summaries := by
        simpa using game.summaries
      placement := by
        simpa [samePlacement] using game.placement
      wireIndistinguishable := game.wireIndistinguishable
      wireIndistinguishableProof := game.wireIndistinguishableProof }

theorem ciphertext_privacy_game_local_network_metadata_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    samePublicMetadataLeakage
        { left with localNetworkMetadata := leftNetwork }
        { right with localNetworkMetadata := rightNetwork }
      ∧ sameBatchTimingLeakage
        { left with localNetworkMetadata := leftNetwork }
        { right with localNetworkMetadata := rightNetwork }
      ∧ game.wireIndistinguishable
      ∧ assumptions.proofSystemZeroKnowledge
      ∧ assumptions.walletMetadataHygiene
      ∧ assumptions.timingAndBatchingPolicy
      ∧ assumptions.networkMetadataPolicy := by
  exact
    ⟨same_public_metadata_leakage_stable_under_local_network_metadata
        (ciphertext_privacy_game_preserves_public_metadata_leakage game)
        leftNetwork
        rightNetwork,
      same_batch_timing_leakage_stable_under_local_network_metadata
        (ciphertext_privacy_game_preserves_batch_timing_leakage game)
        leftNetwork
        rightNetwork,
      ciphertext_privacy_game_only_open_crypto_obligation game,
      assumptionProofs.proofSystemZeroKnowledge,
      assumptionProofs.walletMetadataHygiene,
      assumptionProofs.timingAndBatchingPolicy,
      assumptionProofs.networkMetadataPolicy⟩

theorem ciphertext_privacy_game_all_local_metadata_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions)
    (leftLocal rightLocal : LocalActionMetadata)
    (leftAddress rightAddress : LocalAddressMetadata)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    samePublicMetadataLeakage
        { left with
          localActionMetadata := leftLocal
          localAddressMetadata := leftAddress
          localNetworkMetadata := leftNetwork }
        { right with
          localActionMetadata := rightLocal
          localAddressMetadata := rightAddress
          localNetworkMetadata := rightNetwork }
      ∧ sameBatchTimingLeakage
        { left with
          localActionMetadata := leftLocal
          localAddressMetadata := leftAddress
          localNetworkMetadata := leftNetwork }
        { right with
          localActionMetadata := rightLocal
          localAddressMetadata := rightAddress
          localNetworkMetadata := rightNetwork }
      ∧ game.wireIndistinguishable
      ∧ assumptions.proofSystemZeroKnowledge
      ∧ assumptions.walletMetadataHygiene
      ∧ assumptions.timingAndBatchingPolicy
      ∧ assumptions.networkMetadataPolicy := by
  exact
    ⟨same_public_metadata_leakage_stable_under_all_local_metadata
        (ciphertext_privacy_game_preserves_public_metadata_leakage game)
        leftLocal
        rightLocal
        leftAddress
        rightAddress
        leftNetwork
        rightNetwork,
      same_batch_timing_leakage_stable_under_all_local_metadata
        (ciphertext_privacy_game_preserves_batch_timing_leakage game)
        leftLocal
        rightLocal
        leftAddress
        rightAddress
        leftNetwork
        rightNetwork,
      ciphertext_privacy_game_only_open_crypto_obligation game,
      assumptionProofs.proofSystemZeroKnowledge,
      assumptionProofs.walletMetadataHygiene,
      assumptionProofs.timingAndBatchingPolicy,
      assumptionProofs.networkMetadataPolicy⟩

theorem same_wire_ciphertext_privacy_game_implies_same_allowed_leakage
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    (sameWire : left.ciphertextBytes = right.ciphertextBytes) :
    sameAllowedLeakage left right := by
  exact
    same_allowed_leakage_of_valid_observer_chain_surfaces
      game.leftValid
      game.rightValid
      game.publicInputs
      sameWire
      game.placement

theorem ciphertext_privacy_game_raw_wire_excluded_public_leakage_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    RawWireExcludedPublicLeakageFacts
      left
      right
      game.wireIndistinguishable := by
  exact {
    publicMetadataLeakage :=
      ciphertext_privacy_game_preserves_public_metadata_leakage game
    batchTimingLeakage :=
      ciphertext_privacy_game_preserves_batch_timing_leakage game
    rawWireIndistinguishable :=
      ciphertext_privacy_game_only_open_crypto_obligation game
    sameWireDischargesFullObserverLeakage :=
      fun sameWire =>
        same_wire_ciphertext_privacy_game_implies_same_allowed_leakage
          game
          sameWire
  }

theorem ciphertext_privacy_game_open_assumption_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions) :
    CiphertextPrivacyOpenAssumptionBoundaryFacts
      left
      right
      game.wireIndistinguishable
      assumptions := by
  have boundary :=
    ciphertext_privacy_game_boundary_facts
      game
      assumptionProofs
  exact {
    deterministicPublicBoundary := boundary
    secretResamplingBoundary :=
      ciphertext_privacy_game_secret_resampling_boundary_facts
        game
        assumptionProofs
    rawWireExcludedPublicLeakageBoundary :=
      ciphertext_privacy_game_raw_wire_excluded_public_leakage_facts game
    sameWireDischargesRawWirePrivacy :=
      fun sameWire =>
        same_wire_ciphertext_privacy_game_implies_same_allowed_leakage
          game
          sameWire
    rawWireIndistinguishable := boundary.rawWireIndistinguishable
    proofSystemZeroKnowledge := boundary.proofSystemZeroKnowledge
    walletMetadataHygiene := boundary.walletMetadataHygiene
    timingAndBatchingPolicy := boundary.timingAndBatchingPolicy
    networkMetadataPolicy := boundary.networkMetadataPolicy
  }

theorem ciphertext_privacy_game_local_action_metadata_open_assumption_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions)
    (leftLocal rightLocal : LocalActionMetadata) :
    CiphertextPrivacyOpenAssumptionBoundaryFacts
      { left with localActionMetadata := leftLocal }
      { right with localActionMetadata := rightLocal }
      game.wireIndistinguishable
      assumptions := by
  simpa [ciphertext_privacy_game_resample_local_action_metadata] using
    ciphertext_privacy_game_open_assumption_boundary_facts
      (ciphertext_privacy_game_resample_local_action_metadata
        game
        leftLocal
        rightLocal)
      assumptionProofs

theorem ciphertext_privacy_game_local_address_metadata_open_assumption_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions)
    (leftAddress rightAddress : LocalAddressMetadata) :
    CiphertextPrivacyOpenAssumptionBoundaryFacts
      { left with localAddressMetadata := leftAddress }
      { right with localAddressMetadata := rightAddress }
      game.wireIndistinguishable
      assumptions := by
  simpa [ciphertext_privacy_game_resample_local_address_metadata] using
    ciphertext_privacy_game_open_assumption_boundary_facts
      (ciphertext_privacy_game_resample_local_address_metadata
        game
        leftAddress
        rightAddress)
      assumptionProofs

theorem ciphertext_privacy_game_local_network_metadata_open_assumption_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    CiphertextPrivacyOpenAssumptionBoundaryFacts
      { left with localNetworkMetadata := leftNetwork }
      { right with localNetworkMetadata := rightNetwork }
      game.wireIndistinguishable
      assumptions := by
  simpa [ciphertext_privacy_game_resample_local_network_metadata] using
    ciphertext_privacy_game_open_assumption_boundary_facts
      (ciphertext_privacy_game_resample_local_network_metadata
        game
        leftNetwork
        rightNetwork)
      assumptionProofs

theorem ciphertext_privacy_game_all_local_metadata_open_assumption_boundary_facts
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right)
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions)
    (leftLocal rightLocal : LocalActionMetadata)
    (leftAddress rightAddress : LocalAddressMetadata)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    CiphertextPrivacyOpenAssumptionBoundaryFacts
      { left with
        localActionMetadata := leftLocal
        localAddressMetadata := leftAddress
        localNetworkMetadata := leftNetwork }
      { right with
        localActionMetadata := rightLocal
        localAddressMetadata := rightAddress
        localNetworkMetadata := rightNetwork }
      game.wireIndistinguishable
      assumptions := by
  simpa [ciphertext_privacy_game_resample_all_local_metadata] using
    ciphertext_privacy_game_open_assumption_boundary_facts
      (ciphertext_privacy_game_resample_all_local_metadata
        game
        leftLocal
        rightLocal
        leftAddress
        rightAddress
        leftNetwork
        rightNetwork)
      assumptionProofs

end CiphertextPrivacy
end Privacy
end Hegemon
