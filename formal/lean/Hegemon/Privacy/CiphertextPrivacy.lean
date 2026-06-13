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

def samePublicCiphertextShape
    (left right : ShieldedTransactionWorld) : Prop :=
  samePublicInputs left right
    ∧ left.ciphertextSummaries = right.ciphertextSummaries
    ∧ samePlacement left right

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

theorem ciphertext_privacy_game_only_open_crypto_obligation
    {left right : ShieldedTransactionWorld}
    (game : CiphertextPrivacyGame left right) :
    game.wireIndistinguishable := by
  exact game.wireIndistinguishableProof

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

end CiphertextPrivacy
end Privacy
end Hegemon
