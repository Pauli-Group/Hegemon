import Hegemon.Native.ActionStreamEffect
import Hegemon.Native.AcceptedChain
import Hegemon.Native.BlockReplayRefinement
import Hegemon.Native.BridgeActionPayloadAdmission

namespace Hegemon
namespace Native
namespace BridgeMintSafety

open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.AcceptedChain
open Hegemon.Native.BlockReplayRefinement
open Hegemon.Native.BridgeActionPayloadAdmission

def InboundBridgePayloadAuthorizationFacts
    (input : BridgePayloadInput) : Prop :=
  input.bridgeRoute = true
    ∧ input.stateDeltasAbsent = true
    ∧ input.actionKind = BridgeActionKind.inbound
    ∧ input.inboundProofReceiptNonempty = true
    ∧ input.inboundReplayKeyMatches = true
    ∧ input.inboundDestinationMatches = true
    ∧ input.inboundPayloadHashMatches = true

theorem accepted_inbound_payload_authorization_facts
    {input : BridgePayloadInput}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (accepted : bridgePayloadAccepts input = true) :
    InboundBridgePayloadAuthorizationFacts input := by
  cases input with
  | mk bridgeRoute stateDeltasAbsent actionKind outboundPayloadNonempty
      inboundProofReceiptNonempty inboundReplayKeyMatches
      inboundDestinationMatches inboundPayloadHashMatches =>
      cases bridgeRoute <;>
        cases stateDeltasAbsent <;>
        cases actionKind <;>
        cases outboundPayloadNonempty <;>
        cases inboundProofReceiptNonempty <;>
        cases inboundReplayKeyMatches <;>
        cases inboundDestinationMatches <;>
        cases inboundPayloadHashMatches <;>
        simp [bridgePayloadAccepts, evaluateBridgePayload,
          InboundBridgePayloadAuthorizationFacts] at inbound accepted ⊢

theorem fresh_bridge_replay_import_consumes_once
    {consumed next : List Nat}
    {replay imported : Nat}
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported)) :
    replay ∈ next
      ∧ imported = 1
      ∧ next.Nodup
      ∧ importBridgeReplay next (some replay) =
          Except.error ActionStreamReject.bridgeReplayDuplicate := by
  unfold importBridgeReplay at fresh
  cases present : containsNat replay consumed with
  | true =>
      simp [present] at fresh
  | false =>
      simp [present] at fresh
      rcases fresh with ⟨hnext, himported⟩
      subst next
      subst imported
      have nextNodup :
          (replay :: consumed).Nodup := by
        have replayNotMem : replay ∉ consumed :=
          containsNat_false_not_mem present
        rw [List.nodup_cons]
        exact ⟨replayNotMem, consumedNodup⟩
      simp [importBridgeReplay, containsNat, nextNodup]

theorem accepted_inbound_payload_fresh_replay_mint_safe
    {input : BridgePayloadInput}
    {consumed next : List Nat}
    {replay imported : Nat}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (accepted : bridgePayloadAccepts input = true)
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported)) :
    InboundBridgePayloadAuthorizationFacts input
      ∧ replay ∈ next
      ∧ imported = 1
      ∧ next.Nodup
      ∧ importBridgeReplay next (some replay) =
          Except.error ActionStreamReject.bridgeReplayDuplicate := by
  have payloadFacts :=
    accepted_inbound_payload_authorization_facts inbound accepted
  have replayFacts :=
    fresh_bridge_replay_import_consumes_once consumedNodup fresh
  exact
    ⟨payloadFacts,
      replayFacts.left,
      replayFacts.right.left,
      replayFacts.right.right.left,
      replayFacts.right.right.right⟩

theorem accepted_block_replay_couples_bridge_replay_and_supply
    {input : BlockReplayInput}
    {summary : BlockReplaySummary}
    (initialReplayNodup : input.consumedBridgeReplays.Nodup)
    (accepted : evaluateBlockReplayRefinement input = Except.ok summary) :
    (importedBridgeReplayStateFrom
        input.consumedBridgeReplays
        input.actions).Nodup
      ∧ expectedSupply input = some summary.expectedSupply
      ∧ summary.expectedSupply = input.claimedSupply := by
  have streamOk :=
    accepted_has_action_stream_effect accepted
  have streamConsumedNodup :
      (streamInput input).consumedBridgeReplays.Nodup := by
    simp [streamInput, initialReplayNodup]
  have replayNodup :
      (importedBridgeReplayStateFrom
        input.consumedBridgeReplays
        input.actions).Nodup := by
    have preserved :=
      evaluateActionStreamEffect_preserves_imported_bridge_replay_nodup
        streamConsumedNodup
        streamOk
    simpa [streamInput] using preserved
  have supplyFacts :=
    accepted_claims_expected_supply accepted
  exact ⟨replayNodup, supplyFacts.left, supplyFacts.right⟩

theorem accepted_native_ledger_bridge_replay_supply_coupling
    {initial final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (initialBridgeReplaysNodup :
      initial.consumedBridgeReplays.Nodup)
    (accepted :
      validateNativeLedgerReplayChain initial blocks = some final) :
    expectedNativeSupplyAfter initial.supply blocks = some final.supply
      ∧ final.consumedBridgeReplays.Nodup :=
  ⟨accepted_native_ledger_replay_chain_supply_from accepted,
    accepted_native_ledger_replay_chain_bridge_replays_unique_from
      initialBridgeReplaysNodup
      accepted⟩

end BridgeMintSafety
end Native
end Hegemon
