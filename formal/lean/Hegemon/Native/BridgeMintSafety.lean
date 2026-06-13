import Hegemon.Native.ActionStreamEffect
import Hegemon.Native.AcceptedChain
import Hegemon.Native.BlockReplayRefinement
import Hegemon.Native.BlockReplayInputProjection
import Hegemon.Native.BridgeActionPayloadAdmission

namespace Hegemon
namespace Native
namespace BridgeMintSafety

open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.AcceptedChain
open Hegemon.Native.BlockReplayRefinement
open Hegemon.Native.BlockReplayInputProjection
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

structure InboundBridgeMintAmountSurface where
  decodedPayloadAmount : Nat
  authorizedExternalAmount : Nat
  payloadHashMatches : Bool
deriving DecidableEq, Repr

def inboundBridgeDirectMintDelta
    (input : BridgePayloadInput) : Nat :=
  if input.stateDeltasAbsent then 0 else 1

def bridgeMintAmountAuthorized
    (surface : InboundBridgeMintAmountSurface) : Bool :=
  surface.payloadHashMatches
    && (if surface.decodedPayloadAmount =
          surface.authorizedExternalAmount then true else false)

theorem bridge_mint_amount_authorized_facts
    {surface : InboundBridgeMintAmountSurface}
    (authorized : bridgeMintAmountAuthorized surface = true) :
    surface.payloadHashMatches = true
      ∧ surface.decodedPayloadAmount =
          surface.authorizedExternalAmount := by
  unfold bridgeMintAmountAuthorized at authorized
  cases payload : surface.payloadHashMatches <;> simp [payload] at authorized
  by_cases amountEq :
      surface.decodedPayloadAmount = surface.authorizedExternalAmount
  · simp [amountEq] at authorized
    exact ⟨rfl, amountEq⟩
  · simp [amountEq] at authorized

theorem inbound_payload_with_state_delta_rejects
    {input : BridgePayloadInput}
    (bridge : input.bridgeRoute = true)
    (delta : input.stateDeltasAbsent = false) :
    bridgePayloadAccepts input = false := by
  unfold bridgePayloadAccepts
  have rejected :=
    state_deltas_present_rejects
      bridge
      delta
  rw [rejected]

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

theorem accepted_inbound_payload_direct_mint_delta_zero
    {input : BridgePayloadInput}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (accepted : bridgePayloadAccepts input = true) :
    inboundBridgeDirectMintDelta input = 0 := by
  have facts :=
    accepted_inbound_payload_authorization_facts inbound accepted
  simp [inboundBridgeDirectMintDelta, facts.right.left]

theorem accepted_inbound_decoded_mint_amount_bound
    {input : BridgePayloadInput}
    {surface : InboundBridgeMintAmountSurface}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (accepted : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized surface = true) :
    InboundBridgePayloadAuthorizationFacts input
      ∧ surface.payloadHashMatches = true
      ∧ surface.decodedPayloadAmount =
          surface.authorizedExternalAmount
      ∧ inboundBridgeDirectMintDelta input = 0 := by
  have payloadFacts :=
    accepted_inbound_payload_authorization_facts inbound accepted
  have amountFacts :=
    bridge_mint_amount_authorized_facts authorized
  have noDirectMint :=
    accepted_inbound_payload_direct_mint_delta_zero inbound accepted
  exact
    ⟨payloadFacts,
      amountFacts.left,
      amountFacts.right,
      noDirectMint⟩

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

theorem accepted_inbound_payload_authorized_amount_fresh_replay_safe
    {input : BridgePayloadInput}
    {surface : InboundBridgeMintAmountSurface}
    {consumed next : List Nat}
    {replay imported : Nat}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (accepted : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized surface = true)
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported)) :
    InboundBridgePayloadAuthorizationFacts input
      ∧ surface.payloadHashMatches = true
      ∧ surface.decodedPayloadAmount =
          surface.authorizedExternalAmount
      ∧ inboundBridgeDirectMintDelta input = 0
      ∧ replay ∈ next
      ∧ imported = 1
      ∧ next.Nodup
      ∧ importBridgeReplay next (some replay) =
          Except.error ActionStreamReject.bridgeReplayDuplicate := by
  have mintFacts :=
    accepted_inbound_decoded_mint_amount_bound
      inbound
      accepted
      authorized
  have replayFacts :=
    fresh_bridge_replay_import_consumes_once consumedNodup fresh
  exact
    ⟨mintFacts.left,
      mintFacts.right.left,
      mintFacts.right.right.left,
      mintFacts.right.right.right,
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

theorem accepted_inbound_payload_authorized_amount_ledger_replay_safe
    {input : BridgePayloadInput}
    {surface : InboundBridgeMintAmountSurface}
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized surface = true)
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialBridgeReplaysNodup :
      initial.consumedBridgeReplays.Nodup)
    (acceptedLedger :
      validateNativeLedgerReplayChain initial blocks = some final) :
    expectedNativeSupplyAfter initial.supply blocks = some final.supply
      ∧ final.consumedBridgeReplays.Nodup
      ∧ InboundBridgePayloadAuthorizationFacts input
      ∧ surface.payloadHashMatches = true
      ∧ surface.decodedPayloadAmount =
          surface.authorizedExternalAmount
      ∧ inboundBridgeDirectMintDelta input = 0
      ∧ replay ∈ next
      ∧ imported = 1
      ∧ next.Nodup
      ∧ importBridgeReplay next (some replay) =
          Except.error ActionStreamReject.bridgeReplayDuplicate := by
  have ledgerFacts :=
    accepted_native_ledger_bridge_replay_supply_coupling
      initialBridgeReplaysNodup
      acceptedLedger
  have bridgeFacts :=
    accepted_inbound_payload_authorized_amount_fresh_replay_safe
      inbound
      acceptedPayload
      authorized
      consumedNodup
      fresh
  exact
    ⟨ledgerFacts.left,
      ledgerFacts.right,
      bridgeFacts.left,
      bridgeFacts.right.left,
      bridgeFacts.right.right.left,
      bridgeFacts.right.right.right.left,
      bridgeFacts.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.right.right⟩

theorem accepted_inbound_payload_authorized_amount_projected_replay_safe
    {input : BridgePayloadInput}
    {surface : InboundBridgeMintAmountSurface}
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerReplayState}
    {projections : List NativeBlockReplayProjection}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized surface = true)
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialNullifiersNodup :
      initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.consumedBridgeReplays.Nodup)
    (acceptedProjected :
      projectedLedgerStateAfter initial projections = some final) :
    validateNativeLedgerReplayChain
        initial
        (projectedReplayInputs projections) =
        some final
      ∧ expectedNativeSupplyAfter
          initial.supply
          (projectedReplayInputs projections) =
          some final.supply
      ∧ expectedNativeLeafCountAfter
          initial.leafCount
          (projectedReplayInputs projections) =
          some final.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          initial
          (projectedReplayInputs projections) = true
      ∧ projectedCarriedStatePreconditions initial projections = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup
      ∧ InboundBridgePayloadAuthorizationFacts input
      ∧ surface.payloadHashMatches = true
      ∧ surface.decodedPayloadAmount =
          surface.authorizedExternalAmount
      ∧ inboundBridgeDirectMintDelta input = 0
      ∧ replay ∈ next
      ∧ imported = 1
      ∧ next.Nodup
      ∧ importBridgeReplay next (some replay) =
          Except.error ActionStreamReject.bridgeReplayDuplicate := by
  have replayFacts :=
    accepted_projected_ledger_state_after_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedProjected
  have bridgeFacts :=
    accepted_inbound_payload_authorized_amount_fresh_replay_safe
      inbound
      acceptedPayload
      authorized
      consumedNodup
      fresh
  exact
    ⟨replayFacts.left,
      replayFacts.right.left,
      replayFacts.right.right.left,
      replayFacts.right.right.right.left,
      replayFacts.right.right.right.right.left,
      replayFacts.right.right.right.right.right.left,
      replayFacts.right.right.right.right.right.right,
      bridgeFacts.left,
      bridgeFacts.right.left,
      bridgeFacts.right.right.left,
      bridgeFacts.right.right.right.left,
      bridgeFacts.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.right.right⟩

theorem accepted_inbound_payload_authorized_amount_raw_projected_replay_safe
    {input : BridgePayloadInput}
    {surface : InboundBridgeMintAmountSurface}
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerReplayState}
    {blocks : List RawDecodedNativeReplayBlock}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized surface = true)
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialNullifiersNodup :
      initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerStateAfter initial blocks = some final) :
    validateNativeLedgerReplayChain
        initial
        (rawReplayInputs blocks) =
        some final
      ∧ expectedNativeSupplyAfter
          initial.supply
          (rawReplayInputs blocks) =
          some final.supply
      ∧ expectedNativeLeafCountAfter
          initial.leafCount
          (rawReplayInputs blocks) =
          some final.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          initial
          (rawReplayInputs blocks) = true
      ∧ rawProjectedCarriedStatePreconditions initial blocks = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup
      ∧ InboundBridgePayloadAuthorizationFacts input
      ∧ surface.payloadHashMatches = true
      ∧ surface.decodedPayloadAmount =
          surface.authorizedExternalAmount
      ∧ inboundBridgeDirectMintDelta input = 0
      ∧ replay ∈ next
      ∧ imported = 1
      ∧ next.Nodup
      ∧ importBridgeReplay next (some replay) =
          Except.error ActionStreamReject.bridgeReplayDuplicate := by
  have replayFacts :=
    accepted_raw_projected_ledger_state_after_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  have bridgeFacts :=
    accepted_inbound_payload_authorized_amount_fresh_replay_safe
      inbound
      acceptedPayload
      authorized
      consumedNodup
      fresh
  exact
    ⟨replayFacts.left,
      replayFacts.right.left,
      replayFacts.right.right.left,
      replayFacts.right.right.right.left,
      replayFacts.right.right.right.right.left,
      replayFacts.right.right.right.right.right.left,
      replayFacts.right.right.right.right.right.right,
      bridgeFacts.left,
      bridgeFacts.right.left,
      bridgeFacts.right.right.left,
      bridgeFacts.right.right.right.left,
      bridgeFacts.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.right.right⟩

end BridgeMintSafety
end Native
end Hegemon
