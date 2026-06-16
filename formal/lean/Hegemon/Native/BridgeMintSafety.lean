import Hegemon.Native.ActionStreamEffect
import Hegemon.Native.AcceptedChain
import Hegemon.Native.BlockReplayRefinement
import Hegemon.Native.BlockReplayInputProjection
import Hegemon.Native.BridgeActionPayloadAdmission
import Hegemon.Native.RawIngressSidecarReplayRecoverability

namespace Hegemon
namespace Native
namespace BridgeMintSafety

open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.AcceptedChain
open Hegemon.Native.BlockReplayRefinement
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.BridgeActionPayloadAdmission
open Hegemon.Native.ActionRequestProjectionAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.PendingActionReload
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StagedCiphertextReload
open Hegemon.Native.StagedProofReload

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

structure InboundBridgeMintAssetSurface where
  decodedPayloadAsset : Nat
  authorizedExternalAsset : Nat
  decodedPayloadAmount : Nat
  authorizedExternalAmount : Nat
  nativeAssetId : Nat
  payloadHashMatches : Bool
deriving DecidableEq, Repr

def inboundBridgeDirectMintDelta
    (input : BridgePayloadInput) : Nat :=
  if input.stateDeltasAbsent then 0 else 1

def inboundBridgeAuthorizedAssetDeltaValue
    (surface : InboundBridgeMintAssetSurface)
    (assetId : Nat) : Nat :=
  if assetId = surface.authorizedExternalAsset then
    surface.authorizedExternalAmount
  else
    0

def bridgeMintAmountAuthorized
    (surface : InboundBridgeMintAmountSurface) : Bool :=
  surface.payloadHashMatches
    && (if surface.decodedPayloadAmount =
          surface.authorizedExternalAmount then true else false)

def bridgeMintAssetAuthorized
    (surface : InboundBridgeMintAssetSurface) : Bool :=
  surface.payloadHashMatches
    && (if surface.decodedPayloadAmount =
          surface.authorizedExternalAmount then true else false)
    && (if surface.decodedPayloadAsset =
          surface.authorizedExternalAsset then true else false)
    && (if surface.decodedPayloadAsset =
          surface.nativeAssetId then false else true)

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

theorem bridge_mint_asset_authorized_facts
    {surface : InboundBridgeMintAssetSurface}
    (authorized : bridgeMintAssetAuthorized surface = true) :
    surface.payloadHashMatches = true
      ∧ surface.decodedPayloadAmount =
          surface.authorizedExternalAmount
      ∧ surface.decodedPayloadAsset =
          surface.authorizedExternalAsset
      ∧ surface.decodedPayloadAsset ≠ surface.nativeAssetId := by
  unfold bridgeMintAssetAuthorized at authorized
  cases payload : surface.payloadHashMatches <;>
    simp [payload] at authorized
  by_cases amountEq :
      surface.decodedPayloadAmount = surface.authorizedExternalAmount
  · by_cases assetEq :
        surface.decodedPayloadAsset = surface.authorizedExternalAsset
    · by_cases nativeEq :
          surface.decodedPayloadAsset = surface.nativeAssetId
      · have externalNative :
            surface.authorizedExternalAsset = surface.nativeAssetId := by
          rw [← assetEq, nativeEq]
        simp [amountEq, assetEq, externalNative] at authorized
      · simp [amountEq, assetEq] at authorized
        exact ⟨rfl, amountEq, assetEq, nativeEq⟩
    · simp [amountEq, assetEq] at authorized
  · simp [amountEq] at authorized

theorem bridge_mint_asset_authorized_delta_value
    {surface : InboundBridgeMintAssetSurface}
    (authorized : bridgeMintAssetAuthorized surface = true) :
    inboundBridgeAuthorizedAssetDeltaValue
        surface
        surface.decodedPayloadAsset =
      surface.decodedPayloadAmount := by
  have facts :=
    bridge_mint_asset_authorized_facts authorized
  unfold inboundBridgeAuthorizedAssetDeltaValue
  simp [facts.right.right.left, facts.right.left]

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

theorem imported_bridge_replay_state_preserves_prior_membership
    {replay : Nat}
    {consumed : List Nat}
    {actions : List StreamAction}
    (present : replay ∈ consumed) :
    replay ∈ importedBridgeReplayStateFrom consumed actions := by
  induction actions generalizing consumed with
  | nil =>
      simpa [importedBridgeReplayStateFrom] using present
  | cons action rest ih =>
      unfold importedBridgeReplayStateFrom
      cases imported :
          importBridgeReplay consumed action.bridgeReplayKey with
      | error rejection =>
          simpa [imported] using present
      | ok pair =>
          cases pair with
          | mk next importedCount =>
              have presentNext : replay ∈ next := by
                cases key : action.bridgeReplayKey with
                | none =>
                    simp [importBridgeReplay, key] at imported
                    rcases imported with ⟨nextEq, _importedEq⟩
                    subst next
                    exact present
                | some importedReplay =>
                    unfold importBridgeReplay at imported
                    cases already :
                        containsNat importedReplay consumed with
                    | true =>
                        simp [key, already] at imported
                    | false =>
                        simp [key, already] at imported
                        rcases imported with ⟨nextEq, _importedEq⟩
                        subst next
                        exact List.mem_cons_of_mem importedReplay present
              simpa [imported] using ih presentNext

theorem accepted_native_ledger_bridge_replay_preserves_prior_membership
    {initial final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    {replay : Nat}
    (present : replay ∈ initial.consumedBridgeReplays)
    (accepted :
      validateNativeLedgerReplayChain initial blocks = some final) :
    replay ∈ final.consumedBridgeReplays := by
  induction blocks generalizing initial with
  | nil =>
      simp [validateNativeLedgerReplayChain] at accepted
      subst final
      exact present
  | cons block rest ih =>
      unfold validateNativeLedgerReplayChain at accepted
      by_cases parentEq : block.parentSupply = initial.supply
      · simp [parentEq] at accepted
        by_cases leafEq : block.leafStart = initial.leafCount
        · simp [leafEq] at accepted
          by_cases spentEq :
              block.spentNullifiers = initial.spentNullifiers
          · simp [spentEq] at accepted
            by_cases consumedEq :
                block.consumedBridgeReplays =
                  initial.consumedBridgeReplays
            · simp [consumedEq] at accepted
              cases replayResult : evaluateBlockReplayRefinement block with
              | error rejection =>
                  simp [replayResult] at accepted
              | ok summary =>
                  have presentNext :
                      replay ∈
                        importedBridgeReplayStateFrom
                          initial.consumedBridgeReplays
                          block.actions :=
                    imported_bridge_replay_state_preserves_prior_membership
                      present
                  simp [replayResult] at accepted
                  exact ih
                    (by
                      simpa [nextLedgerState] using presentNext)
                    accepted
            · simp [consumedEq] at accepted
          · simp [spentEq] at accepted
        · simp [leafEq] at accepted
      · simp [parentEq] at accepted

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

theorem accepted_inbound_payload_authorized_amount_fresh_replay_survives_raw_projected_tail
    {input : BridgePayloadInput}
    {surface : InboundBridgeMintAmountSurface}
    {consumed next : List Nat}
    {replay imported : Nat}
    {tailInitial final : NativeLedgerReplayState}
    {blocks : List RawDecodedNativeReplayBlock}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized surface = true)
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (tailConsumedEq :
      tailInitial.consumedBridgeReplays = next)
    (tailNullifiersNodup :
      tailInitial.spentNullifiers.Nodup)
    (acceptedRaw :
      rawProjectedLedgerStateAfter tailInitial blocks = some final) :
    validateNativeLedgerReplayChain
        tailInitial
        (rawReplayInputs blocks) =
        some final
      ∧ expectedNativeSupplyAfter
          tailInitial.supply
          (rawReplayInputs blocks) =
          some final.supply
      ∧ expectedNativeLeafCountAfter
          tailInitial.leafCount
          (rawReplayInputs blocks) =
          some final.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          tailInitial
          (rawReplayInputs blocks) = true
      ∧ rawProjectedCarriedStatePreconditions tailInitial blocks = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup
      ∧ replay ∈ final.consumedBridgeReplays
      ∧ InboundBridgePayloadAuthorizationFacts input
      ∧ surface.payloadHashMatches = true
      ∧ surface.decodedPayloadAmount =
          surface.authorizedExternalAmount
      ∧ inboundBridgeDirectMintDelta input = 0
      ∧ imported = 1
      ∧ importBridgeReplay next (some replay) =
          Except.error ActionStreamReject.bridgeReplayDuplicate := by
  have replayFacts :=
    fresh_bridge_replay_import_consumes_once consumedNodup fresh
  have tailBridgeReplaysNodup :
      tailInitial.consumedBridgeReplays.Nodup := by
    simpa [tailConsumedEq] using replayFacts.right.right.left
  have rawFacts :=
    accepted_raw_projected_ledger_state_after_startup_equivalence
      tailNullifiersNodup
      tailBridgeReplaysNodup
      acceptedRaw
  have replayPresentAtTail :
      replay ∈ tailInitial.consumedBridgeReplays := by
    simpa [tailConsumedEq] using replayFacts.left
  have replaySurvives :
      replay ∈ final.consumedBridgeReplays :=
    accepted_native_ledger_bridge_replay_preserves_prior_membership
      replayPresentAtTail
      rawFacts.left
  have bridgeFacts :=
    accepted_inbound_decoded_mint_amount_bound
      inbound
      acceptedPayload
      authorized
  exact
    ⟨rawFacts.left,
      rawFacts.right.left,
      rawFacts.right.right.left,
      rawFacts.right.right.right.left,
      rawFacts.right.right.right.right.left,
      rawFacts.right.right.right.right.right.left,
      rawFacts.right.right.right.right.right.right,
      replaySurvives,
      bridgeFacts.left,
      bridgeFacts.right.left,
      bridgeFacts.right.right.left,
      bridgeFacts.right.right.right,
      replayFacts.right.left,
      replayFacts.right.right.right⟩

theorem accepted_inbound_payload_authorized_amount_raw_ingress_sidecar_replay_safe
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
    {rawSurface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerReplayState}
    {blocks : List RawDecodedNativeReplayBlock}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized mintSurface = true)
    (rawIngress :
      AcceptedRawIngressSidecarReplay
        rawSurface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : rawSurface.transferState.sidecarRoute = true)
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
    actionRequestProjectionPreconditions
        rawSurface.actionRequest = true
      ∧ pendingActionReloadPreconditions rawSurface.pendingReload = true
      ∧ stagedCiphertextReloadPreconditions
          rawSurface.stagedCiphertextReload = true
      ∧ stagedProofReloadPreconditions rawSurface.stagedProofReload = true
      ∧ rawSurface.transferState.sidecarCiphertextsAvailable = true
      ∧ rawSurface.transferState.sidecarCiphertextSizesPresent = true
      ∧ rawSurface.transferState.sidecarCiphertextSizesMatch = true
      ∧ rawSurface.daSidecarReplay.candidateBinding.daRootMatches = true
      ∧ rawSurface.daSidecarReplay.provenBatchBinding.daRootMatches = true
      ∧ semanticFields.daRoot =
          rawSurface.daSidecarReplay.recursiveSemanticSource.daRoot
      ∧ actionWireReplayProjectionPreconditions
          rawSurface.daSidecarReplay.wireReplayProjection = true
      ∧ rawSurface.daSidecarReplay.wireReplayProjection.actionCount =
          rawSurface.daSidecarReplay.wireReplayProjection.plannedCount
      ∧ rawSurface.daSidecarReplay.wireReplayProjection.actionCount =
          rawSurface.daSidecarReplay.wireReplayProjection.actions.length
      ∧ validateNativeLedgerReplayChain
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
      ∧ mintSurface.payloadHashMatches = true
      ∧ mintSurface.decodedPayloadAmount =
          mintSurface.authorizedExternalAmount
      ∧ inboundBridgeDirectMintDelta input = 0
      ∧ replay ∈ next
      ∧ imported = 1
      ∧ next.Nodup
      ∧ importBridgeReplay next (some replay) =
          Except.error ActionStreamReject.bridgeReplayDuplicate := by
  have rawIngressPreconditions :=
    accepted_raw_ingress_sidecar_replay_exposes_preconditions
      rawIngress
  have rawReplayFacts :=
    accepted_raw_ingress_raw_projected_replay_binds_sidecar_rows
      rawIngress
      sidecarRoute
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  have bridgeFacts :=
    accepted_inbound_payload_authorized_amount_raw_projected_replay_safe
      inbound
      acceptedPayload
      authorized
      consumedNodup
      fresh
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  rcases rawIngressPreconditions with
    ⟨requestPre,
      pendingPre,
      stagedCipherPre,
      stagedProofPre,
      _transferPre,
      _candidateDaRoot,
      _provenBatchDaRoot,
      _provenBatchNonzero,
      wirePre,
      wirePlanned,
      wireActionLength⟩
  rcases rawReplayFacts with
    ⟨_requestPre2,
      _pendingPre2,
      _stagedCipherPre2,
      _stagedProofPre2,
      sidecarAvailable,
      sidecarSizesPresent,
      sidecarSizesMatch,
      candidateDaRoot,
      provenBatchDaRoot,
      semanticDaRoot,
      rawAccepted,
      rawSupply,
      rawLeaf,
      rawCommitmentPlan,
      rawCarried,
      finalNullifiers,
      finalBridgeReplays⟩
  rcases bridgeFacts with
    ⟨_bridgeAccepted,
      _bridgeSupply,
      _bridgeLeaf,
      _bridgeCommitmentPlan,
      _bridgeCarried,
      _bridgeFinalNullifiers,
      _bridgeFinalReplays,
      payloadFacts,
      payloadHash,
      decodedAmount,
      noDirectMint,
      replayMem,
      importedOne,
      nextNodup,
      duplicateRejects⟩
  exact
    ⟨requestPre,
      pendingPre,
      stagedCipherPre,
      stagedProofPre,
      sidecarAvailable,
      sidecarSizesPresent,
      sidecarSizesMatch,
      candidateDaRoot,
      provenBatchDaRoot,
      semanticDaRoot,
      wirePre,
      wirePlanned,
      wireActionLength,
      rawAccepted,
      rawSupply,
      rawLeaf,
      rawCommitmentPlan,
      rawCarried,
      finalNullifiers,
      finalBridgeReplays,
      payloadFacts,
      payloadHash,
      decodedAmount,
      noDirectMint,
      replayMem,
      importedOne,
      nextNodup,
      duplicateRejects⟩

theorem accepted_inbound_payload_authorized_amount_raw_ingress_tree_replay_safe
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
    {rawSurface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized mintSurface = true)
    (rawIngress :
      AcceptedRawIngressSidecarReplay
        rawSurface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : rawSurface.transferState.sidecarRoute = true)
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressLedgerTreePublicationFacts
        rawSurface
        semanticFields
        initial
        final
        blocks
      ∧ InboundBridgePayloadAuthorizationFacts input
      ∧ mintSurface.payloadHashMatches = true
      ∧ mintSurface.decodedPayloadAmount =
          mintSurface.authorizedExternalAmount
      ∧ inboundBridgeDirectMintDelta input = 0
      ∧ replay ∈ next
      ∧ imported = 1
      ∧ next.Nodup
      ∧ importBridgeReplay next (some replay) =
          Except.error ActionStreamReject.bridgeReplayDuplicate
      ∧ final.ledger.spentNullifiers.Nodup
      ∧ final.ledger.consumedBridgeReplays.Nodup := by
  have publicationFacts :=
    raw_ingress_publication_equivalent_to_raw_ledger_tree_replay
      rawIngress
      sidecarRoute
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
    ⟨publicationFacts,
      bridgeFacts.left,
      bridgeFacts.right.left,
      bridgeFacts.right.right.left,
      bridgeFacts.right.right.right.left,
      bridgeFacts.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.right.left,
      bridgeFacts.right.right.right.right.right.right.right,
      publicationFacts.finalSpentNullifiersUnique,
      publicationFacts.finalBridgeReplaysUnique⟩

end BridgeMintSafety
end Native
end Hegemon
