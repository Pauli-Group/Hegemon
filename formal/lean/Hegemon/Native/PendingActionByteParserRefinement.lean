import Hegemon.Native.ActionWireReplayProjectionAdmission
import Hegemon.Native.CodecAdmission
import Hegemon.Native.PendingActionReload
import Hegemon.Resource.BoundedRequestAdmission

namespace Hegemon
namespace Native
namespace PendingActionByteParserRefinement

open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.CodecAdmission
open Hegemon.Native.PendingActionReload
open Hegemon.Resource.BoundedRequestAdmission

structure PendingActionByteParserWireReplayFacts
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (pendingReload : PendingActionReloadInput)
    (wireProjection : ActionWireReplayProjectionInput)
    (wireOutput : ActionWireReplayProjectionOutput) : Prop where
  pendingDecodePreconditions :
    exactDecodePreconditions pendingDecode = true
  pendingDecodeExact :
    pendingDecode.parserAccepts = true
      ∧ pendingDecode.consumedAllBytes = true
      ∧ pendingDecode.canonicalReencodeMatches = true
  blockActionDecodePreconditions :
    blockActionDecodePreconditions blockActionDecode = true
  blockActionDecodeExact :
    actionCountMatches blockActionDecode = true
      ∧ blockActionDecode.everyActionDecodesExactly = true
  blockActionDeclaredCount :
    blockActionDecode.declaredTxCount =
      blockActionDecode.actualActionPayloadCount
  pendingReloadPreconditions :
    pendingActionReloadPreconditions pendingReload = true
  wireProjectionPreconditions :
    actionWireReplayProjectionPreconditions wireProjection = true
  acceptedWireProjection :
    evaluateActionWireReplayProjection wireProjection =
      Except.ok wireOutput
  wireActionCountMatchesDeclared :
    wireProjection.actionCount = blockActionDecode.declaredTxCount
  wireProjectedActionCount :
    wireOutput.projectedActionCount = wireProjection.actionCount
  projectedActionRowsMatchDecodedPayloads :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount

theorem accepted_pending_action_byte_parser_refines_wire_replay_rows
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {pendingReload : PendingActionReloadInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (pendingReloadAccepted :
      pendingActionReloadAccepts pendingReload = true)
    (wireProjectionAccepted :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (wireActionCountMatchesDeclared :
      wireProjection.actionCount =
        blockActionDecode.declaredTxCount) :
    PendingActionByteParserWireReplayFacts
      pendingDecode
      blockActionDecode
      pendingReload
      wireProjection
      wireOutput := by
  have pendingDecodePreconditionsOk :
      exactDecodePreconditions pendingDecode = true :=
    (exact_accepts_iff_preconditions
      (input := pendingDecode)).mp pendingDecodeAccepted
  have pendingDecodeExactOk :
      pendingDecode.parserAccepts = true
        ∧ pendingDecode.consumedAllBytes = true
        ∧ pendingDecode.canonicalReencodeMatches = true :=
    exact_decode_acceptance_excludes_malleability
      pendingDecodeAccepted
  have blockActionDecodePreconditionsOk :
      blockActionDecodePreconditions blockActionDecode = true :=
    (block_action_decode_accepts_iff_preconditions
      (input := blockActionDecode)).mp blockActionDecodeAccepted
  have blockActionDecodeExactOk :
      actionCountMatches blockActionDecode = true
        ∧ blockActionDecode.everyActionDecodesExactly = true :=
    block_action_decode_acceptance_excludes_malleability
      blockActionDecodeAccepted
  have blockActionDeclaredCountOk :
      blockActionDecode.declaredTxCount =
        blockActionDecode.actualActionPayloadCount :=
    block_action_decode_acceptance_binds_declared_count
      blockActionDecodeAccepted
  have pendingReloadPreconditionsOk :
      pendingActionReloadPreconditions pendingReload = true :=
    (accepts_iff_pending_action_reload_preconditions
      (input := pendingReload)).mp pendingReloadAccepted
  have wireProjectionAccepts :
      actionWireReplayProjectionAccepts wireProjection = true := by
    simp [actionWireReplayProjectionAccepts, wireProjectionAccepted]
  have wireProjectionPreconditionsOk :
      actionWireReplayProjectionPreconditions wireProjection = true := by
    simpa [wireProjectionAccepts] using
      (accepts_iff_wire_replay_projection_preconditions wireProjection)
  have wireProjectedActionCountOk :
      wireOutput.projectedActionCount = wireProjection.actionCount :=
    accepted_wire_replay_projection_projected_action_count
      wireProjectionAccepted
  have projectedActionRowsMatchDecodedPayloadsOk :
      wireOutput.projectedActionCount =
        blockActionDecode.actualActionPayloadCount := by
    calc
      wireOutput.projectedActionCount = wireProjection.actionCount :=
        wireProjectedActionCountOk
      _ = blockActionDecode.declaredTxCount :=
        wireActionCountMatchesDeclared
      _ = blockActionDecode.actualActionPayloadCount :=
        blockActionDeclaredCountOk
  exact
    {
      pendingDecodePreconditions := pendingDecodePreconditionsOk,
      pendingDecodeExact := pendingDecodeExactOk,
      blockActionDecodePreconditions := blockActionDecodePreconditionsOk,
      blockActionDecodeExact := blockActionDecodeExactOk,
      blockActionDeclaredCount := blockActionDeclaredCountOk,
      pendingReloadPreconditions := pendingReloadPreconditionsOk,
      wireProjectionPreconditions := wireProjectionPreconditionsOk,
      acceptedWireProjection := wireProjectionAccepted,
      wireActionCountMatchesDeclared := wireActionCountMatchesDeclared,
      wireProjectedActionCount := wireProjectedActionCountOk,
      projectedActionRowsMatchDecodedPayloads :=
        projectedActionRowsMatchDecodedPayloadsOk
    }

structure PendingActionByteParserResourceWireReplayFacts
    (policy : ResourcePolicy)
    (request : ResourceRequest)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (pendingReload : PendingActionReloadInput)
    (wireProjection : ActionWireReplayProjectionInput)
    (wireOutput : ActionWireReplayProjectionOutput) : Prop where
  parserWireReplayFacts :
    PendingActionByteParserWireReplayFacts
      pendingDecode
      blockActionDecode
      pendingReload
      wireProjection
      wireOutput
  resourceFacts :
    AcceptedBoundedRequestFacts policy request
  resourceItemCountMatchesDeclared :
    request.itemCount = blockActionDecode.declaredTxCount
  resourceItemCountMatchesDecodedPayloads :
    request.itemCount = blockActionDecode.actualActionPayloadCount
  resourceItemCountMatchesWireRows :
    request.itemCount = wireOutput.projectedActionCount

theorem accepted_pending_action_byte_parser_with_resource_bounds_refines_wire_replay_rows
    {policy : ResourcePolicy}
    {request : ResourceRequest}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {pendingReload : PendingActionReloadInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    (resourceAccepted :
      evaluateBoundedRequest policy request = none)
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (pendingReloadAccepted :
      pendingActionReloadAccepts pendingReload = true)
    (wireProjectionAccepted :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (wireActionCountMatchesDeclared :
      wireProjection.actionCount =
        blockActionDecode.declaredTxCount)
    (resourceItemCountMatchesDeclared :
      request.itemCount = blockActionDecode.declaredTxCount) :
    PendingActionByteParserResourceWireReplayFacts
      policy
      request
      pendingDecode
      blockActionDecode
      pendingReload
      wireProjection
      wireOutput := by
  have parserFacts :
      PendingActionByteParserWireReplayFacts
        pendingDecode
        blockActionDecode
        pendingReload
        wireProjection
        wireOutput :=
    accepted_pending_action_byte_parser_refines_wire_replay_rows
      pendingDecodeAccepted
      blockActionDecodeAccepted
      pendingReloadAccepted
      wireProjectionAccepted
      wireActionCountMatchesDeclared
  have resourceFacts :
      AcceptedBoundedRequestFacts policy request :=
    accepted_bounded_request_exposes_all_caps resourceAccepted
  have resourceItemCountMatchesDecodedPayloads :
      request.itemCount = blockActionDecode.actualActionPayloadCount := by
    calc
      request.itemCount = blockActionDecode.declaredTxCount :=
        resourceItemCountMatchesDeclared
      _ = blockActionDecode.actualActionPayloadCount :=
        parserFacts.blockActionDeclaredCount
  have resourceItemCountMatchesWireRows :
      request.itemCount = wireOutput.projectedActionCount := by
    calc
      request.itemCount = blockActionDecode.declaredTxCount :=
        resourceItemCountMatchesDeclared
      _ = wireProjection.actionCount :=
        Eq.symm wireActionCountMatchesDeclared
      _ = wireOutput.projectedActionCount :=
        Eq.symm parserFacts.wireProjectedActionCount
  exact
    {
      parserWireReplayFacts := parserFacts,
      resourceFacts := resourceFacts,
      resourceItemCountMatchesDeclared :=
        resourceItemCountMatchesDeclared,
      resourceItemCountMatchesDecodedPayloads :=
        resourceItemCountMatchesDecodedPayloads,
      resourceItemCountMatchesWireRows :=
        resourceItemCountMatchesWireRows
    }

end PendingActionByteParserRefinement
end Native
end Hegemon
