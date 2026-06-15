import Hegemon.Bridge.Replay

namespace Hegemon
namespace Bridge
namespace MintReplayPolicy

inductive ReceiptMintReplayReject where
  | notInboundBridgeMint
  | stateDeltaMintPresent
  | receiptEnvelopeMissing
  | receiptNotVerified
  | receiptPayloadMismatch
  | replayAlreadyConsumed
  | mintNotAuthorized
  | amountDoesNotMatchReceipt
  | amountOutOfBounds
deriving DecidableEq, Repr

structure ReceiptMintReplayInput where
  inboundBridgeMint : Bool
  stateDeltasAbsent : Bool
  receiptEnvelopePresent : Bool
  receiptVerified : Bool
  receiptPayloadMatches : Bool
  replayState : ReplayState
  replayKey : ReplayKey
  mintAuthorized : Bool
  amountMatchesReceipt : Bool
  amountWithinBound : Bool
deriving DecidableEq, Repr

structure ReceiptMintReplayAccepted where
  nextReplayState : ReplayState
deriving DecidableEq, Repr

def evaluateReceiptMintReplay
    (input : ReceiptMintReplayInput) :
      Except ReceiptMintReplayReject ReceiptMintReplayAccepted :=
  if input.inboundBridgeMint = false then
    Except.error ReceiptMintReplayReject.notInboundBridgeMint
  else if input.stateDeltasAbsent = false then
    Except.error ReceiptMintReplayReject.stateDeltaMintPresent
  else if input.receiptEnvelopePresent = false then
    Except.error ReceiptMintReplayReject.receiptEnvelopeMissing
  else if input.receiptVerified = false then
    Except.error ReceiptMintReplayReject.receiptNotVerified
  else if input.receiptPayloadMatches = false then
    Except.error ReceiptMintReplayReject.receiptPayloadMismatch
  else
    match input.replayState.importOne input.replayKey with
    | none => Except.error ReceiptMintReplayReject.replayAlreadyConsumed
    | some nextReplayState =>
        if input.mintAuthorized = false then
          Except.error ReceiptMintReplayReject.mintNotAuthorized
        else if input.amountMatchesReceipt = false then
          Except.error ReceiptMintReplayReject.amountDoesNotMatchReceipt
        else if input.amountWithinBound = false then
          Except.error ReceiptMintReplayReject.amountOutOfBounds
        else
          Except.ok { nextReplayState := nextReplayState }

def receiptMintReplayAccepts
    (input : ReceiptMintReplayInput) : Bool :=
  match evaluateReceiptMintReplay input with
  | Except.ok _ => true
  | Except.error _ => false

def receiptMintReplayRejection
    (input : ReceiptMintReplayInput) :
      Option ReceiptMintReplayReject :=
  match evaluateReceiptMintReplay input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def receiptMintReplayPreconditions
    (input : ReceiptMintReplayInput) : Bool :=
  input.inboundBridgeMint
    && input.stateDeltasAbsent
    && input.receiptEnvelopePresent
    && input.receiptVerified
    && input.receiptPayloadMatches
    && (match input.replayState.importOne input.replayKey with
        | none => false
        | some _ => true)
    && input.mintAuthorized
    && input.amountMatchesReceipt
    && input.amountWithinBound

def ReceiptMintReplayFacts
    (input : ReceiptMintReplayInput)
    (accepted : ReceiptMintReplayAccepted) : Prop :=
  input.inboundBridgeMint = true
    ∧ input.stateDeltasAbsent = true
    ∧ input.receiptEnvelopePresent = true
    ∧ input.receiptVerified = true
    ∧ input.receiptPayloadMatches = true
    ∧ input.replayState.importOne input.replayKey =
        some accepted.nextReplayState
    ∧ input.mintAuthorized = true
    ∧ input.amountMatchesReceipt = true
    ∧ input.amountWithinBound = true

theorem accepts_iff_receipt_mint_replay_preconditions
    (input : ReceiptMintReplayInput) :
    receiptMintReplayAccepts input = true ↔
      receiptMintReplayPreconditions input = true := by
  cases input with
  | mk inboundBridgeMint stateDeltasAbsent receiptEnvelopePresent
      receiptVerified receiptPayloadMatches replayState replayKey
      mintAuthorized amountMatchesReceipt amountWithinBound =>
      unfold receiptMintReplayAccepts receiptMintReplayPreconditions
      unfold evaluateReceiptMintReplay
      cases inboundBridgeMint <;>
        cases stateDeltasAbsent <;>
        cases receiptEnvelopePresent <;>
        cases receiptVerified <;>
        cases receiptPayloadMatches <;>
        cases himport : replayState.importOne replayKey <;>
        cases mintAuthorized <;>
        cases amountMatchesReceipt <;>
        cases amountWithinBound <;>
        simp

theorem receipt_not_verified_rejects_before_replay_or_mint
    {input : ReceiptMintReplayInput}
    (inbound : input.inboundBridgeMint = true)
    (noDelta : input.stateDeltasAbsent = true)
    (present : input.receiptEnvelopePresent = true)
    (notVerified : input.receiptVerified = false) :
    evaluateReceiptMintReplay input =
      Except.error ReceiptMintReplayReject.receiptNotVerified := by
  unfold evaluateReceiptMintReplay
  simp [inbound, noDelta, present, notVerified]

theorem receipt_payload_mismatch_rejects_before_replay
    {input : ReceiptMintReplayInput}
    (inbound : input.inboundBridgeMint = true)
    (noDelta : input.stateDeltasAbsent = true)
    (present : input.receiptEnvelopePresent = true)
    (verified : input.receiptVerified = true)
    (payloadMismatch : input.receiptPayloadMatches = false) :
    evaluateReceiptMintReplay input =
      Except.error ReceiptMintReplayReject.receiptPayloadMismatch := by
  unfold evaluateReceiptMintReplay
  simp [inbound, noDelta, present, verified, payloadMismatch]

theorem consumed_replay_key_rejects
    {input : ReceiptMintReplayInput}
    (inbound : input.inboundBridgeMint = true)
    (noDelta : input.stateDeltasAbsent = true)
    (present : input.receiptEnvelopePresent = true)
    (verified : input.receiptVerified = true)
    (payload : input.receiptPayloadMatches = true)
    (consumed : input.replayKey ∈ input.replayState.consumed) :
    evaluateReceiptMintReplay input =
      Except.error ReceiptMintReplayReject.replayAlreadyConsumed := by
  have duplicate :
      input.replayState.importOne input.replayKey = none := by
    unfold ReplayState.importOne
    simp [consumed]
  unfold evaluateReceiptMintReplay
  simp [inbound, noDelta, present, verified, payload, duplicate]

theorem consumed_replay_key_precedes_mint_authorization
    {input : ReceiptMintReplayInput}
    (inbound : input.inboundBridgeMint = true)
    (noDelta : input.stateDeltasAbsent = true)
    (present : input.receiptEnvelopePresent = true)
    (verified : input.receiptVerified = true)
    (payload : input.receiptPayloadMatches = true)
    (consumed : input.replayKey ∈ input.replayState.consumed)
    (_unauthorized : input.mintAuthorized = false) :
    evaluateReceiptMintReplay input =
      Except.error ReceiptMintReplayReject.replayAlreadyConsumed := by
  exact consumed_replay_key_rejects
    inbound
    noDelta
    present
    verified
    payload
    consumed

theorem mint_not_authorized_rejects_after_verified_fresh_replay
    {input : ReceiptMintReplayInput}
    {nextReplayState : ReplayState}
    (inbound : input.inboundBridgeMint = true)
    (noDelta : input.stateDeltasAbsent = true)
    (present : input.receiptEnvelopePresent = true)
    (verified : input.receiptVerified = true)
    (payload : input.receiptPayloadMatches = true)
    (fresh :
      input.replayState.importOne input.replayKey =
        some nextReplayState)
    (unauthorized : input.mintAuthorized = false) :
    evaluateReceiptMintReplay input =
      Except.error ReceiptMintReplayReject.mintNotAuthorized := by
  unfold evaluateReceiptMintReplay
  simp [inbound, noDelta, present, verified, payload, fresh, unauthorized]

theorem amount_mismatch_rejects_after_authorization
    {input : ReceiptMintReplayInput}
    {nextReplayState : ReplayState}
    (inbound : input.inboundBridgeMint = true)
    (noDelta : input.stateDeltasAbsent = true)
    (present : input.receiptEnvelopePresent = true)
    (verified : input.receiptVerified = true)
    (payload : input.receiptPayloadMatches = true)
    (fresh :
      input.replayState.importOne input.replayKey =
        some nextReplayState)
    (authorized : input.mintAuthorized = true)
    (amountMismatch : input.amountMatchesReceipt = false) :
    evaluateReceiptMintReplay input =
      Except.error ReceiptMintReplayReject.amountDoesNotMatchReceipt := by
  unfold evaluateReceiptMintReplay
  simp [
    inbound,
    noDelta,
    present,
    verified,
    payload,
    fresh,
    authorized,
    amountMismatch
  ]

theorem amount_out_of_bounds_rejects_after_amount_match
    {input : ReceiptMintReplayInput}
    {nextReplayState : ReplayState}
    (inbound : input.inboundBridgeMint = true)
    (noDelta : input.stateDeltasAbsent = true)
    (present : input.receiptEnvelopePresent = true)
    (verified : input.receiptVerified = true)
    (payload : input.receiptPayloadMatches = true)
    (fresh :
      input.replayState.importOne input.replayKey =
        some nextReplayState)
    (authorized : input.mintAuthorized = true)
    (amountMatches : input.amountMatchesReceipt = true)
    (outOfBounds : input.amountWithinBound = false) :
    evaluateReceiptMintReplay input =
      Except.error ReceiptMintReplayReject.amountOutOfBounds := by
  unfold evaluateReceiptMintReplay
  simp [
    inbound,
    noDelta,
    present,
    verified,
    payload,
    fresh,
    authorized,
    amountMatches,
    outOfBounds
  ]

theorem accepted_implies_receipt_mint_replay_facts
    {input : ReceiptMintReplayInput}
    {accepted : ReceiptMintReplayAccepted}
    (ok : evaluateReceiptMintReplay input = Except.ok accepted) :
    ReceiptMintReplayFacts input accepted := by
  cases input with
  | mk inboundBridgeMint stateDeltasAbsent receiptEnvelopePresent
      receiptVerified receiptPayloadMatches replayState replayKey
      mintAuthorized amountMatchesReceipt amountWithinBound =>
      unfold evaluateReceiptMintReplay at ok
      cases inboundBridgeMint <;>
        cases stateDeltasAbsent <;>
        cases receiptEnvelopePresent <;>
        cases receiptVerified <;>
        cases receiptPayloadMatches <;>
        cases himport : replayState.importOne replayKey <;>
        cases mintAuthorized <;>
        cases amountMatchesReceipt <;>
        cases amountWithinBound <;>
        simp [himport, ReceiptMintReplayFacts] at ok ⊢
      subst accepted
      rfl

theorem accepted_imports_replay_key
    {input : ReceiptMintReplayInput}
    {accepted : ReceiptMintReplayAccepted}
    (ok : evaluateReceiptMintReplay input = Except.ok accepted) :
    input.replayKey ∈ accepted.nextReplayState.consumed := by
  have facts := accepted_implies_receipt_mint_replay_facts ok
  exact import_inserts_consumed facts.right.right.right.right.right.left

theorem accepted_prevents_replay_again
    {input : ReceiptMintReplayInput}
    {accepted : ReceiptMintReplayAccepted}
    (ok : evaluateReceiptMintReplay input = Except.ok accepted) :
    accepted.nextReplayState.importOne input.replayKey = none := by
  have facts := accepted_implies_receipt_mint_replay_facts ok
  exact import_prevents_reimport facts.right.right.right.right.right.left

def validInput : ReceiptMintReplayInput :=
  {
    inboundBridgeMint := true,
    stateDeltasAbsent := true,
    receiptEnvelopePresent := true,
    receiptVerified := true,
    receiptPayloadMatches := true,
    replayState := ReplayState.empty,
    replayKey := [byte 1, byte 2, byte 3],
    mintAuthorized := true,
    amountMatchesReceipt := true,
    amountWithinBound := true
  }

theorem valid_input_accepts :
    receiptMintReplayAccepts validInput = true := by
  decide

def unverifiedInput : ReceiptMintReplayInput :=
  { validInput with receiptVerified := false }

theorem unverified_input_rejects :
    receiptMintReplayRejection unverifiedInput =
      some ReceiptMintReplayReject.receiptNotVerified := by
  decide

def replayedInput : ReceiptMintReplayInput :=
  { validInput with
    replayState := { ReplayState.empty with
      consumed := [validInput.replayKey] } }

theorem replayed_input_rejects :
    receiptMintReplayRejection replayedInput =
      some ReceiptMintReplayReject.replayAlreadyConsumed := by
  decide

end MintReplayPolicy
end Bridge
end Hegemon
