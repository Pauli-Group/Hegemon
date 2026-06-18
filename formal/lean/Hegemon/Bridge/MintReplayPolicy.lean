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
  else if input.replayKey ∈ input.replayState.consumed then
    Except.error ReceiptMintReplayReject.replayAlreadyConsumed
  else if input.mintAuthorized = false then
    Except.error ReceiptMintReplayReject.mintNotAuthorized
  else if input.amountMatchesReceipt = false then
    Except.error ReceiptMintReplayReject.amountDoesNotMatchReceipt
  else if input.amountWithinBound = false then
    Except.error ReceiptMintReplayReject.amountOutOfBounds
  else
    match input.replayState.importOne input.replayKey with
    | none => Except.error ReceiptMintReplayReject.replayAlreadyConsumed
    | some nextReplayState =>
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
  if input.inboundBridgeMint = false then
    false
  else if input.stateDeltasAbsent = false then
    false
  else if input.receiptEnvelopePresent = false then
    false
  else if input.receiptVerified = false then
    false
  else if input.receiptPayloadMatches = false then
    false
  else if input.replayKey ∈ input.replayState.consumed then
    false
  else if input.mintAuthorized = false then
    false
  else if input.amountMatchesReceipt = false then
    false
  else if input.amountWithinBound = false then
    false
  else
    match input.replayState.importOne input.replayKey with
    | none => false
    | some _ => true

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

structure ReceiptMintReplayOneShotAuthorizationCertificate
    (input : ReceiptMintReplayInput)
    (accepted : ReceiptMintReplayAccepted) : Prop where
  policyFacts :
    ReceiptMintReplayFacts input accepted
  inboundBridgeMint :
    input.inboundBridgeMint = true
  directStateDeltasAbsent :
    input.stateDeltasAbsent = true
  receiptEnvelopePresent :
    input.receiptEnvelopePresent = true
  receiptVerified :
    input.receiptVerified = true
  receiptPayloadMatches :
    input.receiptPayloadMatches = true
  replayFreshBeforeImport :
    input.replayKey ∉ input.replayState.consumed
  replayImportHandoff :
    input.replayState.importOne input.replayKey =
      some accepted.nextReplayState
  mintAuthorized :
    input.mintAuthorized = true
  amountMatchesReceipt :
    input.amountMatchesReceipt = true
  amountWithinBound :
    input.amountWithinBound = true
  replayImported :
    input.replayKey ∈ accepted.nextReplayState.consumed
  duplicateReplayRejected :
    accepted.nextReplayState.importOne input.replayKey = none

theorem accepts_iff_receipt_mint_replay_preconditions
    (input : ReceiptMintReplayInput) :
    receiptMintReplayAccepts input = true ↔
      receiptMintReplayPreconditions input = true := by
  unfold receiptMintReplayAccepts
    receiptMintReplayPreconditions
    evaluateReceiptMintReplay
  by_cases inbound : input.inboundBridgeMint = false
  · simp [inbound]
  · by_cases noDelta : input.stateDeltasAbsent = false
    · simp [inbound, noDelta]
    · by_cases present : input.receiptEnvelopePresent = false
      · simp [inbound, noDelta, present]
      · by_cases verified : input.receiptVerified = false
        · simp [inbound, noDelta, present, verified]
        · by_cases payload : input.receiptPayloadMatches = false
          · simp [inbound, noDelta, present, verified, payload]
          · by_cases consumed : input.replayKey ∈ input.replayState.consumed
            · simp [inbound, noDelta, present, verified, payload, consumed]
            · by_cases authorized : input.mintAuthorized = false
              · simp [
                  inbound,
                  noDelta,
                  present,
                  verified,
                  payload,
                  consumed,
                  authorized
                ]
              · by_cases amount :
                  input.amountMatchesReceipt = false
                · simp [
                    inbound,
                    noDelta,
                    present,
                    verified,
                    payload,
                    consumed,
                    authorized,
                    amount
                  ]
                · by_cases bound :
                    input.amountWithinBound = false
                  · simp [
                      inbound,
                      noDelta,
                      present,
                      verified,
                      payload,
                      consumed,
                      authorized,
                      amount,
                      bound
                    ]
                  · cases imported :
                      input.replayState.importOne input.replayKey <;>
                    simp [
                      inbound,
                      noDelta,
                      present,
                      verified,
                      payload,
                      consumed,
                      authorized,
                      amount,
                      bound
                    ]

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

theorem direct_state_delta_mint_rejects_before_receipt_replay_or_authorization
    {input : ReceiptMintReplayInput}
    (inbound : input.inboundBridgeMint = true)
    (stateDeltaMintPresent : input.stateDeltasAbsent = false) :
    evaluateReceiptMintReplay input =
      Except.error ReceiptMintReplayReject.stateDeltaMintPresent := by
  unfold evaluateReceiptMintReplay
  simp [inbound, stateDeltaMintPresent]

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
  unfold evaluateReceiptMintReplay
  simp [inbound, noDelta, present, verified, payload, consumed]

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

theorem mint_not_authorized_rejects_before_fresh_replay_import
    {input : ReceiptMintReplayInput}
    (inbound : input.inboundBridgeMint = true)
    (noDelta : input.stateDeltasAbsent = true)
    (present : input.receiptEnvelopePresent = true)
    (verified : input.receiptVerified = true)
    (payload : input.receiptPayloadMatches = true)
    (fresh : input.replayKey ∉ input.replayState.consumed)
    (unauthorized : input.mintAuthorized = false) :
    evaluateReceiptMintReplay input =
      Except.error ReceiptMintReplayReject.mintNotAuthorized := by
  unfold evaluateReceiptMintReplay
  simp [inbound, noDelta, present, verified, payload, fresh, unauthorized]

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
  have notConsumed : input.replayKey ∉ input.replayState.consumed := by
    intro consumed
    have duplicate :
        input.replayState.importOne input.replayKey = none := by
      unfold ReplayState.importOne
      simp [consumed]
    rw [fresh] at duplicate
    contradiction
  exact mint_not_authorized_rejects_before_fresh_replay_import
    inbound
    noDelta
    present
    verified
    payload
    notConsumed
    unauthorized

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
  have notConsumed : input.replayKey ∉ input.replayState.consumed := by
    intro consumed
    have duplicate :
        input.replayState.importOne input.replayKey = none := by
      unfold ReplayState.importOne
      simp [consumed]
    rw [fresh] at duplicate
    contradiction
  unfold evaluateReceiptMintReplay
  simp [
    inbound,
    noDelta,
    present,
    verified,
    payload,
    notConsumed,
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
  have notConsumed : input.replayKey ∉ input.replayState.consumed := by
    intro consumed
    have duplicate :
        input.replayState.importOne input.replayKey = none := by
      unfold ReplayState.importOne
      simp [consumed]
    rw [fresh] at duplicate
    contradiction
  unfold evaluateReceiptMintReplay
  simp [
    inbound,
    noDelta,
    present,
    verified,
    payload,
    notConsumed,
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
        cases mintAuthorized <;>
        cases amountMatchesReceipt <;>
        cases amountWithinBound <;>
        by_cases consumed : replayKey ∈ replayState.consumed <;>
        cases himport : replayState.importOne replayKey <;>
        simp [consumed, himport, ReceiptMintReplayFacts] at ok ⊢
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

theorem accepted_exposes_verified_authorized_amount_and_one_shot_replay
    {input : ReceiptMintReplayInput}
    {accepted : ReceiptMintReplayAccepted}
    (ok : evaluateReceiptMintReplay input = Except.ok accepted) :
    input.inboundBridgeMint = true
      ∧ input.stateDeltasAbsent = true
      ∧ input.receiptEnvelopePresent = true
      ∧ input.receiptVerified = true
      ∧ input.receiptPayloadMatches = true
      ∧ input.mintAuthorized = true
      ∧ input.amountMatchesReceipt = true
      ∧ input.amountWithinBound = true
      ∧ input.replayState.importOne input.replayKey =
        some accepted.nextReplayState
      ∧ input.replayKey ∈ accepted.nextReplayState.consumed
      ∧ accepted.nextReplayState.importOne input.replayKey = none := by
  have facts := accepted_implies_receipt_mint_replay_facts ok
  exact
    ⟨facts.left,
      facts.right.left,
      facts.right.right.left,
      facts.right.right.right.left,
      facts.right.right.right.right.left,
      facts.right.right.right.right.right.right.left,
      facts.right.right.right.right.right.right.right.left,
      facts.right.right.right.right.right.right.right.right,
      facts.right.right.right.right.right.left,
      accepted_imports_replay_key ok,
      accepted_prevents_replay_again ok⟩

theorem accepted_binds_authorized_mint_exception_to_one_shot_replay_key
    {input : ReceiptMintReplayInput}
    {accepted : ReceiptMintReplayAccepted}
    (ok : evaluateReceiptMintReplay input = Except.ok accepted) :
    ReceiptMintReplayOneShotAuthorizationCertificate input accepted := by
  have facts := accepted_implies_receipt_mint_replay_facts ok
  have replayFresh :
      input.replayKey ∉ input.replayState.consumed := by
    intro consumed
    have duplicate :
        input.replayState.importOne input.replayKey = none := by
      unfold ReplayState.importOne
      simp [consumed]
    rw [facts.right.right.right.right.right.left] at duplicate
    contradiction
  exact
    {
      policyFacts := facts,
      inboundBridgeMint := facts.left,
      directStateDeltasAbsent := facts.right.left,
      receiptEnvelopePresent := facts.right.right.left,
      receiptVerified := facts.right.right.right.left,
      receiptPayloadMatches :=
        facts.right.right.right.right.left,
      replayFreshBeforeImport := replayFresh,
      replayImportHandoff :=
        facts.right.right.right.right.right.left,
      mintAuthorized :=
        facts.right.right.right.right.right.right.left,
      amountMatchesReceipt :=
        facts.right.right.right.right.right.right.right.left,
      amountWithinBound :=
        facts.right.right.right.right.right.right.right.right,
      replayImported := accepted_imports_replay_key ok,
      duplicateReplayRejected := accepted_prevents_replay_again ok
    }

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
