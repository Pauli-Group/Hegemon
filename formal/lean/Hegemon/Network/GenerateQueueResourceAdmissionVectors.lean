import Hegemon.Network.QueueResourceAdmission

open Hegemon.Network.QueueResourceAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def optionalReserveRejectJson : Option QueueReserveReject -> String
  | none => "null"
  | some QueueReserveReject.messageExceedsByteBudget =>
      "\"message_exceeds_byte_budget\""
  | some QueueReserveReject.queueByteCounterOverflow =>
      "\"queue_byte_counter_overflow\""
  | some QueueReserveReject.queueByteBudgetExceeded =>
      "\"queue_byte_budget_exceeded\""

def optionalSendRejectJson : Option QueueSendReject -> String
  | none => "null"
  | some (QueueSendReject.reserveRejected reject) =>
      "{\"reserve_rejected\": " ++ optionalReserveRejectJson (some reject) ++ "}"
  | some QueueSendReject.queueFull => "\"queue_full\""
  | some QueueSendReject.queueClosed => "\"queue_closed\""

def queueKindName : QueueKind -> String
  | QueueKind.peerSend => "peer_send"
  | QueueKind.messageEvent => "message_event"

def sendOutcomeName : QueueSendOutcome -> String
  | QueueSendOutcome.accepted => "accepted"
  | QueueSendOutcome.full => "full"
  | QueueSendOutcome.closed => "closed"

def queueKindJson (kind : QueueKind) : String :=
  "\"" ++ queueKindName kind ++ "\""

def sendOutcomeJson (outcome : QueueSendOutcome) : String :=
  "\"" ++ sendOutcomeName outcome ++ "\""

def constantCaseJson (kind : QueueKind) : String :=
  "    {\n"
    ++ "      \"kind\": " ++ queueKindJson kind ++ ",\n"
    ++ "      \"max_queued_bytes\": "
      ++ toString (queueKindMaxQueuedBytes kind) ++ "\n"
    ++ "    }"

def reserveCaseJson (name : String) (input : QueueReserveInput) : String :=
  let result := evaluateQueueReserve input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"current_queued_bytes\": "
      ++ toString input.currentQueuedBytes ++ ",\n"
    ++ "      \"max_queued_bytes\": " ++ toString input.maxQueuedBytes ++ ",\n"
    ++ "      \"message_bytes\": " ++ toString input.messageBytes ++ ",\n"
    ++ "      \"usize_max\": " ++ toString input.usizeMax ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_reject\": "
      ++ optionalReserveRejectJson result ++ ",\n"
    ++ "      \"expected_queued_after\": "
      ++ toString (queuedBytesAfterReserve input) ++ "\n"
    ++ "    }"

def sendCaseJson (name : String) (input : BoundedSendInput) : String :=
  let result := evaluateBoundedSend input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"current_queued_bytes\": "
      ++ toString input.currentQueuedBytes ++ ",\n"
    ++ "      \"max_queued_bytes\": " ++ toString input.maxQueuedBytes ++ ",\n"
    ++ "      \"message_bytes\": " ++ toString input.messageBytes ++ ",\n"
    ++ "      \"usize_max\": " ++ toString input.usizeMax ++ ",\n"
    ++ "      \"send_outcome\": " ++ sendOutcomeJson input.sendOutcome ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_reject\": " ++ optionalSendRejectJson result ++ ",\n"
    ++ "      \"expected_queued_after\": "
      ++ toString (queuedBytesAfterBoundedSend input) ++ "\n"
    ++ "    }"

def rateLimitStateCaseJson (name : String) (input : RateLimitStateBoundInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"current_entries\": " ++ toString input.currentEntries ++ ",\n"
    ++ "      \"max_entries\": " ++ toString input.maxEntries ++ ",\n"
    ++ "      \"expected_retained_before_insert\": "
      ++ toString (rateLimitStateRetainedBeforeInsert input) ++ ",\n"
    ++ "      \"expected_entries_after_insert\": "
      ++ toString (rateLimitStateEntriesAfterInsert input) ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rateLimitStateAccepts input) ++ "\n"
    ++ "    }"

def reserveCases : List (String × QueueReserveInput) := [
  ("peer-exact-limit-reserve-accepted", peerExactLimitReserve),
  ("event-remaining-limit-reserve-accepted", eventRemainingLimitReserve),
  ("peer-message-over-budget-rejected", peerMessageOverBudgetReserve),
  ("peer-queue-budget-exceeded-rejected", peerQueueBudgetExceededReserve),
  ("usize-overflow-rejected", usizeOverflowReserve),
  ("zero-byte-reserve-noop",
    {
      currentQueuedBytes := peerSendQueueMaxQueuedBytes,
      maxQueuedBytes := peerSendQueueMaxQueuedBytes,
      messageBytes := 0,
      usizeMax := usize64Max
    }),
  ("message-over-budget-precedes-overflow",
    {
      currentQueuedBytes := usize64Max,
      maxQueuedBytes := peerSendQueueMaxQueuedBytes,
      messageBytes := peerSendQueueMaxQueuedBytes + 1,
      usizeMax := usize64Max
    })
]

def sendCases : List (String × BoundedSendInput) := [
  ("peer-send-accepted-updates-bytes", peerSendAccepted),
  ("peer-send-full-rolls-back-bytes", peerSendFullRollback),
  ("peer-send-closed-rolls-back-bytes", peerSendClosedRollback),
  ("peer-send-reserve-rejection-precedes-full",
    peerSendReserveRejectedBeforeFull)
  ]

def rateLimitStateCases : List (String × RateLimitStateBoundInput) := [
  ("rate-limit-state-below-cap", rateLimitStateBelowCap),
  ("rate-limit-state-at-cap", rateLimitStateAtCap),
  ("rate-limit-state-over-cap", rateLimitStateOverCap),
  ("rate-limit-state-zero-cap", rateLimitStateZeroCap)
]

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"constants\": [\n"
    ++ String.intercalate ",\n" ([
        QueueKind.peerSend,
        QueueKind.messageEvent
      ].map constantCaseJson) ++ "\n"
    ++ "  ],\n"
    ++ "  \"reserve_cases\": [\n"
    ++ String.intercalate ",\n"
      (reserveCases.map fun item => reserveCaseJson item.fst item.snd)
    ++ "\n"
    ++ "  ],\n"
    ++ "  \"send_cases\": [\n"
    ++ String.intercalate ",\n"
      (sendCases.map fun item => sendCaseJson item.fst item.snd)
    ++ "\n"
    ++ "  ],\n"
    ++ "  \"rate_limit_state_cases\": [\n"
    ++ String.intercalate ",\n"
      (rateLimitStateCases.map fun item => rateLimitStateCaseJson item.fst item.snd)
    ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
