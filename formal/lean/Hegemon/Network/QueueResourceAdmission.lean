import Hegemon.Network.FrameResourceAdmission
import Hegemon.Network.PeerStoreCapacityAdmission

namespace Hegemon
namespace Network
namespace QueueResourceAdmission

def mib (value : Nat) : Nat :=
  value * 1024 * 1024

def peerSendQueueMaxQueuedBytes : Nat :=
  mib 8

def eventChannelMaxQueuedBytes : Nat :=
  mib 32

def usize64Max : Nat :=
  18446744073709551615

inductive QueueKind where
  | peerSend
  | messageEvent
deriving DecidableEq, Repr

def queueKindMaxQueuedBytes : QueueKind -> Nat
  | QueueKind.peerSend => peerSendQueueMaxQueuedBytes
  | QueueKind.messageEvent => eventChannelMaxQueuedBytes

inductive QueueReserveReject where
  | messageExceedsByteBudget
  | queueByteCounterOverflow
  | queueByteBudgetExceeded
deriving DecidableEq, Repr

inductive QueueSendReject where
  | reserveRejected (reject : QueueReserveReject)
  | queueFull
  | queueClosed
deriving DecidableEq, Repr

inductive QueueSendOutcome where
  | accepted
  | full
  | closed
deriving DecidableEq, Repr

structure QueueReserveInput where
  currentQueuedBytes : Nat
  maxQueuedBytes : Nat
  messageBytes : Nat
  usizeMax : Nat
deriving DecidableEq, Repr

structure BoundedSendInput extends QueueReserveInput where
  sendOutcome : QueueSendOutcome
deriving DecidableEq, Repr

def queueReservePreconditions (input : QueueReserveInput) : Prop :=
  ¬ input.messageBytes > input.maxQueuedBytes
    ∧ ¬ input.currentQueuedBytes + input.messageBytes > input.usizeMax
    ∧ ¬ input.currentQueuedBytes + input.messageBytes > input.maxQueuedBytes

def evaluateQueueReserve
    (input : QueueReserveInput) : Option QueueReserveReject :=
  if input.messageBytes > input.maxQueuedBytes then
    some QueueReserveReject.messageExceedsByteBudget
  else if input.currentQueuedBytes + input.messageBytes > input.usizeMax then
    some QueueReserveReject.queueByteCounterOverflow
  else if input.currentQueuedBytes + input.messageBytes > input.maxQueuedBytes then
    some QueueReserveReject.queueByteBudgetExceeded
  else
    none

def queuedBytesAfterReserve (input : QueueReserveInput) : Nat :=
  match evaluateQueueReserve input with
  | none => input.currentQueuedBytes + input.messageBytes
  | some _ => input.currentQueuedBytes

def evaluateBoundedSend (input : BoundedSendInput) :
    Option QueueSendReject :=
  match evaluateQueueReserve input.toQueueReserveInput with
  | some reject => some (QueueSendReject.reserveRejected reject)
  | none =>
      match input.sendOutcome with
      | QueueSendOutcome.accepted => none
      | QueueSendOutcome.full => some QueueSendReject.queueFull
      | QueueSendOutcome.closed => some QueueSendReject.queueClosed

def queuedBytesAfterBoundedSend (input : BoundedSendInput) : Nat :=
  match evaluateQueueReserve input.toQueueReserveInput with
  | some _ => input.currentQueuedBytes
  | none =>
      match input.sendOutcome with
      | QueueSendOutcome.accepted =>
          input.currentQueuedBytes + input.messageBytes
      | QueueSendOutcome.full => input.currentQueuedBytes
      | QueueSendOutcome.closed => input.currentQueuedBytes

structure AcceptedQueueReserveFacts (input : QueueReserveInput) : Prop where
  accepted : evaluateQueueReserve input = none
  messageWithinBudget : ¬ input.messageBytes > input.maxQueuedBytes
  additionDoesNotOverflow :
    ¬ input.currentQueuedBytes + input.messageBytes > input.usizeMax
  queuedBytesWithinBudget :
    ¬ input.currentQueuedBytes + input.messageBytes > input.maxQueuedBytes
  queuedAfter :
    queuedBytesAfterReserve input =
      input.currentQueuedBytes + input.messageBytes

structure AcceptedBoundedSendFacts (input : BoundedSendInput) : Prop where
  accepted : evaluateBoundedSend input = none
  reserveFacts : AcceptedQueueReserveFacts input.toQueueReserveInput
  queuedAfter :
    queuedBytesAfterBoundedSend input =
      input.currentQueuedBytes + input.messageBytes

theorem queue_reserve_accepts_iff
    (input : QueueReserveInput) :
    evaluateQueueReserve input = none ↔
      queueReservePreconditions input := by
  unfold evaluateQueueReserve queueReservePreconditions
  by_cases messageOver : input.messageBytes > input.maxQueuedBytes
  · simp [messageOver]
  · by_cases overflow :
      input.currentQueuedBytes + input.messageBytes > input.usizeMax
    · simp [messageOver, overflow]
    · by_cases budgetOver :
        input.currentQueuedBytes + input.messageBytes > input.maxQueuedBytes
      · simp [messageOver, overflow, budgetOver]
      · simp [messageOver, overflow, budgetOver]

theorem accepted_queue_reserve_exposes_facts
    {input : QueueReserveInput}
    (accepted : evaluateQueueReserve input = none) :
    AcceptedQueueReserveFacts input := by
  have preconditions := (queue_reserve_accepts_iff input).mp accepted
  exact {
    accepted := accepted,
    messageWithinBudget := preconditions.1,
    additionDoesNotOverflow := preconditions.2.1,
    queuedBytesWithinBudget := preconditions.2.2,
    queuedAfter := by simp [queuedBytesAfterReserve, accepted]
  }

theorem message_over_budget_rejects
    {input : QueueReserveInput}
    (messageOver : input.messageBytes > input.maxQueuedBytes) :
    evaluateQueueReserve input =
      some QueueReserveReject.messageExceedsByteBudget := by
  simp [evaluateQueueReserve, messageOver]

theorem counter_overflow_rejects_after_message_ok
    {input : QueueReserveInput}
    (messageOk : ¬ input.messageBytes > input.maxQueuedBytes)
    (overflow :
      input.currentQueuedBytes + input.messageBytes > input.usizeMax) :
    evaluateQueueReserve input =
      some QueueReserveReject.queueByteCounterOverflow := by
  simp [evaluateQueueReserve, messageOk, overflow]

theorem queue_budget_exceeded_rejects_after_message_and_overflow_ok
    {input : QueueReserveInput}
    (messageOk : ¬ input.messageBytes > input.maxQueuedBytes)
    (noOverflow :
      ¬ input.currentQueuedBytes + input.messageBytes > input.usizeMax)
    (budgetOver :
      input.currentQueuedBytes + input.messageBytes > input.maxQueuedBytes) :
    evaluateQueueReserve input =
      some QueueReserveReject.queueByteBudgetExceeded := by
  simp [evaluateQueueReserve, messageOk, noOverflow, budgetOver]

theorem accepted_bounded_send_exposes_facts
    {input : BoundedSendInput}
    (accepted : evaluateBoundedSend input = none) :
    AcceptedBoundedSendFacts input := by
  unfold evaluateBoundedSend at accepted
  cases reserve : evaluateQueueReserve input.toQueueReserveInput with
  | none =>
      cases outcome : input.sendOutcome with
      | accepted =>
          exact {
            accepted := by
              simp [evaluateBoundedSend, reserve, outcome],
            reserveFacts := accepted_queue_reserve_exposes_facts reserve,
            queuedAfter := by
              simp [queuedBytesAfterBoundedSend, reserve, outcome]
          }
      | full =>
          simp [reserve, outcome] at accepted
      | closed =>
          simp [reserve, outcome] at accepted
  | some reject =>
      simp [reserve] at accepted

theorem bounded_send_full_rolls_back_queued_bytes
    {input : BoundedSendInput}
    (reserved : evaluateQueueReserve input.toQueueReserveInput = none)
    (full : input.sendOutcome = QueueSendOutcome.full) :
    evaluateBoundedSend input = some QueueSendReject.queueFull
      ∧ queuedBytesAfterBoundedSend input = input.currentQueuedBytes := by
  constructor
  · simp [evaluateBoundedSend, reserved, full]
  · simp [queuedBytesAfterBoundedSend, reserved, full]

theorem bounded_send_closed_rolls_back_queued_bytes
    {input : BoundedSendInput}
    (reserved : evaluateQueueReserve input.toQueueReserveInput = none)
    (closed : input.sendOutcome = QueueSendOutcome.closed) :
    evaluateBoundedSend input = some QueueSendReject.queueClosed
      ∧ queuedBytesAfterBoundedSend input = input.currentQueuedBytes := by
  constructor
  · simp [evaluateBoundedSend, reserved, closed]
  · simp [queuedBytesAfterBoundedSend, reserved, closed]

theorem bounded_send_reserve_rejection_precedes_channel_state
    {input : BoundedSendInput}
    {reject : QueueReserveReject}
    (rejected :
      evaluateQueueReserve input.toQueueReserveInput = some reject) :
    evaluateBoundedSend input =
      some (QueueSendReject.reserveRejected reject)
      ∧ queuedBytesAfterBoundedSend input = input.currentQueuedBytes := by
  constructor
  · simp [evaluateBoundedSend, rejected]
  · simp [queuedBytesAfterBoundedSend, rejected]

theorem bounded_send_rejection_rolls_back_queued_bytes
    {input : BoundedSendInput}
    {reject : QueueSendReject}
    (rejected : evaluateBoundedSend input = some reject) :
    queuedBytesAfterBoundedSend input = input.currentQueuedBytes := by
  cases reserve : evaluateQueueReserve input.toQueueReserveInput with
  | none =>
      cases outcome : input.sendOutcome <;>
        simp [evaluateBoundedSend, queuedBytesAfterBoundedSend, reserve,
          outcome] at rejected ⊢
  | some reserveReject =>
      simp [queuedBytesAfterBoundedSend, reserve]

inductive NetworkPreHeavyResourceReject where
  | frameRejected (reject : FrameResourceAdmission.FrameReject)
  | queueRejected (reject : QueueSendReject)
deriving DecidableEq, Repr

structure NetworkPreHeavyResourceInput where
  frame : FrameResourceAdmission.FrameDecodeInput
  queue : BoundedSendInput
  peerStoreMaxEntries : Nat
  peerStoreEntriesByRecency : List PeerStoreCapacityAdmission.PeerStoreEntry
deriving DecidableEq, Repr

def evaluateNetworkPreHeavyResourceAdmission
    (input : NetworkPreHeavyResourceInput) :
    Option NetworkPreHeavyResourceReject :=
  match FrameResourceAdmission.evaluateFrameDecode input.frame with
  | some reject =>
      some (NetworkPreHeavyResourceReject.frameRejected reject)
  | none =>
      match evaluateBoundedSend input.queue with
      | some reject =>
          some (NetworkPreHeavyResourceReject.queueRejected reject)
      | none =>
          none

def queuedBytesAfterNetworkPreHeavyResourceAdmission
    (input : NetworkPreHeavyResourceInput) : Nat :=
  match FrameResourceAdmission.evaluateFrameDecode input.frame with
  | some _ => input.queue.currentQueuedBytes
  | none => queuedBytesAfterBoundedSend input.queue

structure AcceptedNetworkPreHeavyResourceFacts
    (input : NetworkPreHeavyResourceInput) : Prop where
  accepted :
    evaluateNetworkPreHeavyResourceAdmission input = none
  frameFacts :
    FrameResourceAdmission.AcceptedFrameDecodeFacts input.frame
  queueFacts :
    AcceptedBoundedSendFacts input.queue
  peerStoreFacts :
    PeerStoreCapacityAdmission.AcceptedPeerStoreCapacityFacts
      input.peerStoreMaxEntries
      input.peerStoreEntriesByRecency
  queueChargeMatchesDecodedFrame :
    input.queue.messageBytes = input.frame.encodedBytes
  frameBytesWithinKindBound :
    input.frame.encodedBytes <=
      FrameResourceAdmission.frameKindMaxLen input.frame.kind
  queueDeltaWithinBudget :
    input.queue.currentQueuedBytes + input.queue.messageBytes <=
      input.queue.maxQueuedBytes
  queuedAfterExact :
    queuedBytesAfterNetworkPreHeavyResourceAdmission input =
      input.queue.currentQueuedBytes + input.queue.messageBytes
  peerStoreRetainedCountBound :
    (PeerStoreCapacityAdmission.enforcePeerStoreCapacity
      input.peerStoreMaxEntries
      input.peerStoreEntriesByRecency).length <=
        input.peerStoreMaxEntries

theorem network_pre_heavy_frame_rejection_precedes_queue_reservation
    {input : NetworkPreHeavyResourceInput}
    {reject : FrameResourceAdmission.FrameReject}
    (frameRejected :
      FrameResourceAdmission.evaluateFrameDecode input.frame =
        some reject) :
    evaluateNetworkPreHeavyResourceAdmission input =
        some (NetworkPreHeavyResourceReject.frameRejected reject)
      ∧ queuedBytesAfterNetworkPreHeavyResourceAdmission input =
        input.queue.currentQueuedBytes := by
  constructor
  · simp [evaluateNetworkPreHeavyResourceAdmission, frameRejected]
  · simp [queuedBytesAfterNetworkPreHeavyResourceAdmission, frameRejected]

theorem network_pre_heavy_queue_rejection_rolls_back_after_frame_acceptance
    {input : NetworkPreHeavyResourceInput}
    {reject : QueueSendReject}
    (frameAccepted :
      FrameResourceAdmission.evaluateFrameDecode input.frame = none)
    (queueRejected : evaluateBoundedSend input.queue = some reject) :
    evaluateNetworkPreHeavyResourceAdmission input =
        some (NetworkPreHeavyResourceReject.queueRejected reject)
      ∧ queuedBytesAfterNetworkPreHeavyResourceAdmission input =
        input.queue.currentQueuedBytes := by
  constructor
  · simp [evaluateNetworkPreHeavyResourceAdmission, frameAccepted, queueRejected]
  · simpa [queuedBytesAfterNetworkPreHeavyResourceAdmission, frameAccepted] using
      bounded_send_rejection_rolls_back_queued_bytes queueRejected

theorem accepted_network_pre_heavy_resource_admission_exposes_facts
    {input : NetworkPreHeavyResourceInput}
    (accepted :
      evaluateNetworkPreHeavyResourceAdmission input = none)
    (queueChargeMatchesDecodedFrame :
      input.queue.messageBytes = input.frame.encodedBytes) :
    AcceptedNetworkPreHeavyResourceFacts input := by
  cases frameAccepted :
      FrameResourceAdmission.evaluateFrameDecode input.frame with
  | some reject =>
      simp [evaluateNetworkPreHeavyResourceAdmission, frameAccepted] at accepted
  | none =>
      cases queueAccepted : evaluateBoundedSend input.queue with
      | some reject =>
          simp [evaluateNetworkPreHeavyResourceAdmission, frameAccepted,
            queueAccepted] at accepted
      | none =>
          have frameFacts :=
            FrameResourceAdmission.accepted_frame_decode_exposes_facts
              frameAccepted
          have queueFacts :=
            accepted_bounded_send_exposes_facts queueAccepted
          have peerStoreFacts :=
            PeerStoreCapacityAdmission.accepted_peer_store_capacity_exposes_bound
              input.peerStoreMaxEntries
              input.peerStoreEntriesByRecency
          exact {
            accepted := by
              simp [evaluateNetworkPreHeavyResourceAdmission, frameAccepted,
                queueAccepted]
            frameFacts := frameFacts
            queueFacts := queueFacts
            peerStoreFacts := peerStoreFacts
            queueChargeMatchesDecodedFrame := queueChargeMatchesDecodedFrame
            frameBytesWithinKindBound := frameFacts.withinBound
            queueDeltaWithinBudget := by
              have within := queueFacts.reserveFacts.queuedBytesWithinBudget
              omega
            queuedAfterExact := by
              simpa [queuedBytesAfterNetworkPreHeavyResourceAdmission,
                frameAccepted] using queueFacts.queuedAfter
            peerStoreRetainedCountBound :=
              peerStoreFacts.retainedCountBound
          }

theorem accepted_network_pre_heavy_resource_charge_within_frame_bound
    {input : NetworkPreHeavyResourceInput}
    (facts : AcceptedNetworkPreHeavyResourceFacts input) :
    input.queue.messageBytes <=
      FrameResourceAdmission.frameKindMaxLen input.frame.kind := by
  rw [facts.queueChargeMatchesDecodedFrame]
  exact facts.frameBytesWithinKindBound

def peerExactLimitReserve : QueueReserveInput :=
  {
    currentQueuedBytes := 0,
    maxQueuedBytes := peerSendQueueMaxQueuedBytes,
    messageBytes := peerSendQueueMaxQueuedBytes,
    usizeMax := usize64Max
  }

theorem peer_exact_limit_reserve_accepts :
    evaluateQueueReserve peerExactLimitReserve = none := by
  decide

def eventRemainingLimitReserve : QueueReserveInput :=
  {
    currentQueuedBytes := eventChannelMaxQueuedBytes - 1,
    maxQueuedBytes := eventChannelMaxQueuedBytes,
    messageBytes := 1,
    usizeMax := usize64Max
  }

theorem event_remaining_limit_reserve_accepts :
    evaluateQueueReserve eventRemainingLimitReserve = none := by
  decide

def peerMessageOverBudgetReserve : QueueReserveInput :=
  {
    currentQueuedBytes := 0,
    maxQueuedBytes := peerSendQueueMaxQueuedBytes,
    messageBytes := peerSendQueueMaxQueuedBytes + 1,
    usizeMax := usize64Max
  }

theorem peer_message_over_budget_rejects :
    evaluateQueueReserve peerMessageOverBudgetReserve =
      some QueueReserveReject.messageExceedsByteBudget := by
  decide

def peerQueueBudgetExceededReserve : QueueReserveInput :=
  {
    currentQueuedBytes := peerSendQueueMaxQueuedBytes,
    maxQueuedBytes := peerSendQueueMaxQueuedBytes,
    messageBytes := 1,
    usizeMax := usize64Max
  }

theorem peer_queue_budget_exceeded_rejects :
    evaluateQueueReserve peerQueueBudgetExceededReserve =
      some QueueReserveReject.queueByteBudgetExceeded := by
  decide

def usizeOverflowReserve : QueueReserveInput :=
  {
    currentQueuedBytes := usize64Max,
    maxQueuedBytes := usize64Max,
    messageBytes := 1,
    usizeMax := usize64Max
  }

theorem usize_overflow_rejects :
    evaluateQueueReserve usizeOverflowReserve =
      some QueueReserveReject.queueByteCounterOverflow := by
  decide

def peerSendAccepted : BoundedSendInput :=
  {
    currentQueuedBytes := 5,
    maxQueuedBytes := peerSendQueueMaxQueuedBytes,
    messageBytes := 7,
    usizeMax := usize64Max,
    sendOutcome := QueueSendOutcome.accepted
  }

theorem peer_send_accepted_updates_queue_bytes :
    evaluateBoundedSend peerSendAccepted = none
      ∧ queuedBytesAfterBoundedSend peerSendAccepted = 12 := by
  decide

def peerSendFullRollback : BoundedSendInput :=
  { peerSendAccepted with sendOutcome := QueueSendOutcome.full }

theorem peer_send_full_rolls_back :
    evaluateBoundedSend peerSendFullRollback =
        some QueueSendReject.queueFull
      ∧ queuedBytesAfterBoundedSend peerSendFullRollback = 5 := by
  decide

def peerSendClosedRollback : BoundedSendInput :=
  { peerSendAccepted with sendOutcome := QueueSendOutcome.closed }

theorem peer_send_closed_rolls_back :
    evaluateBoundedSend peerSendClosedRollback =
        some QueueSendReject.queueClosed
      ∧ queuedBytesAfterBoundedSend peerSendClosedRollback = 5 := by
  decide

def peerSendReserveRejectedBeforeFull : BoundedSendInput :=
  {
    currentQueuedBytes := 0,
    maxQueuedBytes := peerSendQueueMaxQueuedBytes,
    messageBytes := peerSendQueueMaxQueuedBytes + 1,
    usizeMax := usize64Max,
    sendOutcome := QueueSendOutcome.full
  }

theorem peer_send_reserve_rejects_before_full :
    evaluateBoundedSend peerSendReserveRejectedBeforeFull =
        some
          (QueueSendReject.reserveRejected
            QueueReserveReject.messageExceedsByteBudget)
      ∧ queuedBytesAfterBoundedSend peerSendReserveRejectedBeforeFull = 0 := by
  decide

end QueueResourceAdmission
end Network
end Hegemon
