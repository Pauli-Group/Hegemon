import Hegemon.Bytes

namespace Hegemon
namespace Network
namespace SecureChannel

def u64Max : Nat := 18446744073709551615

def bigEndianBytes (width value : Nat) : List Byte :=
  (List.range width).reverse.map fun index => byte (value / (256 ^ index))

def u64be (value : Nat) : List Byte :=
  bigEndianBytes 8 value

def networkKdfDomain : List Byte :=
  asciiBytes "hegemon-network-secure-channel-v2"

def initiatorToResponderLabel : List Byte :=
  asciiBytes "hegemon-network-v2-i2r"

def responderToInitiatorLabel : List Byte :=
  asciiBytes "hegemon-network-v2-r2i"

def sessionAadLabel : List Byte :=
  asciiBytes "hegemon-network-v2-aad"

structure KeyScheduleInput where
  offer : List Byte
  acceptance : List Byte
  confirmation : List Byte
  secretA : List Byte
  secretB : List Byte
deriving DecidableEq, Repr

def keyPreimage (label : List Byte) (input : KeyScheduleInput) : List Byte :=
  networkKdfDomain
    ++ label
    ++ input.offer
    ++ input.acceptance
    ++ input.confirmation
    ++ input.secretA
    ++ input.secretB

def initiatorToResponderPreimage (input : KeyScheduleInput) : List Byte :=
  keyPreimage initiatorToResponderLabel input

def responderToInitiatorPreimage (input : KeyScheduleInput) : List Byte :=
  keyPreimage responderToInitiatorLabel input

def sessionAadPreimage (input : KeyScheduleInput) : List Byte :=
  keyPreimage sessionAadLabel input

inductive Role where
  | initiator
  | responder
deriving DecidableEq, Repr

inductive KeySlot where
  | initiatorToResponder
  | responderToInitiator
deriving DecidableEq, Repr

def sendSlot : Role -> KeySlot
  | Role.initiator => KeySlot.initiatorToResponder
  | Role.responder => KeySlot.responderToInitiator

def recvSlot : Role -> KeySlot
  | Role.initiator => KeySlot.responderToInitiator
  | Role.responder => KeySlot.initiatorToResponder

def nonceFromCounter (counter : Nat) : List Byte :=
  [0, 0, 0, 0] ++ u64be counter

def nextCounter (counter : Nat) : Option Nat :=
  if counter < u64Max then some (counter + 1) else none

theorem directional_labels_distinct :
    initiatorToResponderLabel ≠ responderToInitiatorLabel := by
  native_decide

theorem aad_label_distinct_from_i2r :
    sessionAadLabel ≠ initiatorToResponderLabel := by
  native_decide

theorem aad_label_distinct_from_r2i :
    sessionAadLabel ≠ responderToInitiatorLabel := by
  native_decide

theorem initiator_sends_i2r :
    sendSlot Role.initiator = KeySlot.initiatorToResponder := by
  rfl

theorem initiator_receives_r2i :
    recvSlot Role.initiator = KeySlot.responderToInitiator := by
  rfl

theorem responder_sends_r2i :
    sendSlot Role.responder = KeySlot.responderToInitiator := by
  rfl

theorem responder_receives_i2r :
    recvSlot Role.responder = KeySlot.initiatorToResponder := by
  rfl

theorem send_recv_slots_distinct
    {role : Role} :
    sendSlot role ≠ recvSlot role := by
  cases role <;> decide

theorem key_preimage_starts_with_domain
    {label : List Byte}
    {input : KeyScheduleInput} :
    ∃ rest, keyPreimage label input = networkKdfDomain ++ rest := by
  exists label
    ++ input.offer
    ++ input.acceptance
    ++ input.confirmation
    ++ input.secretA
    ++ input.secretB

def sampleInput : KeyScheduleInput := {
  offer := patternedBytes 9 17,
  acceptance := patternedBytes 11 51,
  confirmation := patternedBytes 13 85,
  secretA := patternedBytes 32 119,
  secretB := patternedBytes 32 153
}

theorem sample_i2r_r2i_preimages_distinct :
    initiatorToResponderPreimage sampleInput ≠
      responderToInitiatorPreimage sampleInput := by
  native_decide

theorem sample_i2r_aad_preimages_distinct :
    initiatorToResponderPreimage sampleInput ≠
      sessionAadPreimage sampleInput := by
  native_decide

theorem nonce_from_counter_zero :
    nonceFromCounter 0 =
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] := by
  native_decide

theorem nonce_from_counter_one :
    nonceFromCounter 1 =
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] := by
  native_decide

theorem nonce_from_counter_max :
    nonceFromCounter u64Max =
      [0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255] := by
  native_decide

theorem nextCounter_accepts_below_max
    {counter : Nat}
    (belowMax : counter < u64Max) :
    nextCounter counter = some (counter + 1) := by
  unfold nextCounter
  simp [belowMax]

theorem nextCounter_rejects_u64_max :
    nextCounter u64Max = none := by
  unfold nextCounter
  simp

end SecureChannel
end Network
end Hegemon
