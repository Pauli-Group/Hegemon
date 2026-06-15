import Hegemon.Bytes

namespace Hegemon
namespace Network
namespace PqNoise

def u64Max : Nat := 18446744073709551615

def bigEndianBytes (width value : Nat) : List Byte :=
  (List.range width).reverse.map fun index => byte (value / (256 ^ index))

def u64be (value : Nat) : List Byte :=
  bigEndianBytes 8 value

def protocolId : List Byte :=
  asciiBytes "/hegemon/pq-noise/1.0.0"

def initiatorToResponderInfo : List Byte :=
  asciiBytes "hegemon-pq-noise-v1-i2r"

def responderToInitiatorInfo : List Byte :=
  asciiBytes "hegemon-pq-noise-v1-r2i"

def sessionAadInfo : List Byte :=
  asciiBytes "hegemon-pq-noise-v1-aad"

structure SessionKeyInput where
  transcriptHash : List Byte
  shared1 : List Byte
  shared2 : List Byte
deriving DecidableEq, Repr

def hkdfSalt (input : SessionKeyInput) : List Byte :=
  input.transcriptHash

def hkdfIkm (input : SessionKeyInput) : List Byte :=
  input.shared1 ++ input.shared2

inductive KeySlot where
  | initiatorToResponder
  | responderToInitiator
deriving DecidableEq, Repr

def expandInfo : KeySlot -> List Byte
  | KeySlot.initiatorToResponder => initiatorToResponderInfo
  | KeySlot.responderToInitiator => responderToInitiatorInfo

inductive Role where
  | initiator
  | responder
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

structure ChannelState where
  role : Role
  sendCounter : Nat
  recvCounter : Nat
deriving DecidableEq, Repr

def initialState (role : Role) : ChannelState :=
  { role := role, sendCounter := 0, recvCounter := 0 }

def protectFrame
    (state : ChannelState) :
    Option (KeySlot × List Byte × ChannelState) :=
  match nextCounter state.sendCounter with
  | none => none
  | some nextSend =>
      some
        (sendSlot state.role,
          nonceFromCounter state.sendCounter,
          { state with sendCounter := nextSend })

def openFrame
    (state : ChannelState) :
    Option (KeySlot × List Byte × ChannelState) :=
  match nextCounter state.recvCounter with
  | none => none
  | some nextRecv =>
      some
        (recvSlot state.role,
          nonceFromCounter state.recvCounter,
          { state with recvCounter := nextRecv })

structure InitHelloSigningInput where
  version : Nat
  mlkemPublicKey : List Byte
  identityKey : List Byte
  nonce : Nat
deriving DecidableEq, Repr

structure RespHelloSigningInput where
  version : Nat
  mlkemPublicKey : List Byte
  mlkemCiphertext : List Byte
  identityKey : List Byte
  nonce : Nat
  transcriptHash : List Byte
deriving DecidableEq, Repr

structure FinishSigningInput where
  mlkemCiphertext : List Byte
  nonce : Nat
  transcriptHash : List Byte
deriving DecidableEq, Repr

def initHelloSigningPreimage (input : InitHelloSigningInput) : List Byte :=
  asciiBytes "init-hello"
    ++ [byte input.version]
    ++ input.mlkemPublicKey
    ++ input.identityKey
    ++ u64be input.nonce

def respHelloSigningPreimage (input : RespHelloSigningInput) : List Byte :=
  asciiBytes "resp-hello"
    ++ [byte input.version]
    ++ input.mlkemPublicKey
    ++ input.mlkemCiphertext
    ++ input.identityKey
    ++ u64be input.nonce
    ++ input.transcriptHash

def finishSigningPreimage (input : FinishSigningInput) : List Byte :=
  asciiBytes "finish"
    ++ input.mlkemCiphertext
    ++ u64be input.nonce
    ++ input.transcriptHash

def sampleSessionInput : SessionKeyInput := {
  transcriptHash := patternedBytes 32 19,
  shared1 := patternedBytes 32 73,
  shared2 := patternedBytes 32 131
}

def sampleInitSigningInput : InitHelloSigningInput := {
  version := 1,
  mlkemPublicKey := patternedBytes 13 29,
  identityKey := patternedBytes 17 41,
  nonce := 72623859790382856
}

def sampleTranscriptHash : List Byte :=
  patternedBytes 32 101

def sampleRespSigningInput : RespHelloSigningInput := {
  version := 1,
  mlkemPublicKey := patternedBytes 11 53,
  mlkemCiphertext := patternedBytes 19 67,
  identityKey := patternedBytes 17 83,
  nonce := 1234605616436508552,
  transcriptHash := sampleTranscriptHash
}

def sampleFinishSigningInput : FinishSigningInput := {
  mlkemCiphertext := patternedBytes 19 151,
  nonce := 11072869122414935808,
  transcriptHash := sampleTranscriptHash
}

theorem hkdf_infos_distinct :
    initiatorToResponderInfo ≠ responderToInitiatorInfo := by
  decide

theorem aad_info_distinct_from_i2r :
    sessionAadInfo ≠ initiatorToResponderInfo := by
  decide

theorem aad_info_distinct_from_r2i :
    sessionAadInfo ≠ responderToInitiatorInfo := by
  decide

theorem aad_info_distinct_from_send
    {role : Role} :
    sessionAadInfo ≠ expandInfo (sendSlot role) := by
  cases role
  · exact aad_info_distinct_from_i2r
  · exact aad_info_distinct_from_r2i

theorem aad_info_distinct_from_recv
    {role : Role} :
    sessionAadInfo ≠ expandInfo (recvSlot role) := by
  cases role
  · exact aad_info_distinct_from_r2i
  · exact aad_info_distinct_from_i2r

theorem sample_hkdf_ikm_is_ordered_shared_secrets :
    hkdfIkm sampleSessionInput =
      sampleSessionInput.shared1 ++ sampleSessionInput.shared2 := by
  rfl

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

theorem nonce_from_counter_zero :
    nonceFromCounter 0 =
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] := by
  decide

theorem nonce_from_counter_max :
    nonceFromCounter u64Max =
      [0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255] := by
  decide

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

theorem initial_state_counters_zero
    {role : Role} :
    (initialState role).sendCounter = 0
      ∧ (initialState role).recvCounter = 0 := by
  simp [initialState]

theorem protectFrame_accepts_below_max
    {state : ChannelState}
    (belowMax : state.sendCounter < u64Max) :
    protectFrame state =
      some
        (sendSlot state.role,
          nonceFromCounter state.sendCounter,
          { state with sendCounter := state.sendCounter + 1 }) := by
  unfold protectFrame
  simp [nextCounter_accepts_below_max belowMax]

theorem openFrame_accepts_below_max
    {state : ChannelState}
    (belowMax : state.recvCounter < u64Max) :
    openFrame state =
      some
        (recvSlot state.role,
          nonceFromCounter state.recvCounter,
          { state with recvCounter := state.recvCounter + 1 }) := by
  unfold openFrame
  simp [nextCounter_accepts_below_max belowMax]

theorem protectFrame_rejects_send_overflow
    {state : ChannelState}
    (atMax : state.sendCounter = u64Max) :
    protectFrame state = none := by
  unfold protectFrame
  rw [atMax, nextCounter_rejects_u64_max]

theorem openFrame_rejects_recv_overflow
    {state : ChannelState}
    (atMax : state.recvCounter = u64Max) :
    openFrame state = none := by
  unfold openFrame
  rw [atMax, nextCounter_rejects_u64_max]

theorem protectFrame_direction_and_counter
    {state next : ChannelState}
    {slot : KeySlot}
    {nonce : List Byte}
    (accepted :
      protectFrame state = some (slot, nonce, next)) :
    slot = sendSlot state.role
      ∧ slot ≠ recvSlot state.role
      ∧ nonce = nonceFromCounter state.sendCounter
      ∧ next.role = state.role
      ∧ next.sendCounter = state.sendCounter + 1
      ∧ next.recvCounter = state.recvCounter := by
  unfold protectFrame at accepted
  unfold nextCounter at accepted
  by_cases belowMax : state.sendCounter < u64Max
  · simp [belowMax] at accepted
    rcases accepted with ⟨hslot, hnonce, hnext⟩
    subst slot
    subst nonce
    subst next
    exact
      ⟨rfl,
        send_recv_slots_distinct,
        rfl,
        rfl,
        rfl,
        rfl⟩
  · simp [belowMax] at accepted

theorem openFrame_direction_and_counter
    {state next : ChannelState}
    {slot : KeySlot}
    {nonce : List Byte}
    (accepted :
      openFrame state = some (slot, nonce, next)) :
    slot = recvSlot state.role
      ∧ slot ≠ sendSlot state.role
      ∧ nonce = nonceFromCounter state.recvCounter
      ∧ next.role = state.role
      ∧ next.sendCounter = state.sendCounter
      ∧ next.recvCounter = state.recvCounter + 1 := by
  unfold openFrame at accepted
  unfold nextCounter at accepted
  by_cases belowMax : state.recvCounter < u64Max
  · simp [belowMax] at accepted
    rcases accepted with ⟨hslot, hnonce, hnext⟩
    subst slot
    subst nonce
    subst next
    exact
      ⟨rfl,
        Ne.symm send_recv_slots_distinct,
        rfl,
        rfl,
        rfl,
        rfl⟩
  · simp [belowMax] at accepted

theorem init_hello_preimage_starts_with_domain
    {input : InitHelloSigningInput} :
    ∃ rest, initHelloSigningPreimage input = asciiBytes "init-hello" ++ rest := by
  exists [byte input.version]
    ++ input.mlkemPublicKey
    ++ input.identityKey
    ++ u64be input.nonce

theorem resp_hello_preimage_starts_with_domain
    {input : RespHelloSigningInput} :
    ∃ rest, respHelloSigningPreimage input = asciiBytes "resp-hello" ++ rest := by
  exists [byte input.version]
    ++ input.mlkemPublicKey
    ++ input.mlkemCiphertext
    ++ input.identityKey
    ++ u64be input.nonce
    ++ input.transcriptHash

theorem finish_preimage_starts_with_domain
    {input : FinishSigningInput} :
    ∃ rest, finishSigningPreimage input = asciiBytes "finish" ++ rest := by
  exists input.mlkemCiphertext
    ++ u64be input.nonce
    ++ input.transcriptHash

theorem sample_init_resp_preimages_distinct :
    initHelloSigningPreimage sampleInitSigningInput ≠
      respHelloSigningPreimage sampleRespSigningInput := by
  decide

theorem sample_resp_finish_preimages_distinct :
    respHelloSigningPreimage sampleRespSigningInput ≠
      finishSigningPreimage sampleFinishSigningInput := by
  decide

theorem sample_resp_preimage_binds_transcript_hash :
    respHelloSigningPreimage sampleRespSigningInput =
      asciiBytes "resp-hello"
        ++ [1]
        ++ sampleRespSigningInput.mlkemPublicKey
        ++ sampleRespSigningInput.mlkemCiphertext
        ++ sampleRespSigningInput.identityKey
        ++ u64be sampleRespSigningInput.nonce
        ++ sampleTranscriptHash := by
  decide

theorem sample_finish_preimage_binds_transcript_hash :
    finishSigningPreimage sampleFinishSigningInput =
      asciiBytes "finish"
        ++ sampleFinishSigningInput.mlkemCiphertext
        ++ u64be sampleFinishSigningInput.nonce
        ++ sampleTranscriptHash := by
  decide

end PqNoise
end Network
end Hegemon
