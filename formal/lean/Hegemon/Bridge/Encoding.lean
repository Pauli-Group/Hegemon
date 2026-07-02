import Hegemon.Bytes

namespace Hegemon
namespace Bridge

def scaleCompactBigWidth (value : Nat) : Nat :=
  if value < 2 ^ 32 then
    4
  else if value < 2 ^ 40 then
    5
  else if value < 2 ^ 48 then
    6
  else if value < 2 ^ 56 then
    7
  else
    8

def scaleCompactLen (value : Nat) : List Byte :=
  if value < 2 ^ 6 then
    [byte (value * 4)]
  else if value < 2 ^ 14 then
    littleEndianBytes 2 (value * 4 + 1)
  else if value < 2 ^ 30 then
    littleEndianBytes 4 (value * 4 + 2)
  else
    let used := scaleCompactBigWidth value
    [byte ((used - 4) * 4 + 3)] ++ littleEndianBytes used value

structure BridgeMessageV1 where
  sourceChainId : List Byte
  destinationChainId : List Byte
  appFamilyId : Nat
  messageNonce : Nat
  sourceHeight : Nat
  payloadHash : List Byte
  payload : List Byte
deriving DecidableEq, Repr

def BridgeMessageV1.fixedPrefix (message : BridgeMessageV1) : List Byte :=
  message.sourceChainId
    ++ message.destinationChainId
    ++ u16le message.appFamilyId
    ++ u128le message.messageNonce
    ++ u64le message.sourceHeight
    ++ message.payloadHash

def BridgeMessageV1.encode (message : BridgeMessageV1) : List Byte :=
  message.fixedPrefix ++ scaleCompactLen message.payload.length ++ message.payload

theorem scaleCompactLen_lt64 {value : Nat} :
    value < 64 ->
    scaleCompactLen value = [byte (value * 4)] := by
  intro valueSmall
  unfold scaleCompactLen
  simp [valueSmall]

theorem bridgeMessageEncode_eq_prefix_len_payload (message : BridgeMessageV1) :
    message.encode = message.fixedPrefix ++ scaleCompactLen message.payload.length ++ message.payload := by
  rfl

theorem bridgeMessageEncode_length (message : BridgeMessageV1) :
    message.encode.length =
      message.fixedPrefix.length + (scaleCompactLen message.payload.length).length + message.payload.length := by
  simp [BridgeMessageV1.encode, Nat.add_assoc]

theorem bridgeMessageEncode_smallPayload (message : BridgeMessageV1) :
    message.payload.length < 64 ->
    message.encode = message.fixedPrefix ++ [byte (message.payload.length * 4)] ++ message.payload := by
  intro payloadSmall
  rw [bridgeMessageEncode_eq_prefix_len_payload]
  rw [scaleCompactLen_lt64 payloadSmall]

end Bridge
end Hegemon
