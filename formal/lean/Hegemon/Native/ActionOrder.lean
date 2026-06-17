import Hegemon.Bytes

namespace Hegemon
namespace Native

abbrev OrderKey := List Byte
abbrev BindingHash := List Byte
abbrev NullifierBytes := List Byte
abbrev SemanticHash := List Byte
abbrev RawTxHash := List Byte

structure OrderedAction where
  isTransfer : Bool
  key : OrderKey
deriving DecidableEq, Repr

structure TransferOrderPreimageInput where
  bindingHash : BindingHash
  nullifiers : List NullifierBytes
  localReceivedMs : Nat
deriving DecidableEq, Repr

structure NonTransferOrderPreimageInput where
  familyId : Nat
  actionId : Nat
  semanticHash : SemanticHash
  nullifiers : List NullifierBytes
  localReceivedMs : Nat
  localTxHash : RawTxHash
deriving DecidableEq, Repr

def transfer (key : OrderKey) : OrderedAction :=
  { isTransfer := true, key }

def nonTransfer (key : OrderKey) : OrderedAction :=
  { isTransfer := false, key }

def concatByteRows : List (List Byte) -> List Byte
  | [] => []
  | row :: rest => row ++ concatByteRows rest

def transferOrderPreimage
    (input : TransferOrderPreimageInput) : OrderKey :=
  input.bindingHash ++ concatByteRows input.nullifiers

def nonTransferOrderDomain : List Byte :=
  asciiBytes "non-transfer"

def nonTransferOrderPreimage
    (input : NonTransferOrderPreimageInput) : OrderKey :=
  nonTransferOrderDomain
    ++ u16le input.familyId
    ++ u16le input.actionId
    ++ input.semanticHash
    ++ concatByteRows input.nullifiers

def transferOrderAction
    (input : TransferOrderPreimageInput) : OrderedAction :=
  transfer (transferOrderPreimage input)

def nonTransferOrderAction
    (input : NonTransferOrderPreimageInput) : OrderedAction :=
  nonTransfer (nonTransferOrderPreimage input)

def lexLt : List Byte -> List Byte -> Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | left :: leftTail, right :: rightTail =>
      if left = right then
        lexLt leftTail rightTail
      else
        left < right

def lexLe (left right : OrderKey) : Bool :=
  if left = right then true else lexLt left right

def transferKeys : List OrderedAction -> List OrderKey
  | [] => []
  | action :: rest =>
      if action.isTransfer then
        action.key :: transferKeys rest
      else
        transferKeys rest

def keysNondecreasing : List OrderKey -> Bool
  | [] => true
  | [_] => true
  | first :: second :: rest =>
      lexLe first second && keysNondecreasing (second :: rest)

def canonicalTransferOrder (actions : List OrderedAction) : Bool :=
  keysNondecreasing (transferKeys actions)

theorem empty_canonical :
    canonicalTransferOrder [] = true := by
  rfl

theorem single_transfer_canonical
    {key : OrderKey} :
    canonicalTransferOrder [transfer key] = true := by
  unfold canonicalTransferOrder transferKeys transfer
  change keysNondecreasing [key] = true
  rfl

theorem non_transfer_ignored
    {key : OrderKey} {rest : List OrderedAction} :
    canonicalTransferOrder (nonTransfer key :: rest) =
      canonicalTransferOrder rest := by
  simp [canonicalTransferOrder, transferKeys, nonTransfer]

theorem ordered_pair_accepts
    {left right : OrderKey}
    (h : lexLe left right = true) :
    canonicalTransferOrder [transfer left, transfer right] = true := by
  simp [canonicalTransferOrder, transferKeys, keysNondecreasing, transfer, h]

theorem descending_pair_rejects
    {left right : OrderKey}
    (h : lexLe left right = false) :
    canonicalTransferOrder [transfer left, transfer right] = false := by
  simp [canonicalTransferOrder, transferKeys, keysNondecreasing, transfer, h]

theorem equal_pair_accepts
    {key : OrderKey} :
    canonicalTransferOrder [transfer key, transfer key] = true := by
  simp [canonicalTransferOrder, transferKeys, keysNondecreasing, transfer, lexLe]

theorem transfer_order_preimage_ignores_local_received_ms
    (input : TransferOrderPreimageInput)
    (localReceivedMs : Nat) :
    transferOrderPreimage { input with localReceivedMs := localReceivedMs } =
      transferOrderPreimage input := by
  rfl

theorem transfer_order_action_ignores_local_received_ms
    (input : TransferOrderPreimageInput)
    (localReceivedMs : Nat) :
    transferOrderAction { input with localReceivedMs := localReceivedMs } =
      transferOrderAction input := by
  rfl

theorem non_transfer_order_preimage_ignores_local_metadata
    (input : NonTransferOrderPreimageInput)
    (localReceivedMs : Nat)
    (localTxHash : RawTxHash) :
    nonTransferOrderPreimage
        { input with
          localReceivedMs := localReceivedMs
          localTxHash := localTxHash } =
      nonTransferOrderPreimage input := by
  rfl

theorem non_transfer_order_action_ignores_local_metadata
    (input : NonTransferOrderPreimageInput)
    (localReceivedMs : Nat)
    (localTxHash : RawTxHash) :
    nonTransferOrderAction
        { input with
          localReceivedMs := localReceivedMs
          localTxHash := localTxHash } =
      nonTransferOrderAction input := by
  rfl

theorem transfer_order_preimage_eq_of_public_fields
    {left right : TransferOrderPreimageInput}
    (bindingHash : left.bindingHash = right.bindingHash)
    (nullifiers : left.nullifiers = right.nullifiers) :
    transferOrderPreimage left = transferOrderPreimage right := by
  cases left
  cases right
  simp [transferOrderPreimage] at bindingHash nullifiers ⊢
  simp [bindingHash, nullifiers]

theorem non_transfer_order_preimage_eq_of_public_fields
    {left right : NonTransferOrderPreimageInput}
    (familyId : left.familyId = right.familyId)
    (actionId : left.actionId = right.actionId)
    (semanticHash : left.semanticHash = right.semanticHash)
    (nullifiers : left.nullifiers = right.nullifiers) :
    nonTransferOrderPreimage left = nonTransferOrderPreimage right := by
  cases left
  cases right
  simp [nonTransferOrderPreimage] at familyId actionId semanticHash nullifiers ⊢
  simp [familyId, actionId, semanticHash, nullifiers]

theorem transfer_relative_order_ignores_local_received_ms
    (left right : TransferOrderPreimageInput)
    (leftReceivedMs rightReceivedMs : Nat) :
    lexLe
        (transferOrderPreimage
          { left with localReceivedMs := leftReceivedMs })
        (transferOrderPreimage
          { right with localReceivedMs := rightReceivedMs }) =
      lexLe (transferOrderPreimage left) (transferOrderPreimage right) := by
  rfl

theorem canonical_transfer_pair_order_ignores_local_received_ms
    (left right : TransferOrderPreimageInput)
    (leftReceivedMs rightReceivedMs : Nat) :
    canonicalTransferOrder
        [ transferOrderAction
            { left with localReceivedMs := leftReceivedMs },
          transferOrderAction
            { right with localReceivedMs := rightReceivedMs } ] =
      canonicalTransferOrder
        [ transferOrderAction left,
          transferOrderAction right ] := by
  rfl

theorem non_transfer_relative_order_ignores_local_metadata
    (left right : NonTransferOrderPreimageInput)
    (leftReceivedMs rightReceivedMs : Nat)
    (leftTxHash rightTxHash : RawTxHash) :
    lexLe
        (nonTransferOrderPreimage
          { left with
            localReceivedMs := leftReceivedMs
            localTxHash := leftTxHash })
        (nonTransferOrderPreimage
          { right with
            localReceivedMs := rightReceivedMs
            localTxHash := rightTxHash }) =
      lexLe (nonTransferOrderPreimage left) (nonTransferOrderPreimage right) := by
  rfl

end Native
end Hegemon
