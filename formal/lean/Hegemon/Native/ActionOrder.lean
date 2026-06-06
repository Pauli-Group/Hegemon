import Hegemon.Bytes

namespace Hegemon
namespace Native

abbrev OrderKey := List Byte

structure OrderedAction where
  isTransfer : Bool
  key : OrderKey
deriving DecidableEq, Repr

def transfer (key : OrderKey) : OrderedAction :=
  { isTransfer := true, key }

def nonTransfer (key : OrderKey) : OrderedAction :=
  { isTransfer := false, key }

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

end Native
end Hegemon
