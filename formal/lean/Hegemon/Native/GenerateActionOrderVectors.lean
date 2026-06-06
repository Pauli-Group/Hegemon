import Hegemon.Native.ActionOrder

open Hegemon
open Hegemon.Native

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def lowKey : OrderKey :=
  patternedBytes 32 0x01

def midKey : OrderKey :=
  patternedBytes 32 0x40

def highKey : OrderKey :=
  patternedBytes 32 0xa0

def actionJson (action : OrderedAction) : String :=
  "{ \"is_transfer\": " ++ boolJson action.isTransfer
    ++ ", \"key\": \"" ++ hexBytes action.key ++ "\" }"

def actionsJson (actions : List OrderedAction) : String :=
  "[" ++ String.intercalate ", " (actions.map actionJson) ++ "]"

def actionOrderCaseJson (name : String) (actions : List OrderedAction) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"actions\": " ++ actionsJson actions ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (canonicalTransferOrder actions) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"action_order_cases\": [\n"
    ++ actionOrderCaseJson "empty-block-is-canonical" [] ++ ",\n"
    ++ actionOrderCaseJson "single-transfer-is-canonical" [transfer midKey] ++ ",\n"
    ++ actionOrderCaseJson "ascending-transfer-keys-accepted" [transfer lowKey, transfer midKey, transfer highKey] ++ ",\n"
    ++ actionOrderCaseJson "equal-transfer-keys-accepted" [transfer midKey, transfer midKey] ++ ",\n"
    ++ actionOrderCaseJson "descending-transfer-keys-rejected" [transfer highKey, transfer lowKey] ++ ",\n"
    ++ actionOrderCaseJson "tail-inversion-rejected" [transfer lowKey, transfer highKey, transfer midKey] ++ ",\n"
    ++ actionOrderCaseJson "non-transfer-actions-ignored" [nonTransfer highKey, transfer lowKey, nonTransfer lowKey, transfer midKey] ++ ",\n"
    ++ actionOrderCaseJson "only-non-transfer-actions-accepted" [nonTransfer highKey, nonTransfer lowKey] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
