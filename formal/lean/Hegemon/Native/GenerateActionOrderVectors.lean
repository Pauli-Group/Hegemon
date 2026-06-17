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

def bindingHashA : BindingHash :=
  patternedBytes 64 0x10

def bindingHashB : BindingHash :=
  patternedBytes 64 0x50

def nullifierA : NullifierBytes :=
  patternedBytes 48 0x80

def nullifierB : NullifierBytes :=
  patternedBytes 48 0xb0

def nullifierC : NullifierBytes :=
  patternedBytes 48 0xe0

def inlineArrivalZero : TransferOrderPreimageInput :=
  { bindingHash := bindingHashA
    nullifiers := [nullifierA]
    localReceivedMs := 0 }

def inlineArrivalMax : TransferOrderPreimageInput :=
  { bindingHash := bindingHashA
    nullifiers := [nullifierA]
    localReceivedMs := 18446744073709551615 }

def sidecarArrivalHigh : TransferOrderPreimageInput :=
  { bindingHash := bindingHashA
    nullifiers := [nullifierA]
    localReceivedMs := 987654321 }

def twoNullifierTransfer : TransferOrderPreimageInput :=
  { bindingHash := bindingHashA
    nullifiers := [nullifierA, nullifierB]
    localReceivedMs := 17 }

def bindingDriftTransfer : TransferOrderPreimageInput :=
  { bindingHash := bindingHashB
    nullifiers := [nullifierA]
    localReceivedMs := 17 }

def nullifierDriftTransfer : TransferOrderPreimageInput :=
  { bindingHash := bindingHashA
    nullifiers := [nullifierC]
    localReceivedMs := 17 }

def actionJson (action : OrderedAction) : String :=
  "{ \"is_transfer\": " ++ boolJson action.isTransfer
    ++ ", \"key\": \"" ++ hexBytes action.key ++ "\" }"

def actionsJson (actions : List OrderedAction) : String :=
  "[" ++ String.intercalate ", " (actions.map actionJson) ++ "]"

def hexStringList (values : List (List Byte)) : String :=
  "[" ++ String.intercalate ", " (values.map fun value => "\"" ++ hexBytes value ++ "\"") ++ "]"

def actionOrderCaseJson (name : String) (actions : List OrderedAction) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"actions\": " ++ actionsJson actions ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (canonicalTransferOrder actions) ++ "\n"
    ++ "    }"

def transferPreimageCaseJson
    (name route : String)
    (input : TransferOrderPreimageInput)
    (resampledReceivedMs : Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"route\": \"" ++ route ++ "\",\n"
    ++ "      \"binding_hash\": \"" ++ hexBytes input.bindingHash ++ "\",\n"
    ++ "      \"nullifiers\": " ++ hexStringList input.nullifiers ++ ",\n"
    ++ "      \"received_ms\": " ++ toString input.localReceivedMs ++ ",\n"
    ++ "      \"resampled_received_ms\": " ++ toString resampledReceivedMs ++ ",\n"
    ++ "      \"expected_preimage\": \"" ++ hexBytes (transferOrderPreimage input) ++ "\",\n"
    ++ "      \"expected_preimage_len\": " ++ toString (transferOrderPreimage input).length ++ ",\n"
    ++ "      \"expected_same_after_resample\": "
      ++ boolJson
        (transferOrderPreimage { input with localReceivedMs := resampledReceivedMs } =
          transferOrderPreimage input)
      ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 2,\n"
    ++ "  \"action_order_cases\": [\n"
    ++ actionOrderCaseJson "empty-block-is-canonical" [] ++ ",\n"
    ++ actionOrderCaseJson "single-transfer-is-canonical" [transfer midKey] ++ ",\n"
    ++ actionOrderCaseJson "ascending-transfer-keys-accepted" [transfer lowKey, transfer midKey, transfer highKey] ++ ",\n"
    ++ actionOrderCaseJson "equal-transfer-keys-accepted" [transfer midKey, transfer midKey] ++ ",\n"
    ++ actionOrderCaseJson "descending-transfer-keys-rejected" [transfer highKey, transfer lowKey] ++ ",\n"
    ++ actionOrderCaseJson "tail-inversion-rejected" [transfer lowKey, transfer highKey, transfer midKey] ++ ",\n"
    ++ actionOrderCaseJson "non-transfer-actions-ignored" [nonTransfer highKey, transfer lowKey, nonTransfer lowKey, transfer midKey] ++ ",\n"
    ++ actionOrderCaseJson "only-non-transfer-actions-accepted" [nonTransfer highKey, nonTransfer lowKey] ++ "\n"
    ++ "  ],\n"
    ++ "  \"transfer_order_preimage_cases\": [\n"
    ++ transferPreimageCaseJson "inline-transfer-arrival-zero" "inline" inlineArrivalZero 42 ++ ",\n"
    ++ transferPreimageCaseJson "inline-transfer-arrival-max" "inline" inlineArrivalMax 0 ++ ",\n"
    ++ transferPreimageCaseJson "sidecar-transfer-arrival-high" "sidecar" sidecarArrivalHigh 1 ++ ",\n"
    ++ transferPreimageCaseJson "inline-transfer-two-nullifiers" "inline" twoNullifierTransfer 88 ++ ",\n"
    ++ transferPreimageCaseJson "binding-hash-drift-changes-preimage" "inline" bindingDriftTransfer 17 ++ ",\n"
    ++ transferPreimageCaseJson "nullifier-drift-changes-preimage" "sidecar" nullifierDriftTransfer 17 ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
