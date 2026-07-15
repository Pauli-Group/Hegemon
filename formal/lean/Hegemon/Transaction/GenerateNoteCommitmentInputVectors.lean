import Hegemon.Transaction.NoteCommitmentInputs

open Hegemon
open Hegemon.Transaction.NoteCommitmentInputs

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def byteListJson (values : List Byte) : String :=
  natListJson (values.map Hegemon.byte)

def noteCaseJson
    (name : String)
    (value assetId : Nat)
    (pkRecipient pkAuth rho randomness : List Byte) : String :=
  let inputs := noteCommitmentInputs value assetId pkRecipient rho randomness pkAuth
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"value\": " ++ toString value ++ ",\n"
    ++ "      \"asset_id\": " ++ toString assetId ++ ",\n"
    ++ "      \"pk_recipient\": " ++ byteListJson pkRecipient ++ ",\n"
    ++ "      \"pk_auth\": " ++ byteListJson pkAuth ++ ",\n"
    ++ "      \"rho\": " ++ byteListJson rho ++ ",\n"
    ++ "      \"r\": " ++ byteListJson randomness ++ ",\n"
    ++ "      \"expected_inputs\": " ++ natListJson inputs ++ ",\n"
    ++ "      \"expected_input_count\": " ++ toString inputs.length ++ "\n"
    ++ "    }"

def assetCaseJson (name : String) (assetId : Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"asset_id\": " ++ toString assetId ++ ",\n"
    ++ "      \"expected_canonical\": " ++ boolJson (canonicalAssetId assetId) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"note_domain_tag\": " ++ toString noteDomainTag ++ ",\n"
    ++ "  \"note_commitment_input_cases\": [\n"
    ++ noteCaseJson
        "patterned-field-order"
        42
        7
        (patternedBytes 32 1)
        (patternedBytes 32 101)
        (patternedBytes 32 201)
        (patternedBytes 32 51) ++ ",\n"
    ++ noteCaseJson
        "distinct-high-byte-limbs"
        9007199254740991
        4242
        (patternedBytes 32 250)
        (patternedBytes 32 77)
        (patternedBytes 32 33)
        (patternedBytes 32 155) ++ ",\n"
    ++ noteCaseJson
        "zero-randomness-limb"
        42
        7
        zeroBytes32
        zeroBytes32
        zeroBytes32
        zeroBytes32 ++ ",\n"
    ++ noteCaseJson
        "field-modulus-randomness-limb-alias"
        42
        7
        zeroBytes32
        zeroBytes32
        zeroBytes32
        fieldModulusLowLimbBytes32 ++ "\n"
    ++ "  ],\n"
    ++ "  \"asset_id_cases\": [\n"
    ++ assetCaseJson "native" 0 ++ ",\n"
    ++ assetCaseJson "ordinary" 7 ++ ",\n"
    ++ assetCaseJson "padding-sentinel" balanceSlotPaddingAssetId ++ ",\n"
    ++ assetCaseJson "padding-field-alias" balanceSlotPaddingFieldId ++ ",\n"
    ++ assetCaseJson "field-modulus" fieldModulus ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
