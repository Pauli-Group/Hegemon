import Hegemon.Transaction.NullifierInputs

open Hegemon
open Hegemon.Transaction.NullifierInputs

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def byteListJson (values : List Byte) : String :=
  natListJson (values.map Hegemon.byte)

def nullifierCaseJson
    (name : String)
    (prfKey position : Nat)
    (rho : List Byte) : String :=
  let inputs := nullifierInputs prfKey position rho
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"prf_key\": " ++ toString prfKey ++ ",\n"
    ++ "      \"position\": " ++ toString position ++ ",\n"
    ++ "      \"rho\": " ++ byteListJson rho ++ ",\n"
    ++ "      \"expected_inputs\": " ++ natListJson inputs ++ ",\n"
    ++ "      \"expected_input_count\": " ++ toString inputs.length ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"nullifier_domain_tag\": " ++ toString nullifierDomainTag ++ ",\n"
    ++ "  \"nullifier_input_cases\": [\n"
    ++ nullifierCaseJson
        "patterned-rho-order"
        123456789
        42
        (patternedBytes 32 9) ++ ",\n"
    ++ nullifierCaseJson
        "max-position-distinct-limbs"
        18446744069414584320
        4294967295
        (patternedBytes 32 241) ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
