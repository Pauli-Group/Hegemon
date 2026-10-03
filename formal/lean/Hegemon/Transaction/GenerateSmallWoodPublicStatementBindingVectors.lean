import Hegemon.Transaction.SmallWoodPublicStatementBinding

namespace Hegemon
namespace Transaction
namespace SmallWoodPublicStatementBinding

open Hegemon.Transaction.SmallWoodTranscriptBinding

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def sampleVerifierPublicValues : List Nat :=
  (List.range verifierPublicInputBaseLength).map fun value => value + 11

def stablecoinVerifierPublicValues : List Nat :=
  (List.range verifierPublicInputBaseLength).map fun value => value + 101

def publicStatementCaseJson
    (name : String)
    (verifierPublicValues statementValues : List Nat)
    (circuitVersion cryptoSuite : Nat) : String :=
  let expectedStatementValues :=
    smallwoodPublicStatementValues verifierPublicValues circuitVersion cryptoSuite
  let expectedStatementBytes :=
    smallwoodPublicStatementBytes expectedStatementValues
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"verifier_public_values\": " ++ natListJson verifierPublicValues ++ ",\n"
    ++ "      \"statement_values\": " ++ natListJson statementValues ++ ",\n"
    ++ "      \"circuit_version\": " ++ toString circuitVersion ++ ",\n"
    ++ "      \"crypto_suite\": " ++ toString cryptoSuite ++ ",\n"
    ++ "      \"expected_statement_values\": "
    ++ natListJson expectedStatementValues ++ ",\n"
    ++ "      \"expected_statement_bytes_hex\": \""
    ++ hexBytes expectedStatementBytes ++ "\",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson
      (validSmallwoodPublicStatementValues
        verifierPublicValues
        statementValues
        circuitVersion
        cryptoSuite)
    ++ "\n"
    ++ "    }"

def activeStatementValues : List Nat :=
  smallwoodPublicStatementValues
    sampleVerifierPublicValues
    activeCircuitVersion
    activeCryptoSuite

def stablecoinStatementValues : List Nat :=
  smallwoodPublicStatementValues
    stablecoinVerifierPublicValues
    activeCircuitVersion
    activeCryptoSuite

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"verifier_public_input_base_length\": "
    ++ toString verifierPublicInputBaseLength ++ ",\n"
    ++ "  \"smallwood_public_statement_value_count\": "
    ++ toString smallwoodPublicStatementValueCount ++ ",\n"
    ++ "  \"active_circuit_version\": "
    ++ toString activeCircuitVersion ++ ",\n"
    ++ "  \"active_crypto_suite\": "
    ++ toString activeCryptoSuite ++ ",\n"
    ++ "  \"smallwood_public_statement_binding_cases\": [\n"
    ++ publicStatementCaseJson
      "active-append-version-binding"
      sampleVerifierPublicValues
      activeStatementValues
      activeCircuitVersion
      activeCryptoSuite ++ ",\n"
    ++ publicStatementCaseJson
      "stablecoin-shaped-append-version-binding"
      stablecoinVerifierPublicValues
      stablecoinStatementValues
      activeCircuitVersion
      activeCryptoSuite ++ ",\n"
    ++ publicStatementCaseJson
      "truncated-verifier-public-vector-rejected"
      (sampleVerifierPublicValues.take (verifierPublicInputBaseLength - 1))
      activeStatementValues
      activeCircuitVersion
      activeCryptoSuite ++ ",\n"
    ++ publicStatementCaseJson
      "extended-public-statement-rejected"
      sampleVerifierPublicValues
      (activeStatementValues ++ [999])
      activeCircuitVersion
      activeCryptoSuite ++ ",\n"
    ++ publicStatementCaseJson
      "version-suffix-mismatch-rejected"
      sampleVerifierPublicValues
      activeStatementValues
      (activeCircuitVersion + 1)
      activeCryptoSuite ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

end SmallWoodPublicStatementBinding
end Transaction
end Hegemon

def main : IO Unit :=
  IO.print Hegemon.Transaction.SmallWoodPublicStatementBinding.vectorJson
