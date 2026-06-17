import Hegemon.Transaction.SmallWoodPublicStatementBinding

namespace Hegemon
namespace Transaction
namespace SmallWoodPublicStatementBinding

open Hegemon.Transaction.SmallWoodTranscriptBinding

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def sampleP3PublicValues : List Nat :=
  (List.range p3PublicInputBaseLength).map fun value => value + 11

def stablecoinP3PublicValues : List Nat :=
  (List.range p3PublicInputBaseLength).map fun value => value + 101

def publicStatementCaseJson
    (name : String)
    (p3PublicValues statementValues : List Nat)
    (circuitVersion cryptoSuite : Nat) : String :=
  let expectedStatementValues :=
    smallwoodPublicStatementValues p3PublicValues circuitVersion cryptoSuite
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"p3_public_values\": " ++ natListJson p3PublicValues ++ ",\n"
    ++ "      \"statement_values\": " ++ natListJson statementValues ++ ",\n"
    ++ "      \"circuit_version\": " ++ toString circuitVersion ++ ",\n"
    ++ "      \"crypto_suite\": " ++ toString cryptoSuite ++ ",\n"
    ++ "      \"expected_statement_values\": "
    ++ natListJson expectedStatementValues ++ ",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson
      (validSmallwoodPublicStatementValues
        p3PublicValues
        statementValues
        circuitVersion
        cryptoSuite)
    ++ "\n"
    ++ "    }"

def activeStatementValues : List Nat :=
  smallwoodPublicStatementValues
    sampleP3PublicValues
    activeCircuitVersion
    activeCryptoSuite

def stablecoinStatementValues : List Nat :=
  smallwoodPublicStatementValues
    stablecoinP3PublicValues
    activeCircuitVersion
    activeCryptoSuite

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"p3_public_input_base_length\": "
    ++ toString p3PublicInputBaseLength ++ ",\n"
    ++ "  \"smallwood_public_statement_value_count\": "
    ++ toString smallwoodPublicStatementValueCount ++ ",\n"
    ++ "  \"active_circuit_version\": "
    ++ toString activeCircuitVersion ++ ",\n"
    ++ "  \"active_crypto_suite\": "
    ++ toString activeCryptoSuite ++ ",\n"
    ++ "  \"smallwood_public_statement_binding_cases\": [\n"
    ++ publicStatementCaseJson
      "active-append-version-binding"
      sampleP3PublicValues
      activeStatementValues
      activeCircuitVersion
      activeCryptoSuite ++ ",\n"
    ++ publicStatementCaseJson
      "stablecoin-shaped-append-version-binding"
      stablecoinP3PublicValues
      stablecoinStatementValues
      activeCircuitVersion
      activeCryptoSuite ++ ",\n"
    ++ publicStatementCaseJson
      "truncated-p3-public-vector-rejected"
      (sampleP3PublicValues.take (p3PublicInputBaseLength - 1))
      activeStatementValues
      activeCircuitVersion
      activeCryptoSuite ++ ",\n"
    ++ publicStatementCaseJson
      "extended-public-statement-rejected"
      sampleP3PublicValues
      (activeStatementValues ++ [999])
      activeCircuitVersion
      activeCryptoSuite ++ ",\n"
    ++ publicStatementCaseJson
      "version-suffix-mismatch-rejected"
      sampleP3PublicValues
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
