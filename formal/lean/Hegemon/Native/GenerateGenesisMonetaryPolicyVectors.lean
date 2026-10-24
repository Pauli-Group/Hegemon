import Hegemon.Native.GenesisMonetaryPolicy

namespace Hegemon.Native.GenesisMonetaryPolicyVectors
open GenesisMonetaryPolicy

def caseJson (name : String) (context : GenesisContext) : String :=
  let projection := freshNativeGenesis context
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"pow_bits\": " ++ toString context.powBits ++ ",\n"
    ++ "      \"network_tag\": " ++ toString context.networkTag ++ ",\n"
    ++ "      \"timestamp_ms\": " ++ toString context.timestampMs ++ ",\n"
    ++ "      \"expected_height\": " ++ toString projection.height ++ ",\n"
    ++ "      \"expected_supply_digest\": \"" ++ toString projection.supplyDigest ++ "\",\n"
    ++ "      \"expected_tx_count\": " ++ toString projection.txCount ++ ",\n"
    ++ "      \"expected_message_count\": " ++ toString projection.messageCount ++ ",\n"
    ++ "      \"expected_action_bytes_len\": " ++ toString projection.actionBytes.length ++ ",\n"
    ++ "      \"expected_funded_native_note_count\": " ++ toString projection.fundedNativeNotes.length ++ ",\n"
    ++ "      \"expected_nullifier_count\": " ++ toString projection.spentNullifiers.length ++ ",\n"
    ++ "      \"expected_coinbase_allocation\": \"" ++ toString projection.coinbaseAllocation ++ "\",\n"
    ++ "      \"expected_genesis_subsidy\": \"" ++ toString (Hegemon.Consensus.blockSubsidy projection.height) ++ "\"\n"
    ++ "    }"

def vectorJson : String :=
  "{\n  \"schema_version\": 1,\n"
    ++ "  \"boundary\": \"fresh-native-genesis-monetary-projection-not-universal-rust-refinement\",\n"
    ++ "  \"genesis_monetary_policy_cases\": [\n"
    ++ caseJson "native-default-pow" { powBits := 0x1e10c6f7, networkTag := 0, timestampMs := 0 } ++ ",\n"
    ++ caseJson "easier-valid-compact-pow" { powBits := 0x207fffff, networkTag := 0, timestampMs := 0 } ++ ",\n"
    ++ caseJson "bitcoin-style-compact-pow" { powBits := 0x1d00ffff, networkTag := 1, timestampMs := 1700000000000 } ++ "\n"
    ++ "  ]\n}\n"

end Hegemon.Native.GenesisMonetaryPolicyVectors

def main : IO Unit := IO.print Hegemon.Native.GenesisMonetaryPolicyVectors.vectorJson
