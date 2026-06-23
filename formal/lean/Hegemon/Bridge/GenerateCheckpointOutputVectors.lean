import Hegemon.Bridge.CheckpointOutput

open Hegemon
open Hegemon.Bridge.CheckpointOutput

def outputCaseJson (name : String) (output : OutputInput) : String :=
  let canonical := canonicalPreimage output
  let wire := wireBytes output
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"source_chain_id_hex\": \"" ++ hexBytes output.sourceChainId ++ "\",\n"
    ++ "      \"rules_hash_hex\": \"" ++ hexBytes output.rulesHash ++ "\",\n"
    ++ "      \"trusted_checkpoint_digest_hex\": \""
      ++ hexBytes output.trustedCheckpointDigest ++ "\",\n"
    ++ "      \"checkpoint_height\": " ++ toString output.checkpointHeight ++ ",\n"
    ++ "      \"checkpoint_header_hash_hex\": \"" ++ hexBytes output.checkpointHeaderHash ++ "\",\n"
    ++ "      \"checkpoint_cumulative_work_hex\": \"" ++ hexBytes output.checkpointCumulativeWork ++ "\",\n"
    ++ "      \"canonical_tip_height\": " ++ toString output.canonicalTipHeight ++ ",\n"
    ++ "      \"canonical_tip_header_hash_hex\": \"" ++ hexBytes output.canonicalTipHeaderHash ++ "\",\n"
    ++ "      \"canonical_tip_cumulative_work_hex\": \"" ++ hexBytes output.canonicalTipCumulativeWork ++ "\",\n"
    ++ "      \"message_root_hex\": \"" ++ hexBytes output.messageRoot ++ "\",\n"
    ++ "      \"message_hash_hex\": \"" ++ hexBytes output.messageHash ++ "\",\n"
    ++ "      \"message_nonce_decimal\": \"" ++ toString output.messageNonce ++ "\",\n"
    ++ "      \"confirmations_checked\": " ++ toString output.confirmationsChecked ++ ",\n"
    ++ "      \"min_work_checked_hex\": \"" ++ hexBytes output.minWorkChecked ++ "\",\n"
    ++ "      \"expected_canonical_hex\": \"" ++ hexBytes canonical ++ "\",\n"
    ++ "      \"expected_canonical_len\": " ++ toString canonical.length ++ ",\n"
    ++ "      \"expected_wire_hex\": \"" ++ hexBytes wire ++ "\",\n"
    ++ "      \"expected_wire_len\": " ++ toString wire.length ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_checkpoint_output_cases\": [\n"
    ++ outputCaseJson "sample-output" sampleOutput ++ ",\n"
    ++ outputCaseJson "max-scalar-output" maxScalarOutput ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
