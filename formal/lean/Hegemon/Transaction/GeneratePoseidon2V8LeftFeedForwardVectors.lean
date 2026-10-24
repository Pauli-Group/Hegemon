import Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives

set_option maxHeartbeats 0

def natArrayJson (values : List Nat) : String :=
  "[" ++ String.intercalate "," (values.map toString) ++ "]"

def stringJson (value : String) : String := "\"" ++ value ++ "\""

def packedCaseJson (call : Nat) : String :=
  let left := caseLeft call
  let right := caseRight call
  let domain := poseidon2V8MerkleDomain
  "{\"call\":" ++ toString call ++ ",\"domain\":" ++ toString domain
    ++ ",\"left\":" ++ natArrayJson left ++ ",\"right\":" ++ natArrayJson right
    ++ ",\"initial_state\":" ++ natArrayJson (compressionFrame domain left right)
    ++ ",\"raw_final_state\":" ++ natArrayJson (rawPermutation domain left right)
    ++ ",\"digest\":" ++ natArrayJson (compress14 domain left right) ++ "}"

def fieldJson (name : String) (value : List Nat) : String :=
  "  " ++ stringJson name ++ ": " ++ natArrayJson value ++ ",\n"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema\": \"hegemon.poseidon2-v8.compff01-primitive-vectors-v1\",\n"
    ++ "  \"claim_scope\": \"lean_executable_field_framing_and_finite_kats\",\n"
    ++ "  \"generator\": \"Hegemon.Transaction.GeneratePoseidon2V8LeftFeedForwardVectors\",\n"
    ++ "  \"compression_mode_id\": " ++ stringJson compressionModeId ++ ",\n"
    ++ "  \"compression_mode_marker\": " ++ toString compressionModeMarker ++ ",\n"
    ++ "  \"parameter_set_id\": " ++ stringJson Poseidon2Width16Kernel.parameterSetId ++ ",\n"
    ++ "  \"parameter_set_sha256\": " ++ stringJson Poseidon2Width16Kernel.parameterSetSha256 ++ ",\n"
    ++ "  \"historical_semantic_target\": " ++ stringJson semanticTargetId ++ ",\n"
    ++ "  \"source_compiler_refinement_proved\": false,\n"
    ++ "  \"universal_accepted_witness_soundness_proved\": false,\n"
    ++ "  \"g1_qualified\": false,\n"
    ++ "  \"g7_qualified\": false,\n"
    ++ "  \"production_authority\": false,\n"
    ++ fieldJson "poseidon2_sponge_kat_domain2_1_2_3_4"
      (poseidon2V8Sponge poseidon2V8NullifierDomain [1, 2, 3, 4])
    ++ fieldJson "poseidon2_compress14_kat_ranges"
      (compress14 poseidon2V8MerkleDomain (List.range digestWords)
        ((List.range digestWords).map fun value => value + digestWords))
    ++ fieldJson "poseidon2_compress14_kat_merkle_domain"
      (compress14 0x4845_475f_4d45_524b (List.range digestWords)
        ((List.range digestWords).map fun value => value + digestWords))
    ++ fieldJson "poseidon2_nullifier_kat" (exactV8Nullifier 0 1 2 [3, 4, 5, 6])
    ++ fieldJson "stablecoin_config_digest_kat" katConfigDigest
    ++ fieldJson "stablecoin_before_root_kat" katBeforeRoot
    ++ fieldJson "stablecoin_mint_after_root_kat" katMintAfterRoot
    ++ fieldJson "stablecoin_burn_after_root_kat" katBurnAfterRoot
    ++ fieldJson "stablecoin_issuer_commitment_kat" katConfig.issuerCommitment
    ++ fieldJson "stablecoin_issuer_authorization_kat"
      (stablecoinIssuerAuthorization stablecoinV8KatIntent stablecoinV8KatIssuerSecret)
    ++ "  \"packed_compression_cases\": [\n    "
    ++ String.intercalate ",\n    " ((List.range packedCallCount).map packedCaseJson)
    ++ "\n  ]\n}\n"

def main : IO Unit := IO.print vectorJson
