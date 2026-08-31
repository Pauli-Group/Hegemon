import Hegemon.Transaction.Poseidon2V8SemanticAdequacy
import Hegemon.Transaction.Poseidon2V8DecoderRefinement

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8SemanticAdequacy
open Hegemon.Transaction.Poseidon2V8DecoderRefinement

def boolJson (value : Bool) : String := if value then "true" else "false"

def stringJson (value : String) : String := "\"" ++ value ++ "\""

def natArrayJson (values : List Nat) : String :=
  "[" ++ String.intercalate "," (values.map toString) ++ "]"

def natMatrixJson (values : List (List Nat)) : String :=
  "[" ++ String.intercalate "," (values.map natArrayJson) ++ "]"

def semanticFamilyJson (family : SemanticFamily) : String :=
  "{\"name\":" ++ stringJson family.name ++ ",\"external_to_private_relation\":"
    ++ boolJson family.externalToPrivateRelation ++ "}"

def semanticFamiliesJson : String :=
  "[" ++ String.intercalate "," (exactSemanticFamilies.map semanticFamilyJson) ++ "]"

def coverageName : CheckedInSemanticAdequacyCoverage → String
  | .typedLoweringReplay => "typed_lowering_replay"
  | .sourceVerifierCanonicalRelowering => "source_verifier_canonical_relowering"
  | .universalAcceptedWitnessSoundness => "universal_accepted_witness_soundness"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema\": " ++ stringJson refinementReceiptSchema ++ ",\n"
    ++ "  \"semantic_target\": " ++ stringJson semanticTargetId ++ ",\n"
    ++ "  \"relation_program\": \"HGV8RP03\",\n"
    ++ "  \"checked_in_coverage\": "
    ++ stringJson (coverageName checkedInSemanticAdequacyCoverage) ++ ",\n"
    ++ "  \"typed_lowering_replay_available\": true,\n"
    ++ "  \"arbitrary_packed_assignment_decoder_available\": true,\n"
    ++ "  \"canonical_typed_relowering_source_verifier_enforced\": true,\n"
    ++ "  \"source_semantic_gate_enforced\": true,\n"
    ++ "  \"source_semantic_gate_lean_model_theorem\": true,\n"
    ++ "  \"concrete_rust_to_lean_universal_refinement_proved\": false,\n"
    ++ "  \"decoder_source_vector\": " ++ natMatrixJson decoderSources ++ ",\n"
    ++ "  \"decoder_family_counts\": "
    ++ natArrayJson [252, 252, 23, 23, 77, 94] ++ ",\n"
    ++ "  \"decoder_operation_counts\": "
    ++ natArrayJson ((List.range 11).map operationCount) ++ ",\n"
    ++ "  \"decoder_activity_mask_branches\": " ++ natArrayJson activityMaskBranches ++ ",\n"
    ++ "  \"decoder_authorization_mode_branches\": "
    ++ natArrayJson authorizationModeBranches ++ ",\n"
    ++ "  \"decoder_stablecoin_direction_branches\": "
    ++ natArrayJson stablecoinDirectionBranches ++ ",\n"
    ++ "  \"decoder_stable_tree_index_branches\": "
    ++ natArrayJson stableTreeIndexBranches ++ ",\n"
    ++ "  \"decoder_note_hash_word_order\": " ++ natArrayJson noteHashWordOrder ++ ",\n"
    ++ "  \"relowering_compared_packed_words\": "
    ++ toString reloweringComparedPackedWords ++ ",\n"
    ++ "  \"poseidon2_primitive_specification\": "
    ++ stringJson poseidon2V8PrimitiveSpecificationId ++ ",\n"
    ++ "  \"exact_poseidon2_primitive_interpretation_available\": "
    ++ boolJson checkedInExactPoseidon2PrimitiveInterpretationAvailable ++ ",\n"
    ++ "  \"poseidon2_sponge_kat_domain2_1_2_3_4\": "
    ++ natArrayJson (poseidon2V8Sponge poseidon2V8NullifierDomain [1, 2, 3, 4]) ++ ",\n"
    ++ "  \"poseidon2_compress14_kat_ranges\": "
    ++ natArrayJson (poseidon2V8Compress14 poseidon2V8MerkleDomain
      (List.range digestWords) ((List.range digestWords).map (fun value => value + digestWords)))
    ++ ",\n"
    ++ "  \"poseidon2_nullifier_kat\": "
    ++ natArrayJson (exactV8Nullifier 0 1 2 [3, 4, 5, 6]) ++ ",\n"
    ++ "  \"stablecoin_primitive_specification\": "
    ++ stringJson stablecoinV8PrimitiveSpecificationId ++ ",\n"
    ++ "  \"exact_stablecoin_transition_interpretation_available\": "
    ++ boolJson checkedInExactStablecoinTransitionInterpretationAvailable ++ ",\n"
    ++ "  \"stablecoin_config_digest_kat\": "
    ++ natArrayJson stablecoinV8KatConfigDigest ++ ",\n"
    ++ "  \"stablecoin_before_root_kat\": " ++ natArrayJson stablecoinV8KatBeforeRoot ++ ",\n"
    ++ "  \"stablecoin_mint_after_root_kat\": "
    ++ natArrayJson stablecoinV8MintKatPublic.afterRoot ++ ",\n"
    ++ "  \"stablecoin_burn_after_root_kat\": "
    ++ natArrayJson stablecoinV8BurnKatPublic.afterRoot ++ ",\n"
    ++ "  \"stablecoin_issuer_commitment_kat\": "
    ++ natArrayJson stablecoinV8KatConfig.issuerCommitment ++ ",\n"
    ++ "  \"stablecoin_issuer_authorization_kat\": "
    ++ natArrayJson stablecoinV8MintKatPublic.issuerAuthorization ++ ",\n"
    ++ "  \"stablecoin_mint_kat_accepts\": true,\n"
    ++ "  \"stablecoin_burn_kat_accepts\": true,\n"
    ++ "  \"ciphertext_primitive_specification\": "
    ++ stringJson ciphertextV8PrimitiveSpecificationId ++ ",\n"
    ++ "  \"exact_ciphertext_framing_and_projection_available\": "
    ++ boolJson checkedInExactCiphertextFramingAndProjectionAvailable ++ ",\n"
    ++ "  \"ciphertext_blake2b_kat_input\": " ++ natArrayJson ciphertextV8KatBytes ++ ",\n"
    ++ "  \"ciphertext_blake2b_kat_frame\": "
    ++ natArrayJson (exactV8CiphertextHashFrame ciphertextV8KatBytes) ++ ",\n"
    ++ "  \"ciphertext_blake2b_kat_digest\": "
    ++ natArrayJson ciphertextV8KatExpectedDigestBytes ++ ",\n"
    ++ "  \"ciphertext_blake2b_kat_commitment_words\": "
    ++ natArrayJson ciphertextV8KatExpectedCommitmentWords ++ ",\n"
    ++ "  \"exact_primitive_interpretation_refinement_proved\": "
    ++ boolJson checkedInExactPrimitiveInterpretationRefinementAvailable ++ ",\n"
    ++ "  \"universal_accepted_witness_soundness_proved\": false,\n"
    ++ "  \"production_authority\": false,\n"
    ++ "  \"verified_rust_semantics_extraction_absent\": true,\n"
    ++ "  \"in_lean_rfc7693_blake2b384_implementation_absent\": true,\n"
    ++ "  \"public_words\": " ++ toString publicWordCount ++ ",\n"
    ++ "  \"typed_witness_words\": " ++ toString typedWitnessWordCount ++ ",\n"
    ++ "  \"packed_witness_words\": " ++ toString packedWitnessWordCount ++ ",\n"
    ++ "  \"inputs\": " ++ toString inputCount ++ ",\n"
    ++ "  \"outputs\": " ++ toString outputCount ++ ",\n"
    ++ "  \"activity_masks\": 16,\n"
    ++ "  \"authorization_modes\": 3,\n"
    ++ "  \"merkle_depth\": " ++ toString merkleDepth ++ ",\n"
    ++ "  \"balance_slots\": " ++ toString balanceSlotCount ++ ",\n"
    ++ "  \"value_bound_exclusive\": " ++ toString valueBound ++ ",\n"
    ++ "  \"stablecoin_value_bound_exclusive\": " ++ toString stablecoinValueBound ++ ",\n"
    ++ "  \"stablecoin_scalar_bound_exclusive\": " ++ toString stablecoinScalarBound ++ ",\n"
    ++ "  \"ciphertext_bytes_per_active_output\": " ++ toString inlineCiphertextBytes ++ ",\n"
    ++ "  \"universal_soundness_obligations\": ["
    ++ String.intercalate ","
      ([ "canonical_public_statement", "canonical_witness_shape", "cryptographic_links",
          "per_asset_balance", "stablecoin_transition" ].map stringJson)
    ++ "],\n"
    ++ "  \"semantic_families\": " ++ semanticFamiliesJson ++ "\n"
    ++ "}\n"

def main : IO Unit := IO.print vectorJson
