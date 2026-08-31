import Hegemon.Transaction.Poseidon2V8RelationProgram

namespace Hegemon
namespace Transaction
namespace GeneratePoseidon2V8RelationProgramVectors

open Poseidon2V8RelationProgram

def natArrayJson (values : List Nat) : String :=
  "[" ++ String.intercalate "," (values.map toString) ++ "]"

def stringJson (value : String) : String :=
  "\"" ++ value ++ "\""

def sectionNames : List String :=
  [ "geometry",
    "public_map_version_domain",
    "poseidon_parameter_manifest_digest",
    "ordered_nonlinear_identities",
    "linear_csr_compiler_families_and_symbolic_targets",
    "hash_schedule_and_call_roles",
    "binding_descriptors",
    "executable_nonlinear_expression_program",
    "executable_csr_expression_and_attempt_program" ]

def mutationCases : List (String × Bool) :=
  [ ("magic", true),
    ("grammar", true),
    ("section_order", true),
    ("section_tag", true),
    ("section_item_count", true),
    ("section_payload_length", true),
    ("geometry", true),
    ("public_map_descriptor", true),
    ("poseidon_parameter_manifest_digest", true),
    ("nonlinear_identity_descriptor", true),
    ("nonlinear_identity_order", true),
    ("linear_offset", true),
    ("linear_index", true),
    ("linear_coefficient", true),
    ("symbolic_public_target", true),
    ("linear_compiler_family", true),
    ("linear_compiler_family_order", true),
    ("hash_call_role", true),
    ("binding_descriptor", true),
    ("nonlinear_expression_opcode", true),
    ("nonlinear_expression_operand", true),
    ("nonlinear_expression_root", true),
    ("csr_expression_opcode", true),
    ("csr_expression_operand", true),
    ("csr_attempt_global", true),
    ("csr_attempt_family", true),
    ("csr_attempt_local", true),
    ("csr_attempt_emission", true),
    ("csr_witness_index", true),
    ("csr_coefficient_root", true),
    ("csr_target_root", true),
    ("statement_numeric_value", false) ]

def mutationCaseJson (entry : String × Bool) : String :=
  "{\"name\":" ++ stringJson entry.1 ++
    ",\"expected_relation_id_change\":" ++
    (if entry.2 then "true" else "false") ++ "}"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema\": \"hegemon.poseidon2-v8.relation-program-transcript-v2\",\n"
    ++ "  \"claim_scope\": \"canonical_statement_independent_executable_program_identity_kat\",\n"
    ++ "  \"artifact_available\": true,\n"
    ++ "  \"magic_ascii\": \"HGV8RP03\",\n"
    ++ "  \"magic_bytes\": " ++ natArrayJson transcriptMagic ++ ",\n"
    ++ "  \"grammar\": " ++ toString transcriptGrammar ++ ",\n"
    ++ "  \"header_bytes\": "
    ++ natArrayJson (transcriptMagic ++ u16le transcriptGrammar ++ u16le transcriptSectionCount)
    ++ ",\n"
    ++ "  \"hash\": \"SHA-512\",\n"
    ++ "  \"digest_bytes\": " ++ toString transcriptDigestBytes ++ ",\n"
    ++ "  \"native_relation_id_derivation\": \"sha512_digest_prefix\",\n"
    ++ "  \"native_relation_id_bytes\": " ++ toString nativeRelationIdBytes ++ ",\n"
    ++ "  \"transcript_bytes\": " ++ toString canonicalProgramTranscriptBytes ++ ",\n"
    ++ "  \"section_header\": \"u16le_tag_u32le_item_count_u64le_payload_bytes\",\n"
    ++ "  \"section_header_bytes\": 14,\n"
    ++ "  \"section_tags\": [1,2,3,4,5,6,7,8,9],\n"
    ++ "  \"section_names\": ["
    ++ String.intercalate "," (sectionNames.map stringJson) ++ "],\n"
    ++ "  \"descriptor_opcodes\": {\"public_identity\":513,\"public_range\":514,"
    ++ "\"intent_zero_range\":515,\"domain_or_marker\":516,"
    ++ "\"compiler_normalization\":517,\"nonlinear_identity\":1025,"
    ++ "\"linear_csr_family\":1281,\"sponge_call\":1537,"
    ++ "\"compress14_call\":1538,\"binding_start\":1793,\"binding_stop\":2048},\n"
    ++ "  \"exact_binding_opcodes\": [1793,1794,1795,1796,1797,1798,1799,1800],\n"
    ++ "  \"exact_binding_descriptors\": ["
    ++ "{\"opcode\":1793,\"words\":[8,7,1,10,2,6,4],\"label\":\"hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2\\u0000SMZ9\"},"
    ++ "{\"opcode\":1794,\"words\":[120,18446744069414584321],\"label\":\"HGV8TX02.statement[0,120)->verifier.public[0,120);canonical-goldilocks\"},"
    ++ "{\"opcode\":1795,\"words\":[7,87,94],\"label\":\"relation.binding[0,7)=expected-action-intent=call[93].final[0,7)\"},"
    ++ "{\"opcode\":1796,\"words\":[0,247,247,5,252,31,283,364,647,39,686],\"label\":\"rows=raw[0,247);dense[247,252);inline[252,283);hash[283,647);stable[647,686)\"},"
    ++ "{\"opcode\":1797,\"words\":[125,128,16,48],\"label\":\"calls[125,128).initial[0,16)=0\"},"
    ++ "{\"opcode\":1798,\"words\":[0],\"label\":\"auxiliary-witness-words=0\"},"
    ++ "{\"opcode\":1799,\"words\":[64,8,830,19899,20473,21303,5,6,2,23,20,5],\"label\":\"DirectPacked64Poseidon2V8Sha512Smz9\\u0000Sha512Poseidon2V8Smz9\\u0000rho5-open6-beta2-N23-q20-eta5\"},"
    ++ "{\"opcode\":1800,\"words\":[64,48],\"label\":\"SHA-512\\u0000HGV8RP03-canonical-executable-program-prefix[0,48)\"}],\n"
    ++ "  \"compound_label_separator_byte\": 0,\n"
    ++ "  \"public_descriptor_count\": 56,\n"
    ++ "  \"public_descriptor_opcode_runs\": [[513,1],[514,28],[515,4],[516,22],[517,1]],\n"
    ++ "  \"poseidon_parameter_set_sha256_bytes\": "
    ++ natArrayJson poseidonParameterSetSha256 ++ ",\n"
    ++ "  \"fixed_geometry\": {\"statement_words\":120,\"binding_limbs\":7,"
    ++ "\"relation_rows\":686,\"proof_geometry_columns\":368,"
    ++ "\"live_hash_calls\":125,\"padded_hash_calls\":128,"
    ++ "\"nonlinear_identities\":830,\"minimum_linear_constraints\":19899,"
    ++ "\"maximum_linear_constraints\":20473,"
    ++ "\"maximum_summed_identity_union\":21303,"
    ++ "\"linear_compiler_families\":86,\"linear_compiler_family_instances\":20569,"
    ++ "\"nonlinear_expression_nodes\":8271,\"nonlinear_expression_roots\":830,"
    ++ "\"csr_expression_nodes\":565,\"csr_expression_roots\":0,"
    ++ "\"hash_call_descriptors\":125,"
    ++ "\"global_binding_descriptors\":8,\"packed_witness_words\":43904},\n"
    ++ "  \"statement_values_serialized\": false,\n"
    ++ "  \"final_program_sha512\": " ++ stringJson canonicalProgramSha512Hex ++ ",\n"
    ++ "  \"final_relation_id_48\": " ++ stringJson canonicalNativeRelationIdHex ++ ",\n"
    ++ "  \"source_recomputation_required\": true,\n"
    ++ "  \"mutation_cases\": [\n    "
    ++ String.intercalate ",\n    " (mutationCases.map mutationCaseJson)
    ++ "\n  ]\n"
    ++ "}\n"

end GeneratePoseidon2V8RelationProgramVectors
end Transaction
end Hegemon

def main : IO Unit :=
  IO.print Hegemon.Transaction.GeneratePoseidon2V8RelationProgramVectors.vectorJson
