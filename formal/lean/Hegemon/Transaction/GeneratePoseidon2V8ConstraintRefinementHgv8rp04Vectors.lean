import Hegemon.Transaction.Poseidon2V8ConstraintRefinementHgv8rp04

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8ConstraintRefinementHgv8rp04

def boolJson (value : Bool) : String := if value then "true" else "false"

def natArrayJson (values : List Nat) : String :=
  "[" ++ String.intercalate "," (values.map toString) ++ "]"

def stringJson (value : String) : String := "\"" ++ value ++ "\""

def callRoleJson (role : CallRoleRange) : String :=
  "{\"name\":" ++ stringJson role.name ++ ",\"start\":" ++ toString role.start
    ++ ",\"end\":" ++ toString role.stop ++ "}"

def callRolesJson : String :=
  "[" ++ String.intercalate "," (callRoleTable.map callRoleJson) ++ "]"

structure HashKernelGeometryVector where
  width : Nat
  statementWords : Nat
  bindingLimbs : Nat
  liveCalls : Nat
  paddedCalls : Nat
  groups : Nat
  sboxWiresPerCall : Nat
  rowsPerGroup : Nat
  constraintsPerGroup : Nat
  hashRows : Nat
  hashConstraints : Nat
  dummyZeroLinearConstraints : Nat
  hashRowStart : Nat
  stableRowStart : Nat
  stableRows : Nat
  relationRows : Nat
  packingFactor : Nat
  relationDegree : Nat
deriving DecidableEq, Repr

def activeHashKernelGeometry : HashKernelGeometryVector :=
  { width := Poseidon2Width16Kernel.width
    statementWords := publicStatementWordCount
    bindingLimbs := relationBindingLimbCount
    liveCalls := liveHashCallCount
    paddedCalls := paddedHashCallCount
    groups := hashGroupCount
    sboxWiresPerCall := Poseidon2Width16Kernel.sboxWiresPerCall
    rowsPerGroup := hashRowsPerGroup
    constraintsPerGroup := hashConstraintsPerGroup
    hashRows := hashRowCount
    hashConstraints := hashConstraintCount
    dummyZeroLinearConstraints := dummyZeroLinearConstraintCount
    hashRowStart := Poseidon2V8ConstraintRefinementHgv8rp04.hashRowStart
    stableRowStart := Poseidon2V8ConstraintRefinementHgv8rp04.stableRowStart
    stableRows := stableRowCount
    relationRows := relationRowCount
    packingFactor := Poseidon2V8ConstraintRefinementHgv8rp04.packingFactor
    relationDegree := relationConstraintDegree }

def hashKernelGeometryAccepts (candidate : HashKernelGeometryVector) : Bool :=
  decide (candidate = activeHashKernelGeometry)

def geometryJson (geometry : HashKernelGeometryVector) : String :=
  "{\"width\":" ++ toString geometry.width
    ++ ",\"statement_words\":" ++ toString geometry.statementWords
    ++ ",\"binding_limbs\":" ++ toString geometry.bindingLimbs
    ++ ",\"live_calls\":" ++ toString geometry.liveCalls
    ++ ",\"padded_calls\":" ++ toString geometry.paddedCalls
    ++ ",\"groups\":" ++ toString geometry.groups
    ++ ",\"sbox_wires_per_call\":" ++ toString geometry.sboxWiresPerCall
    ++ ",\"rows_per_group\":" ++ toString geometry.rowsPerGroup
    ++ ",\"constraints_per_group\":" ++ toString geometry.constraintsPerGroup
    ++ ",\"hash_rows\":" ++ toString geometry.hashRows
    ++ ",\"hash_constraints\":" ++ toString geometry.hashConstraints
    ++ ",\"dummy_zero_linear_constraints\":"
    ++ toString geometry.dummyZeroLinearConstraints
    ++ ",\"hash_row_start\":" ++ toString geometry.hashRowStart
    ++ ",\"stable_row_start\":" ++ toString geometry.stableRowStart
    ++ ",\"stable_rows\":" ++ toString geometry.stableRows
    ++ ",\"relation_rows\":" ++ toString geometry.relationRows
    ++ ",\"packing_factor\":" ++ toString geometry.packingFactor
    ++ ",\"relation_degree\":" ++ toString geometry.relationDegree ++ "}"

def mutationCaseJson (name : String) (candidate : HashKernelGeometryVector) : String :=
  "{\"name\":" ++ stringJson name ++ ",\"candidate\":" ++ geometryJson candidate
    ++ ",\"expected_hash_kernel_geometry_valid\":"
    ++ boolJson (hashKernelGeometryAccepts candidate) ++ "}"

def mutationCases : List (String × HashKernelGeometryVector) :=
  [ ("width", { activeHashKernelGeometry with width := 12 }),
    ("statement_words", { activeHashKernelGeometry with statementWords := 119 }),
    ("binding_limbs", { activeHashKernelGeometry with bindingLimbs := 6 }),
    ("live_calls", { activeHashKernelGeometry with liveCalls := 189 }),
    ("padded_calls", { activeHashKernelGeometry with paddedCalls := 192 }),
    ("groups", { activeHashKernelGeometry with groups := 3 }),
    ("sbox_wires", { activeHashKernelGeometry with sboxWiresPerCall := 149 }),
    ("rows_per_group", { activeHashKernelGeometry with rowsPerGroup := 181 }),
    ("constraints_per_group",
      { activeHashKernelGeometry with constraintsPerGroup := 165 }),
    ("hash_rows", { activeHashKernelGeometry with hashRows := 546 }),
    ("hash_constraints", { activeHashKernelGeometry with hashConstraints := 498 }),
    ("dummy_zero_bindings",
      { activeHashKernelGeometry with dummyZeroLinearConstraints := 47 }),
    ("hash_row_start", { activeHashKernelGeometry with hashRowStart := 282 }),
    ("stable_row_start", { activeHashKernelGeometry with stableRowStart := 829 }),
    ("stable_rows", { activeHashKernelGeometry with stableRows := 38 }),
    ("relation_rows", { activeHashKernelGeometry with relationRows := 868 }),
    ("packing_factor", { activeHashKernelGeometry with packingFactor := 63 }),
    ("relation_degree", { activeHashKernelGeometry with relationDegree := 7 }) ]

def rowIndexCaseJson (call stateLane : Nat) : String :=
  "{\"call\":" ++ toString call ++ ",\"state_lane\":" ++ toString stateLane
    ++ ",\"group\":" ++ toString (hashCallGroup call)
    ++ ",\"lane\":" ++ toString (hashCallLane call)
    ++ ",\"initial_witness_index\":"
    ++ toString (hashCallInitialWitnessIndex call stateLane)
    ++ ",\"final_witness_index\":"
    ++ toString (hashCallFinalWitnessIndex call stateLane) ++ "}"

def rowIndexCasesJson : String :=
  "[" ++ String.intercalate ","
    [ rowIndexCaseJson 0 0,
      rowIndexCaseJson 63 15,
      rowIndexCaseJson 64 0,
      rowIndexCaseJson 124 15,
      rowIndexCaseJson 125 0,
      rowIndexCaseJson 127 15 ] ++ "]"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema\": \"hegemon.poseidon2-v8.source-executable-refinement-rp04-v1\",\n"
    ++ "  \"claim_scope\": \"source_program_specialization_and_all_64_packed_lanes\",\n"
    ++ "  \"parameter_set_id\": "
    ++ stringJson Poseidon2Width16Kernel.parameterSetId ++ ",\n"
    ++ "  \"parameter_set_sha256\": "
    ++ stringJson Poseidon2Width16Kernel.parameterSetSha256 ++ ",\n"
    ++ "  \"semantic_target_id\": " ++ stringJson semanticTargetId ++ ",\n"
    ++ "  \"compiler_coverage\": \"source_executable_program_bound\",\n"
    ++ "  \"compiler_complete\": true,\n"
    ++ "  \"source_executable_program_refinement_available\": true,\n"
    ++ "  \"compiled_machine_refinement_available\": false,\n"
    ++ "  \"full_relation_receipt_available\": false,\n"
    ++ "  \"program_transcript_bytes\": "
    ++ toString Poseidon2V8RelationProgramHgv8rp04.canonicalProgramTranscriptBytes ++ ",\n"
    ++ "  \"program_sha512\": "
    ++ stringJson Poseidon2V8RelationProgramHgv8rp04.canonicalProgramSha512Hex ++ ",\n"
    ++ "  \"relation_id_48\": "
    ++ stringJson Poseidon2V8RelationProgramHgv8rp04.canonicalNativeRelationIdHex ++ ",\n"
    ++ "  \"nonlinear_expression_nodes\": 8130,\n"
    ++ "  \"nonlinear_roots\": 773,\n"
    ++ "  \"csr_expression_nodes\": 564,\n"
    ++ "  \"csr_attempts\": 20602,\n"
    ++ "  \"packed_nonlinear_lanes\": 64,\n"
    ++ "  \"geometry\": " ++ geometryJson activeHashKernelGeometry ++ ",\n"
    ++ "  \"call_roles\": " ++ callRolesJson ++ ",\n"
    ++ "  \"row_index_cases\": " ++ rowIndexCasesJson ++ ",\n"
    ++ "  \"zero_permutation\": "
    ++ natArrayJson (Poseidon2Width16Kernel.permutation
      (List.replicate Poseidon2Width16Kernel.width 0)) ++ ",\n"
    ++ "  \"sequential_permutation\": "
    ++ natArrayJson (Poseidon2Width16Kernel.permutation
      (List.range Poseidon2Width16Kernel.width)) ++ ",\n"
    ++ "  \"mutation_cases\": [\n    "
    ++ String.intercalate ",\n    "
      (mutationCases.map fun named => mutationCaseJson named.1 named.2)
    ++ "\n  ]\n"
    ++ "}\n"

def main : IO Unit := IO.print vectorJson
