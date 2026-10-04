import Hegemon.Native.NullifierAccumulator

open Hegemon.Native.NullifierAccumulator

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def nestedNatListJson (values : List (List Nat)) : String :=
  "[" ++ String.intercalate ", " (values.map natListJson) ++ "]"

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def vectorCaseJson (name : String) (blocks : List (List Nat)) : String :=
  let result := appendBlocks empty blocks
  let valid := result.isOk
  let leafCount := match result with
    | Except.ok state => state.leafCount
    | Except.error _ => 0
  let heights := match result with
    | Except.ok state => peakHeights state
    | Except.error _ => []
  let leaves := match result with
    | Except.ok state => peakLeaves state
    | Except.error _ => []
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"blocks\": " ++ nestedNatListJson blocks ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson valid ++ ",\n"
    ++ "      \"expected_leaf_count\": " ++ toString leafCount ++ ",\n"
    ++ "      \"expected_peak_heights\": " ++ natListJson heights ++ ",\n"
    ++ "      \"expected_peak_leaves\": " ++ nestedNatListJson leaves ++ ",\n"
    ++ "      \"expected_merge_counts\": " ++ natListJson (mergeCounts blocks) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 3,\n"
    ++ "  \"hash_algorithm\": \"RFC7693-BLAKE2b-384\",\n"
    ++ "  \"accumulator_version\": 3,\n"
    ++ "  \"nullifier_bytes\": 48,\n"
    ++ "  \"leaf_domain\": \"hegemon.nullifier-mmr.blake2b-384.leaf-v3\",\n"
    ++ "  \"node_domain\": \"hegemon.nullifier-mmr.blake2b-384.node-v3\",\n"
    ++ "  \"root_domain\": \"hegemon.nullifier-mmr.blake2b-384.root-v3\",\n"
    ++ "  \"state_domain\": \"hegemon.nullifier-mmr.blake2b-384.state-v3\",\n"
    ++ "  \"nullifier_accumulator_cases\": [\n"
    ++ vectorCaseJson "empty" [] ++ ",\n"
    ++ vectorCaseJson "singleton" [[1]] ++ ",\n"
    ++ vectorCaseJson "multi-block-with-empty" multiBlockFixture ++ ",\n"
    ++ vectorCaseJson "eight-leaf-carry" [[1, 2, 3], [], [4, 5], [6, 7, 8]] ++ ",\n"
    ++ vectorCaseJson "zero-rejected" [[1], [], [0, 2]] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
