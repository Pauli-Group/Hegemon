import Hegemon.Transaction.MerklePath

open Hegemon.Transaction

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def merkleCaseJson
    (name : String)
    (depth leaf position : Nat)
    (siblings : List Digest)
    (providedRoot : Digest) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"depth\": " ++ toString depth ++ ",\n"
    ++ "      \"leaf\": " ++ toString leaf ++ ",\n"
    ++ "      \"position\": " ++ toString position ++ ",\n"
    ++ "      \"siblings\": " ++ natListJson siblings ++ ",\n"
    ++ "      \"expected_fold_root\": "
      ++ toString (foldPathWith mockMerkleNode leaf position siblings) ++ ",\n"
    ++ "      \"provided_root\": " ++ toString providedRoot ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (verifyPathWithDepth mockMerkleNode depth leaf position siblings providedRoot) ++ "\n"
    ++ "    }"

def foldRoot (leaf position : Nat) (siblings : List Digest) : Digest :=
  foldPathWith mockMerkleNode leaf position siblings

def wrongRoot (leaf position : Nat) (siblings : List Digest) : Digest :=
  (foldRoot leaf position siblings + 1) % digestMod

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"merkle_path_cases\": [\n"
    ++ merkleCaseJson "depth-zero-empty-path" 0 7 0 [] (foldRoot 7 0 []) ++ ",\n"
    ++ merkleCaseJson "position-zero-left-left" 2 10 0 [20, 30] (foldRoot 10 0 [20, 30]) ++ ",\n"
    ++ merkleCaseJson "position-one-right-left" 2 10 1 [20, 30] (foldRoot 10 1 [20, 30]) ++ ",\n"
    ++ merkleCaseJson "position-two-left-right" 2 10 2 [20, 30] (foldRoot 10 2 [20, 30]) ++ ",\n"
    ++ merkleCaseJson "position-five-right-left-right" 3 11 5 [22, 33, 44] (foldRoot 11 5 [22, 33, 44]) ++ ",\n"
    ++ merkleCaseJson "wrong-root-rejected" 2 10 1 [20, 30] (wrongRoot 10 1 [20, 30]) ++ ",\n"
    ++ merkleCaseJson "wrong-length-rejected" 2 10 0 [20] (foldRoot 10 0 [20]) ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
