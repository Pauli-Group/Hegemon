import Hegemon.Bytes
import HegemonCrypto.SmallWoodSmz8ProofWire

namespace HegemonCrypto
namespace GenerateSmallWoodSmz8ProofWireVectors

open SmallWoodSmz8ProofWire
open SmallWoodSmz8ProofWire.Examples

structure WireCase where
  name : String
  bytes : List CanonicalBytes.Byte

def cases : List WireCase :=
  [ { name := "canonical-zero-length-paths", bytes := canonicalMinimalProof.encode },
    { name := "wrong-magic", bytes := wrongMagicBytes },
    { name := "wrong-path-count", bytes := wrongCountProof.encode },
    { name := "excessive-path-depth", bytes := excessiveDepthProof.encode },
    { name := "trailing-byte", bytes := trailingBytes } ]

def accepted (bytes : List CanonicalBytes.Byte) : Bool :=
  (decodeProofExact bytes).isSome

def hexBytes (bytes : List CanonicalBytes.Byte) : String :=
  Hegemon.hexBytes (bytes.map Fin.val)

def renderCase (wireCase : WireCase) : String :=
  "    {\"name\": \"" ++ wireCase.name
    ++ "\", \"proof_hex\": \"" ++ hexBytes wireCase.bytes
    ++ "\", \"accepted\": " ++ toString (accepted wireCase.bytes) ++ "}"

def render : String :=
  "{\n  \"schema_version\": 1,\n  \"profile\": {\n"
    ++ "    \"magic_ascii\": \"SMZ8\",\n"
    ++ "    \"opened_leaf_count\": " ++ toString openedLeafCount ++ ",\n"
    ++ "    \"opened_leaf_tape_bytes\": " ++ toString openedLeafTapeBytes ++ ",\n"
    ++ "    \"opened_leaf_tapes_bytes\": " ++ toString openedLeafTapesBytes ++ ",\n"
    ++ "    \"maximum_auth_path_depth\": " ++ toString maximumAuthPathDepth ++ ",\n"
    ++ "    \"maximum_inner_proof_bytes\": " ++ toString maximumInnerProofBytes ++ "\n"
    ++ "  },\n  \"cases\": [\n"
    ++ String.intercalate ",\n" (cases.map renderCase)
    ++ "\n  ]\n}"

end GenerateSmallWoodSmz8ProofWireVectors
end HegemonCrypto

def main : IO Unit :=
  IO.println HegemonCrypto.GenerateSmallWoodSmz8ProofWireVectors.render
