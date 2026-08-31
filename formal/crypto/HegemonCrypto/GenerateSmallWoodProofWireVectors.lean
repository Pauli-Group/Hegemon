import Hegemon.Bytes
import HegemonCrypto.SmallWoodNativeRefinement

namespace HegemonCrypto
namespace GenerateSmallWoodProofWireVectors

open CanonicalBytes
open SmallWoodProofWire
open SmallWoodProofWireExamples
open SmallWood.NativeRefinement

structure WireCase where
  name : String
  bytes : List Byte

def cases : List WireCase :=
  [ { name := "canonical-minimal", bytes := canonicalMinimalProof.encode },
    { name := "wrong-magic", bytes := wrongMagicBytes },
    { name := "trailing-byte", bytes := trailingBytes },
    { name := "zero-nonzero-matrix-shape", bytes := invalidZeroShapeProof.encode },
    { name := "excessive-matrix-rows", bytes := excessiveRowsProof.encode },
    { name := "noncanonical-field-word", bytes := noncanonicalFieldProof.encode },
    { name := "zero-length-auth-path", bytes := emptyAuthPathProof.encode },
    { name := "invalid-opened-witness-mode", bytes := invalidOpenedWitnessModeBytes } ]

def accepted (bytes : List Byte) : Bool :=
  (decodeProofExact bytes).isSome

def activeArtifactCases : List WireCase :=
  [ { name := "canonical-active-artifact", bytes := canonicalActiveArtifactBytes },
    { name := "trailing-outer-artifact", bytes := trailingOuterArtifactBytes },
    { name := "wrong-backend-artifact", bytes := wrongBackendArtifactBytes },
    { name := "missing-stark-inputs-artifact", bytes := missingStarkInputsArtifactBytes },
    { name := "wrong-circuit-version-artifact", bytes := wrongCircuitVersionArtifactBytes },
    { name := "wrong-crypto-suite-artifact", bytes := wrongCryptoSuiteArtifactBytes },
    { name := "wrong-arithmetization-artifact", bytes := wrongArithmetizationArtifactBytes },
    { name := "auxiliary-word-artifact", bytes := auxiliaryWordArtifactBytes },
    { name := "trailing-inner-proof-artifact", bytes := trailingInnerProofArtifactBytes },
    { name := "noncanonical-field-artifact", bytes := noncanonicalFieldArtifactBytes },
    { name := "empty-inner-proof-artifact", bytes := emptyInnerProofArtifactBytes } ]

def activeArtifactAccepted (bytes : List Byte) : Bool :=
  activeArtifactParserAccepts bytes

def hexBytes (bytes : List Byte) : String :=
  Hegemon.hexBytes (bytes.map Fin.val)

def renderCase (wireCase : WireCase) : String :=
  "    {\"name\": \"" ++ wireCase.name
    ++ "\", \"proof_hex\": \"" ++ hexBytes wireCase.bytes
    ++ "\", \"accepted\": " ++ toString (accepted wireCase.bytes) ++ "}"

def renderActiveArtifactCase (wireCase : WireCase) : String :=
  "    {\"name\": \"" ++ wireCase.name
    ++ "\", \"artifact_hex\": \"" ++ hexBytes wireCase.bytes
    ++ "\", \"accepted\": " ++
      toString (activeArtifactAccepted wireCase.bytes) ++ "}"

def render : String :=
  "{\n  \"schema_version\": 1,\n  \"cases\": [\n"
    ++ String.intercalate ",\n" (cases.map renderCase)
    ++ "\n  ],\n  \"active_artifact_cases\": [\n"
    ++ String.intercalate ",\n" (activeArtifactCases.map renderActiveArtifactCase)
    ++ "\n  ]\n}"

end GenerateSmallWoodProofWireVectors
end HegemonCrypto

def main : IO Unit :=
  IO.println HegemonCrypto.GenerateSmallWoodProofWireVectors.render
