import Hegemon.Transaction.SmallWoodTranscriptBinding

namespace Hegemon
namespace Transaction
namespace SmallWoodTranscriptBinding

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def transcriptCaseJson
    (name : String)
    (circuitVersion cryptoSuite arithmetization : Nat)
    (statementBytes : List Byte) : String :=
  let profileMaterial :=
    smallwoodProfileMaterial circuitVersion cryptoSuite arithmetization
  let unpadded :=
    unpaddedTranscript circuitVersion cryptoSuite arithmetization statementBytes
  let transcript :=
    smallwoodTranscriptBinding circuitVersion cryptoSuite arithmetization statementBytes
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"circuit_version\": " ++ toString circuitVersion ++ ",\n"
    ++ "      \"crypto_suite\": " ++ toString cryptoSuite ++ ",\n"
    ++ "      \"arithmetization\": " ++ toString arithmetization ++ ",\n"
    ++ "      \"statement_bytes_hex\": \"" ++ hexBytes statementBytes ++ "\",\n"
    ++ "      \"expected_profile_material_hex\": \""
    ++ hexBytes profileMaterial ++ "\",\n"
    ++ "      \"expected_unpadded_transcript_hex\": \""
    ++ hexBytes unpadded ++ "\",\n"
    ++ "      \"expected_transcript_binding_hex\": \""
    ++ hexBytes transcript ++ "\",\n"
    ++ "      \"expected_padding_len\": "
    ++ toString (paddingLength unpadded) ++ ",\n"
    ++ "      \"expected_padding_bytes\": "
    ++ natListJson (paddingBytes unpadded) ++ ",\n"
    ++ "      \"expected_aligned_to_eight\": "
    ++ boolJson (transcript.length % 8 == 0) ++ "\n"
    ++ "    }"

def activeCaseStatement : List Byte :=
  sampleStatementBytes

def statementMutationBytes : List Byte :=
  patternedBytes 37 91

def trailingZeroExtensionStatementBytes : List Byte :=
  activeCaseStatement ++ [0]

def paddingBoundaryStatementBytes : List Byte :=
  patternedBytes 40 11

def deployedArithmetizationCases : List (String × Nat) :=
  [ ("bridge64-v1-profile-material", arithBridge64V1),
    ("direct-packed64-v1-profile-material", arithDirectPacked64V1),
    ("direct-packed64-compact-bindings-v1-profile-material",
      arithDirectPacked64CompactBindingsV1),
    ("direct-packed128-compact-bindings-v1-profile-material",
      arithDirectPacked128CompactBindingsV1),
    ("direct-packed16-compact-bindings-v1-profile-material",
      arithDirectPacked16CompactBindingsV1),
    ("direct-packed32-compact-bindings-v1-profile-material",
      arithDirectPacked32CompactBindingsV1),
    ("direct-packed64-compact-bindings-skip-initial-mds-v1-profile-material",
      arithDirectPacked64CompactBindingsSkipInitialMdsV1),
    ("direct-packed64-inline-merkle-compact-bindings-skip-initial-mds-v1-profile-material",
      arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1),
    ("direct-packed128-inline-merkle-compact-bindings-skip-initial-mds-v1-profile-material",
      arithDirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1) ]

def deployedArithmetizationCaseJsons : List String :=
  deployedArithmetizationCases.map fun case =>
    transcriptCaseJson
      case.1
      activeCircuitVersion
      activeCryptoSuite
      case.2
      activeCaseStatement

def vectorJson : String :=
  let coreCases :=
    [ transcriptCaseJson
        "active-inline-merkle-binding"
        activeCircuitVersion
        activeCryptoSuite
        arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        activeCaseStatement,
      transcriptCaseJson
        "statement-byte-mutation-changes-binding"
        activeCircuitVersion
        activeCryptoSuite
        arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        statementMutationBytes,
      transcriptCaseJson
        "trailing-zero-extension-changes-binding"
        activeCircuitVersion
        activeCryptoSuite
        arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        trailingZeroExtensionStatementBytes,
      transcriptCaseJson
        "version-mutation-changes-profile-material"
        (activeCircuitVersion + 1)
        activeCryptoSuite
        arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        activeCaseStatement,
      transcriptCaseJson
        "legacy-direct-packed-arithmetization-changes-profile-material"
        activeCircuitVersion
        activeCryptoSuite
        arithDirectPacked64V1
        activeCaseStatement,
      transcriptCaseJson
        "padding-boundary-statement-remains-eight-byte-aligned"
        activeCircuitVersion
        activeCryptoSuite
        arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        paddingBoundaryStatementBytes ]
  let cases := coreCases ++ deployedArithmetizationCaseJsons
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"smallwood_binding_transcript_domain_hex\": \""
    ++ hexBytes smallwoodBindingTranscriptDomain ++ "\",\n"
    ++ "  \"smallwood_public_statement_domain_hex\": \""
    ++ hexBytes smallwoodPublicStatementDomain ++ "\",\n"
    ++ "  \"smallwood_field_xof_domain_hex\": \""
    ++ hexBytes smallwoodFieldXofDomain ++ "\",\n"
    ++ "  \"smallwood_transcript_binding_cases\": [\n"
    ++ String.intercalate ",\n" cases ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

end SmallWoodTranscriptBinding
end Transaction
end Hegemon

def main : IO Unit :=
  IO.print Hegemon.Transaction.SmallWoodTranscriptBinding.vectorJson
