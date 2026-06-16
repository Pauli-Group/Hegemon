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

def paddingBoundaryStatementBytes : List Byte :=
  patternedBytes 40 11

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"smallwood_binding_transcript_domain_hex\": \""
    ++ hexBytes smallwoodBindingTranscriptDomain ++ "\",\n"
    ++ "  \"smallwood_public_statement_domain_hex\": \""
    ++ hexBytes smallwoodPublicStatementDomain ++ "\",\n"
    ++ "  \"smallwood_field_xof_domain_hex\": \""
    ++ hexBytes smallwoodFieldXofDomain ++ "\",\n"
    ++ "  \"smallwood_transcript_binding_cases\": [\n"
    ++ transcriptCaseJson
      "active-inline-merkle-binding"
      activeCircuitVersion
      activeCryptoSuite
      arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
      activeCaseStatement ++ ",\n"
    ++ transcriptCaseJson
      "statement-byte-mutation-changes-binding"
      activeCircuitVersion
      activeCryptoSuite
      arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
      statementMutationBytes ++ ",\n"
    ++ transcriptCaseJson
      "version-mutation-changes-profile-material"
      (activeCircuitVersion + 1)
      activeCryptoSuite
      arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
      activeCaseStatement ++ ",\n"
    ++ transcriptCaseJson
      "legacy-direct-packed-arithmetization-changes-profile-material"
      activeCircuitVersion
      activeCryptoSuite
      arithDirectPacked64V1
      activeCaseStatement ++ ",\n"
    ++ transcriptCaseJson
      "padding-boundary-statement-remains-eight-byte-aligned"
      activeCircuitVersion
      activeCryptoSuite
      arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
      paddingBoundaryStatementBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

end SmallWoodTranscriptBinding
end Transaction
end Hegemon

def main : IO Unit :=
  IO.print Hegemon.Transaction.SmallWoodTranscriptBinding.vectorJson
