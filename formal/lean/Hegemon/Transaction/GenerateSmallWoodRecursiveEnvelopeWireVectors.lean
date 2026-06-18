import Hegemon.Transaction.SmallWoodRecursiveEnvelopeWire

open Hegemon
open Hegemon.Transaction.SmallWoodRecursiveEnvelopeWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def wireRejectionJson : Option RecursiveEnvelopeWireReject -> String
  | none => "null"
  | some RecursiveEnvelopeWireReject.parserRejected => "\"parser_rejected\""
  | some RecursiveEnvelopeWireReject.trailingBytes => "\"trailing_bytes\""
  | some RecursiveEnvelopeWireReject.nonCanonicalEncoding =>
      "\"non_canonical_encoding\""

def admissionRejectionJson :
    Option RecursiveEnvelopeAdmissionReject -> String
  | none => "null"
  | some RecursiveEnvelopeAdmissionReject.descriptorMismatch =>
      "\"descriptor_mismatch\""

def wireCaseJson (case : RecursiveEnvelopeWireCase) : String :=
  let result := evaluateRecursiveEnvelopeWire case
  "    {\n"
    ++ "      \"name\": \"" ++ case.name ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes case.rawBytes ++ "\",\n"
    ++ "      \"canonical_hex\": \"" ++ hexBytes case.canonicalBytes ++ "\",\n"
    ++ "      \"expected_len\": " ++ toString case.rawBytes.length ++ ",\n"
    ++ "      \"parser_accepts\": " ++ boolJson case.parserAccepts ++ ",\n"
    ++ "      \"consumed_all_bytes\": "
    ++ boolJson case.consumedAllBytes ++ ",\n"
    ++ "      \"canonical_reencode_matches\": "
    ++ boolJson case.canonicalReencodeMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ wireRejectionJson result ++ "\n"
    ++ "    }"

def admissionCaseJson
    (case : RecursiveEnvelopeAdmissionCase) : String :=
  let result := evaluateRecursiveEnvelopeAdmission case
  "    {\n"
    ++ "      \"name\": \"" ++ case.name ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes case.rawBytes ++ "\",\n"
    ++ "      \"expected_descriptor_hex\": \""
    ++ hexBytes case.expectedDescriptorBytes ++ "\",\n"
    ++ "      \"expected_wire_valid\": "
    ++ boolJson case.wireAccepts ++ ",\n"
    ++ "      \"descriptor_matches\": "
    ++ boolJson case.descriptorMatches ++ ",\n"
    ++ "      \"expected_admission_valid\": "
    ++ boolJson (result == none && case.wireAccepts = true) ++ ",\n"
    ++ "      \"expected_admission_rejection\": "
    ++ admissionRejectionJson result ++ "\n"
    ++ "    }"

def wireCasesJson : List RecursiveEnvelopeWireCase -> String
  | [] => ""
  | [case] => wireCaseJson case
  | case :: rest => wireCaseJson case ++ ",\n" ++ wireCasesJson rest

def admissionCasesJson : List RecursiveEnvelopeAdmissionCase -> String
  | [] => ""
  | [case] => admissionCaseJson case
  | case :: rest => admissionCaseJson case ++ ",\n" ++ admissionCasesJson rest

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"smallwood_recursive_envelope_wire_cases\": [\n"
    ++ wireCasesJson allWireCases ++ "\n"
    ++ "  ],\n"
    ++ "  \"smallwood_recursive_envelope_admission_cases\": [\n"
    ++ admissionCasesJson allAdmissionCases ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
