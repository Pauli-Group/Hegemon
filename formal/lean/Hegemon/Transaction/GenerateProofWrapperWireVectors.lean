import Hegemon.Transaction.ProofWrapperWire

open Hegemon
open Hegemon.Transaction.ProofWrapperWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option ProofWrapperWireReject -> String
  | none => "null"
  | some ProofWrapperWireReject.parserRejected => "\"parser_rejected\""
  | some ProofWrapperWireReject.trailingBytes => "\"trailing_bytes\""
  | some ProofWrapperWireReject.nonCanonicalEncoding =>
      "\"non_canonical_encoding\""

def admissionRejectionJson : Option ProofWrapperWireAdmissionReject -> String
  | none => "null"
  | some ProofWrapperWireAdmissionReject.nullifierVectorMismatch =>
      "\"nullifier_vector_mismatch\""

def caseJson (case : ProofWrapperWireCase) : String :=
  let result := evaluateProofWrapperWireRejection case
  "    {\n"
    ++ "      \"name\": \"" ++ case.name ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes case.rawBytes ++ "\",\n"
    ++ "      \"canonical_hex\": \"" ++ hexBytes case.canonicalBytes ++ "\",\n"
    ++ "      \"expected_len\": " ++ toString case.rawBytes.length ++ ",\n"
    ++ "      \"parser_accepts\": " ++ boolJson case.parserAccepts ++ ",\n"
    ++ "      \"consumed_all_bytes\": " ++ boolJson case.consumedAllBytes ++ ",\n"
    ++ "      \"canonical_reencode_matches\": "
    ++ boolJson case.canonicalReencodeMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def casesJson : List ProofWrapperWireCase -> String
  | [] => ""
  | [case] => caseJson case
  | case :: rest => caseJson case ++ ",\n" ++ casesJson rest

def admissionCaseJson (case : ProofWrapperWireAdmissionCase) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ case.name ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes case.rawBytes ++ "\",\n"
    ++ "      \"canonical_hex\": \"" ++ hexBytes case.canonicalBytes ++ "\",\n"
    ++ "      \"expected_wire_valid\": " ++ boolJson case.wireAccepts ++ ",\n"
    ++ "      \"expected_admission_valid\": " ++ boolJson case.admissionAccepts ++ ",\n"
    ++ "      \"expected_admission_rejection\": "
    ++ admissionRejectionJson case.admissionReject ++ "\n"
    ++ "    }"

def admissionCasesJson : List ProofWrapperWireAdmissionCase -> String
  | [] => ""
  | [case] => admissionCaseJson case
  | case :: rest => admissionCaseJson case ++ ",\n" ++ admissionCasesJson rest

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 2,\n"
    ++ "  \"transaction_proof_wrapper_wire_cases\": [\n"
    ++ casesJson allCases ++ "\n"
    ++ "  ],\n"
    ++ "  \"transaction_proof_wrapper_wire_to_admission_cases\": [\n"
    ++ admissionCasesJson allWireToAdmissionCases ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
