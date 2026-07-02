import Hegemon.Native.Risc0ReleaseVerifier

open Hegemon.Native.Risc0ReleaseVerifier

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option Risc0ReleaseReject -> String
  | none => "null"
  | some Risc0ReleaseReject.imageIdMismatch => "\"image_id_mismatch\""
  | some Risc0ReleaseReject.journalDecodeFailed => "\"journal_decode_failed\""
  | some Risc0ReleaseReject.verifierDisabled => "\"verifier_disabled\""

def risc0ReleaseCaseJson (name : String) (input : Risc0ReleaseInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"image_id_matches\": " ++ boolJson input.imageIdMatches ++ ",\n"
    ++ "      \"journal_decodes\": " ++ boolJson input.journalDecodes ++ ",\n"
    ++ "      \"verifier_enabled\": " ++ boolJson input.verifierEnabled ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (risc0ReleaseVerifierAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (risc0ReleaseVerifierRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"risc0_release_verifier_cases\": [\n"
    ++ risc0ReleaseCaseJson "future-verifier-enabled-accepts"
      validFutureVerifier ++ ",\n"
    ++ risc0ReleaseCaseJson "release-disabled-after-prechecks"
      releaseDisabledVerifier ++ ",\n"
    ++ risc0ReleaseCaseJson "image-id-mismatch-precedes-decode"
      { releaseDisabledVerifier with
        imageIdMatches := false,
        journalDecodes := false } ++ ",\n"
    ++ risc0ReleaseCaseJson "journal-decode-failure-precedes-disabled"
      { releaseDisabledVerifier with journalDecodes := false } ++ ",\n"
    ++ risc0ReleaseCaseJson "image-id-mismatch-precedes-enabled"
      { validFutureVerifier with imageIdMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
